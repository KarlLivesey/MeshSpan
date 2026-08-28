// SPDX-License-Identifier: GPL-2.0-only

//! Quinn endpoint construction with mandatory bidirectional certificate verification.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
};
use thiserror::Error;

use meshspan_protocol::WireLimits;

const ALPN: &[u8] = b"meshspan-private/1";

/// One node's certificate chain and private identity key.
pub struct NodeCredentials {
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl NodeCredentials {
    /// Wraps a non-empty node certificate chain and its private key.
    ///
    /// # Errors
    ///
    /// Rejects an empty or excessively deep chain before TLS construction.
    pub fn new(
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, TransportError> {
        if certificate_chain.is_empty() || certificate_chain.len() > 8 {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self {
            certificate_chain,
            private_key,
        })
    }
}

/// Negotiated/resource-aware stream and flow-control bounds.
#[derive(Clone, Copy, Debug)]
pub struct TransportLimits {
    /// Private control-message framing limits.
    pub wire: WireLimits,
    /// Configurable per-peer bidirectional stream concurrency.
    pub maximum_bidirectional_streams: u32,
    /// Receive credit reserved independently for each stream.
    pub stream_receive_window: u32,
    /// Aggregate receive credit for one peer connection.
    pub connection_receive_window: u32,
}

impl TransportLimits {
    /// Validates non-zero resource-derived transport limits.
    ///
    /// # Errors
    ///
    /// Rejects zero stream/window values or a connection window smaller than one stream.
    pub const fn new(
        wire: WireLimits,
        maximum_bidirectional_streams: u32,
        stream_receive_window: u32,
        connection_receive_window: u32,
    ) -> Result<Self, TransportError> {
        if maximum_bidirectional_streams == 0
            || stream_receive_window == 0
            || connection_receive_window < stream_receive_window
        {
            Err(TransportError::InvalidConfiguration)
        } else {
            Ok(Self {
                wire,
                maximum_bidirectional_streams,
                stream_receive_window,
                connection_receive_window,
            })
        }
    }
}

/// Creates a listening QUIC endpoint requiring a certificate rooted in `client_roots`.
///
/// # Errors
///
/// Rejects invalid certificates, keys, trust roots, limits or socket binding failure.
pub fn server_endpoint(
    bind_address: SocketAddr,
    credentials: NodeCredentials,
    client_roots: RootCertStore,
    limits: TransportLimits,
) -> Result<Endpoint, TransportError> {
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|_| TransportError::InvalidConfiguration)?;
    let mut tls = RustlsServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(credentials.certificate_chain, credentials.private_key)
        .map_err(|_| TransportError::InvalidConfiguration)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        QuicServerConfig::try_from(tls).map_err(|_| TransportError::InvalidConfiguration)?;
    let mut server = ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(transport_config(limits)?);
    Endpoint::server(server, bind_address).map_err(TransportError::Io)
}

/// Creates a client endpoint presenting its node certificate and trusting `server_roots`.
///
/// # Errors
///
/// Rejects invalid certificates, keys, trust roots, limits or socket binding failure.
pub fn client_endpoint(
    bind_address: SocketAddr,
    credentials: NodeCredentials,
    server_roots: RootCertStore,
    limits: TransportLimits,
) -> Result<Endpoint, TransportError> {
    let mut tls = RustlsClientConfig::builder()
        .with_root_certificates(server_roots)
        .with_client_auth_cert(credentials.certificate_chain, credentials.private_key)
        .map_err(|_| TransportError::InvalidConfiguration)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        QuicClientConfig::try_from(tls).map_err(|_| TransportError::InvalidConfiguration)?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    client.transport_config(transport_config(limits)?);
    let mut endpoint = Endpoint::client(bind_address).map_err(TransportError::Io)?;
    endpoint.set_default_client_config(client);
    Ok(endpoint)
}

/// Connects to one peer using the certificate DNS name fixed by enrolment.
///
/// # Errors
///
/// Reports local connection setup or authenticated QUIC handshake failure.
pub async fn connect(
    endpoint: &Endpoint,
    remote_address: SocketAddr,
    certificate_name: &str,
) -> Result<Connection, TransportError> {
    if certificate_name.is_empty() || certificate_name.len() > 253 {
        return Err(TransportError::InvalidConfiguration);
    }
    Ok(endpoint.connect(remote_address, certificate_name)?.await?)
}

fn transport_config(limits: TransportLimits) -> Result<Arc<TransportConfig>, TransportError> {
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(limits.maximum_bidirectional_streams));
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.stream_receive_window(
        VarInt::from_u64(u64::from(limits.stream_receive_window))
            .map_err(|_| TransportError::InvalidConfiguration)?,
    );
    transport.receive_window(
        VarInt::from_u64(u64::from(limits.connection_receive_window))
            .map_err(|_| TransportError::InvalidConfiguration)?,
    );
    Ok(Arc::new(transport))
}

/// Stable transport boundary failures without certificate or message contents.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Configuration, key material, trust roots or resource limits are invalid.
    #[error("private transport configuration is invalid")]
    InvalidConfiguration,
    /// UDP endpoint creation or binding failed.
    #[error("private transport socket failed")]
    Io(#[source] io::Error),
    /// A connection could not be initiated.
    #[error("private transport connection setup failed")]
    Connect(#[from] quinn::ConnectError),
    /// The QUIC/TLS handshake or established connection failed.
    #[error("private transport connection failed")]
    Connection(#[from] quinn::ConnectionError),
    /// Writing a bounded stream failed.
    #[error("private transport stream write failed")]
    Write(#[from] quinn::WriteError),
    /// Finishing a bounded stream failed.
    #[error("private transport stream finish failed")]
    Finish(#[from] quinn::ClosedStream),
    /// Reading an exact bounded stream prefix or payload failed.
    #[error("private transport stream read failed")]
    Read(#[from] quinn::ReadExactError),
    /// A peer certificate or claimed enrolled identity did not match.
    #[error("private transport peer identity is not trusted")]
    UntrustedPeer,
    /// A stream kind or frame violates the private wire contract.
    #[error("private transport stream frame is invalid")]
    InvalidFrame,
    /// Authenticated peers do not share an exact supported protocol version.
    #[error("private transport protocol version is unsupported")]
    UnsupportedProtocol,
    /// Snapshot identity, offset, bound or digest verification failed.
    #[error("private transport snapshot was rejected")]
    SnapshotRejected,
    /// Protobuf framing or semantic validation rejected the message.
    #[error("private transport wire contract rejected the message")]
    Wire(#[from] meshspan_protocol::WireContractError),
}
