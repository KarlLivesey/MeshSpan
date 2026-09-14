// SPDX-License-Identifier: GPL-2.0-only

//! Dedicated federation mTLS socket with replaceable admission roots and no node-protocol ALPN.

use crate::{NodeCredentials, TransportError, TransportLimits};
use rustls::RootCertStore;
use std::{net::SocketAddr, sync::RwLock};

const ALPN: &[u8] = b"meshspan-federation/1";

/// One federation-only QUIC socket. An empty trust set disables new connections.
///
/// TLS roots admit only a handshake; the caller must additionally authenticate the
/// exact committed certificate, relationship and signed session before serving data.
/// Existing connections must be revalidated/closed by that caller after authority changes.
pub struct FederationEndpoint {
    endpoint: quinn::Endpoint,
    credentials: NodeCredentials,
    limits: TransportLimits,
    client: RwLock<Option<quinn::ClientConfig>>,
}

impl FederationEndpoint {
    /// Binds without accepting or initiating peer connections until trust is installed.
    /// # Errors
    /// Rejects invalid socket configuration or binding failure.
    pub fn bind(
        address: SocketAddr,
        credentials: NodeCredentials,
        limits: TransportLimits,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            endpoint: crate::tls::endpoint(address, None)?,
            credentials,
            limits,
            client: RwLock::new(None),
        })
    }

    /// Replaces handshake trust without rebinding the UDP socket or dropping established IO.
    /// An empty root set disables both incoming and outgoing handshakes.
    /// # Errors
    /// Rejects unusable credentials/roots/limits or unavailable configuration state.
    pub fn replace_trust(&self, roots: RootCertStore) -> Result<(), TransportError> {
        let configs = if roots.is_empty() {
            None
        } else {
            Some((
                crate::tls::prepare_server_config_with_alpn(
                    self.credentials_copy()?,
                    roots.clone(),
                    self.limits,
                    ALPN,
                    Some(std::time::Duration::from_secs(5)),
                )?,
                crate::tls::prepare_client_config_with_alpn(
                    self.credentials_copy()?,
                    roots,
                    self.limits,
                    ALPN,
                    Some(std::time::Duration::from_secs(5)),
                )?,
            ))
        };
        let mut client = self
            .client
            .write()
            .map_err(|_| TransportError::InvalidConfiguration)?;
        if let Some((server, outgoing)) = configs {
            self.endpoint.set_server_config(Some(server));
            *client = Some(outgoing);
        } else {
            self.endpoint.set_server_config(None);
            *client = None;
        }
        Ok(())
    }

    /// Waits for an incoming handshake; the owner must apply a deadline to its completion.
    pub async fn accept(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept().await
    }

    /// Initiates mutual TLS using the currently installed federation trust.
    /// # Errors
    /// Rejects absent trust, malformed names or failed handshakes. Callers bound the deadline.
    pub async fn connect(
        &self,
        address: SocketAddr,
        certificate_name: &str,
    ) -> Result<quinn::Connection, TransportError> {
        if certificate_name.is_empty() || certificate_name.len() > 253 {
            return Err(TransportError::InvalidConfiguration);
        }
        let config = self
            .client
            .read()
            .map_err(|_| TransportError::InvalidConfiguration)?
            .clone()
            .ok_or(TransportError::InvalidConfiguration)?;
        Ok(self
            .endpoint
            .connect_with(config, address, certificate_name)?
            .await?)
    }

    /// Returns the bound address, including an operating-system-selected port.
    /// # Errors
    /// Reports a socket address lookup failure.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(TransportError::Io)
    }

    /// Stops handshakes and closes all connections owned by this endpoint.
    pub fn close(&self) {
        self.endpoint
            .close(0_u32.into(), b"federation endpoint stopped");
    }

    /// Waits until closed connections have completed the QUIC drain period.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }

    fn credentials_copy(&self) -> Result<NodeCredentials, TransportError> {
        NodeCredentials::new(
            self.credentials.certificate_chain.clone(),
            self.credentials.private_key.clone_key(),
        )
    }
}
