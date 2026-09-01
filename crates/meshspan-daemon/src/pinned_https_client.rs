// SPDX-License-Identifier: GPL-2.0-only

//! Minimal bounded TLS 1.3 HTTP/1.1 client authenticated by an exact invitation pin.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use axum::http::Uri;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAXIMUM_HEADER_BYTES: usize = 16 * 1_024;

pub(crate) async fn post_pinned_json(
    origin: &str,
    route: &str,
    certificate_fingerprint: [u8; 32],
    body: &[u8],
    maximum_response_bytes: usize,
) -> Result<Vec<u8>, PinnedHttpsClientError> {
    if certificate_fingerprint == [0; 32]
        || body.is_empty()
        || route.is_empty()
        || !route.starts_with('/')
    {
        return Err(PinnedHttpsClientError::InvalidRequest);
    }
    let uri: Uri = origin
        .parse()
        .map_err(|_| PinnedHttpsClientError::InvalidRequest)?;
    if uri.scheme_str() != Some("https") || uri.path() != "/" || uri.query().is_some() {
        return Err(PinnedHttpsClientError::InvalidRequest);
    }
    let authority = uri
        .authority()
        .ok_or(PinnedHttpsClientError::InvalidRequest)?;
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(443);
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| PinnedHttpsClientError::Unavailable)?
        .map_err(|_| PinnedHttpsClientError::Unavailable)?;
    let provider = Arc::new(meshspan_rustls_provider::provider());
    let verifier = Arc::new(PinnedCertificateVerifier {
        expected: certificate_fingerprint,
        provider: Arc::clone(&provider),
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| PinnedHttpsClientError::InvalidRequest)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| PinnedHttpsClientError::InvalidRequest)?;
    let mut tls = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(Arc::new(config)).connect(server_name, stream),
    )
    .await
    .map_err(|_| PinnedHttpsClientError::Unavailable)?
    .map_err(|_| PinnedHttpsClientError::Rejected)?;
    let request = request_head(authority.as_str(), route, body.len())?;
    tokio::time::timeout(IO_TIMEOUT, async {
        tls.write_all(&request).await?;
        tls.write_all(body).await?;
        tls.flush().await
    })
    .await
    .map_err(|_| PinnedHttpsClientError::Unavailable)?
    .map_err(|_| PinnedHttpsClientError::Unavailable)?;
    let limit = maximum_response_bytes
        .checked_add(MAXIMUM_HEADER_BYTES)
        .ok_or(PinnedHttpsClientError::InvalidRequest)?;
    let mut response = Vec::with_capacity(limit.min(64 * 1_024));
    tokio::time::timeout(
        IO_TIMEOUT,
        tls.take(u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX))
            .read_to_end(&mut response),
    )
    .await
    .map_err(|_| PinnedHttpsClientError::Unavailable)?
    .map_err(|_| PinnedHttpsClientError::Unavailable)?;
    if response.len() > limit {
        return Err(PinnedHttpsClientError::InvalidResponse);
    }
    parse_response(&response, maximum_response_bytes)
}

fn request_head(
    host: &str,
    route: &str,
    body_length: usize,
) -> Result<Vec<u8>, PinnedHttpsClientError> {
    if host.bytes().any(|byte| byte.is_ascii_control())
        || route
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(PinnedHttpsClientError::InvalidRequest);
    }
    Ok(format!(
        "POST {route} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {body_length}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes())
}

fn parse_response(
    response: &[u8],
    maximum_body_bytes: usize,
) -> Result<Vec<u8>, PinnedHttpsClientError> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(PinnedHttpsClientError::InvalidResponse)?;
    if split > MAXIMUM_HEADER_BYTES {
        return Err(PinnedHttpsClientError::InvalidResponse);
    }
    let headers = std::str::from_utf8(&response[..split])
        .map_err(|_| PinnedHttpsClientError::InvalidResponse)?;
    let mut lines = headers.split("\r\n");
    if lines.next() != Some("HTTP/1.1 201 Created") {
        return Err(PinnedHttpsClientError::Rejected);
    }
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(PinnedHttpsClientError::InvalidResponse);
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(PinnedHttpsClientError::InvalidResponse);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(PinnedHttpsClientError::InvalidResponse);
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| PinnedHttpsClientError::InvalidResponse)?,
            );
        }
    }
    let body = response
        .get(split + 4..)
        .ok_or(PinnedHttpsClientError::InvalidResponse)?;
    if content_length != Some(body.len()) || body.is_empty() || body.len() > maximum_body_bytes {
        return Err(PinnedHttpsClientError::InvalidResponse);
    }
    Ok(body.to_vec())
}

struct PinnedCertificateVerifier {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for PinnedCertificateVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedCertificateVerifier")
    }
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if intermediates.len() <= 8
            && <[u8; 32]>::from(Sha256::digest(end_entity.as_ref())) == self.expected
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum PinnedHttpsClientError {
    #[error("pinned HTTPS request is invalid")]
    InvalidRequest,
    #[error("pinned HTTPS endpoint is unavailable")]
    Unavailable,
    #[error("pinned HTTPS peer or request was rejected")]
    Rejected,
    #[error("pinned HTTPS response is invalid")]
    InvalidResponse,
}
