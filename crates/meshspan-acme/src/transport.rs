// SPDX-License-Identifier: GPL-2.0-only

//! Concrete ACME adapter over the shared bounded rustls HTTP transport.

use std::{future::Future, sync::Arc, time::Duration};

use hyper::Method;
use rustls::ClientConfig;

use crate::{
    AcmeHttpMethod, AcmeHttpResponse, AcmeResponseHeaders, AcmeTransport, AcmeTransportError,
    AcmeTransportRequest,
    rustls_http::{RustlsHttpClient, RustlsHttpError, RustlsHttpRequest},
};

const USER_AGENT_VALUE: &str = "MeshSpan/0.1 ACME";

/// Direct userspace ACME client using injected rustls trust and no external proxy or service.
pub struct RustlsAcmeTransport {
    client: RustlsHttpClient,
}

impl RustlsAcmeTransport {
    /// Creates a transport with explicit finite connection and whole-request deadlines.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive timeouts.
    pub fn new(
        tls: Arc<ClientConfig>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, AcmeTransportError> {
        RustlsHttpClient::new(tls, connect_timeout, request_timeout)
            .map(|client| Self { client })
            .map_err(map_error)
    }

    async fn exchange(
        &self,
        request: &AcmeTransportRequest,
    ) -> Result<AcmeHttpResponse, AcmeTransportError> {
        let method = match request.method {
            AcmeHttpMethod::Get => Method::GET,
            AcmeHttpMethod::Head => Method::HEAD,
            AcmeHttpMethod::Post => Method::POST,
        };
        let response = self
            .client
            .send(RustlsHttpRequest {
                method,
                url: &request.url,
                body: &request.body,
                content_type: request.content_type,
                bearer_token: None,
                user_agent: USER_AGENT_VALUE,
            })
            .await
            .map_err(map_error)?;
        AcmeHttpResponse::new(
            response.status,
            AcmeResponseHeaders::new(response.headers).map_err(|_| AcmeTransportError::Rejected)?,
            response.body,
        )
        .map_err(|_| AcmeTransportError::Rejected)
    }
}

impl AcmeTransport for RustlsAcmeTransport {
    fn send(
        &mut self,
        request: &AcmeTransportRequest,
    ) -> impl Future<Output = Result<AcmeHttpResponse, AcmeTransportError>> + Send {
        self.exchange(request)
    }
}

const fn map_error(error: RustlsHttpError) -> AcmeTransportError {
    match error {
        RustlsHttpError::Unavailable => AcmeTransportError::Unavailable,
        RustlsHttpError::InvalidRequest | RustlsHttpError::Rejected => AcmeTransportError::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, sync::Arc};

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{Request, Response, header::HeaderValue, service::service_fn};
    use hyper_util::rt::TokioIo;
    use meshspan_test_certificates::CertificateAuthority;
    use rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    };
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[tokio::test]
    async fn transport_performs_a_real_bounded_tls_http_exchange()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = CertificateAuthority::new()?;
        let issued = authority.issue_node("localhost")?.into_parts();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server_config = server_config(&issued)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(|_| "accept failed")?;
            let tls = TlsAcceptor::from(Arc::new(server_config))
                .accept(tcp)
                .await
                .map_err(|_| "TLS accept failed")?;
            let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
                let body = format!("{} {}", request.method(), request.uri());
                let mut response = Response::new(Full::new(Bytes::from(body)));
                response.headers_mut().insert(
                    "replay-nonce",
                    HeaderValue::from_static("nonce_from_server"),
                );
                Ok::<_, Infallible>(response)
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await
                .map_err(|_| "HTTP serve failed")
        });
        let mut transport = RustlsAcmeTransport::new(
            Arc::new(client_config(authority.certificate_der())?),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )?;
        let response = transport
            .send(&AcmeTransportRequest {
                method: AcmeHttpMethod::Get,
                url: format!("https://localhost:{}/directory?test=1", address.port()),
                body: Vec::new(),
                content_type: None,
            })
            .await?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"GET /directory?test=1");
        assert_eq!(
            crate::AcmeWire::replay_nonce(&response)?,
            "nonce_from_server"
        );
        server.await??;
        Ok(())
    }

    fn server_config(
        issued: &(Vec<u8>, Vec<u8>),
    ) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let provider = Arc::new(meshspan_rustls_provider::provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(issued.0.clone())],
                PrivatePkcs8KeyDer::from(issued.1.clone()).into(),
            )?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }

    fn client_config(authority: &[u8]) -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(authority.to_vec()))?;
        let provider = Arc::new(meshspan_rustls_provider::provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}
