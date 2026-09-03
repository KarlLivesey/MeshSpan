// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated webhook adapter over the shared bounded rustls HTTP transport.

use std::{future::Future, sync::Arc, time::Duration};

use hyper::Method;
use meshspan_contracts::ContractError;
use rustls::ClientConfig;

use crate::{
    WebhookHttpRequest, WebhookHttpResponse, WebhookHttpTransport,
    rustls_http::{RustlsHttpClient, RustlsHttpError, RustlsHttpRequest},
};

const CONTENT_TYPE_JSON: &str = "application/json";
const USER_AGENT_VALUE: &str = "MeshSpan/0.1 DNS-Webhook";

/// Direct userspace HTTPS webhook transport using injected rustls trust.
pub struct RustlsWebhookHttpTransport {
    client: RustlsHttpClient,
}

impl RustlsWebhookHttpTransport {
    /// Creates a webhook transport with finite connection and request deadlines.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive timeouts.
    pub fn new(
        tls: Arc<ClientConfig>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, ContractError> {
        RustlsHttpClient::new(tls, connect_timeout, request_timeout)
            .map(|client| Self { client })
            .map_err(map_error)
    }

    async fn exchange(
        &self,
        request: &WebhookHttpRequest,
        bearer_token: &[u8],
    ) -> Result<WebhookHttpResponse, ContractError> {
        validate_token(bearer_token)?;
        let response = self
            .client
            .send(RustlsHttpRequest {
                method: Method::POST,
                url: &request.url,
                body: &request.body,
                content_type: Some(CONTENT_TYPE_JSON),
                bearer_token: Some(bearer_token),
                user_agent: USER_AGENT_VALUE,
            })
            .await
            .map_err(map_error)?;
        Ok(WebhookHttpResponse {
            status: response.status,
            body: response.body,
        })
    }
}

impl WebhookHttpTransport for RustlsWebhookHttpTransport {
    fn send(
        &mut self,
        request: &WebhookHttpRequest,
        bearer_token: &[u8],
    ) -> impl Future<Output = Result<WebhookHttpResponse, ContractError>> + Send {
        self.exchange(request, bearer_token)
    }
}

fn validate_token(token: &[u8]) -> Result<(), ContractError> {
    if !crate::rustls_http::valid_bearer_token(token) {
        return Err(ContractError::InvalidInput);
    }
    Ok(())
}

const fn map_error(error: RustlsHttpError) -> ContractError {
    match error {
        RustlsHttpError::InvalidRequest => ContractError::InvalidInput,
        RustlsHttpError::Unavailable | RustlsHttpError::Rejected => ContractError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, sync::Arc, time::Duration};

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{Request, Response, header::AUTHORIZATION, service::service_fn};
    use hyper_util::rt::TokioIo;
    use meshspan_test_certificates::CertificateAuthority;
    use rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    };
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[test]
    fn bearer_tokens_cannot_inject_headers_or_escape_bounds() {
        assert_eq!(validate_token(b"short"), Err(ContractError::InvalidInput));
        assert_eq!(
            validate_token(b"valid-length-token\r\nattack"),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(
            validate_token(&vec![b'a'; 2_049]),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(validate_token(b"valid-webhook-token"), Ok(()));
    }

    #[tokio::test]
    async fn sends_bearer_auth_over_a_real_tls_connection() -> Result<(), Box<dyn std::error::Error>>
    {
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
                let authorised = request
                    .headers()
                    .get(AUTHORIZATION)
                    .is_some_and(|value| value.as_bytes() == b"Bearer valid-webhook-token");
                let response = if authorised {
                    Response::new(Full::new(Bytes::from_static(b"accepted")))
                } else {
                    let mut response = Response::new(Full::new(Bytes::new()));
                    *response.status_mut() = hyper::StatusCode::UNAUTHORIZED;
                    response
                };
                Ok::<_, Infallible>(response)
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await
                .map_err(|_| "HTTP serve failed")
        });
        let mut transport = RustlsWebhookHttpTransport::new(
            Arc::new(client_config(authority.certificate_der())?),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )?;
        let response = transport
            .send(
                &WebhookHttpRequest {
                    url: format!("https://localhost:{}/dns", address.port()),
                    body: br#"{"version":1}"#.to_vec(),
                },
                b"valid-webhook-token",
            )
            .await?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"accepted");
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
