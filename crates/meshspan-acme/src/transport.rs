// SPDX-License-Identifier: GPL-2.0-only

//! Concrete asynchronous HTTP/1.1-over-rustls ACME transport.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt as _, Full};
use hyper::header::{CONNECTION, CONTENT_TYPE, HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::{
    AcmeHttpMethod, AcmeHttpResponse, AcmeResponseHeaders, AcmeTransport, AcmeTransportError,
    AcmeTransportRequest,
};

const MAXIMUM_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const MAXIMUM_TIMEOUT: Duration = Duration::from_mins(5);
const USER_AGENT_VALUE: &str = "MeshSpan/0.1 ACME";

/// Direct userspace ACME client using injected rustls trust and no external proxy or service.
pub struct RustlsAcmeTransport {
    tls: Arc<ClientConfig>,
    connect_timeout: Duration,
    request_timeout: Duration,
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
        if connect_timeout.is_zero()
            || request_timeout.is_zero()
            || connect_timeout > MAXIMUM_TIMEOUT
            || request_timeout > MAXIMUM_TIMEOUT
        {
            return Err(AcmeTransportError::Rejected);
        }
        Ok(Self {
            tls,
            connect_timeout,
            request_timeout,
        })
    }

    async fn exchange(
        &self,
        request: &AcmeTransportRequest,
    ) -> Result<AcmeHttpResponse, AcmeTransportError> {
        let endpoint = HttpsEndpoint::parse(&request.url)?;
        let tcp = timeout(
            self.connect_timeout,
            TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
        )
        .await
        .map_err(|_| AcmeTransportError::Unavailable)?
        .map_err(|_| AcmeTransportError::Unavailable)?;
        tcp.set_nodelay(true)
            .map_err(|_| AcmeTransportError::Unavailable)?;
        let server_name = ServerName::try_from(endpoint.host.clone())
            .map_err(|_| AcmeTransportError::Rejected)?;
        let tls = timeout(
            self.connect_timeout,
            TlsConnector::from(self.tls.clone()).connect(server_name, tcp),
        )
        .await
        .map_err(|_| AcmeTransportError::Unavailable)?
        .map_err(|_| AcmeTransportError::Rejected)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| AcmeTransportError::Rejected)?;
        let connection_task = tokio::spawn(connection);
        let exchange = async {
            let outbound = build_request(request, &endpoint)?;
            let inbound = sender
                .send_request(outbound)
                .await
                .map_err(|_| AcmeTransportError::Unavailable)?;
            read_response(inbound).await
        };
        let result = timeout(self.request_timeout, exchange)
            .await
            .map_err(|_| AcmeTransportError::Unavailable)?;
        connection_task.abort();
        let _ = connection_task.await;
        result
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

fn build_request(
    source: &AcmeTransportRequest,
    endpoint: &HttpsEndpoint,
) -> Result<Request<Full<Bytes>>, AcmeTransportError> {
    let method = match source.method {
        AcmeHttpMethod::Get => Method::GET,
        AcmeHttpMethod::Head => Method::HEAD,
        AcmeHttpMethod::Post => Method::POST,
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(&endpoint.path_and_query)
        .header(HOST, &endpoint.authority)
        .header(USER_AGENT, USER_AGENT_VALUE)
        .header(CONNECTION, "close");
    if let Some(content_type) = source.content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(&source.body)))
        .map_err(|_| AcmeTransportError::Rejected)
}

async fn read_response(
    mut response: hyper::Response<hyper::body::Incoming>,
) -> Result<AcmeHttpResponse, AcmeTransportError> {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            value
                .to_str()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
                .map_err(|_| AcmeTransportError::Rejected)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut body = BytesMut::new();
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|_| AcmeTransportError::Rejected)?;
        let data = frame.data_ref().ok_or(AcmeTransportError::Rejected)?;
        if body.len().saturating_add(data.len()) > MAXIMUM_RESPONSE_BODY_BYTES {
            return Err(AcmeTransportError::Rejected);
        }
        body.extend_from_slice(data);
    }
    AcmeHttpResponse::new(
        status,
        AcmeResponseHeaders::new(headers).map_err(|_| AcmeTransportError::Rejected)?,
        body.to_vec(),
    )
    .map_err(|_| AcmeTransportError::Rejected)
}

struct HttpsEndpoint {
    authority: String,
    host: String,
    port: u16,
    path_and_query: String,
}

impl HttpsEndpoint {
    fn parse(url: &str) -> Result<Self, AcmeTransportError> {
        crate::wire::bounded_url(url).map_err(|_| AcmeTransportError::Rejected)?;
        let remainder = url
            .strip_prefix("https://")
            .ok_or(AcmeTransportError::Rejected)?;
        let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        let suffix = &remainder[authority_end..];
        let (host, port) = split_authority(authority)?;
        let path_and_query = if suffix.is_empty() {
            "/".to_owned()
        } else if suffix.starts_with('?') {
            format!("/{suffix}")
        } else {
            suffix.to_owned()
        };
        Ok(Self {
            authority: authority.to_owned(),
            host,
            port,
            path_and_query,
        })
    }
}

fn split_authority(authority: &str) -> Result<(String, u16), AcmeTransportError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or(AcmeTransportError::Rejected)?;
        let port = parse_port_suffix(suffix)?;
        return Ok((host.to_owned(), port));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        return Ok((host.to_owned(), parse_port(port)?));
    }
    Ok((authority.to_owned(), 443))
}

fn parse_port_suffix(value: &str) -> Result<u16, AcmeTransportError> {
    if value.is_empty() {
        Ok(443)
    } else {
        value
            .strip_prefix(':')
            .ok_or(AcmeTransportError::Rejected)
            .and_then(parse_port)
    }
}

fn parse_port(value: &str) -> Result<u16, AcmeTransportError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(AcmeTransportError::Rejected)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use hyper::Response;
    use hyper::header::HeaderValue;
    use hyper::service::service_fn;
    use meshspan_test_certificates::CertificateAuthority;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[test]
    fn endpoint_parsing_preserves_authority_and_origin_form() -> Result<(), AcmeTransportError> {
        let endpoint = HttpsEndpoint::parse("https://[::1]:14000/acme?order=1")?;
        assert_eq!(endpoint.authority, "[::1]:14000");
        assert_eq!(endpoint.host, "::1");
        assert_eq!(endpoint.port, 14_000);
        assert_eq!(endpoint.path_and_query, "/acme?order=1");

        let endpoint = HttpsEndpoint::parse("https://ca.example.test?directory=1")?;
        assert_eq!(endpoint.host, "ca.example.test");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path_and_query, "/?directory=1");
        Ok(())
    }

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
