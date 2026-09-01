// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use meshspan_api_contract::HealthStatus;
use meshspan_test_certificates::CertificateAuthority;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;

use super::{HttpsServer, ReadinessSource, public_contract_api_router};

const CERTIFICATE_NAME: &str = "node.meshspan.test";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_tls13_listener_isolates_plaintext_and_serves_https() -> Result<(), Box<dyn Error>> {
    let certificates = TestCertificates::new()?;
    let server = HttpsServer::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Arc::new(certificates.server_config()?),
        public_contract_api_router(Arc::new(Ready))?,
    )
    .await?;
    let address = server.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.run_until(async move {
        drop(shutdown_rx.await);
    }));

    assert_plaintext_is_rejected(address).await?;
    let response = https_request(address, certificates.client_config()?).await?;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("\"status\":\"ready\""));
    assert!(response.contains("meshspan-api-version: latest"));

    assert!(shutdown_tx.send(()).is_ok());
    server_task.await??;
    Ok(())
}

async fn assert_plaintext_is_rejected(address: SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(b"GET /api/latest/health HTTP/1.1\r\nHost: node.meshspan.test\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(1), stream.read_to_end(&mut response)).await??;
    assert!(!response.starts_with(b"HTTP/"));
    Ok(())
}

async fn https_request(
    address: SocketAddr,
    config: ClientConfig,
) -> Result<String, Box<dyn Error>> {
    let stream = TcpStream::connect(address).await?;
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(CERTIFICATE_NAME)?.to_owned();
    let mut stream = connector.connect(name, stream).await?;
    stream
        .write_all(
            b"GET /api/latest/health HTTP/1.1\r\nHost: node.meshspan.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8(response)?)
}

struct TestCertificates {
    authority: CertificateDer<'static>,
    private_key: Vec<u8>,
    server: CertificateDer<'static>,
}

struct Ready;

impl ReadinessSource for Ready {
    fn status(&self) -> HealthStatus {
        HealthStatus::Ready
    }
}

impl TestCertificates {
    fn new() -> Result<Self, Box<dyn Error>> {
        let authority = CertificateAuthority::new()?;
        let server = authority.issue_node(CERTIFICATE_NAME)?.into_parts();
        Ok(Self {
            authority: CertificateDer::from(authority.certificate_der().to_vec()),
            private_key: server.1,
            server: CertificateDer::from(server.0),
        })
    }

    fn server_config(&self) -> Result<ServerConfig, Box<dyn Error>> {
        let provider = Arc::new(meshspan_rustls_provider::provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![self.server.clone()],
                PrivatePkcs8KeyDer::from(self.private_key.clone()).into(),
            )?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }

    fn client_config(&self) -> Result<ClientConfig, Box<dyn Error>> {
        let provider = Arc::new(meshspan_rustls_provider::provider());
        let mut roots = RootCertStore::empty();
        roots.add(self.authority.clone())?;
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}
