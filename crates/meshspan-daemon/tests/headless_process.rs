// SPDX-License-Identifier: GPL-2.0-only

//! Real-process proof for headless startup, HTTPS setup and durable restart.

use std::error::Error;
use std::fs;
use std::net::{SocketAddr, TcpListener as StandardTcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use meshspan_daemon::{ClaimFile, LocalNodeIdentity};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;

const CERTIFICATE_NAME: &str = "meshspan.local";
const WAIT_LIMIT: Duration = Duration::from_secs(15);
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

#[tokio::test]
async fn real_headless_process_creates_mesh_over_https_and_restarts() -> Result<(), Box<dyn Error>>
{
    let fixture = ProcessFixture::new()?;
    let mut process = fixture.start()?;
    let claim = wait_for_claim(&fixture.claim_path).await?;
    let client = wait_for_client(&fixture.identity_path).await?;
    wait_for_status(fixture.address, &client, "claim_required").await?;

    let encoded_claim = claim.expose_encoded();
    let body = serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "claim": encoded_claim.as_str(),
        "mesh_name": "Process mesh",
        "administrator_name": "Administrator",
        "host_name": "Test host",
        "node_name": "Test node"
    });
    let response = request(
        fixture.address,
        &client,
        "POST",
        "/api/latest/setup/meshes",
        Some(&serde_json::to_vec(&body)?),
    )
    .await?;
    assert!(response.starts_with("HTTP/1.1 201 Created\r\n"));
    assert!(response.contains("\"api_key\":\"meshspan-key-v1."));
    let created: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    let api_key = created["api_key"]
        .as_str()
        .ok_or("setup response omitted the API key")?;
    let session_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000002",
        "authentication": { "method": "api_key", "secret": api_key },
        "client_label": null,
        "remember": false
    }))?;
    assert!(!fixture.claim_path.exists());
    wait_for_status(fixture.address, &client, "configured").await?;
    assert_session_created(fixture.address, &client, &session_body).await?;

    process.kill()?;
    process.wait()?;
    process = fixture.start()?;
    wait_for_status(fixture.address, &client, "configured").await?;
    assert_session_created(fixture.address, &client, &session_body).await?;
    process.kill()?;
    process.wait()?;
    Ok(())
}

async fn assert_session_created(
    address: SocketAddr,
    client: &ClientConfig,
    body: &[u8],
) -> Result<(), Box<dyn Error>> {
    let response = request(address, client, "POST", "/api/latest/sessions", Some(body)).await?;
    if response.starts_with("HTTP/1.1 201 Created\r\n")
        && response.contains("set-cookie: meshspan_session=")
        && response.contains("meshspan-csrf-token:")
    {
        Ok(())
    } else {
        Err("headless process did not create the expected HTTPS session".into())
    }
}

fn response_body(response: &str) -> Result<&str, Box<dyn Error>> {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| "HTTP response omitted its body boundary".into())
}

struct ProcessFixture {
    _temporary: TempDir,
    address: SocketAddr,
    claim_path: PathBuf,
    identity_path: PathBuf,
    state_path: PathBuf,
    storage_path: PathBuf,
}

impl ProcessFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temporary = TempDir::new()?;
        let state_path = temporary.path().join("state");
        let storage_path = temporary.path().join("storage");
        fs::create_dir(&storage_path)?;
        Ok(Self {
            address: unused_address()?,
            claim_path: state_path.join("first-boot.claim"),
            identity_path: state_path.join("secrets/node-identity.pk8"),
            state_path,
            storage_path,
            _temporary: temporary,
        })
    }

    fn start(&self) -> Result<Child, Box<dyn Error>> {
        Ok(Command::new(env!("CARGO_BIN_EXE_meshspan-daemon"))
            .arg("--daemon-state-dir")
            .arg(&self.state_path)
            .arg("--storage-path")
            .arg(&self.storage_path)
            .arg("--https-listen")
            .arg(self.address.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?)
    }
}

async fn wait_for_claim(file_path: &Path) -> Result<meshspan_domain::ClaimBundle, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        match ClaimFile::read(file_path) {
            Ok(claim) => return Ok(claim),
            Err(_) if Instant::now() < deadline => sleep(RETRY_INTERVAL).await,
            Err(error) => return Err(error.into()),
        }
    }
}

async fn wait_for_client(file_path: &Path) -> Result<ClientConfig, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        match LocalNodeIdentity::open(file_path, CERTIFICATE_NAME) {
            Ok(identity) => return client_config(identity.bootstrap_certificate_der()),
            Err(_) if Instant::now() < deadline => sleep(RETRY_INTERVAL).await,
            Err(error) => return Err(error.into()),
        }
    }
}

fn client_config(certificate: &[u8]) -> Result<ClientConfig, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(certificate.to_vec()))?;
    Ok(
        ClientConfig::builder_with_provider(Arc::new(meshspan_rustls_provider::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

async fn wait_for_status(
    address: SocketAddr,
    client: &ClientConfig,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let response = request(address, client, "GET", "/api/latest/setup/status", None).await;
        if response
            .as_ref()
            .is_ok_and(|response| response.contains(&format!("\"state\":\"{expected}\"")))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("headless process did not reach the expected setup state".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn request(
    address: SocketAddr,
    client: &ClientConfig,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
) -> Result<String, Box<dyn Error>> {
    let stream = TcpStream::connect(address).await?;
    let connector = TlsConnector::from(Arc::new(client.clone()));
    let name = ServerName::try_from(CERTIFICATE_NAME)?.to_owned();
    let mut stream = connector.connect(name, stream).await?;
    let body = body.unwrap_or_default();
    let headers = format!(
        "{method} {target} HTTP/1.1\r\nHost: {CERTIFICATE_NAME}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8(response)?)
}

fn unused_address() -> Result<SocketAddr, std::io::Error> {
    StandardTcpListener::bind("127.0.0.1:0")?.local_addr()
}
