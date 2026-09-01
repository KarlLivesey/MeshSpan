// SPDX-License-Identifier: GPL-2.0-only

//! Real-process proof for headless startup, HTTPS setup and durable restart.

use std::error::Error;
use std::fs;
use std::fs::OpenOptions;
use std::net::{SocketAddr, TcpListener as StandardTcpListener};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use meshspan_daemon::{ClaimFile, LocalNodeIdentity, LocalWrappingKey};
use meshspan_domain::{InitialBootstrapMaterial, OperationId, UnixMicros};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
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
    let administrator_id = bootstrap_administrator_id(&claim, &fixture.identity_path)?;
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
    save_and_verify_recovery_bundle(&fixture, &client, api_key, &created).await?;
    let session_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000002",
        "authentication": { "method": "api_key", "secret": api_key },
        "client_label": null,
        "remember": false
    }))?;
    assert!(!fixture.claim_path.exists());
    wait_for_status(fixture.address, &client, "configured").await?;
    let target_marker = wait_for_storage_marker(&fixture.storage_path).await?;
    let provider_journal = wait_for_live_provider(&fixture).await?;
    assert_wrapping_key_committed(&fixture)?;
    assert_eq!(
        fs::read(fixture.storage_path.join("operator-file.txt"))?,
        b"untouched"
    );
    assert_session_created(fixture.address, &client, &session_body).await?;
    assert_volume_inventory_empty(fixture.address, &client, api_key).await?;
    create_user(fixture.address, &client, api_key).await?;
    create_volume(fixture.address, &client, api_key, &administrator_id).await?;
    assert_volume_visible(fixture.address, &client, api_key).await?;

    process.kill()?;
    process.wait()?;
    process = fixture.start()?;
    wait_for_status(fixture.address, &client, "configured").await?;
    assert_eq!(
        wait_for_storage_marker(&fixture.storage_path).await?,
        target_marker
    );
    assert_eq!(wait_for_live_provider(&fixture).await?, provider_journal);
    assert_wrapping_key_committed(&fixture)?;
    assert_session_created(fixture.address, &client, &session_body).await?;
    assert_volume_visible(fixture.address, &client, api_key).await?;
    assert_user_visible(fixture.address, &client, api_key).await?;
    process.kill()?;
    process.wait()?;
    Ok(())
}

fn assert_wrapping_key_committed(fixture: &ProcessFixture) -> Result<(), Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(&fixture.identity_path, CERTIFICATE_NAME)?;
    let node_id = InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?;
    let local_key =
        LocalWrappingKey::open(&fixture.state_path.join("secrets/node-wrapping-key.x25519"))?;
    let database = PartitionDatabase::open(
        &fixture.state_path.join("root-authority.sqlite3"),
        InitialBootstrapMaterial::root_partition_id(node_id)?,
        UnixMicros::new(1),
    )?;
    let repository = AuthoritativeRepository::new(database);
    let stored = repository
        .node_wrapping_key(node_id)?
        .ok_or("authoritative node wrapping key missing")?;
    assert_eq!(stored.public_key, local_key.public_key());
    assert_eq!(stored.generation, 1);
    let recipients = repository.volume_key_recipients()?;
    assert_eq!(recipients.len(), 2);
    assert!(recipients.contains(&local_key.public_key()));
    Ok(())
}

async fn assert_volume_inventory_empty(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/volumes?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if response.starts_with("HTTP/1.1 200 OK\r\n") && response.contains("\"volumes\":[]") {
        Ok(())
    } else {
        Err("headless process did not return its authorised volume inventory".into())
    }
}

async fn save_and_verify_recovery_bundle(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    api_key: &str,
    setup: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let recovery_bundle = setup["recovery_bundle"]
        .as_str()
        .ok_or("setup response omitted the recovery bundle")?;
    let recovery_code = setup["recovery_code"]
        .as_str()
        .ok_or("setup response omitted the recovery code")?;
    let recovery_challenge = setup["recovery_challenge"]
        .as_str()
        .ok_or("setup response omitted the recovery challenge")?;
    let mesh_id = setup["mesh_id"]
        .as_str()
        .ok_or("setup response omitted the mesh identity")?;
    write_private(
        &fixture.saved_recovery_bundle_path,
        recovery_bundle.as_bytes(),
    )?;
    write_private(&fixture.saved_recovery_code_path, recovery_code.as_bytes())?;
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000005",
        "mesh_id": mesh_id,
        "recovery_challenge": recovery_challenge
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        fixture.address,
        client,
        "POST",
        "/api/latest/admin/recovery-bundle-verifications",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if !response.starts_with("HTTP/1.1 200 OK\r\n") {
        return Err(format!(
            "headless recovery verification returned {}: {}",
            response.lines().next().unwrap_or("an invalid response"),
            response_body(&response).unwrap_or("invalid response")
        )
        .into());
    }
    if fixture.pending_recovery_bundle_path.exists()
        || fs::read_to_string(&fixture.saved_recovery_bundle_path)? != recovery_bundle
        || fs::read_to_string(&fixture.saved_recovery_code_path)? != recovery_code
    {
        return Err("headless recovery save verification did not preserve the offline copy".into());
    }
    Ok(())
}

fn write_private(file_path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file_path)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    Ok(())
}

async fn create_volume(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    owner_principal_id: &str,
) -> Result<(), Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000004",
        "name": "Process files",
        "owner_principal_ids": [owner_principal_id]
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/admin/volumes",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if response.starts_with("HTTP/1.1 201 Created\r\n")
        && response.contains("\"name\":\"Process files\"")
    {
        Ok(())
    } else {
        Err(format!(
            "headless process volume creation returned {}: {}",
            response.lines().next().unwrap_or("an invalid response"),
            response_body(&response).unwrap_or("invalid response")
        )
        .into())
    }
}

async fn assert_volume_visible(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/volumes?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if response.starts_with("HTTP/1.1 200 OK\r\n")
        && response.contains("\"name\":\"Process files\"")
    {
        Ok(())
    } else {
        Err(format!(
            "headless process did not return its committed volume: {}",
            response_body(&response).unwrap_or("invalid response")
        )
        .into())
    }
}

async fn create_user(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000003",
        "display_name": "Managed user"
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/admin/users",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if response.starts_with("HTTP/1.1 201 Created\r\n") {
        Ok(())
    } else {
        Err(format!(
            "headless process user creation returned {}",
            response.lines().next().unwrap_or("an invalid response")
        )
        .into())
    }
}

fn bootstrap_administrator_id(
    claim: &meshspan_domain::ClaimBundle,
    identity_path: &Path,
) -> Result<String, Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(identity_path, CERTIFICATE_NAME)?;
    let node_id = InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?;
    let mut operation = [0_u8; 16];
    operation[6] = 0x40;
    operation[8] = 0x80;
    operation[15] = 1;
    let material =
        InitialBootstrapMaterial::derive(claim, OperationId::from_bytes(operation)?, node_id)?;
    Ok(uuid_text(material.administrator_id.as_bytes()))
}

fn uuid_text(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

async fn assert_user_visible(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/admin/users?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if response.starts_with("HTTP/1.1 200 OK\r\n") && response.contains("Managed user") {
        Ok(())
    } else {
        Err("restarted process did not return the committed user".into())
    }
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
    pending_recovery_bundle_path: PathBuf,
    saved_recovery_bundle_path: PathBuf,
    saved_recovery_code_path: PathBuf,
}

impl ProcessFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temporary = TempDir::new()?;
        let state_path = temporary.path().join("state");
        let storage_path = temporary.path().join("storage");
        fs::create_dir(&storage_path)?;
        fs::write(storage_path.join("operator-file.txt"), b"untouched")?;
        Ok(Self {
            address: unused_address()?,
            claim_path: state_path.join("first-boot.claim"),
            identity_path: state_path.join("secrets/node-identity.pk8"),
            state_path,
            storage_path,
            pending_recovery_bundle_path: temporary
                .path()
                .join("state/secrets/pending-offline-recovery.bundle"),
            saved_recovery_bundle_path: temporary.path().join("offline-recovery.bundle"),
            saved_recovery_code_path: temporary.path().join("offline-recovery.code"),
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

async fn wait_for_storage_marker(storage_path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let marker_path = storage_path.join(".meshspan/target.marker");
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        match fs::read(&marker_path) {
            Ok(marker) => return Ok(marker),
            Err(_) if Instant::now() < deadline => sleep(RETRY_INTERVAL).await,
            Err(error) => return Err(error.into()),
        }
    }
}

async fn wait_for_live_provider(fixture: &ProcessFixture) -> Result<PathBuf, Box<dyn Error>> {
    let pack = fixture
        .storage_path
        .join(".meshspan/packs/0000000000000001.sqlite3");
    let journals = fixture.state_path.join("storage-targets");
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let journal = fs::read_dir(&journals).ok().and_then(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "sqlite3")
                })
        });
        if pack.is_file()
            && let Some(journal) = journal
        {
            return Ok(journal);
        }
        if Instant::now() >= deadline {
            return Err("registered storage folder never became a live provider".into());
        }
        sleep(RETRY_INTERVAL).await;
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
    request_with_headers(address, client, method, target, body, &[]).await
}

async fn request_with_headers(
    address: SocketAddr,
    client: &ClientConfig,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    additional_headers: &[(&str, &str)],
) -> Result<String, Box<dyn Error>> {
    let stream = TcpStream::connect(address).await?;
    let connector = TlsConnector::from(Arc::new(client.clone()));
    let name = ServerName::try_from(CERTIFICATE_NAME)?.to_owned();
    let mut stream = connector.connect(name, stream).await?;
    let body = body.unwrap_or_default();
    let mut headers = format!(
        "{method} {target} HTTP/1.1\r\nHost: {CERTIFICATE_NAME}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let insertion = headers
        .len()
        .checked_sub(2)
        .ok_or("HTTP header construction underflowed")?;
    for (name, value) in additional_headers.iter().rev() {
        headers.insert_str(insertion, &format!("{name}: {value}\r\n"));
    }
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8(response)?)
}

fn unused_address() -> Result<SocketAddr, std::io::Error> {
    StandardTcpListener::bind("127.0.0.1:0")?.local_addr()
}
