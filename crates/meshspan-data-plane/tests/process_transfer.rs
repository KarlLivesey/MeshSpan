// SPDX-License-Identifier: GPL-2.0-only

//! Three independent storage-process proof over authenticated Quinn/mTLS.

use std::error::Error;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use meshspan_contracts::{
    BoundedBytes, ReservationClass, ShardIdentity, ShardReadPermit, ShardWritePermit,
    StoragePermitMacKey, read_permit_mac, write_permit_mac,
};
use meshspan_data_plane::{RemoteShardRouter, RemoteShardService, get_shard, put_shard};
use meshspan_domain::{
    EntropyError, MeshId, NodeId, OperationId, PartitionId, RandomSource, Revision, TargetId,
    UnixMicros,
};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::{ProtocolVersion, RequestHeader};
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, StoragePermitVerifier,
    UsageLimit,
};
use meshspan_transport::{
    NodeCredentials, PeerBinding, PeerRegistry, TransportLimits, accept_stream,
    certificate_fingerprint, client_endpoint, connect, server_endpoint,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tempfile::TempDir;

const CERTIFICATE_NAME: &str = "meshspan.internal";
const CHILD_NODE_ENV: &str = "MESHSPAN_STAGE4_PROCESS_NODE";
const WAIT_LIMIT: Duration = Duration::from_secs(15);
const RETRY_INTERVAL: Duration = Duration::from_millis(25);
const PERMIT_KEY: [u8; 32] = [42; 32];
const CLIENT_NODE_BYTE: u8 = 200;

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(19);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_storage_processes_round_trip_independent_verified_shards()
-> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let certificates = ProcessCertificates::write(temporary.path())?;
    let launches = build_launches(temporary.path(), &certificates)?;
    let mut processes = launches
        .iter()
        .map(|launch| spawn_node(launch, &certificates))
        .collect::<Result<Vec<_>, _>>()?;
    for launch in &launches {
        wait_for_file(&launch.ready_path).await?;
    }

    let limits = wire_limits()?;
    let client = client_endpoint(
        loopback(),
        credentials(&certificates.client_certificate, &certificates.client_key)?,
        roots(&certificates.authority_certificate)?,
        transport_limits(limits)?,
    )?;
    for launch in &launches {
        exercise_node(&client, launch, limits).await?;
    }
    client.wait_idle().await;
    for (process, launch) in processes.iter_mut().zip(&launches) {
        wait_for_success(process, launch).await?;
        for sibling in &launch.sibling_paths {
            assert_eq!(fs::read(sibling)?, b"ordinary sibling");
        }
    }
    Ok(())
}

#[test]
fn stage_four_storage_process() -> Result<(), Box<dyn Error>> {
    let Some(config) = ChildConfig::from_environment()? else {
        return Ok(());
    };
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(run_storage_process(config))
}

async fn exercise_node(
    client: &quinn::Endpoint,
    launch: &NodeLaunch,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let connection = connect(client, launch.address, CERTIFICATE_NAME).await?;
    let registry = PeerRegistry::new([PeerBinding {
        node_id: launch.node_id,
        incarnation: 1,
        certificate_fingerprint: certificate_fingerprint(&launch.certificate),
    }])?;
    assert_eq!(
        registry.authenticate_connection(&connection)?.node_id(),
        launch.node_id
    );
    let client_node = NodeId::from_bytes([CLIENT_NODE_BYTE; 16])?;
    for (target_index, target) in launch.target_ids.iter().copied().enumerate() {
        let payload = BoundedBytes::copy_from(
            format!(
                "verified remote bytes from process {} target {target_index}",
                launch.number
            )
            .as_bytes(),
            1_024,
        )?;
        let shard = shard(launch.number, target_index)?;
        let write = write_permit(launch.number, target_index, target, shard, payload.len())?;
        let read = read_permit(launch.number, target_index, target, shard)?;
        let receipt = put_shard(
            &connection,
            request_header(client_node, write.operation_id)?,
            write,
            &payload,
            limits,
        )
        .await?;
        assert_eq!(receipt.target_id, target);
        let returned = get_shard(
            &connection,
            request_header(client_node, read.operation_id)?,
            read,
            1_024,
            limits,
        )
        .await?;
        assert_eq!(returned.as_slice(), payload.as_slice());
    }
    connection.close(0_u32.into(), b"process transfer complete");
    Ok(())
}

async fn run_storage_process(config: ChildConfig) -> Result<(), Box<dyn Error>> {
    let mut router = create_router(&config)?;
    let authority = CertificateDer::from(fs::read(&config.authority_path)?);
    let certificate = CertificateDer::from(fs::read(&config.certificate_path)?);
    let endpoint = server_endpoint(
        config.address,
        credentials(&certificate, &fs::read(&config.private_key_path)?)?,
        roots(&authority)?,
        transport_limits(wire_limits()?)?,
    )?;
    fs::write(&config.ready_path, b"ready")?;
    let connection = tokio::time::timeout(WAIT_LIMIT, async {
        endpoint
            .accept()
            .await
            .ok_or(meshspan_transport::TransportError::InvalidConfiguration)?
            .await
            .map_err(meshspan_transport::TransportError::from)
    })
    .await??;
    let client_certificate = CertificateDer::from(fs::read(&config.client_certificate_path)?);
    let client_node = NodeId::from_bytes([CLIENT_NODE_BYTE; 16])?;
    let registry = PeerRegistry::new([PeerBinding {
        node_id: client_node,
        incarnation: 1,
        certificate_fingerprint: certificate_fingerprint(&client_certificate),
    }])?;
    assert_eq!(
        registry.authenticate_connection(&connection)?.node_id(),
        client_node
    );
    for _ in 0..4 {
        let stream = tokio::time::timeout(WAIT_LIMIT, accept_stream(&connection)).await??;
        router
            .serve_stream(stream, wire_limits()?, UnixMicros::new(20))
            .await?;
    }
    let _peer_close = tokio::time::timeout(WAIT_LIMIT, connection.closed()).await;
    endpoint.close(0_u32.into(), b"process proof complete");
    endpoint.wait_idle().await;
    Ok(())
}

fn create_router(
    config: &ChildConfig,
) -> Result<RemoteShardRouter<FolderShardStore>, Box<dyn Error>> {
    let mut services = Vec::with_capacity(2);
    for target_index in 0..2 {
        services.push(create_service(config, target_index)?);
    }
    Ok(RemoteShardRouter::new(services, 2)?)
}

fn create_service(
    config: &ChildConfig,
    target_index: usize,
) -> Result<RemoteShardService<FolderShardStore>, Box<dyn Error>> {
    let storage_path = config.storage_path.join(format!("target-{target_index}"));
    fs::create_dir_all(&storage_path)?;
    fs::write(storage_path.join("ordinary.txt"), b"ordinary sibling")?;
    let mut random = FixedRandom;
    let mesh_id = mesh_id()?;
    let target_id = target_id(config.number, target_index)?;
    let limit_multiplier = u64::try_from(target_index.saturating_add(1))?;
    let usage_limit = UsageLimit::bytes(8_192_u64.saturating_mul(limit_multiplier))?;
    let folder = RegisteredFolder::register_new(
        &storage_path,
        FolderRegistration {
            mesh_id,
            target_id,
            generation: 1,
            usage_limit,
        },
        &mut random,
    )?;
    let provider = FolderShardStore::open(
        folder,
        &config.state_path,
        CapacityPolicy {
            usage_limit,
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(mesh_id, 1, StoragePermitMacKey::from_bytes(PERMIT_KEY)?)?,
        UnixMicros::new(1),
        &mut random,
    )?;
    Ok(RemoteShardService::new(
        provider,
        StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        mesh_id,
        target_id,
        1,
        1_024,
    )?)
}

struct ChildConfig {
    number: u8,
    address: SocketAddr,
    storage_path: PathBuf,
    state_path: PathBuf,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    authority_path: PathBuf,
    client_certificate_path: PathBuf,
    ready_path: PathBuf,
}

impl ChildConfig {
    fn from_environment() -> Result<Option<Self>, Box<dyn Error>> {
        let Ok(number) = std::env::var(CHILD_NODE_ENV) else {
            return Ok(None);
        };
        Ok(Some(Self {
            number: number.parse()?,
            address: required_environment("MESHSPAN_STAGE4_ADDRESS")?.parse()?,
            storage_path: required_environment("MESHSPAN_STAGE4_STORAGE")?.into(),
            state_path: required_environment("MESHSPAN_STAGE4_STATE")?.into(),
            certificate_path: required_environment("MESHSPAN_STAGE4_CERTIFICATE")?.into(),
            private_key_path: required_environment("MESHSPAN_STAGE4_PRIVATE_KEY")?.into(),
            authority_path: required_environment("MESHSPAN_STAGE4_AUTHORITY")?.into(),
            client_certificate_path: required_environment("MESHSPAN_STAGE4_CLIENT_CERT")?.into(),
            ready_path: required_environment("MESHSPAN_STAGE4_READY")?.into(),
        }))
    }
}

fn required_environment(name: &str) -> Result<String, Box<dyn Error>> {
    std::env::var(name).map_err(Into::into)
}

struct NodeLaunch {
    number: u8,
    node_id: NodeId,
    target_ids: [TargetId; 2],
    address: SocketAddr,
    storage_path: PathBuf,
    state_path: PathBuf,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    certificate: CertificateDer<'static>,
    ready_path: PathBuf,
    log_path: PathBuf,
    sibling_paths: [PathBuf; 2],
}

fn build_launches(
    directory: &Path,
    certificates: &ProcessCertificates,
) -> Result<Vec<NodeLaunch>, Box<dyn Error>> {
    (1_u8..=3)
        .zip(&certificates.servers)
        .map(|(number, certificate)| {
            let storage_path = directory.join(format!("storage-{number}"));
            Ok(NodeLaunch {
                number,
                node_id: NodeId::from_bytes([number; 16])?,
                target_ids: [target_id(number, 0)?, target_id(number, 1)?],
                address: available_address()?,
                state_path: directory.join(format!("state-{number}")),
                certificate_path: certificate.certificate_path.clone(),
                private_key_path: certificate.private_key_path.clone(),
                certificate: certificate.certificate.clone(),
                ready_path: directory.join(format!("ready-{number}")),
                log_path: directory.join(format!("node-{number}.log")),
                sibling_paths: [
                    storage_path.join("target-0/ordinary.txt"),
                    storage_path.join("target-1/ordinary.txt"),
                ],
                storage_path,
            })
        })
        .collect()
}

fn spawn_node(
    launch: &NodeLaunch,
    certificates: &ProcessCertificates,
) -> Result<Child, Box<dyn Error>> {
    let log = fs::File::create(&launch.log_path)?;
    let error_log = log.try_clone()?;
    Ok(Command::new(std::env::current_exe()?)
        .args(["--exact", "stage_four_storage_process", "--nocapture"])
        .env(CHILD_NODE_ENV, launch.number.to_string())
        .env("MESHSPAN_STAGE4_ADDRESS", launch.address.to_string())
        .env("MESHSPAN_STAGE4_STORAGE", &launch.storage_path)
        .env("MESHSPAN_STAGE4_STATE", &launch.state_path)
        .env("MESHSPAN_STAGE4_CERTIFICATE", &launch.certificate_path)
        .env("MESHSPAN_STAGE4_PRIVATE_KEY", &launch.private_key_path)
        .env("MESHSPAN_STAGE4_AUTHORITY", &certificates.authority_path)
        .env(
            "MESHSPAN_STAGE4_CLIENT_CERT",
            &certificates.client_certificate_path,
        )
        .env("MESHSPAN_STAGE4_READY", &launch.ready_path)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(error_log))
        .spawn()?)
}

async fn wait_for_file(file: &Path) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    while !file.exists() {
        if started.elapsed() >= WAIT_LIMIT {
            return Err(format!("timed out waiting for {}", file.display()).into());
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
    Ok(())
}

async fn wait_for_success(process: &mut Child, launch: &NodeLaunch) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    loop {
        if let Some(exit) = process.try_wait()? {
            if exit.success() {
                return Ok(());
            }
            let log = fs::read_to_string(&launch.log_path).unwrap_or_default();
            return Err(format!("node {} failed with {exit}: {log}", launch.number).into());
        }
        if started.elapsed() >= WAIT_LIMIT {
            process.kill()?;
            let _exit = process.wait()?;
            return Err(format!("timed out waiting for node {}", launch.number).into());
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

struct WrittenCertificate {
    certificate: CertificateDer<'static>,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
}

struct ProcessCertificates {
    authority_certificate: CertificateDer<'static>,
    authority_path: PathBuf,
    client_certificate: CertificateDer<'static>,
    client_key: Vec<u8>,
    client_certificate_path: PathBuf,
    servers: Vec<WrittenCertificate>,
}

impl ProcessCertificates {
    fn write(directory: &Path) -> Result<Self, Box<dyn Error>> {
        let mut parameters = CertificateParams::new(Vec::<String>::new())?;
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .key_usages
            .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
        let authority_key = KeyPair::generate()?;
        let authority_certificate = parameters.self_signed(&authority_key)?.der().clone();
        let issuer = Issuer::new(parameters, authority_key);
        let authority_path = directory.join("authority.der");
        fs::write(&authority_path, authority_certificate.as_ref())?;
        let (client_certificate, client_key) = leaf(&issuer)?;
        let client_certificate_path = directory.join("client.der");
        fs::write(&client_certificate_path, client_certificate.as_ref())?;
        let mut servers = Vec::with_capacity(3);
        for number in 1_u8..=3 {
            let (certificate, key) = leaf(&issuer)?;
            let certificate_path = directory.join(format!("server-{number}.der"));
            let private_key_path = directory.join(format!("server-{number}.key"));
            fs::write(&certificate_path, certificate.as_ref())?;
            fs::write(&private_key_path, key)?;
            servers.push(WrittenCertificate {
                certificate,
                certificate_path,
                private_key_path,
            });
        }
        Ok(Self {
            authority_certificate,
            authority_path,
            client_certificate,
            client_key,
            client_certificate_path,
            servers,
        })
    }
}

fn leaf(
    issuer: &Issuer<'_, KeyPair>,
) -> Result<(CertificateDer<'static>, Vec<u8>), Box<dyn Error>> {
    let mut parameters = CertificateParams::new(vec![CERTIFICATE_NAME.to_owned()])?;
    parameters
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    parameters.extended_key_usages.extend([
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ]);
    let key = KeyPair::generate()?;
    let certificate: Certificate = parameters.signed_by(&key, issuer)?;
    Ok((certificate.der().clone(), key.serialize_der()))
}

fn write_permit(
    node_number: u8,
    target_index: usize,
    target_id: TargetId,
    shard: ShardIdentity,
    byte_count: usize,
) -> Result<ShardWritePermit, Box<dyn Error>> {
    let key = StoragePermitMacKey::from_bytes(PERMIT_KEY)?;
    let operation_byte = node_number.saturating_add(u8::try_from(target_index)?.saturating_mul(8));
    let mut permit = ShardWritePermit {
        operation_id: OperationId::from_bytes([operation_byte; 16])?,
        mesh_id: mesh_id()?,
        target_id,
        target_generation: 1,
        shard,
        reservation_class: ReservationClass::ForegroundWrite,
        maximum_bytes: u64::try_from(byte_count)?,
        authorization_revision: Revision::new(5),
        expires_at: UnixMicros::new(1_000),
        permit_digest: [0; 32],
    };
    permit.permit_digest = write_permit_mac(&key, permit);
    Ok(permit)
}

fn read_permit(
    node_number: u8,
    target_index: usize,
    target_id: TargetId,
    shard: ShardIdentity,
) -> Result<ShardReadPermit, Box<dyn Error>> {
    let key = StoragePermitMacKey::from_bytes(PERMIT_KEY)?;
    let target_byte = u8::try_from(target_index)?.saturating_mul(8);
    let mut operation = [node_number.saturating_add(target_byte); 16];
    operation[15] = operation[15].saturating_add(32);
    let mut permit = ShardReadPermit {
        operation_id: OperationId::from_bytes(operation)?,
        mesh_id: mesh_id()?,
        target_id,
        target_generation: 1,
        shard,
        authorization_revision: Revision::new(5),
        expires_at: UnixMicros::new(1_000),
        permit_digest: [0; 32],
    };
    permit.permit_digest = read_permit_mac(&key, permit);
    Ok(permit)
}

fn request_header(sender: NodeId, operation: OperationId) -> Result<RequestHeader, Box<dyn Error>> {
    Ok(RequestHeader {
        version: Some(ProtocolVersion { major: 1, minor: 0 }),
        mesh_id: mesh_id()?.as_bytes().to_vec(),
        partition_id: PartitionId::from_bytes([3; 16])?.as_bytes().to_vec(),
        routing_epoch: 1,
        sender_node_id: sender.as_bytes().to_vec(),
        sender_incarnation: 1,
        request_id: operation.as_bytes().to_vec(),
        operation_id: operation.as_bytes().to_vec(),
        deadline_unix_micros: 1_000,
        trace_id: operation.as_bytes().to_vec(),
    })
}

fn shard(number: u8, target_index: usize) -> Result<ShardIdentity, Box<dyn Error>> {
    Ok(ShardIdentity {
        manifest_digest: [7; 32],
        stripe_index: 6,
        shard_index: u16::from(number).saturating_add(u16::try_from(target_index)?),
        generation: 4,
    })
}

fn mesh_id() -> Result<MeshId, Box<dyn Error>> {
    MeshId::from_bytes([9; 16]).map_err(Into::into)
}

fn target_id(number: u8, target_index: usize) -> Result<TargetId, Box<dyn Error>> {
    let index = u8::try_from(target_index)?;
    let value = number
        .saturating_add(32)
        .saturating_add(index.saturating_mul(8));
    TargetId::from_bytes([value; 16]).map_err(Into::into)
}

fn credentials(
    certificate: &CertificateDer<'static>,
    key: &[u8],
) -> Result<NodeCredentials, meshspan_transport::TransportError> {
    NodeCredentials::new(
        vec![certificate.clone()],
        PrivatePkcs8KeyDer::from(key.to_vec()).into(),
    )
}

fn roots(certificate: &CertificateDer<'static>) -> Result<RootCertStore, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone())?;
    Ok(roots)
}

fn wire_limits() -> Result<WireLimits, Box<dyn Error>> {
    Ok(WireLimits::new(64 * 1_024, 8, 256, 4_096)?)
}

fn transport_limits(limits: WireLimits) -> Result<TransportLimits, Box<dyn Error>> {
    Ok(TransportLimits::new(limits, 32, 64 * 1_024, 1024 * 1_024)?)
}

fn available_address() -> Result<SocketAddr, Box<dyn Error>> {
    let socket = UdpSocket::bind(loopback())?;
    Ok(socket.local_addr()?)
}

const fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}
