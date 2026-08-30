// SPDX-License-Identifier: GPL-2.0-only

//! Real folder-provider transfer over authenticated Quinn/mTLS streams.

use std::error::Error;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use meshspan_contracts::{
    BoundedBytes, RemovalPermit, ReservationClass, ShardIdentity, ShardReadPermit,
    ShardWritePermit, StoragePermitMacKey, read_permit_mac, removal_permit_mac, write_permit_mac,
};
use meshspan_data_plane::{
    DataPlaneError, RemoteShardService, get_shard, put_shard, reclaim_shard, tombstone_shard,
};
use meshspan_domain::{
    EntropyError, MeshId, NodeId, OperationId, PartitionId, RandomSource, Revision, TargetId,
    UnixMicros,
};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::{ErrorCode, ProtocolVersion, RequestHeader};
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
const PERMIT_KEY: [u8; 32] = [42; 32];

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(17);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_mtls_stream_proves_exact_remote_shard_lifecycle() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let limits = wire_limits()?;
    let transport_limits = TransportLimits::new(limits, 32, 64 * 1_024, 1024 * 1_024)?;
    let certificates = Certificates::new()?;
    let server_node = node(1)?;
    let client_node = node(2)?;
    let server = server_endpoint(
        loopback(),
        certificates.server_credentials()?,
        roots(&certificates.authority)?,
        transport_limits,
    )?;
    let client = client_endpoint(
        loopback(),
        certificates.client_credentials()?,
        roots(&certificates.authority)?,
        transport_limits,
    )?;
    let address = server.local_addr()?;
    let incoming = async {
        server
            .accept()
            .await
            .ok_or(meshspan_transport::TransportError::InvalidConfiguration)?
            .await
            .map_err(meshspan_transport::TransportError::from)
    };
    let (client_connection, server_connection) =
        tokio::try_join!(connect(&client, address, CERTIFICATE_NAME), incoming)?;
    let client_peer = authenticate(
        &server_connection,
        client_node,
        &certificates.client_certificate,
    )?;
    authenticate(
        &client_connection,
        server_node,
        &certificates.server_certificate,
    )?;

    let mut service = fixture.service()?;
    tokio::try_join!(
        serve_lifecycle(&server_connection, &mut service, client_peer, limits),
        prove_client_lifecycle(&client_connection, &fixture, client_node, limits),
    )?;
    client_connection.close(0_u32.into(), b"test complete");
    server_connection.close(0_u32.into(), b"test complete");
    client.wait_idle().await;
    server.wait_idle().await;
    Ok(())
}

async fn serve_lifecycle(
    connection: &quinn::Connection,
    service: &mut RemoteShardService<FolderShardStore>,
    peer: meshspan_transport::AuthenticatedPeer,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    for index in 0..9 {
        let stream = accept_stream(connection).await?;
        let result = service
            .serve_stream(stream, peer, limits, UnixMicros::new(20 + index))
            .await;
        if index == 0 {
            assert!(matches!(result, Err(DataPlaneError::InvalidMessage)));
        } else {
            result?;
        }
    }
    Ok(())
}

async fn prove_client_lifecycle(
    connection: &quinn::Connection,
    fixture: &Fixture,
    client_node: NodeId,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let payload = BoundedBytes::copy_from(b"one shard over several bounded frames", 1_024)?;
    let write = fixture.write_permit(payload.len())?;
    let read = fixture.read_permit()?;
    let removal = fixture.removal_permit()?;
    reject_sender_impersonation(connection, fixture, write, &payload, limits).await?;
    reject_forged_write(connection, fixture, client_node, write, &payload, limits).await?;
    prove_put_and_get(
        connection,
        fixture,
        client_node,
        write,
        read,
        &payload,
        limits,
    )
    .await?;
    reject_forged_removal(connection, fixture, client_node, removal, limits).await?;
    let tombstone = tombstone_shard(
        connection,
        request_header(fixture.mesh, client_node, removal.operation_id)?,
        removal,
        limits,
    )
    .await?;
    let replayed_tombstone = tombstone_shard(
        connection,
        request_header(fixture.mesh, client_node, removal.operation_id)?,
        removal,
        limits,
    )
    .await?;
    assert_eq!(replayed_tombstone, tombstone);
    let reclamation = reclaim_shard(
        connection,
        request_header(fixture.mesh, client_node, tombstone.operation_id)?,
        tombstone,
        limits,
    )
    .await?;
    let replayed_reclamation = reclaim_shard(
        connection,
        request_header(fixture.mesh, client_node, tombstone.operation_id)?,
        tombstone,
        limits,
    )
    .await?;
    assert_eq!(replayed_reclamation, reclamation);
    assert_eq!(reclamation.reclaimed_bytes, payload.len() as u64);
    Ok(())
}

async fn reject_sender_impersonation(
    connection: &quinn::Connection,
    fixture: &Fixture,
    write: ShardWritePermit,
    payload: &BoundedBytes,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    assert!(
        put_shard(
            connection,
            request_header(
                fixture.mesh,
                NodeId::from_bytes([99; 16])?,
                write.operation_id
            )?,
            write,
            payload,
            limits,
        )
        .await
        .is_err()
    );
    Ok(())
}

async fn reject_forged_write(
    connection: &quinn::Connection,
    fixture: &Fixture,
    client_node: NodeId,
    mut forged: ShardWritePermit,
    payload: &BoundedBytes,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    forged.permit_digest[0] ^= 1;
    assert!(matches!(
        put_shard(
            connection,
            request_header(fixture.mesh, client_node, forged.operation_id)?,
            forged,
            payload,
            limits,
        )
        .await,
        Err(DataPlaneError::Remote(ErrorCode::Unauthorised))
    ));
    Ok(())
}

async fn prove_put_and_get(
    connection: &quinn::Connection,
    fixture: &Fixture,
    client_node: NodeId,
    write: ShardWritePermit,
    read: ShardReadPermit,
    payload: &BoundedBytes,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let receipt = put_shard(
        connection,
        request_header(fixture.mesh, client_node, write.operation_id)?,
        write,
        payload,
        limits,
    )
    .await?;
    let expected_digest: [u8; 32] = blake3::hash(payload.as_slice()).into();
    assert_eq!(receipt.digest, expected_digest);
    let returned = get_shard(
        connection,
        request_header(fixture.mesh, client_node, read.operation_id)?,
        read,
        1_024,
        limits,
    )
    .await?;
    assert_eq!(returned.as_slice(), payload.as_slice());
    Ok(())
}

async fn reject_forged_removal(
    connection: &quinn::Connection,
    fixture: &Fixture,
    client_node: NodeId,
    mut forged: RemovalPermit,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    forged.permit_digest[0] ^= 1;
    assert!(matches!(
        tombstone_shard(
            connection,
            request_header(fixture.mesh, client_node, forged.operation_id)?,
            forged,
            limits,
        )
        .await,
        Err(DataPlaneError::Remote(ErrorCode::Unauthorised))
    ));
    Ok(())
}

struct Fixture {
    temporary: TempDir,
    mesh: MeshId,
    target: TargetId,
    shard: ShardIdentity,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            temporary: TempDir::new()?,
            mesh: MeshId::from_bytes([9; 16])?,
            target: TargetId::from_bytes([8; 16])?,
            shard: ShardIdentity {
                manifest_digest: [7; 32],
                stripe_index: 6,
                shard_index: 5,
                generation: 4,
            },
        })
    }

    fn service(&self) -> Result<RemoteShardService<FolderShardStore>, Box<dyn Error>> {
        let storage_path = self.temporary.path().join("storage");
        let state_path = self.temporary.path().join("state");
        fs::create_dir(&storage_path)?;
        let mut random = FixedRandom;
        let folder = RegisteredFolder::register_new(
            &storage_path,
            FolderRegistration {
                mesh_id: self.mesh,
                target_id: self.target,
                generation: 3,
                usage_limit: UsageLimit::DEFAULT,
            },
            &mut random,
        )?;
        let verifier = StoragePermitVerifier::new(
            self.mesh,
            1,
            Revision::new(1),
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        )?;
        let provider = FolderShardStore::open(
            folder,
            &state_path,
            CapacityPolicy {
                usage_limit: UsageLimit::DEFAULT,
                repair_reserve_bytes: 0,
                revision: Revision::new(1),
            },
            verifier,
            UnixMicros::new(1),
            &mut random,
        )?;
        Ok(RemoteShardService::new(
            provider,
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
            self.mesh,
            node(1)?,
            self.target,
            3,
            1_024,
        )?)
    }

    fn write_permit(&self, bytes: usize) -> Result<ShardWritePermit, Box<dyn Error>> {
        let key = StoragePermitMacKey::from_bytes(PERMIT_KEY)?;
        let mut permit = ShardWritePermit {
            operation_id: OperationId::from_bytes([1; 16])?,
            mesh_id: self.mesh,
            target_id: self.target,
            target_generation: 3,
            shard: self.shard,
            reservation_class: ReservationClass::ForegroundWrite,
            maximum_bytes: u64::try_from(bytes)?,
            authorization_revision: Revision::new(5),
            expires_at: UnixMicros::new(1_000),
            permit_digest: [0; 32],
        };
        permit.permit_digest = write_permit_mac(&key, permit);
        Ok(permit)
    }

    fn read_permit(&self) -> Result<ShardReadPermit, Box<dyn Error>> {
        let key = StoragePermitMacKey::from_bytes(PERMIT_KEY)?;
        let mut permit = ShardReadPermit {
            operation_id: OperationId::from_bytes([2; 16])?,
            mesh_id: self.mesh,
            target_id: self.target,
            target_generation: 3,
            shard: self.shard,
            authorization_revision: Revision::new(5),
            expires_at: UnixMicros::new(1_000),
            permit_digest: [0; 32],
        };
        permit.permit_digest = read_permit_mac(&key, permit);
        Ok(permit)
    }

    fn removal_permit(&self) -> Result<RemovalPermit, Box<dyn Error>> {
        let key = StoragePermitMacKey::from_bytes(PERMIT_KEY)?;
        let mut permit = RemovalPermit {
            operation_id: OperationId::from_bytes([3; 16])?,
            mesh_id: self.mesh,
            target_id: self.target,
            shard: self.shard,
            target_generation: 3,
            authority_epoch: 1,
            catalogue_revision: Revision::new(1),
            expires_at: UnixMicros::new(1_000),
            permit_digest: [0; 32],
        };
        permit.permit_digest = removal_permit_mac(&key, permit);
        Ok(permit)
    }
}

struct Certificates {
    authority: CertificateDer<'static>,
    server_certificate: CertificateDer<'static>,
    server_key: Vec<u8>,
    client_certificate: CertificateDer<'static>,
    client_key: Vec<u8>,
}

impl Certificates {
    fn new() -> Result<Self, Box<dyn Error>> {
        let mut parameters = CertificateParams::new(Vec::<String>::new())?;
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .key_usages
            .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
        let authority_key = KeyPair::generate()?;
        let authority = parameters.self_signed(&authority_key)?.der().clone();
        let issuer = Issuer::new(parameters, authority_key);
        let (server_certificate, server_key) = leaf(&issuer)?;
        let (client_certificate, client_key) = leaf(&issuer)?;
        Ok(Self {
            authority,
            server_certificate,
            server_key,
            client_certificate,
            client_key,
        })
    }

    fn server_credentials(&self) -> Result<NodeCredentials, meshspan_transport::TransportError> {
        credentials(&self.server_certificate, &self.server_key)
    }

    fn client_credentials(&self) -> Result<NodeCredentials, meshspan_transport::TransportError> {
        credentials(&self.client_certificate, &self.client_key)
    }
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

fn authenticate(
    connection: &quinn::Connection,
    node_id: NodeId,
    certificate: &CertificateDer<'static>,
) -> Result<meshspan_transport::AuthenticatedPeer, Box<dyn Error>> {
    let registry = PeerRegistry::new([PeerBinding {
        node_id,
        incarnation: 1,
        certificate_fingerprint: certificate_fingerprint(certificate),
    }])?;
    let authenticated = registry.authenticate_connection(connection)?;
    assert_eq!(authenticated.node_id(), node_id);
    Ok(authenticated)
}

fn request_header(
    mesh_id: MeshId,
    sender: NodeId,
    operation: OperationId,
) -> Result<RequestHeader, Box<dyn Error>> {
    let partition = PartitionId::from_bytes([3; 16])?;
    Ok(RequestHeader {
        version: Some(ProtocolVersion { major: 1, minor: 0 }),
        mesh_id: mesh_id.as_bytes().to_vec(),
        partition_id: partition.as_bytes().to_vec(),
        routing_epoch: 1,
        sender_node_id: sender.as_bytes().to_vec(),
        sender_incarnation: 1,
        request_id: operation.as_bytes().to_vec(),
        operation_id: operation.as_bytes().to_vec(),
        deadline_unix_micros: 1_000,
        trace_id: operation.as_bytes().to_vec(),
    })
}

fn roots(certificate: &CertificateDer<'static>) -> Result<RootCertStore, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone())?;
    Ok(roots)
}

fn wire_limits() -> Result<WireLimits, Box<dyn Error>> {
    Ok(WireLimits::new(64 * 1_024, 8, 256, 4_096)?)
}

const fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn node(value: u8) -> Result<NodeId, Box<dyn Error>> {
    NodeId::from_bytes([value; 16]).map_err(Into::into)
}
