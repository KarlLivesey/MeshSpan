// SPDX-License-Identifier: GPL-2.0-only

//! Real authenticated QUIC proof from cleanup work to exact provider receipts and commands.

use std::error::Error;
use std::fs;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use meshspan_cluster::{
    CleanupConnectionSource, CleanupNetworkContext, CleanupNetworkError, CleanupWorkAction,
    CleanupWorkEntry, CleanupWorkerError, CleanupWorkerOutcome, MAXIMUM_CLEANUP_REQUEST_TIMEOUT,
    dispatch_cleanup_work_over_quic,
};
use meshspan_contracts::{
    BoundedBytes, ContractVersion, PutShardRequest, RemovalPermit, RequestContext,
    ReservationClass, ReserveStorageRequest, ShardIdentity, StoragePermitMacKey,
    removal_permit_mac,
};
use meshspan_data_plane::RemoteShardService;
use meshspan_domain::{
    DurationMicros, EntropyError, MeshId, NodeId, OperationId, PartitionId, RandomSource, Revision,
    TargetId, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, VersionCleanupItem, VersionCleanupItemCompletion,
    VersionCleanupPermitAttempt,
};
use meshspan_protocol::WireLimits;
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, StoragePermitVerifier,
    UsageLimit,
};
use meshspan_test_certificates::CertificateAuthority;
use meshspan_transport::{
    AuthenticatedPeer, NodeCredentials, PeerBinding, PeerRegistry, TransportLimits, accept_stream,
    certificate_fingerprint, client_endpoint, connect, server_endpoint,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tempfile::TempDir;

const CERTIFICATE_NAME: &str = "meshspan.internal";
const PERMIT_KEY: [u8; 32] = [42; 32];
const PAYLOAD: &[u8] = b"encrypted cleanup network shard";

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(17);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_cleanup_work_crosses_quic_and_returns_exact_commands()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let limits = WireLimits::new(64 * 1_024, 8, 256, 4_096)?;
    let certificates = Certificates::new()?;
    let (client, server, client_connection, server_connection) =
        connections(&certificates, limits).await?;
    let client_peer = authenticate_client(&server_connection, fixture.client_node, &certificates)?;
    let storage_peer =
        authenticate_storage(&client_connection, fixture.storage_node, &certificates)?;
    let wrong_peer = authenticate_storage(
        &client_connection,
        NodeId::from_bytes([99; 16])?,
        &certificates,
    )?;
    let source = FixedConnectionSource {
        connection: client_connection.clone(),
        peer: storage_peer,
    };
    let wrong_source = FixedConnectionSource {
        connection: client_connection.clone(),
        peer: wrong_peer,
    };
    let mut service = fixture.service()?;
    let tombstone_entry = fixture.tombstone_entry()?;
    let network_context = fixture.network_context(limits)?;
    let server_task = serve_transitions(&server_connection, &mut service, client_peer, limits);
    let client_task = prove_transitions(
        &source,
        &wrong_source,
        network_context,
        &tombstone_entry,
        fixture.payload_length,
    );
    tokio::try_join!(server_task, client_task)?;
    client_connection.close(0_u32.into(), b"test complete");
    server_connection.close(0_u32.into(), b"test complete");
    client.wait_idle().await;
    server.wait_idle().await;
    Ok(())
}

async fn serve_transitions(
    connection: &quinn::Connection,
    service: &mut RemoteShardService<FolderShardStore>,
    peer: AuthenticatedPeer,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    for observed_at in [20, 30] {
        service
            .serve_stream(
                accept_stream(connection).await?,
                peer,
                limits,
                UnixMicros::new(observed_at),
            )
            .await?;
    }
    Ok(())
}

async fn prove_transitions(
    source: &FixedConnectionSource,
    wrong_source: &FixedConnectionSource,
    context: CleanupNetworkContext,
    tombstone_entry: &CleanupWorkEntry,
    payload_length: u64,
) -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        dispatch_cleanup_work_over_quic(
            wrong_source,
            context,
            *tombstone_entry,
            UnixMicros::new(10),
        )
        .await,
        Err(CleanupNetworkError::Worker(
            CleanupWorkerError::InconsistentAuthority
        ))
    ));
    let tombstone_outcome =
        dispatch_cleanup_work_over_quic(source, context, *tombstone_entry, UnixMicros::new(10))
            .await?;
    let completion = completion(&tombstone_outcome)?;
    assert_eq!(completion.reporter_node_id, source.peer.node_id());
    assert_eq!(completion.reporter_incarnation, source.peer.incarnation());
    let reclaim_entry = CleanupWorkEntry {
        cleanup_operation_id: tombstone_entry.cleanup_operation_id,
        item: tombstone_entry.item,
        action: CleanupWorkAction::Reclaim(completion),
    };
    let reclaim_outcome =
        dispatch_cleanup_work_over_quic(source, context, reclaim_entry, UnixMicros::new(25))
            .await?;
    let CleanupWorkerOutcome::CommandReady(command) = reclaim_outcome else {
        return Err("network cleanup did not return reclamation command".into());
    };
    let AuthoritativeCommand::ConfirmVersionCleanupReclamation(command) = command.as_ref() else {
        return Err("network cleanup did not return reclamation command".into());
    };
    assert_eq!(command.reporter_node_id, source.peer.node_id());
    assert_eq!(command.reporter_incarnation, source.peer.incarnation());
    assert_eq!(command.receipt.reclaimed_bytes, payload_length);
    Ok(())
}

struct FixedConnectionSource {
    connection: quinn::Connection,
    peer: AuthenticatedPeer,
}

impl CleanupConnectionSource for FixedConnectionSource {
    fn connection_for(
        &self,
        _storage_node_id: NodeId,
    ) -> impl Future<
        Output = Result<
            (quinn::Connection, AuthenticatedPeer),
            meshspan_data_plane::DataPlaneError,
        >,
    > + Send {
        let connection = self.connection.clone();
        let peer = self.peer;
        async move { Ok((connection, peer)) }
    }
}

#[test]
fn cleanup_network_context_rejects_unbounded_or_unfenced_requests() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let limits = WireLimits::new(64 * 1_024, 8, 256, 4_096)?;
    for (routing_epoch, incarnation, timeout) in [
        (0, 1, DurationMicros::new(1)),
        (1, 0, DurationMicros::new(1)),
        (1, 1, DurationMicros::new(0)),
        (
            1,
            1,
            DurationMicros::new(MAXIMUM_CLEANUP_REQUEST_TIMEOUT.get() + 1),
        ),
    ] {
        assert!(matches!(
            CleanupNetworkContext::new(
                fixture.mesh_id,
                fixture.partition_id,
                routing_epoch,
                fixture.client_node,
                incarnation,
                timeout,
                limits,
            ),
            Err(CleanupNetworkError::InvalidContext)
        ));
    }
    Ok(())
}

fn completion(
    outcome: &CleanupWorkerOutcome,
) -> Result<VersionCleanupItemCompletion, Box<dyn Error>> {
    let CleanupWorkerOutcome::CommandReady(command) = outcome else {
        return Err("network cleanup did not return tombstone command".into());
    };
    let AuthoritativeCommand::CompleteVersionCleanupItem(command) = command.as_ref() else {
        return Err("network cleanup did not return tombstone command".into());
    };
    Ok(VersionCleanupItemCompletion {
        cleanup_operation_id: command.cleanup_operation_id,
        item_index: command.item_index,
        permit_attempt_sequence: command.permit_attempt_sequence,
        receipt: command.receipt,
        reporter_node_id: command.reporter_node_id,
        reporter_incarnation: command.reporter_incarnation,
        completion_operation_id: OperationId::from_bytes([12; 16])?,
        completed_at: UnixMicros::new(21),
        revision: Revision::new(11),
    })
}

struct Fixture {
    temporary: TempDir,
    mesh_id: MeshId,
    partition_id: PartitionId,
    client_node: NodeId,
    storage_node: NodeId,
    target_id: TargetId,
    shard: ShardIdentity,
    payload_length: u64,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            temporary: TempDir::new()?,
            mesh_id: MeshId::from_bytes([1; 16])?,
            partition_id: PartitionId::from_bytes([2; 16])?,
            client_node: NodeId::from_bytes([3; 16])?,
            storage_node: NodeId::from_bytes([4; 16])?,
            target_id: TargetId::from_bytes([5; 16])?,
            shard: ShardIdentity {
                manifest_digest: [6; 32],
                stripe_index: 7,
                shard_index: 8,
                generation: 9,
            },
            payload_length: u64::try_from(PAYLOAD.len())?,
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
                mesh_id: self.mesh_id,
                target_id: self.target_id,
                generation: 1,
                usage_limit: UsageLimit::DEFAULT,
            },
            &mut random,
        )?;
        let verifier = StoragePermitVerifier::new(
            self.mesh_id,
            1,
            Revision::new(1),
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        )?;
        let mut provider = FolderShardStore::open(
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
        self.install_shard(&mut provider)?;
        Ok(RemoteShardService::new(
            provider,
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
            self.mesh_id,
            self.storage_node,
            self.target_id,
            1,
            1_024,
        )?)
    }

    fn install_shard(&self, provider: &mut FolderShardStore) -> Result<(), Box<dyn Error>> {
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([10; 16])?,
            deadline: UnixMicros::new(1_000),
            expected_revision: Some(Revision::new(1)),
        };
        let bytes = BoundedBytes::copy_from(PAYLOAD, 1_024)?;
        assert_eq!(bytes.len() as u64, self.payload_length);
        let reservation = provider.reserve(ReserveStorageRequest {
            context,
            target_id: self.target_id,
            target_generation: 1,
            class: ReservationClass::ForegroundWrite,
            bytes: self.payload_length,
            observed_at: UnixMicros::new(2),
        })?;
        provider.put_exact(
            &PutShardRequest {
                context,
                reservation,
                shard: self.shard,
                expected_length: self.payload_length,
                expected_digest: blake3::hash(bytes.as_slice()).into(),
                bytes,
            },
            UnixMicros::new(3),
        )?;
        Ok(())
    }

    fn tombstone_entry(&self) -> Result<CleanupWorkEntry, Box<dyn Error>> {
        let item = VersionCleanupItem {
            item_index: 0,
            removal_operation_id: OperationId::from_bytes([11; 16])?,
            shard: self.shard,
            target_id: self.target_id,
            target_generation: 1,
            storage_node_id: self.storage_node,
            revision: Revision::new(8),
        };
        let mut permit = RemovalPermit {
            operation_id: item.removal_operation_id,
            mesh_id: self.mesh_id,
            target_id: self.target_id,
            shard: self.shard,
            target_generation: 1,
            authority_epoch: 1,
            catalogue_revision: Revision::new(1),
            expires_at: UnixMicros::new(1_000),
            permit_digest: [0; 32],
        };
        permit.permit_digest =
            removal_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, permit);
        Ok(CleanupWorkEntry {
            cleanup_operation_id: OperationId::from_bytes([13; 16])?,
            item,
            action: CleanupWorkAction::Tombstone {
                inventory_sealed_revision: Revision::new(9),
                attempt: VersionCleanupPermitAttempt {
                    cleanup_operation_id: OperationId::from_bytes([13; 16])?,
                    item_index: 0,
                    attempt_sequence: 1,
                    permit,
                    issue_operation_id: OperationId::from_bytes([14; 16])?,
                    issued_at: UnixMicros::new(9),
                    revision: Revision::new(10),
                },
            },
        })
    }

    fn network_context(&self, limits: WireLimits) -> Result<CleanupNetworkContext, Box<dyn Error>> {
        Ok(CleanupNetworkContext::new(
            self.mesh_id,
            self.partition_id,
            1,
            self.client_node,
            1,
            DurationMicros::new(100),
            limits,
        )?)
    }
}

async fn connections(
    certificates: &Certificates,
    limits: WireLimits,
) -> Result<
    (
        quinn::Endpoint,
        quinn::Endpoint,
        quinn::Connection,
        quinn::Connection,
    ),
    Box<dyn Error>,
> {
    let transport_limits = TransportLimits::new(limits, 8, 64 * 1_024, 1024 * 1_024)?;
    let server = server_endpoint(
        loopback(),
        credentials(&certificates.server_certificate, &certificates.server_key)?,
        roots(&certificates.authority)?,
        transport_limits,
    )?;
    let client = client_endpoint(
        loopback(),
        credentials(&certificates.client_certificate, &certificates.client_key)?,
        roots(&certificates.authority)?,
        transport_limits,
    )?;
    let incoming = async {
        server
            .accept()
            .await
            .ok_or(meshspan_transport::TransportError::InvalidConfiguration)?
            .await
            .map_err(meshspan_transport::TransportError::from)
    };
    let (client_connection, server_connection) = tokio::try_join!(
        connect(&client, server.local_addr()?, CERTIFICATE_NAME),
        incoming
    )?;
    Ok((client, server, client_connection, server_connection))
}

fn authenticate_storage(
    connection: &quinn::Connection,
    node_id: NodeId,
    certificates: &Certificates,
) -> Result<AuthenticatedPeer, Box<dyn Error>> {
    Ok(PeerRegistry::new([PeerBinding {
        node_id,
        incarnation: 7,
        certificate_fingerprint: certificate_fingerprint(&certificates.server_certificate),
    }])?
    .authenticate_connection(connection)?)
}

fn authenticate_client(
    connection: &quinn::Connection,
    node_id: NodeId,
    certificates: &Certificates,
) -> Result<AuthenticatedPeer, Box<dyn Error>> {
    Ok(PeerRegistry::new([PeerBinding {
        node_id,
        incarnation: 1,
        certificate_fingerprint: certificate_fingerprint(&certificates.client_certificate),
    }])?
    .authenticate_connection(connection)?)
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
        let authority = CertificateAuthority::new()?;
        let (server_certificate, server_key) =
            certificate_parts(authority.issue_node(CERTIFICATE_NAME)?);
        let (client_certificate, client_key) =
            certificate_parts(authority.issue_node(CERTIFICATE_NAME)?);
        Ok(Self {
            authority: CertificateDer::from(authority.certificate_der().to_vec()),
            server_certificate,
            server_key,
            client_certificate,
            client_key,
        })
    }
}

fn certificate_parts(
    issued: meshspan_test_certificates::IssuedCertificate,
) -> (CertificateDer<'static>, Vec<u8>) {
    let (certificate, private_key) = issued.into_parts();
    (CertificateDer::from(certificate), private_key)
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

const fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}
