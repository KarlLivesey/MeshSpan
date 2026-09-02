// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::Duration;

use meshspan_consensus::{ConsensusCore, CoreConfig, MemberIncarnations, compile_plan, flat_plan};
use meshspan_domain::{
    AuditEventId, HostId, MeshId, PartitionId, PrincipalId, QuorumPlanId, Revision, RoleId,
};
use meshspan_metadata::{BootstrapMesh, PartitionDatabase, RecordName};
use meshspan_test_certificates::{CertificateAuthority, IssuedCertificate};
use zeroize::Zeroizing;

use super::*;
use crate::{ConsensusNetwork, ConsensusNetworkConfig, ConsensusNetworkError, ConsensusPeerConfig};

#[tokio::test]
async fn single_owner_returns_only_a_durable_exact_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = NodeId::from_bytes([1; 16])?;
    let driver = driver(&directory.path().join("authority.sqlite3"), local)?;
    let transport: Arc<dyn ConsensusMessageTransport> = Arc::new(|_, _| {});
    let (authority, runtime) =
        spawn_metadata_authority(driver, transport, MetadataAuthorityConfig::default())?;
    authority.begin_election().await?;
    let (context, initial_command) = command(local, [2; 16])?;
    let receipt = authority
        .commit_or_resolve(context, initial_command.clone())
        .await?;
    assert_eq!(receipt.operation_id, context.operation_id);
    assert_eq!(receipt.committed_revision, Revision::new(1));

    let replay = authority
        .commit_or_resolve(context, initial_command)
        .await?;
    assert_eq!(replay.result_digest, receipt.result_digest);
    let (_, changed) = command(local, [9; 16])?;
    assert_eq!(
        authority.commit_or_resolve(context, changed).await,
        Err(MetadataAuthorityRequestError::Conflict)
    );
    authority.shutdown().await?;
    runtime.await??;
    Ok(())
}

#[tokio::test]
async fn follower_rejects_before_enqueuing_a_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = NodeId::from_bytes([11; 16])?;
    let driver = driver(&directory.path().join("follower.sqlite3"), local)?;
    let transport: Arc<dyn ConsensusMessageTransport> = Arc::new(|_, _| {});
    let (authority, runtime) =
        spawn_metadata_authority(driver, transport, MetadataAuthorityConfig::default())?;
    let (context, command) = command(local, [12; 16])?;
    assert_eq!(
        authority.commit_or_resolve(context, command).await,
        Err(MetadataAuthorityRequestError::NotLeader { leader_id: None })
    );
    authority.shutdown().await?;
    runtime.await??;
    Ok(())
}

#[tokio::test]
async fn rejected_preflight_does_not_append_or_stop_the_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = NodeId::from_bytes([13; 16])?;
    let driver = driver(&directory.path().join("rejected-preflight.sqlite3"), local)?;
    let transport: Arc<dyn ConsensusMessageTransport> = Arc::new(|_, _| {});
    let (authority, runtime) =
        spawn_metadata_authority(driver, transport, MetadataAuthorityConfig::default())?;
    authority.begin_election().await?;
    let (mut context, command) = command(local, [14; 16])?;
    context.expected_revision = Some(Revision::new(99));
    assert_eq!(
        authority.commit_or_resolve(context, command.clone()).await,
        Err(MetadataAuthorityRequestError::Rejected)
    );

    context.expected_revision = Some(Revision::ZERO);
    let receipt = authority.commit_or_resolve(context, command).await?;
    assert_eq!(receipt.committed_revision, Revision::new(1));
    assert_eq!(receipt.committed_position.index, 1);
    authority.shutdown().await?;
    runtime.await??;
    Ok(())
}

#[tokio::test]
async fn conflicting_queued_commands_do_not_poison_later_work()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = NodeId::from_bytes([15; 16])?;
    let driver = driver(&directory.path().join("queued-conflict.sqlite3"), local)?;
    let transport: Arc<dyn ConsensusMessageTransport> = Arc::new(|_, _| {});
    let (authority, runtime) =
        spawn_metadata_authority(driver, transport, MetadataAuthorityConfig::default())?;
    authority.begin_election().await?;
    let (bootstrap_context, bootstrap) = command(local, [16; 16])?;
    authority
        .commit_or_resolve(bootstrap_context, bootstrap)
        .await?;

    let first = named_user_command(bootstrap_context.actor_principal_id, 101, "Duplicate user")?;
    let second = named_user_command(bootstrap_context.actor_principal_id, 111, "Duplicate user")?;
    let (first_outcome, second_outcome) = tokio::join!(
        authority.commit_or_resolve(first.0, first.1),
        authority.commit_or_resolve(second.0, second.1),
    );
    assert_eq!(first_outcome?.committed_revision, Revision::new(2));
    assert_eq!(second_outcome, Err(MetadataAuthorityRequestError::Rejected));

    let third = named_user_command(bootstrap_context.actor_principal_id, 121, "Surviving user")?;
    assert_eq!(
        authority
            .commit_or_resolve(third.0, third.1)
            .await?
            .committed_revision,
        Revision::new(3)
    );
    authority.shutdown().await?;
    runtime.await??;
    Ok(())
}

#[tokio::test]
async fn three_independent_repositories_commit_and_resolve_one_exact_operation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let nodes = [
        NodeId::from_bytes([61; 16])?,
        NodeId::from_bytes([62; 16])?,
        NodeId::from_bytes([63; 16])?,
    ];
    let plan = plan(&nodes)?;
    let handles = Arc::new(Mutex::new(BTreeMap::new()));
    let mut authorities = Vec::new();
    for (index, node_id) in nodes.into_iter().enumerate() {
        let driver = driver_with_plan(
            &directory.path().join(format!("node-{index}.sqlite3")),
            node_id,
            &plan,
        )?;
        let transport: Arc<dyn ConsensusMessageTransport> = Arc::new(InMemoryTransport {
            from: node_id,
            peers: Arc::clone(&handles),
        });
        let config = MetadataAuthorityConfig {
            heartbeat_interval: Duration::from_millis(20),
            election_timeout: Duration::from_secs(60),
            election_check_interval: Duration::from_millis(10),
            ..MetadataAuthorityConfig::default()
        };
        authorities.push(spawn_replication_fixture_authority(
            driver, transport, config,
        )?);
    }
    {
        let mut registered = handles.lock().map_err(|_| "transport registry poisoned")?;
        for (node_id, (handle, _)) in nodes.into_iter().zip(&authorities) {
            registered.insert(node_id, handle.clone());
        }
    }
    authorities[0].0.begin_election().await?;
    let (context, command) = command(nodes[0], [64; 16])?;
    let receipt = tokio::time::timeout(
        Duration::from_secs(5),
        commit_after_election(&authorities[0].0, context, &command),
    )
    .await
    .map_err(|_| "leader commit timed out")??;
    assert_eq!(receipt.operation_id, context.operation_id);

    for (index, (authority, _)) in authorities.iter().enumerate() {
        let replay = tokio::time::timeout(
            Duration::from_secs(5),
            resolve_after_replication(authority, context, &command),
        )
        .await
        .map_err(|_| format!("replica {index} resolution timed out"))??;
        assert_eq!(replay.result_digest, receipt.result_digest);
    }
    for (authority, _) in &authorities {
        authority.shutdown().await?;
    }
    for (_, runtime) in authorities {
        runtime.await??;
    }
    Ok(())
}

#[tokio::test]
async fn three_real_quinn_nodes_re_elect_and_commit_after_leader_loss()
-> Result<(), Box<dyn std::error::Error>> {
    let mut cluster = RealAuthorityCluster::start()?;
    cluster.authorities[0].0.begin_election().await?;
    let (bootstrap_context, bootstrap) = command(cluster.nodes[0], [85; 16])?;
    let bootstrap_receipt = tokio::time::timeout(
        Duration::from_secs(15),
        commit_after_election(&cluster.authorities[0].0, bootstrap_context, &bootstrap),
    )
    .await??;
    assert_eq!(bootstrap_receipt.committed_revision, Revision::new(1));

    cluster.stop_first_authority().await?;
    let (user_context, user) = user_command(bootstrap_context.actor_principal_id)?;
    let user_receipt = tokio::time::timeout(
        Duration::from_secs(15),
        commit_after_election(&cluster.authorities[0].0, user_context, &user),
    )
    .await??;
    assert_eq!(user_receipt.committed_revision, Revision::new(2));
    let follower_receipt = tokio::time::timeout(
        Duration::from_secs(15),
        resolve_after_replication(&cluster.authorities[1].0, user_context, &user),
    )
    .await??;
    assert_eq!(follower_receipt.result_digest, user_receipt.result_digest);

    cluster.shutdown().await?;
    Ok(())
}

type AuthorityTask = (
    MetadataAuthorityHandle,
    JoinHandle<Result<(), MetadataAuthorityRuntimeError>>,
);

struct RealAuthorityCluster {
    _directory: tempfile::TempDir,
    nodes: [NodeId; 3],
    authorities: Vec<AuthorityTask>,
    forwarders: Vec<JoinHandle<()>>,
}

impl RealAuthorityCluster {
    fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let certificate_authority = CertificateAuthority::new()?;
        let authority_certificate = certificate_authority.certificate_der().to_vec();
        let nodes = [
            NodeId::from_bytes([81; 16])?,
            NodeId::from_bytes([82; 16])?,
            NodeId::from_bytes([83; 16])?,
        ];
        let identities = [
            certificate_authority.issue_node("meshspan.internal")?,
            certificate_authority.issue_node("meshspan.internal")?,
            certificate_authority.issue_node("meshspan.internal")?,
        ];
        let addresses = [
            unused_udp_address()?,
            unused_udp_address()?,
            unused_udp_address()?,
        ];
        let partition_id = PartitionId::from_bytes([20; 16])?;
        let plan = plan(&nodes)?;
        let (networks, inbound) = start_networks(
            &nodes,
            &addresses,
            &identities,
            &authority_certificate,
            MeshId::from_bytes([84; 16])?,
            partition_id,
        )?;
        let authorities = start_authorities(&directory, &nodes, &plan, networks)?;
        let forwarders = start_forwarders(inbound, &authorities);
        Ok(Self {
            _directory: directory,
            nodes,
            authorities,
            forwarders,
        })
    }

    async fn stop_first_authority(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let (authority, runtime) = self.authorities.remove(0);
        authority.shutdown().await?;
        runtime.await??;
        Ok(())
    }

    async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        for (authority, _) in &self.authorities {
            authority.shutdown().await?;
        }
        for (_, runtime) in self.authorities {
            runtime.await??;
        }
        for forwarder in self.forwarders {
            forwarder.abort();
            let _cancelled = forwarder.await;
        }
        Ok(())
    }
}

fn start_networks(
    nodes: &[NodeId; 3],
    addresses: &[SocketAddr; 3],
    identities: &[IssuedCertificate; 3],
    trust_anchor: &[u8],
    mesh_id: MeshId,
    partition_id: PartitionId,
) -> Result<
    (
        Vec<ConsensusNetwork>,
        Vec<mpsc::Receiver<PeerConsensusMessage>>,
    ),
    ConsensusNetworkError,
> {
    let mut networks = Vec::new();
    let mut inbound = Vec::new();
    for index in 0..nodes.len() {
        let (sender, receiver) = mpsc::channel(256);
        networks.push(ConsensusNetwork::start(
            network_config(
                index,
                nodes,
                addresses,
                identities,
                trust_anchor,
                mesh_id,
                partition_id,
            ),
            sender,
        )?);
        inbound.push(receiver);
    }
    Ok((networks, inbound))
}

fn start_authorities(
    directory: &tempfile::TempDir,
    nodes: &[NodeId; 3],
    plan: &meshspan_consensus::CompiledQuorumPlan,
    networks: Vec<ConsensusNetwork>,
) -> Result<Vec<AuthorityTask>, Box<dyn std::error::Error>> {
    networks
        .into_iter()
        .enumerate()
        .map(|(index, network)| {
            let driver = driver_with_plan(
                &directory.path().join(format!("quinn-node-{index}.sqlite3")),
                nodes[index],
                plan,
            )?;
            let transport: Arc<dyn ConsensusMessageTransport> = Arc::new(network);
            let config = authority_config(index)?;
            Ok(spawn_replication_fixture_authority(
                driver, transport, config,
            )?)
        })
        .collect()
}

fn authority_config(index: usize) -> Result<MetadataAuthorityConfig, Box<dyn std::error::Error>> {
    let election_timeout = Duration::from_millis(
        350_u64
            .checked_add(u64::try_from(index)?.saturating_mul(250))
            .ok_or("election timeout overflowed")?,
    );
    Ok(MetadataAuthorityConfig {
        heartbeat_interval: Duration::from_millis(40),
        election_timeout,
        election_check_interval: Duration::from_millis(20),
        ..MetadataAuthorityConfig::default()
    })
}

fn start_forwarders(
    inbound: Vec<mpsc::Receiver<PeerConsensusMessage>>,
    authorities: &[AuthorityTask],
) -> Vec<JoinHandle<()>> {
    inbound
        .into_iter()
        .zip(authorities)
        .map(|(mut receiver, (authority, _))| {
            let authority = authority.clone();
            tokio::spawn(async move {
                while let Some(message) = receiver.recv().await {
                    if authority.receive_peer(message).await.is_err() {
                        return;
                    }
                }
            })
        })
        .collect()
}

struct InMemoryTransport {
    from: NodeId,
    peers: Arc<Mutex<BTreeMap<NodeId, MetadataAuthorityHandle>>>,
}

fn spawn_replication_fixture_authority(
    driver: PartitionConsensusDriver<AuthoritativeRepository>,
    transport: Arc<dyn ConsensusMessageTransport>,
    config: MetadataAuthorityConfig,
) -> Result<AuthorityTask, MetadataAuthorityStartError> {
    // These fixtures start from an already formed three-voter plan so they can isolate replication
    // and transport. Production authorities always coordinate membership from enrolled learners.
    spawn_metadata_authority_runtime(driver, transport, config, false)
}

impl ConsensusMessageTransport for InMemoryTransport {
    fn send(&self, to: NodeId, message: CoreMessage) {
        let Ok(peers) = self.peers.lock() else {
            return;
        };
        let Some(peer) = peers.get(&to) else {
            return;
        };
        let _full_or_closed = peer
            .events
            .try_send(AuthorityEvent::Peer(PeerConsensusMessage {
                from: self.from,
                sender_incarnation: 1,
                message,
            }));
    }
}

async fn commit_after_election(
    authority: &MetadataAuthorityHandle,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
    loop {
        match authority.commit_or_resolve(context, command.clone()).await {
            Err(
                MetadataAuthorityRequestError::NotLeader { .. }
                | MetadataAuthorityRequestError::Unavailable,
            ) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            outcome => return outcome,
        }
    }
}

async fn resolve_after_replication(
    authority: &MetadataAuthorityHandle,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
    loop {
        match authority.commit_or_resolve(context, command.clone()).await {
            Err(
                MetadataAuthorityRequestError::NotLeader { .. }
                | MetadataAuthorityRequestError::Unavailable,
            ) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            outcome => return outcome,
        }
    }
}

fn driver(
    file_path: &std::path::Path,
    local: NodeId,
) -> Result<PartitionConsensusDriver<AuthoritativeRepository>, Box<dyn std::error::Error>> {
    let plan = plan(&[local])?;
    driver_with_plan(file_path, local, &plan)
}

fn plan(
    nodes: &[NodeId],
) -> Result<meshspan_consensus::CompiledQuorumPlan, Box<dyn std::error::Error>> {
    Ok(compile_plan(flat_plan(
        QuorumPlanId::from_bytes([21; 16])?,
        1,
        nodes.iter().copied().collect(),
        BTreeSet::new(),
    )?)?)
}

fn driver_with_plan(
    file_path: &std::path::Path,
    local: NodeId,
    plan: &meshspan_consensus::CompiledQuorumPlan,
) -> Result<PartitionConsensusDriver<AuthoritativeRepository>, Box<dyn std::error::Error>> {
    let partition_id = PartitionId::from_bytes([20; 16])?;
    let database = PartitionDatabase::open(file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    repository.initialise_consensus_quorum_plan(plan, UnixMicros::new(2))?;
    let incarnations = MemberIncarnations::new(
        plan.members()
            .into_iter()
            .map(|node_id| (node_id, 1))
            .collect(),
        plan,
    )?;
    let core = ConsensusCore::new(CoreConfig {
        partition_id,
        local_node_id: local,
        local_incarnation: 1,
        plan: plan.clone(),
        member_incarnations: incarnations,
    })?;
    Ok(PartitionConsensusDriver::new(core, repository))
}

fn command(
    node_id: NodeId,
    mesh_marker: [u8; 16],
) -> Result<(CommandContext, AuthoritativeCommand), Box<dyn std::error::Error>> {
    let administrator_id = PrincipalId::from_bytes([30; 16])?;
    let context = CommandContext {
        operation_id: OperationId::from_bytes([31; 16])?,
        actor_principal_id: administrator_id,
        audit_event_id: AuditEventId::from_bytes([32; 16])?,
        occurred_at: UnixMicros::new(10),
        expected_revision: Some(Revision::ZERO),
    };
    Ok((
        context,
        crate::protected_volume_test_support::protected_bootstrap(BootstrapMesh {
            mesh_id: MeshId::from_bytes(mesh_marker)?,
            mesh_name: RecordName::new("Authority mesh")?,
            administrator_id,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([33; 16])?,
            host_id: HostId::from_bytes([34; 16])?,
            host_name: RecordName::new("Host")?,
            node_id,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        })?,
    ))
}

fn user_command(
    administrator_id: PrincipalId,
) -> Result<(CommandContext, AuthoritativeCommand), Box<dyn std::error::Error>> {
    let context = CommandContext {
        operation_id: OperationId::from_bytes([91; 16])?,
        actor_principal_id: administrator_id,
        audit_event_id: AuditEventId::from_bytes([92; 16])?,
        occurred_at: UnixMicros::new(20),
        expected_revision: Some(Revision::new(1)),
    };
    Ok((
        context,
        AuthoritativeCommand::CreateUser(meshspan_metadata::CreateUser {
            principal_id: PrincipalId::from_bytes([93; 16])?,
            name: RecordName::new("Post-failover user")?,
        }),
    ))
}

fn named_user_command(
    administrator_id: PrincipalId,
    marker: u8,
    name: &str,
) -> Result<(CommandContext, AuthoritativeCommand), Box<dyn std::error::Error>> {
    let context = CommandContext {
        operation_id: OperationId::from_bytes([marker; 16])?,
        actor_principal_id: administrator_id,
        audit_event_id: AuditEventId::from_bytes([marker.saturating_add(1); 16])?,
        occurred_at: UnixMicros::new(i64::from(marker)),
        expected_revision: None,
    };
    Ok((
        context,
        AuthoritativeCommand::CreateUser(meshspan_metadata::CreateUser {
            principal_id: PrincipalId::from_bytes([marker.saturating_add(2); 16])?,
            name: RecordName::new(name)?,
        }),
    ))
}

fn network_config(
    local_index: usize,
    nodes: &[NodeId; 3],
    addresses: &[SocketAddr; 3],
    identities: &[IssuedCertificate; 3],
    trust_anchor: &[u8],
    mesh_id: MeshId,
    partition_id: PartitionId,
) -> ConsensusNetworkConfig {
    let peers = (0..nodes.len())
        .filter(|index| *index != local_index)
        .map(|index| ConsensusPeerConfig {
            node_id: nodes[index],
            incarnation: 1,
            address: addresses[index],
            certificate_der: identities[index].certificate_der().to_vec(),
            certificate_name: "meshspan.internal".to_owned(),
        })
        .collect();
    ConsensusNetworkConfig {
        local_node_id: nodes[local_index],
        local_incarnation: 1,
        mesh_id,
        partition_id,
        routing_epoch: 1,
        roles: vec![meshspan_protocol::v1::NodeRole::MetadataVoter],
        listen_address: addresses[local_index],
        client_address: SocketAddr::from(([127, 0, 0, 1], 0)),
        certificate_chain_der: vec![identities[local_index].certificate_der().to_vec()],
        private_key_pkcs8: Zeroizing::new(identities[local_index].private_key().to_vec()),
        trust_anchors: vec![trust_anchor.to_vec()],
        peers,
        snapshot_staging_path: None,
    }
}

fn unused_udp_address() -> Result<SocketAddr, std::io::Error> {
    UdpSocket::bind("127.0.0.1:0")?.local_addr()
}
