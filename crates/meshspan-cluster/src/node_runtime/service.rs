// SPDX-License-Identifier: GPL-2.0-only

//! Single-owner headless service loop composing network, consensus and durable state.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use meshspan_consensus::{
    ConsensusCore, CoreConfig, CoreInput, MEMBERSHIP_COMMAND_VERSION, MemberIncarnations,
    MembershipTransitionCommand, ProposalId, Role, compile_plan, flat_plan,
};
use meshspan_domain::{
    BackupId, NodeId, OperationId, PartitionId, QuorumPlanId, Revision, SnapshotId, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeRepository, LogPosition as MetadataLogPosition, PartitionBackupManifest,
    PartitionDatabase, PartitionSnapshotManifest, PreservedVote, restore_partition_snapshot,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use super::NodeRuntimeError;
use super::config::NodeConfig;
use super::network::{OutboundSnapshot, PeerMessage, PeerNetwork, ReceivedSnapshot};
use super::proof_metadata::ProofMetadata;
use crate::membership::{MembershipCoordinatorError, plan_next_transition, validate_transition};
use crate::{ClusterDriverError, DriverEffect, PartitionConsensusDriver};

const MEMBERSHIP_EPOCH: u64 = 1;
const METADATA_COMMAND_VERSION: u16 = 1;
const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(200);
const MAXIMUM_CONTROL_LINE_BYTES: usize = 128;
const EVENT_CAPACITY: usize = 256;

enum NodeEvent {
    Peer(PeerMessage),
    Control {
        request: ControlRequest,
        response: oneshot::Sender<&'static str>,
    },
}

#[derive(Clone, Copy)]
enum ControlRequest {
    Elect,
    Propose(u8),
    Status(u8),
    Info,
    Invalid,
}

/// Runs one fixed three-voter proof process until it is terminated.
///
/// # Errors
///
/// Fails closed on invalid arguments, trust material, durable state or runtime IO.
pub async fn run_stage_three_node(
    arguments: impl Iterator<Item = String>,
) -> Result<(), NodeRuntimeError> {
    let config = NodeConfig::parse(arguments)?;
    if config.bootstrap && config.node_id != node_id(1)? {
        return Err(NodeRuntimeError::InvalidConfiguration);
    }
    let (peer_messages, received_peer_messages) = mpsc::channel(EVENT_CAPACITY);
    let (snapshots, mut received_snapshots) = mpsc::channel(1);
    let network = PeerNetwork::start(&config, peer_messages, snapshots)?;
    if !config.bootstrap && !config.state_path.try_exists()? {
        let received = received_snapshots
            .recv()
            .await
            .ok_or(NodeRuntimeError::InvalidConfiguration)?;
        install_admission_snapshot(&config, received)?;
    }
    let mut repository = open_repository(&config)?;
    let core = restore_core(&config, &mut repository)?;
    let mut driver = PartitionConsensusDriver::new(core, repository);
    let (events, mut received_events) = mpsc::channel(EVENT_CAPACITY);
    let proof_metadata = ProofMetadata::load(&config)?;
    let mut snapshot_dispatch = SnapshotDispatch::new(config.state_path.clone());
    spawn_peer_forwarder(events.clone(), received_peer_messages);
    spawn_snapshot_rejector(received_snapshots);
    spawn_control_listener(config.control_address, events).await?;

    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = heartbeat.tick(), if driver.role() == Role::Leader => {
                let effects = driver.step(CoreInput::Heartbeat, now())?;
                apply_effects(
                    &mut driver,
                    &network,
                    &proof_metadata,
                    &mut snapshot_dispatch,
                    effects,
                )?;
            }
            event = received_events.recv() => {
                let event = event.ok_or(NodeRuntimeError::InvalidConfiguration)?;
                handle_event(
                    event,
                    &mut driver,
                    &network,
                    &proof_metadata,
                    &mut snapshot_dispatch,
                )?;
            }
        }
    }
}

fn open_repository(config: &NodeConfig) -> Result<AuthoritativeRepository, NodeRuntimeError> {
    let database = PartitionDatabase::open(&config.state_path, partition_id()?, now())?;
    Ok(AuthoritativeRepository::new(database))
}

fn restore_core(
    config: &NodeConfig,
    repository: &mut AuthoritativeRepository,
) -> Result<ConsensusCore, NodeRuntimeError> {
    let bootstrap_plan = bootstrap_plan()?;
    let active_plan = match repository.load_active_consensus_quorum_plan()? {
        Some(plan) => plan,
        None => repository.initialise_consensus_quorum_plan(&bootstrap_plan, now())?,
    };
    let recovery_plan = active_plan.recovery_configuration_plan().clone();
    let incarnations = restore_incarnations(repository, &active_plan)?;
    let durable = repository.load_consensus_state(active_plan.membership_epoch())?;
    ConsensusCore::restore_active(
        CoreConfig {
            partition_id: partition_id()?,
            local_node_id: config.node_id,
            local_incarnation: 1,
            plan: recovery_plan,
            member_incarnations: incarnations,
        },
        durable,
        active_plan,
    )
    .map_err(Into::into)
}

fn bootstrap_plan() -> Result<meshspan_consensus::CompiledQuorumPlan, NodeRuntimeError> {
    let voters = BTreeSet::from([node_id(1)?]);
    Ok(compile_plan(flat_plan(
        QuorumPlanId::from_bytes([7; 16])?,
        MEMBERSHIP_EPOCH,
        voters,
        BTreeSet::new(),
    )?)?)
}

fn install_admission_snapshot(
    config: &NodeConfig,
    received: ReceivedSnapshot,
) -> Result<(), NodeRuntimeError> {
    let active = meshspan_consensus::ActiveQuorumPlan::decode(&received.snapshot.quorum_plan)
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    let meshspan_consensus::ActiveQuorumPlan::Stable(plan) = active else {
        return Err(NodeRuntimeError::InvalidConfiguration);
    };
    if !plan.spec().voters.contains(&received.from)
        || !plan.spec().learners.contains(&config.node_id)
        || plan.proof_digest() != received.snapshot.quorum_plan_digest
        || plan.spec().membership_epoch != received.snapshot.membership_epoch
    {
        return Err(NodeRuntimeError::InvalidConfiguration);
    }
    let snapshot_id = SnapshotId::from_bytes(received.snapshot.snapshot_id)?;
    let included = received.snapshot.included_position;
    let manifest = PartitionSnapshotManifest {
        snapshot_id,
        backup: PartitionBackupManifest {
            backup_id: BackupId::from_bytes(snapshot_id.as_bytes())?,
            partition_id: partition_id()?,
            applied_position: MetadataLogPosition {
                term: included.term,
                index: included.index,
            },
            state_revision: Revision::new(received.snapshot.state_revision),
            schema_version: received.snapshot.format_version,
            byte_length: received.snapshot.total_bytes,
            digest: received.snapshot.digest,
            created_at: now(),
        },
        membership_epoch: received.snapshot.membership_epoch,
        quorum_plan_digest: received.snapshot.quorum_plan_digest,
    };
    let database = restore_partition_snapshot(
        &received.snapshot.staging_path,
        &config.state_path,
        manifest,
        &plan,
        PreservedVote {
            current_term: 1,
            voted_for: None,
            membership_epoch: 0,
        },
        now(),
    )?;
    let membership = AuthoritativeRepository::new(database)
        .partition_membership()?
        .ok_or(NodeRuntimeError::InvalidConfiguration)?;
    if membership.admitted_learners().get(&config.node_id) != Some(&1) {
        return Err(NodeRuntimeError::InvalidConfiguration);
    }
    received
        .installed
        .send(())
        .map_err(|()| NodeRuntimeError::InvalidConfiguration)
}

fn spawn_peer_forwarder(
    events: mpsc::Sender<NodeEvent>,
    mut peer_messages: mpsc::Receiver<PeerMessage>,
) {
    tokio::spawn(async move {
        while let Some(message) = peer_messages.recv().await {
            if events.send(NodeEvent::Peer(message)).await.is_err() {
                break;
            }
        }
    });
}

fn spawn_snapshot_rejector(mut snapshots: mpsc::Receiver<ReceivedSnapshot>) {
    tokio::spawn(async move { while snapshots.recv().await.is_some() {} });
}

async fn spawn_control_listener(
    address: std::net::SocketAddr,
    events: mpsc::Sender<NodeEvent>,
) -> Result<(), NodeRuntimeError> {
    let listener = TcpListener::bind(address).await?;
    tokio::spawn(async move {
        while let Ok((stream, _peer_address)) = listener.accept().await {
            let connection_events = events.clone();
            tokio::spawn(async move {
                let _closed = serve_control(stream, connection_events).await;
            });
        }
    });
    Ok(())
}

async fn serve_control(
    mut stream: TcpStream,
    events: mpsc::Sender<NodeEvent>,
) -> Result<(), NodeRuntimeError> {
    let request = read_control_request(&mut stream).await?;
    let (send_response, receive_response) = oneshot::channel();
    events
        .send(NodeEvent::Control {
            request,
            response: send_response,
        })
        .await
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    let response = receive_response
        .await
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.shutdown().await?;
    Ok(())
}

async fn read_control_request(stream: &mut TcpStream) -> Result<ControlRequest, NodeRuntimeError> {
    let mut bytes = Vec::with_capacity(MAXIMUM_CONTROL_LINE_BYTES);
    while bytes.len() <= MAXIMUM_CONTROL_LINE_BYTES {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            let line = std::str::from_utf8(&bytes).unwrap_or_default();
            return Ok(parse_control_request(line));
        }
        bytes.push(byte);
    }
    Ok(ControlRequest::Invalid)
}

fn parse_control_request(line: &str) -> ControlRequest {
    match line {
        "ELECT" => ControlRequest::Elect,
        "INFO" => ControlRequest::Info,
        _ => parse_numbered_request(line).unwrap_or(ControlRequest::Invalid),
    }
}

fn parse_numbered_request(line: &str) -> Option<ControlRequest> {
    let (command, value) = line.split_once(' ')?;
    let value = value.parse::<u8>().ok().filter(|value| *value > 0)?;
    match command {
        "PROPOSE" => Some(ControlRequest::Propose(value)),
        "STATUS" => Some(ControlRequest::Status(value)),
        _ => None,
    }
}

fn handle_event(
    event: NodeEvent,
    driver: &mut PartitionConsensusDriver<AuthoritativeRepository>,
    network: &PeerNetwork,
    proof_metadata: &ProofMetadata,
    snapshot_dispatch: &mut SnapshotDispatch,
) -> Result<(), NodeRuntimeError> {
    match event {
        NodeEvent::Peer(peer) => {
            let effects = match driver.step(
                CoreInput::Message {
                    from: peer.from,
                    sender_incarnation: peer.sender_incarnation,
                    message: peer.message,
                },
                now(),
            ) {
                Ok(effects) => effects,
                Err(ClusterDriverError::Core(
                    meshspan_consensus::CoreError::StaleMember
                    | meshspan_consensus::CoreError::InvalidInput,
                )) => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            apply_effects(driver, network, proof_metadata, snapshot_dispatch, effects)
        }
        NodeEvent::Control { request, response } => {
            let answer =
                handle_control(request, driver, network, proof_metadata, snapshot_dispatch)?;
            let _receiver_closed = response.send(answer);
            Ok(())
        }
    }
}

fn handle_control(
    request: ControlRequest,
    driver: &mut PartitionConsensusDriver<AuthoritativeRepository>,
    network: &PeerNetwork,
    proof_metadata: &ProofMetadata,
    snapshot_dispatch: &mut SnapshotDispatch,
) -> Result<&'static str, NodeRuntimeError> {
    match request {
        ControlRequest::Elect => {
            let effects = driver.step(CoreInput::ElectionTimeout, now())?;
            apply_effects(driver, network, proof_metadata, snapshot_dispatch, effects)?;
            Ok("ELECTION_STARTED")
        }
        ControlRequest::Propose(value) if driver.role() == Role::Leader => {
            let effects = driver.step(
                CoreInput::Propose {
                    proposal_id: ProposalId(u64::from(value)),
                    operation_id: operation_id(value)?,
                    command_version: 1,
                    command: vec![value],
                },
                now(),
            )?;
            apply_effects(driver, network, proof_metadata, snapshot_dispatch, effects)?;
            Ok("ACCEPTED")
        }
        ControlRequest::Propose(_) => Ok(redirect_response(driver.leader_id())),
        ControlRequest::Status(value)
            if driver
                .persistence()
                .resolve_operation(operation_id(value)?)?
                .is_some() =>
        {
            Ok("COMMITTED")
        }
        ControlRequest::Status(_) => Ok("UNKNOWN"),
        ControlRequest::Info => Ok(role_response(driver)),
        ControlRequest::Invalid => Ok("INVALID"),
    }
}

fn apply_effects(
    driver: &mut PartitionConsensusDriver<AuthoritativeRepository>,
    network: &PeerNetwork,
    proof_metadata: &ProofMetadata,
    snapshot_dispatch: &mut SnapshotDispatch,
    effects: Vec<DriverEffect>,
) -> Result<(), NodeRuntimeError> {
    let mut pending = VecDeque::from(effects);
    loop {
        if let Some(effect) = pending.pop_front() {
            match effect {
                DriverEffect::Send { to, message } => network.send(to, message),
                DriverEffect::ApplyCommitted { entries } => {
                    for entry in entries {
                        apply_committed_entry(driver, proof_metadata, &entry, &mut pending)?;
                    }
                }
                DriverEffect::Rejected { .. }
                | DriverEffect::RoleChanged { .. }
                | DriverEffect::ProposalAppended { .. }
                | DriverEffect::ReadBarrierReady { .. } => {}
            }
            continue;
        }
        dispatch_learner_snapshots(driver, network, snapshot_dispatch)?;
        let planned = maybe_plan_membership_transition(driver)?;
        if planned.is_empty() {
            return Ok(());
        }
        pending.extend(planned);
    }
}

struct SnapshotDispatch {
    state_path: std::path::PathBuf,
    sent: BTreeSet<NodeId>,
}

impl SnapshotDispatch {
    fn new(state_path: std::path::PathBuf) -> Self {
        Self {
            state_path,
            sent: BTreeSet::new(),
        }
    }
}

fn dispatch_learner_snapshots(
    driver: &PartitionConsensusDriver<AuthoritativeRepository>,
    network: &PeerNetwork,
    dispatch: &mut SnapshotDispatch,
) -> Result<(), NodeRuntimeError> {
    if driver.role() != Role::Leader {
        return Ok(());
    }
    let meshspan_consensus::ActiveQuorumPlan::Stable(plan) = driver.active_plan() else {
        return Ok(());
    };
    let Some(membership) = driver.persistence().partition_membership()? else {
        return Ok(());
    };
    for learner in &plan.spec().learners {
        if dispatch.sent.contains(learner) || !membership.admitted_learners().contains_key(learner)
        {
            continue;
        }
        let snapshot_id = learner_snapshot_id(plan, *learner)?;
        let destination = dispatch.state_path.with_extension(format!(
            "learner-{}-epoch-{}.snapshot",
            node_number(*learner).ok_or(NodeRuntimeError::InvalidConfiguration)?,
            plan.spec().membership_epoch,
        ));
        remove_owned_snapshot(&destination)?;
        let manifest =
            driver
                .persistence()
                .create_snapshot(snapshot_id, &destination, plan, now())?;
        let quorum_plan = meshspan_consensus::ActiveQuorumPlan::Stable(plan.clone())
            .encode()
            .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
        network.send_snapshot(
            *learner,
            OutboundSnapshot {
                path: destination,
                manifest,
                quorum_plan,
            },
        );
        dispatch.sent.insert(*learner);
    }
    Ok(())
}

fn learner_snapshot_id(
    plan: &meshspan_consensus::CompiledQuorumPlan,
    learner: NodeId,
) -> Result<SnapshotId, NodeRuntimeError> {
    let mut bytes: [u8; 16] = plan.proof_digest()[..16]
        .try_into()
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    for (target, source) in bytes.iter_mut().zip(learner.as_bytes()) {
        *target ^= source;
    }
    SnapshotId::from_bytes(bytes).map_err(Into::into)
}

fn remove_owned_snapshot(file_path: &std::path::Path) -> Result<(), NodeRuntimeError> {
    match std::fs::symlink_metadata(file_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            std::fs::remove_file(file_path).map_err(Into::into)
        }
        Ok(_) => Err(NodeRuntimeError::InvalidConfiguration),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn apply_committed_entry(
    driver: &mut PartitionConsensusDriver<AuthoritativeRepository>,
    proof_metadata: &ProofMetadata,
    entry: &meshspan_consensus::LogEntry,
    pending: &mut VecDeque<DriverEffect>,
) -> Result<(), NodeRuntimeError> {
    if entry.command_version == METADATA_COMMAND_VERSION {
        let decoded = proof_metadata.decode(entry)?;
        driver.persistence_mut().apply_committed(
            MetadataLogPosition {
                term: entry.position.term,
                index: entry.position.index,
            },
            decoded.context,
            &decoded.command,
        )?;
        pending.extend(driver.step(CoreInput::AppliedThrough(entry.position.index), now())?);
        return Ok(());
    }
    if entry.command_version != MEMBERSHIP_COMMAND_VERSION {
        return Err(NodeRuntimeError::InvalidConfiguration);
    }
    let command = MembershipTransitionCommand::decode(&entry.command)
        .map_err(MembershipCoordinatorError::from)?;
    let evidence_entry = match &command {
        MembershipTransitionCommand::PromoteLearner { evidence, .. } => {
            driver.log_entry(evidence.committed_position.index).cloned()
        }
        MembershipTransitionCommand::AdmitLearner { .. }
        | MembershipTransitionCommand::FinaliseStable { .. } => None,
    };
    let membership = driver
        .persistence()
        .partition_membership()?
        .ok_or(MembershipCoordinatorError::InvalidAuthority)?;
    let incarnations = validate_transition(
        driver.active_plan(),
        driver.member_incarnations(),
        membership.active_voters(),
        membership.admitted_learners(),
        &command,
        evidence_entry.as_ref(),
    )?;
    pending.extend(driver.step(CoreInput::AppliedThrough(entry.position.index), now())?);
    if driver.role() == Role::Leader {
        pending.extend(driver.step(CoreInput::Heartbeat, now())?);
    }
    let activation = match command {
        MembershipTransitionCommand::AdmitLearner { joint_plan, .. }
        | MembershipTransitionCommand::PromoteLearner { joint_plan, .. } => {
            CoreInput::ActivateJointPlan {
                joint_plan,
                member_incarnations: incarnations,
                committed_position: entry.position,
            }
        }
        MembershipTransitionCommand::FinaliseStable { plan } => CoreInput::ActivateStablePlan {
            plan,
            member_incarnations: incarnations,
            committed_position: entry.position,
        },
    };
    pending.extend(driver.step(activation, now())?);
    Ok(())
}

fn maybe_plan_membership_transition(
    driver: &mut PartitionConsensusDriver<AuthoritativeRepository>,
) -> Result<Vec<DriverEffect>, NodeRuntimeError> {
    if driver.role() != Role::Leader
        || driver
            .last_log_entry()
            .is_some_and(|entry| entry.position.index > driver.commit_index())
    {
        return Ok(Vec::new());
    }
    let Some(membership) = driver.persistence().partition_membership()? else {
        return Ok(Vec::new());
    };
    let committed = driver.committed_entry().cloned();
    let command = plan_next_transition(
        driver.active_plan(),
        driver.member_incarnations(),
        membership.active_voters(),
        membership.admitted_learners(),
        committed.as_ref(),
        |node| driver.peer_matched_index(node),
    )?;
    let Some(command) = command else {
        return Ok(Vec::new());
    };
    let command_bytes = command.encode().map_err(MembershipCoordinatorError::from)?;
    driver
        .step(
            CoreInput::Propose {
                proposal_id: membership_proposal_id(&command)?,
                operation_id: membership_operation_id(&command)?,
                command_version: MEMBERSHIP_COMMAND_VERSION,
                command: command_bytes,
            },
            now(),
        )
        .map_err(Into::into)
}

fn restore_incarnations(
    repository: &AuthoritativeRepository,
    active_plan: &meshspan_consensus::ActiveQuorumPlan,
) -> Result<MemberIncarnations, NodeRuntimeError> {
    let values = if let Some(membership) = repository.partition_membership()? {
        let mut values = membership.active_voters().clone();
        values.extend(membership.admitted_learners());
        active_plan
            .members()
            .into_iter()
            .map(|node| {
                values
                    .get(&node)
                    .copied()
                    .map(|incarnation| (node, incarnation))
                    .ok_or(NodeRuntimeError::InvalidConfiguration)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?
    } else {
        active_plan
            .members()
            .into_iter()
            .map(|node| (node, 1))
            .collect()
    };
    MemberIncarnations::for_members(values, &active_plan.members()).map_err(Into::into)
}

fn membership_proposal_id(
    command: &MembershipTransitionCommand,
) -> Result<ProposalId, NodeRuntimeError> {
    let epoch = transition_epoch(command);
    let value = epoch
        .checked_mul(4)
        .and_then(|value| value.checked_add(u64::from(transition_kind(command))))
        .map(|value| value | (1_u64 << 63))
        .ok_or(NodeRuntimeError::InvalidConfiguration)?;
    Ok(ProposalId(value))
}

fn membership_operation_id(
    command: &MembershipTransitionCommand,
) -> Result<OperationId, NodeRuntimeError> {
    let digest = transition_digest(command);
    let mut bytes: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    bytes[0] ^= transition_kind(command);
    OperationId::from_bytes(bytes).map_err(Into::into)
}

const fn transition_kind(command: &MembershipTransitionCommand) -> u8 {
    match command {
        MembershipTransitionCommand::AdmitLearner { .. } => 1,
        MembershipTransitionCommand::PromoteLearner { .. } => 2,
        MembershipTransitionCommand::FinaliseStable { .. } => 3,
    }
}

fn transition_epoch(command: &MembershipTransitionCommand) -> u64 {
    match command {
        MembershipTransitionCommand::AdmitLearner { joint_plan, .. }
        | MembershipTransitionCommand::PromoteLearner { joint_plan, .. } => {
            joint_plan.membership_epoch()
        }
        MembershipTransitionCommand::FinaliseStable { plan } => plan.spec().membership_epoch,
    }
}

fn transition_digest(command: &MembershipTransitionCommand) -> [u8; 32] {
    match command {
        MembershipTransitionCommand::AdmitLearner { joint_plan, .. }
        | MembershipTransitionCommand::PromoteLearner { joint_plan, .. } => {
            joint_plan.proof_digest()
        }
        MembershipTransitionCommand::FinaliseStable { plan } => plan.proof_digest(),
    }
}

fn role_response(driver: &PartitionConsensusDriver<AuthoritativeRepository>) -> &'static str {
    match driver.role() {
        Role::Leader => "LEADER",
        Role::Candidate => "CANDIDATE",
        Role::Follower if driver.leader_id().is_some() => "FOLLOWER_WITH_LEADER",
        Role::Follower => "FOLLOWER",
    }
}

fn redirect_response(leader: Option<NodeId>) -> &'static str {
    match leader.and_then(node_number) {
        Some(1) => "REDIRECT 1",
        Some(2) => "REDIRECT 2",
        Some(3) => "REDIRECT 3",
        _ => "NO_LEADER",
    }
}

fn node_number(node: NodeId) -> Option<u8> {
    let bytes = node.as_bytes();
    bytes
        .iter()
        .all(|byte| *byte == bytes[0])
        .then_some(bytes[0])
}

fn node_id(value: u8) -> Result<NodeId, NodeRuntimeError> {
    NodeId::from_bytes([value; 16]).map_err(Into::into)
}

fn operation_id(value: u8) -> Result<OperationId, NodeRuntimeError> {
    OperationId::from_bytes([value; 16]).map_err(Into::into)
}

fn partition_id() -> Result<PartitionId, NodeRuntimeError> {
    PartitionId::from_bytes([8; 16]).map_err(Into::into)
}

fn now() -> UnixMicros {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    UnixMicros::new(i64::try_from(micros).unwrap_or(i64::MAX))
}
