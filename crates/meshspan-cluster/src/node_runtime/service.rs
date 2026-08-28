// SPDX-License-Identifier: GPL-2.0-only

//! Single-owner headless service loop composing network, consensus and durable state.

use std::collections::{BTreeSet, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use meshspan_consensus::{
    ConsensusCore, CoreConfig, CoreInput, MemberIncarnations, ProposalId, Role, compile_plan,
    flat_plan,
};
use meshspan_domain::{NodeId, OperationId, PartitionId, QuorumPlanId, UnixMicros};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use super::NodeRuntimeError;
use super::config::NodeConfig;
use super::network::{PeerMessage, PeerNetwork};
use crate::{DriverEffect, PartitionConsensusDriver};

const MEMBERSHIP_EPOCH: u64 = 1;
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
    let repository = open_repository(&config)?;
    let core = restore_core(&config, &repository)?;
    let mut driver = PartitionConsensusDriver::new(core, repository);
    let (events, mut received_events) = mpsc::channel(EVENT_CAPACITY);
    let (peer_messages, received_peer_messages) = mpsc::channel(EVENT_CAPACITY);
    let network = PeerNetwork::start(&config, peer_messages)?;
    spawn_peer_forwarder(events.clone(), received_peer_messages);
    spawn_control_listener(config.control_address, events).await?;

    let mut committed = BTreeSet::new();
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = heartbeat.tick(), if driver.role() == Role::Leader => {
                let effects = driver.step(CoreInput::Heartbeat, now())?;
                apply_effects(&mut driver, &network, &mut committed, effects)?;
            }
            event = received_events.recv() => {
                let event = event.ok_or(NodeRuntimeError::InvalidConfiguration)?;
                handle_event(event, &mut driver, &network, &mut committed)?;
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
    repository: &AuthoritativeRepository,
) -> Result<ConsensusCore, NodeRuntimeError> {
    let voters = (1..=3).map(node_id).collect::<Result<BTreeSet<_>, _>>()?;
    let plan = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([7; 16])?,
        MEMBERSHIP_EPOCH,
        voters.clone(),
        BTreeSet::new(),
    )?)?;
    let incarnations =
        MemberIncarnations::new(voters.into_iter().map(|node| (node, 1)).collect(), &plan)?;
    let durable = repository.load_consensus_state(MEMBERSHIP_EPOCH)?;
    ConsensusCore::restore(
        CoreConfig {
            partition_id: partition_id()?,
            local_node_id: config.node_id,
            local_incarnation: 1,
            plan,
            member_incarnations: incarnations,
        },
        durable,
    )
    .map_err(Into::into)
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
    committed: &mut BTreeSet<OperationId>,
) -> Result<(), NodeRuntimeError> {
    match event {
        NodeEvent::Peer(peer) => {
            let effects = driver.step(
                CoreInput::Message {
                    from: peer.from,
                    sender_incarnation: peer.sender_incarnation,
                    message: peer.message,
                },
                now(),
            )?;
            apply_effects(driver, network, committed, effects)
        }
        NodeEvent::Control { request, response } => {
            let answer = handle_control(request, driver, network, committed)?;
            let _receiver_closed = response.send(answer);
            Ok(())
        }
    }
}

fn handle_control(
    request: ControlRequest,
    driver: &mut PartitionConsensusDriver<AuthoritativeRepository>,
    network: &PeerNetwork,
    committed: &mut BTreeSet<OperationId>,
) -> Result<&'static str, NodeRuntimeError> {
    match request {
        ControlRequest::Elect => {
            let effects = driver.step(CoreInput::ElectionTimeout, now())?;
            apply_effects(driver, network, committed, effects)?;
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
            apply_effects(driver, network, committed, effects)?;
            Ok("ACCEPTED")
        }
        ControlRequest::Propose(_) => Ok(redirect_response(driver.leader_id())),
        ControlRequest::Status(value) if committed.contains(&operation_id(value)?) => {
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
    committed: &mut BTreeSet<OperationId>,
    effects: Vec<DriverEffect>,
) -> Result<(), NodeRuntimeError> {
    let mut pending = VecDeque::from(effects);
    while let Some(effect) = pending.pop_front() {
        match effect {
            DriverEffect::Send { to, message } => network.send(to, message),
            DriverEffect::ApplyCommitted { entries } => {
                let applied_index = entries
                    .last()
                    .ok_or(NodeRuntimeError::InvalidConfiguration)?
                    .position
                    .index;
                committed.extend(entries.into_iter().map(|entry| entry.operation_id));
                pending.extend(driver.step(CoreInput::AppliedThrough(applied_index), now())?);
            }
            DriverEffect::Rejected { .. }
            | DriverEffect::RoleChanged { .. }
            | DriverEffect::ProposalAppended { .. }
            | DriverEffect::ReadBarrierReady { .. } => {}
        }
    }
    Ok(())
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
