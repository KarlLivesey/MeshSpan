// SPDX-License-Identifier: GPL-2.0-only

//! Bounded single-owner reactor for the root metadata consensus authority.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use meshspan_consensus::{CoreError, CoreInput, CoreMessage, ProposalId, Role};
use meshspan_domain::{NodeId, OperationId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, CommandReceipt,
    METADATA_COMMAND_VERSION, encode_authoritative_command,
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::{ClusterDriverError, DriverEffect, PartitionConsensusDriver};

const DEFAULT_EVENT_CAPACITY: usize = 256;
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(200);
const DEFAULT_ELECTION_TIMEOUT: Duration = Duration::from_millis(1_200);
const DEFAULT_ELECTION_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// One authenticated peer message admitted to the local authority reactor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerConsensusMessage {
    /// Enrolled sender identity established by mTLS routing.
    pub from: NodeId,
    /// Sender process incarnation carried by the authenticated connection.
    pub sender_incarnation: u64,
    /// Strictly decoded consensus message.
    pub message: CoreMessage,
}

/// Non-blocking private transport used only for already validated consensus messages.
pub trait ConsensusMessageTransport: Send + Sync + 'static {
    /// Queues one message for its exact enrolled destination.
    fn send(&self, to: NodeId, message: CoreMessage);
}

impl<F> ConsensusMessageTransport for F
where
    F: Fn(NodeId, CoreMessage) + Send + Sync + 'static,
{
    fn send(&self, to: NodeId, message: CoreMessage) {
        self(to, message);
    }
}

/// Validated timing and queue bounds for one authority reactor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataAuthorityConfig {
    /// Maximum queued submissions, peer messages and lifecycle signals.
    pub event_capacity: usize,
    /// Leader replication heartbeat cadence.
    pub heartbeat_interval: Duration,
    /// Follower silence required before campaigning.
    pub election_timeout: Duration,
    /// Maximum delay before noticing an expired election deadline.
    pub election_check_interval: Duration,
}

impl Default for MetadataAuthorityConfig {
    fn default() -> Self {
        Self {
            event_capacity: DEFAULT_EVENT_CAPACITY,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            election_timeout: DEFAULT_ELECTION_TIMEOUT,
            election_check_interval: DEFAULT_ELECTION_CHECK_INTERVAL,
        }
    }
}

impl MetadataAuthorityConfig {
    /// Rejects useless queues and timing which could busy-loop the appliance.
    ///
    /// # Errors
    ///
    /// Returns an error when a bound is zero or election timeout cannot exceed heartbeat cadence.
    pub fn validate(self) -> Result<Self, MetadataAuthorityStartError> {
        if self.event_capacity == 0
            || self.heartbeat_interval.is_zero()
            || self.election_timeout <= self.heartbeat_interval
            || self.election_check_interval.is_zero()
        {
            return Err(MetadataAuthorityStartError::InvalidConfiguration);
        }
        Ok(self)
    }
}

/// Cloneable bounded ingress to the single repository/consensus owner.
#[derive(Clone)]
pub struct MetadataAuthorityHandle {
    events: mpsc::Sender<AuthorityEvent>,
}

impl MetadataAuthorityHandle {
    /// Submits or exactly resolves one operation, returning only after committed application.
    ///
    /// # Errors
    ///
    /// Returns redirect/unavailable/conflict/failed without inventing a successful receipt.
    pub async fn commit_or_resolve(
        &self,
        context: CommandContext,
        command: AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        let (respond, response) = oneshot::channel();
        self.events
            .send(AuthorityEvent::Submit(Box::new(AuthoritySubmission {
                context,
                command,
                respond,
            })))
            .await
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)?;
        response
            .await
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)?
    }

    /// Queues one already authenticated peer message under the same owner.
    ///
    /// # Errors
    ///
    /// Fails when the authority has stopped or its bounded queue is unavailable.
    pub async fn receive_peer(
        &self,
        message: PeerConsensusMessage,
    ) -> Result<(), MetadataAuthorityRequestError> {
        self.events
            .send(AuthorityEvent::Peer(message))
            .await
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)
    }

    /// Requests an immediate campaign, primarily for deterministic startup and fault proofs.
    ///
    /// # Errors
    ///
    /// Fails when the authority has stopped.
    pub async fn begin_election(&self) -> Result<(), MetadataAuthorityRequestError> {
        self.events
            .send(AuthorityEvent::BeginElection)
            .await
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)
    }

    /// Requests an orderly stop and waits for the owner to acknowledge it.
    ///
    /// # Errors
    ///
    /// Fails when the authority has already stopped.
    pub async fn shutdown(&self) -> Result<(), MetadataAuthorityRequestError> {
        let (respond, response) = oneshot::channel();
        self.events
            .send(AuthorityEvent::Shutdown(respond))
            .await
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)?;
        response
            .await
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)
    }
}

/// Starts one task which exclusively owns consensus and its SQLite repository.
///
/// # Errors
///
/// Rejects invalid reactor bounds before spawning any task.
pub fn spawn_metadata_authority(
    driver: PartitionConsensusDriver<AuthoritativeRepository>,
    transport: Arc<dyn ConsensusMessageTransport>,
    config: MetadataAuthorityConfig,
) -> Result<
    (
        MetadataAuthorityHandle,
        JoinHandle<Result<(), MetadataAuthorityRuntimeError>>,
    ),
    MetadataAuthorityStartError,
> {
    let config = config.validate()?;
    let (events, received_events) = mpsc::channel(config.event_capacity);
    let handle = MetadataAuthorityHandle { events };
    let runtime = MetadataAuthorityRuntime::new(driver, transport, config, received_events);
    Ok((handle, tokio::spawn(runtime.run())))
}

enum AuthorityEvent {
    Submit(Box<AuthoritySubmission>),
    Peer(PeerConsensusMessage),
    BeginElection,
    Shutdown(oneshot::Sender<()>),
}

struct AuthoritySubmission {
    context: CommandContext,
    command: AuthoritativeCommand,
    respond: oneshot::Sender<Result<CommandReceipt, MetadataAuthorityRequestError>>,
}

struct PendingOperation {
    request_digest: [u8; 32],
    waiters: Vec<oneshot::Sender<Result<CommandReceipt, MetadataAuthorityRequestError>>>,
}

struct QueuedOperation {
    context: CommandContext,
    command: AuthoritativeCommand,
    request_digest: [u8; 32],
    waiters: Vec<oneshot::Sender<Result<CommandReceipt, MetadataAuthorityRequestError>>>,
}

struct MetadataAuthorityRuntime {
    driver: PartitionConsensusDriver<AuthoritativeRepository>,
    transport: Arc<dyn ConsensusMessageTransport>,
    config: MetadataAuthorityConfig,
    events: mpsc::Receiver<AuthorityEvent>,
    pending: BTreeMap<OperationId, PendingOperation>,
    queued: VecDeque<QueuedOperation>,
    next_proposal_id: u64,
    last_leader_contact: Instant,
}

impl MetadataAuthorityRuntime {
    fn new(
        driver: PartitionConsensusDriver<AuthoritativeRepository>,
        transport: Arc<dyn ConsensusMessageTransport>,
        config: MetadataAuthorityConfig,
        events: mpsc::Receiver<AuthorityEvent>,
    ) -> Self {
        Self {
            driver,
            transport,
            config,
            events,
            pending: BTreeMap::new(),
            queued: VecDeque::new(),
            next_proposal_id: 1,
            last_leader_contact: Instant::now(),
        }
    }

    async fn run(mut self) -> Result<(), MetadataAuthorityRuntimeError> {
        let mut heartbeat = tokio::time::interval(self.config.heartbeat_interval);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut election_check = tokio::time::interval(self.config.election_check_interval);
        election_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let outcome = tokio::select! {
                _ = heartbeat.tick(), if self.driver.role() == Role::Leader => {
                    self.process_input(CoreInput::Heartbeat)
                }
                _ = election_check.tick(), if self.driver.role() != Role::Leader => {
                    self.check_election_timeout()
                }
                event = self.events.recv() => {
                    let Some(event) = event else {
                        self.fail_pending();
                        return Ok(());
                    };
                    if self.handle_event(event)? {
                        return Ok(());
                    }
                    Ok(())
                }
            };
            if let Err(error) = outcome {
                self.fail_pending();
                return Err(error);
            }
        }
    }

    fn handle_event(
        &mut self,
        event: AuthorityEvent,
    ) -> Result<bool, MetadataAuthorityRuntimeError> {
        match event {
            AuthorityEvent::Submit(submission) => self.submit(*submission)?,
            AuthorityEvent::Peer(peer) => self.receive_peer(peer)?,
            AuthorityEvent::BeginElection => self.process_input(CoreInput::ElectionTimeout)?,
            AuthorityEvent::Shutdown(respond) => {
                self.fail_pending();
                let _closed = respond.send(());
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn submit(
        &mut self,
        submission: AuthoritySubmission,
    ) -> Result<(), MetadataAuthorityRuntimeError> {
        let AuthoritySubmission {
            context,
            command,
            respond,
        } = submission;
        let request_digest = command.request_digest(context);
        if let Some(receipt) = self
            .driver
            .persistence()
            .resolve_operation(context.operation_id)?
        {
            let outcome = if receipt.request_digest == request_digest {
                Ok(receipt)
            } else {
                Err(MetadataAuthorityRequestError::Conflict)
            };
            let _closed = respond.send(outcome);
            return Ok(());
        }
        if let Some(pending) = self.pending.get_mut(&context.operation_id) {
            if pending.request_digest == request_digest {
                pending.waiters.push(respond);
            } else {
                let _closed = respond.send(Err(MetadataAuthorityRequestError::Conflict));
            }
            return Ok(());
        }
        if let Some(queued) = self
            .queued
            .iter_mut()
            .find(|queued| queued.context.operation_id == context.operation_id)
        {
            if queued.request_digest == request_digest {
                queued.waiters.push(respond);
            } else {
                let _closed = respond.send(Err(MetadataAuthorityRequestError::Conflict));
            }
            return Ok(());
        }
        if self.driver.role() != Role::Leader {
            let _closed = respond.send(Err(MetadataAuthorityRequestError::NotLeader {
                leader_id: self.driver.leader_id(),
            }));
            return Ok(());
        }
        if self.queued.len() >= self.config.event_capacity {
            let _closed = respond.send(Err(MetadataAuthorityRequestError::Unavailable));
            return Ok(());
        }
        self.queued.push_back(QueuedOperation {
            context,
            command,
            request_digest,
            waiters: vec![respond],
        });
        self.process_effects(Vec::new(), None)
    }

    fn admit_next(
        &mut self,
    ) -> Result<Option<(Vec<DriverEffect>, OperationId)>, MetadataAuthorityRuntimeError> {
        let Some(queued) = self.queued.pop_front() else {
            return Ok(None);
        };
        if self.driver.role() != Role::Leader {
            respond_to_waiters(
                queued.waiters,
                Err(MetadataAuthorityRequestError::NotLeader {
                    leader_id: self.driver.leader_id(),
                }),
            );
            return Ok(Some((Vec::new(), queued.context.operation_id)));
        }
        if let Some(receipt) = self
            .driver
            .persistence()
            .resolve_operation(queued.context.operation_id)?
        {
            let outcome = if receipt.request_digest == queued.request_digest {
                Ok(receipt)
            } else {
                Err(MetadataAuthorityRequestError::Conflict)
            };
            respond_to_waiters(queued.waiters, outcome);
            return Ok(Some((Vec::new(), queued.context.operation_id)));
        }
        if let Err(error) = self
            .driver
            .preflight_authoritative_command(queued.context, &queued.command)
        {
            respond_to_waiters(queued.waiters, Err(map_preflight_error(&error)));
            return Ok(Some((Vec::new(), queued.context.operation_id)));
        }
        let bytes = match encode_authoritative_command(queued.context, &queued.command) {
            Ok(bytes) => bytes,
            Err(meshspan_metadata::MetadataCommandCodecError::Unsupported) => {
                respond_to_waiters(
                    queued.waiters,
                    Err(MetadataAuthorityRequestError::Unsupported),
                );
                return Ok(Some((Vec::new(), queued.context.operation_id)));
            }
            Err(_) => {
                respond_to_waiters(queued.waiters, Err(MetadataAuthorityRequestError::Failed));
                return Ok(Some((Vec::new(), queued.context.operation_id)));
            }
        };
        let proposal_id = ProposalId(self.next_proposal_id);
        self.next_proposal_id = self
            .next_proposal_id
            .checked_add(1)
            .ok_or(MetadataAuthorityRuntimeError::ProposalSpaceExhausted)?;
        self.pending.insert(
            queued.context.operation_id,
            PendingOperation {
                request_digest: queued.request_digest,
                waiters: queued.waiters,
            },
        );
        let effects = match self.driver.step(
            CoreInput::Propose {
                proposal_id,
                operation_id: queued.context.operation_id,
                command_version: METADATA_COMMAND_VERSION,
                command: bytes,
            },
            now(),
        ) {
            Ok(effects) => effects,
            Err(error) => {
                self.finish_pending(queued.context.operation_id, Err(map_driver_error(&error)));
                return Err(error.into());
            }
        };
        Ok(Some((effects, queued.context.operation_id)))
    }

    fn receive_peer(
        &mut self,
        peer: PeerConsensusMessage,
    ) -> Result<(), MetadataAuthorityRuntimeError> {
        let is_leader_contact = matches!(peer.message, CoreMessage::AppendRequest(_));
        let effects = match self.driver.step(
            CoreInput::Message {
                from: peer.from,
                sender_incarnation: peer.sender_incarnation,
                message: peer.message,
            },
            now(),
        ) {
            Ok(effects) => effects,
            Err(ClusterDriverError::Core(CoreError::StaleMember | CoreError::InvalidInput)) => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if is_leader_contact {
            self.last_leader_contact = Instant::now();
        }
        self.process_effects(effects, None)
    }

    fn check_election_timeout(&mut self) -> Result<(), MetadataAuthorityRuntimeError> {
        if self.last_leader_contact.elapsed() < self.config.election_timeout {
            return Ok(());
        }
        self.last_leader_contact = Instant::now();
        self.process_input(CoreInput::ElectionTimeout)
    }

    fn process_input(&mut self, input: CoreInput) -> Result<(), MetadataAuthorityRuntimeError> {
        let effects = self.driver.step(input, now())?;
        self.process_effects(effects, None)
    }

    fn process_effects(
        &mut self,
        effects: Vec<DriverEffect>,
        rejection_operation: Option<OperationId>,
    ) -> Result<(), MetadataAuthorityRuntimeError> {
        let mut pending_effects = effects
            .into_iter()
            .map(|effect| (effect, rejection_operation))
            .collect::<VecDeque<_>>();
        loop {
            let Some((effect, rejection_operation)) = pending_effects.pop_front() else {
                if !self.pending.is_empty() {
                    break;
                }
                let Some((effects, operation_id)) = self.admit_next()? else {
                    break;
                };
                pending_effects.extend(
                    effects
                        .into_iter()
                        .map(|effect| (effect, Some(operation_id))),
                );
                continue;
            };
            match effect {
                DriverEffect::Send { to, message } => self.transport.send(to, message),
                DriverEffect::ApplyCommitted { entries } => {
                    for entry in entries {
                        if entry.command_version != METADATA_COMMAND_VERSION {
                            return Err(MetadataAuthorityRuntimeError::UnsupportedCommittedEntry);
                        }
                        let applied = self.driver.apply_authoritative_committed(&entry, now())?;
                        self.finish_pending(applied.receipt.operation_id, Ok(applied.receipt));
                        pending_effects
                            .extend(applied.effects.into_iter().map(|effect| (effect, None)));
                    }
                }
                DriverEffect::Rejected { .. } => {
                    if let Some(operation_id) = rejection_operation {
                        self.finish_pending(
                            operation_id,
                            Err(MetadataAuthorityRequestError::Failed),
                        );
                    }
                }
                DriverEffect::RoleChanged { .. }
                | DriverEffect::ProposalAppended { .. }
                | DriverEffect::ReadBarrierReady { .. } => {}
            }
        }
        Ok(())
    }

    fn finish_pending(
        &mut self,
        operation_id: OperationId,
        outcome: Result<CommandReceipt, MetadataAuthorityRequestError>,
    ) {
        if let Some(pending) = self.pending.remove(&operation_id) {
            for waiter in pending.waiters {
                let _closed = waiter.send(outcome);
            }
        }
    }

    fn fail_pending(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        for operation in pending.into_values() {
            for waiter in operation.waiters {
                let _closed = waiter.send(Err(MetadataAuthorityRequestError::Unavailable));
            }
        }
        let queued = std::mem::take(&mut self.queued);
        for operation in queued {
            respond_to_waiters(
                operation.waiters,
                Err(MetadataAuthorityRequestError::Unavailable),
            );
        }
    }
}

fn respond_to_waiters(
    waiters: Vec<oneshot::Sender<Result<CommandReceipt, MetadataAuthorityRequestError>>>,
    outcome: Result<CommandReceipt, MetadataAuthorityRequestError>,
) {
    for waiter in waiters {
        let _closed = waiter.send(outcome);
    }
}

fn map_preflight_error(error: &ClusterDriverError) -> MetadataAuthorityRequestError {
    match error {
        ClusterDriverError::Authority(meshspan_metadata::RepositoryError::OperationConflict) => {
            MetadataAuthorityRequestError::Conflict
        }
        ClusterDriverError::Authority(error) if error.is_command_rejection() => {
            MetadataAuthorityRequestError::Rejected
        }
        _ => MetadataAuthorityRequestError::Failed,
    }
}

fn map_driver_error(error: &ClusterDriverError) -> MetadataAuthorityRequestError {
    match error {
        ClusterDriverError::Authority(meshspan_metadata::RepositoryError::OperationConflict) => {
            MetadataAuthorityRequestError::Conflict
        }
        ClusterDriverError::CommandCodec(
            meshspan_metadata::MetadataCommandCodecError::Unsupported,
        ) => MetadataAuthorityRequestError::Unsupported,
        _ => MetadataAuthorityRequestError::Failed,
    }
}

fn now() -> UnixMicros {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_micros()).ok())
        .unwrap_or(i64::MAX);
    UnixMicros::new(micros)
}

/// Request outcomes safe to map onto public HTTP without exposing authority internals.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MetadataAuthorityRequestError {
    /// The receiving node is not leader; the authenticated hint may be absent.
    #[error("metadata authority is not leader")]
    NotLeader {
        /// Last authenticated leader known to this node.
        leader_id: Option<NodeId>,
    },
    /// The authority task or required quorum is unavailable.
    #[error("metadata authority is unavailable")]
    Unavailable,
    /// Operation identity is already bound to different semantic input.
    #[error("metadata operation conflicts with durable state")]
    Conflict,
    /// The exact command is well-formed but violates current authoritative state.
    #[error("metadata operation is rejected by authoritative state")]
    Rejected,
    /// This closed command codec version does not support the requested family.
    #[error("metadata operation is unsupported")]
    Unsupported,
    /// Persistence, validation or consensus failed closed.
    #[error("metadata authority failed closed")]
    Failed,
}

/// Startup rejection before an authority task exists.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MetadataAuthorityStartError {
    /// A queue or duration bound is invalid.
    #[error("metadata authority configuration is invalid")]
    InvalidConfiguration,
}

/// Fatal single-owner task failures.
#[derive(Debug, Error)]
pub enum MetadataAuthorityRuntimeError {
    /// Consensus driver or durable repository failed closed.
    #[error("metadata authority driver failed")]
    Driver(#[from] ClusterDriverError),
    /// Repository query failed closed.
    #[error("metadata authority repository failed")]
    Repository(#[from] meshspan_metadata::RepositoryError),
    /// Proposal correlation space cannot advance without wrapping.
    #[error("metadata authority proposal space is exhausted")]
    ProposalSpaceExhausted,
    /// A membership or future command entered a runtime not yet configured to apply it.
    #[error("metadata authority received an unsupported committed entry")]
    UnsupportedCommittedEntry,
}

#[cfg(test)]
mod tests;
