// SPDX-License-Identifier: GPL-2.0-only

//! Validated consensus inputs, messages, persistence mutations and effects.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{NodeId, OperationId, PartitionId};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ActiveQuorumPlan, CompiledQuorumPlan, JointQuorumPlan};

const MAXIMUM_LOG_ENTRY_BYTES: usize = 16 * 1_024 * 1_024;
const MAXIMUM_APPEND_ENTRIES: usize = 64;

/// Term/index pair inside exactly one metadata partition.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogPosition {
    /// Zero only for the genesis position.
    pub term: u64,
    /// Zero only for the genesis position.
    pub index: u64,
}

impl LogPosition {
    /// Genesis position before the first log entry.
    pub const GENESIS: Self = Self { term: 0, index: 0 };

    pub(super) const fn is_valid(self) -> bool {
        (self.index == 0) == (self.term == 0)
    }
}

/// One bounded, digest-bound semantic command in the replicated log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEntry {
    /// Exact term/index allocated by the leader.
    pub position: LogPosition,
    /// Idempotency identity resolved by the metadata kernel.
    pub operation_id: OperationId,
    /// Independently versioned command format.
    pub command_version: u16,
    /// Bounded canonical semantic command bytes.
    pub command: Vec<u8>,
    /// SHA-256 of version and command bytes.
    pub command_digest: [u8; 32],
}

impl LogEntry {
    /// Constructs a bounded log entry and independently derives its digest.
    ///
    /// # Errors
    ///
    /// Rejects genesis/invalid positions, a zero version or payload beyond 16 MiB.
    pub fn new(
        position: LogPosition,
        operation_id: OperationId,
        command_version: u16,
        command: Vec<u8>,
    ) -> Result<Self, CoreError> {
        if !position.is_valid()
            || position == LogPosition::GENESIS
            || command_version == 0
            || command.len() > MAXIMUM_LOG_ENTRY_BYTES
        {
            return Err(CoreError::InvalidInput);
        }
        let command_digest = command_digest(command_version, &command);
        Ok(Self {
            position,
            operation_id,
            command_version,
            command,
            command_digest,
        })
    }

    pub(super) fn validate(&self) -> Result<(), CoreError> {
        if !self.position.is_valid()
            || self.position == LogPosition::GENESIS
            || self.command_version == 0
            || self.command.len() > MAXIMUM_LOG_ENTRY_BYTES
            || self.command_digest != command_digest(self.command_version, &self.command)
        {
            Err(CoreError::InvalidInput)
        } else {
            Ok(())
        }
    }

    /// Returns the digest chaining this complete log record to its successor.
    #[must_use]
    pub fn entry_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"meshspan.consensus.log-entry.v1");
        digest.update(self.position.term.to_be_bytes());
        digest.update(self.position.index.to_be_bytes());
        digest.update(self.operation_id.as_bytes());
        digest.update(self.command_version.to_be_bytes());
        digest.update(self.command_digest);
        digest.finalize().into()
    }
}

/// Exact positive driver persistence correlation identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PersistenceId(pub u64);

/// Exact positive client proposal correlation identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProposalId(pub u64);

/// Exact positive local linearizable-read correlation identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadBarrierId(pub u64);

/// Current volatile role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Replicates from a current leader or waits for an election.
    Follower,
    /// Collects one election quorum in the current term.
    Candidate,
    /// Replicates and commits under the current plan.
    Leader,
}

/// Exact positive incarnation for every recognised voter and learner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberIncarnations(BTreeMap<NodeId, u64>);

impl MemberIncarnations {
    /// Validates complete, positive incarnation coverage for voters and learners.
    ///
    /// # Errors
    ///
    /// Rejects missing, extra or zero-incarnation members.
    pub fn new(
        values: BTreeMap<NodeId, u64>,
        plan: &CompiledQuorumPlan,
    ) -> Result<Self, CoreError> {
        let expected: BTreeSet<NodeId> = plan
            .spec()
            .voters
            .union(&plan.spec().learners)
            .copied()
            .collect();
        Self::for_members(values, &expected)
    }

    /// Validates complete, positive incarnation coverage for an exact stable or joint member set.
    ///
    /// # Errors
    ///
    /// Rejects missing, extra or zero-incarnation members.
    pub fn for_members(
        values: BTreeMap<NodeId, u64>,
        expected: &BTreeSet<NodeId>,
    ) -> Result<Self, CoreError> {
        if values.keys().copied().collect::<BTreeSet<_>>() != *expected
            || values.values().any(|value| *value == 0)
        {
            Err(CoreError::InvalidConfiguration)
        } else {
            Ok(Self(values))
        }
    }

    /// Returns the exact accepted incarnation for one member.
    #[must_use]
    pub fn incarnation(&self, node_id: NodeId) -> Option<u64> {
        self.0.get(&node_id).copied()
    }

    pub(crate) fn matches_members(&self, members: &BTreeSet<NodeId>) -> bool {
        self.0.keys().copied().collect::<BTreeSet<_>>() == *members
            && self.0.values().all(|incarnation| *incarnation > 0)
    }

    pub(crate) fn preserves(&self, previous: &Self, incumbent_members: &BTreeSet<NodeId>) -> bool {
        incumbent_members
            .iter()
            .all(|member| self.incarnation(*member) == previous.incarnation(*member))
    }

    pub(crate) const fn values(&self) -> &BTreeMap<NodeId, u64> {
        &self.0
    }
}

/// Immutable local core construction input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreConfig {
    /// Owning metadata partition.
    pub partition_id: PartitionId,
    /// This process's enrolled node identity.
    pub local_node_id: NodeId,
    /// Positive restart-fencing incarnation.
    pub local_incarnation: u64,
    /// Independently compiled immutable quorum plan.
    pub plan: CompiledQuorumPlan,
    /// Exact accepted incarnation of every plan member.
    pub member_incarnations: MemberIncarnations,
}

/// Exact durable state recovered atomically before the deterministic core starts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DurableCoreState {
    /// Last durably observed term.
    pub current_term: u64,
    /// Candidate durably voted for in `current_term`, if any.
    pub voted_for: Option<NodeId>,
    /// Contiguous durable log above the current snapshot boundary.
    pub log: Vec<LogEntry>,
    /// Highest state-machine position durably applied to authoritative metadata.
    pub applied_index: u64,
}

/// Candidate request for one vote in a term.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteRequest {
    /// Candidate term.
    pub term: u64,
    /// Candidate node identity.
    pub candidate: NodeId,
    /// Candidate incarnation fenced by current membership.
    pub candidate_incarnation: u64,
    /// Candidate's last durable log position.
    pub last_log: LogPosition,
    /// Exact membership epoch.
    pub membership_epoch: u64,
    /// Exact compiled plan digest.
    pub plan_digest: [u8; 32],
}

/// Voter response to a candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteResponse {
    /// Responder's durable current term.
    pub term: u64,
    /// Whether this voter granted the candidate.
    pub granted: bool,
    /// Exact membership epoch used for the decision.
    pub membership_epoch: u64,
    /// Exact compiled quorum plan used for the decision.
    pub plan_digest: [u8; 32],
}

/// Leader log replication or heartbeat request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendRequest {
    /// Leader term.
    pub term: u64,
    /// Leader identity.
    pub leader: NodeId,
    /// Leader incarnation fenced by current membership.
    pub leader_incarnation: u64,
    /// Position immediately before `entries`.
    pub previous: LogPosition,
    /// Digest of the previous entry, or all zeroes at genesis.
    pub previous_digest: [u8; 32],
    /// Contiguous bounded entries.
    pub entries: Vec<LogEntry>,
    /// Leader's current committed index.
    pub leader_commit_index: u64,
    /// Optional exact linearizable-read probe correlation.
    pub read_barrier_id: Option<ReadBarrierId>,
    /// Exact membership epoch.
    pub membership_epoch: u64,
    /// Exact compiled plan digest.
    pub plan_digest: [u8; 32],
}

/// Follower replication response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendResponse {
    /// Responder's durable current term.
    pub term: u64,
    /// Whether previous position/digest and all entries were accepted.
    pub accepted: bool,
    /// Highest matching durable index when accepted.
    pub matched_index: u64,
    /// Positive next-index hint when rejected or caught up.
    pub next_index_hint: u64,
    /// Exact read probe being answered, if the request carried one.
    pub read_barrier_id: Option<ReadBarrierId>,
    /// Exact membership epoch used for the response.
    pub membership_epoch: u64,
    /// Exact compiled quorum plan used for the response.
    pub plan_digest: [u8; 32],
}

/// Closed peer messages owned by the consensus core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreMessage {
    /// Candidate vote solicitation.
    VoteRequest(VoteRequest),
    /// Voter response.
    VoteResponse(VoteResponse),
    /// Leader replication/heartbeat.
    AppendRequest(AppendRequest),
    /// Follower replication result.
    AppendResponse(AppendResponse),
}

/// Explicit deterministic inputs; no ambient clock, network, disk or randomness exists here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreInput {
    /// Election timer selected by the driver expired.
    ElectionTimeout,
    /// Current leader's driver heartbeat timer expired.
    Heartbeat,
    /// One authenticated, framed, semantically decoded peer message arrived.
    Message {
        /// Exact authenticated sender.
        from: NodeId,
        /// Exact sender incarnation from mTLS-bound connection context.
        sender_incarnation: u64,
        /// Hostile typed message requiring independent state validation.
        message: CoreMessage,
    },
    /// Driver proved the exact requested mutation durable.
    Persisted(PersistenceId),
    /// Current leader received one bounded semantic command proposal.
    Propose {
        /// Caller correlation.
        proposal_id: ProposalId,
        /// Idempotent metadata operation.
        operation_id: OperationId,
        /// Positive command format version.
        command_version: u16,
        /// Bounded canonical command bytes.
        command: Vec<u8>,
    },
    /// Current leader begins one quorum-confirmed linearizable read barrier.
    BeginReadBarrier(ReadBarrierId),
    /// Applies a committed old+new membership entry after its log position is applied.
    ActivateJointPlan {
        /// Independently proved old+new plan.
        joint_plan: Box<JointQuorumPlan>,
        /// Exact authoritative incarnations for every old or newly admitted member.
        member_incarnations: MemberIncarnations,
        /// Applied log position containing the transition command.
        committed_position: LogPosition,
    },
    /// Applies the committed stable successor after the joint phase.
    ActivateStablePlan {
        /// Exact successor previously carried by the active joint plan.
        plan: Box<CompiledQuorumPlan>,
        /// Exact authoritative incarnations for every member retained by the stable plan.
        member_incarnations: MemberIncarnations,
        /// Applied log position containing the finalisation command.
        committed_position: LogPosition,
    },
    /// State-machine driver applied every committed entry through this index.
    AppliedThrough(u64),
}

/// One atomic persistence request that must complete before dependent effects are emitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableMutation {
    /// New durable term/vote pair, or no vote-state change.
    pub vote_state: Option<(u64, Option<NodeId>)>,
    /// First index to truncate before append, or no log change.
    pub truncate_from: Option<u64>,
    /// Contiguous entries installed after truncation.
    pub append: Vec<LogEntry>,
    /// Adjacent membership epoch to persist before emitting messages under a new plan.
    pub membership_epoch: Option<u64>,
    /// Canonical active-plan replacement committed at one already-applied log position.
    pub quorum_plan: Option<DurableQuorumPlan>,
}

/// One atomic stable/joint plan activation persisted with its membership epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableQuorumPlan {
    /// Independently proved active phase.
    pub active_plan: ActiveQuorumPlan,
    /// Applied log position containing the authoritative transition command.
    pub activated_position: LogPosition,
}

/// Driver effects emitted by one deterministic step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreEffect {
    /// Persist exactly this mutation atomically, then return `Persisted(id)`.
    Persist {
        /// Correlation identity.
        id: PersistenceId,
        /// Exact durable mutation.
        mutation: DurableMutation,
    },
    /// Send a typed message on the independent consensus stream.
    Send {
        /// Authenticated destination node.
        to: NodeId,
        /// Typed message encoded only by the protocol adapter.
        message: CoreMessage,
    },
    /// Local role/term changed.
    RoleChanged {
        /// New role.
        role: Role,
        /// Current durable term.
        term: u64,
    },
    /// Leader accepted a proposal at this local position; it is not yet committed.
    ProposalAppended {
        /// Caller correlation.
        proposal_id: ProposalId,
        /// Allocated log position.
        position: LogPosition,
    },
    /// Entries became committed and must be applied in order by the metadata driver.
    CommitReady {
        /// Contiguous entries above the prior commit index.
        entries: Vec<LogEntry>,
    },
    /// Read quorum is current and the local state machine has applied this position.
    ReadBarrierReady {
        /// Caller correlation.
        read_barrier_id: ReadBarrierId,
        /// Minimum state-machine position safe to read.
        applied_index: u64,
    },
    /// Input cannot complete on this node without inventing success.
    Rejected {
        /// Stable rejection category.
        error: CoreError,
    },
}

/// Stable deterministic core rejection categories.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CoreError {
    /// Construction state does not match the compiled plan.
    #[error("consensus core configuration is invalid")]
    InvalidConfiguration,
    /// Input has invalid bounds, digest, order, term or identity semantics.
    #[error("consensus input is invalid")]
    InvalidInput,
    /// Sender identity/incarnation/epoch/plan is stale or unknown.
    #[error("consensus sender or membership is stale")]
    StaleMember,
    /// Another atomic persistence request must finish first.
    #[error("consensus persistence is pending")]
    PersistencePending,
    /// Persistence acknowledgement does not match the requested mutation.
    #[error("consensus persistence acknowledgement is stale")]
    StalePersistence,
    /// Only the current leader can accept the operation.
    #[error("consensus node is not the current leader")]
    NotLeader,
    /// Monotonic term, index or correlation space is exhausted.
    #[error("consensus numeric space is exhausted")]
    Exhausted,
}

pub(super) fn validate_append_entries(request: &AppendRequest) -> Result<(), CoreError> {
    if request.term == 0
        || !request.previous.is_valid()
        || request.entries.len() > MAXIMUM_APPEND_ENTRIES
        || request
            .read_barrier_id
            .is_some_and(|read_barrier_id| read_barrier_id.0 == 0)
        || (request.previous == LogPosition::GENESIS && request.previous_digest != [0; 32])
    {
        return Err(CoreError::InvalidInput);
    }
    let mut expected = request
        .previous
        .index
        .checked_add(1)
        .ok_or(CoreError::Exhausted)?;
    for entry in &request.entries {
        entry.validate()?;
        if entry.position.index != expected || entry.position.term > request.term {
            return Err(CoreError::InvalidInput);
        }
        expected = expected.checked_add(1).ok_or(CoreError::Exhausted)?;
    }
    Ok(())
}

fn command_digest(version: u16, command: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.consensus.command.v1");
    digest.update(version.to_be_bytes());
    digest.update(
        u64::try_from(command.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(command);
    digest.finalize().into()
}
