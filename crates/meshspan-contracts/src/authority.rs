// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable metadata-repository and consensus-engine contracts.

use meshspan_domain::{CommitOutcome, OperationId, PartitionId, Revision};

use crate::{
    BoundedBytes, BoundedItems, ComponentLifecycle, ContractError, RequestContext, VersionedPayload,
};

/// Durable consensus log position within exactly one partition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogPosition {
    /// Monotonic election term.
    pub term: u64,
    /// Monotonic log index after the installed snapshot boundary.
    pub index: u64,
}

/// Closed semantic command families accepted by the metadata state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataCommandKind {
    /// Mesh, partition, node or component topology mutation.
    Topology,
    /// User, group, authentication, owner, role or permission mutation.
    IdentityAccess,
    /// Volume or namespace metadata mutation.
    Namespace,
    /// Protection, locality or acknowledgement policy mutation.
    Policy,
    /// Work, repair, drain or snapshot lifecycle mutation.
    Lifecycle,
    /// Membership, routing or partition handoff mutation.
    ClusterControl,
}

/// One bounded semantic state-machine command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataCommand {
    /// Common operation identity, contract and compare-and-swap context.
    pub context: RequestContext,
    /// Exact owning partition.
    pub partition_id: PartitionId,
    /// Closed command family used for admission and routing.
    pub kind: MetadataCommandKind,
    /// Independently versioned canonical command payload.
    pub payload: VersionedPayload,
    /// Digest of the complete canonical command and actor context.
    pub request_digest: [u8; 32],
}

/// Durable typed result of applying one metadata command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataResult {
    /// Idempotency identity of the applied or replayed command.
    pub operation_id: OperationId,
    /// Exact semantic outcome.
    pub outcome: CommitOutcome,
    /// Authority revision after the command.
    pub committed_revision: Revision,
    /// Independently versioned bounded result payload.
    pub result: VersionedPayload,
    /// Digest binding the complete result.
    pub result_digest: [u8; 32],
}

/// Stable state returned when resolving an operation after timeout or lost response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationState {
    /// No operation with that identity is durably known.
    Absent,
    /// Work is durable but not terminal.
    InProgress,
    /// The exact terminal result is durable.
    Complete(MetadataResult),
    /// The operation was durably rejected without a matching mutation.
    Rejected(ContractError),
}

/// Bounded typed repository query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataQuery {
    /// Owning partition.
    pub partition_id: PartitionId,
    /// Query format and canonical parameters.
    pub query: VersionedPayload,
    /// Optional exact authority revision, or latest permitted revision.
    pub at_revision: Option<Revision>,
    /// Opaque continuation cursor.
    pub cursor: Option<BoundedBytes>,
    /// Positive implementation-bounded page size.
    pub limit: usize,
}

/// One stable revision-bound query page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataPage {
    /// Exact revision against which every row and cursor was evaluated.
    pub revision: Revision,
    /// Canonical bounded result records.
    pub records: BoundedItems<VersionedPayload>,
    /// Opaque cursor for the next page, or `None` at the end.
    pub next_cursor: Option<BoundedBytes>,
}

/// Verified partition snapshot at one exact applied log position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySnapshot {
    /// Owning partition identity.
    pub partition_id: PartitionId,
    /// Exact included consensus position.
    pub position: LogPosition,
    /// Exact included state revision.
    pub state_revision: Revision,
    /// Snapshot format version and bounded canonical payload.
    pub payload: VersionedPayload,
    /// Digest verified before installation.
    pub digest: [u8; 32],
}

/// Transactional state-machine persistence without SQL exposure.
pub trait MetadataRepository: ComponentLifecycle {
    /// Applies one committed command and its result/audit records atomically.
    ///
    /// # Errors
    ///
    /// Rejects gaps, stale revisions, conflicting replay or violated domain invariants.
    fn apply(
        &mut self,
        position: LogPosition,
        command: &MetadataCommand,
    ) -> Result<MetadataResult, ContractError>;

    /// Executes one bounded revision-bound query.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursors, unbounded requests or unavailable revisions.
    fn query(&self, query: &MetadataQuery) -> Result<MetadataPage, ContractError>;

    /// Resolves one operation identity after replay, timeout or lost response.
    ///
    /// # Errors
    ///
    /// Returns a stable repository failure without inventing an operation outcome.
    fn operation_status(&self, operation_id: OperationId) -> Result<OperationState, ContractError>;

    /// Creates a verified snapshot at the exact applied position.
    ///
    /// # Errors
    ///
    /// Rejects positions not exactly represented by current committed state.
    fn create_snapshot(&self) -> Result<RepositorySnapshot, ContractError>;

    /// Installs a staged verified snapshot without rolling back newer consensus identity.
    ///
    /// # Errors
    ///
    /// Rejects wrong partition, stale position, digest mismatch or unsupported schema.
    fn install_snapshot(
        &mut self,
        snapshot: &RepositorySnapshot,
    ) -> Result<LogPosition, ContractError>;

    /// Checks persisted relational and domain invariants with bounded findings.
    ///
    /// # Errors
    ///
    /// Returns corruption or unavailability instead of treating an incomplete check as clean.
    fn check_invariants(&self) -> Result<BoundedItems<VersionedPayload>, ContractError>;
}

/// One bounded proposal submitted to the consensus core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusProposal {
    /// Exact owning partition.
    pub partition_id: PartitionId,
    /// Mutation and deadline context.
    pub context: RequestContext,
    /// Versioned semantic command; never SQL or file bytes.
    pub command: VersionedPayload,
    /// Digest independently checked before append.
    pub command_digest: [u8; 32],
}

/// Proof that a proposal reached one exact committed log position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusCommit {
    /// Exact partition.
    pub partition_id: PartitionId,
    /// Committed term and index.
    pub position: LogPosition,
    /// Membership/quorum-plan epoch used to prove commitment.
    pub membership_epoch: u64,
    /// Digest of the proved quorum plan.
    pub quorum_proof_digest: [u8; 32],
}

/// Replicated-log ordering without application-state or SQL knowledge.
pub trait ConsensusEngine: ComponentLifecycle {
    /// Proposes one bounded semantic command.
    ///
    /// # Errors
    ///
    /// Returns stale, unavailable or unsupported rather than claiming unproved commitment.
    fn propose(&mut self, proposal: &ConsensusProposal) -> Result<ConsensusCommit, ContractError>;

    /// Establishes a current-leader linearizable read barrier.
    ///
    /// # Errors
    ///
    /// Returns unavailable when the configured read/election proof cannot complete.
    fn read_barrier(
        &mut self,
        partition_id: PartitionId,
        deadline: meshspan_domain::UnixMicros,
    ) -> Result<ConsensusCommit, ContractError>;

    /// Stages and activates a verified consensus/application snapshot.
    ///
    /// # Errors
    ///
    /// Rejects stale votes, wrong partition, unproved plans or corrupt snapshot bytes.
    fn install_snapshot(
        &mut self,
        snapshot: &RepositorySnapshot,
    ) -> Result<ConsensusCommit, ContractError>;
}
