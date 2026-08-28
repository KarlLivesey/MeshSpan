// SPDX-License-Identifier: GPL-2.0-only

//! Atomic authoritative command application and exact operation resolution.

mod apply;
mod backup;
mod bootstrap;
mod cluster;
mod component;
mod consensus;
mod group_closure;
mod identity;
mod kernel;
mod membership;
mod namespace;
mod query;
mod quorum_plan;
mod receipt;
mod routing;
mod snapshot;
mod tags;
mod verify;
mod volume_head;

use meshspan_domain::{OperationId, Revision, ScopeId, ScopeRoute};
use thiserror::Error;

use crate::{MetadataStoreError, PartitionDatabase};

pub use backup::{PartitionBackupManifest, restore_partition_backup};
pub use consensus::{ConsensusStoreError, PartitionConsensusPersistence};
pub use kernel::{
    AuthoritativeMetadataKernel, RepositoryConformanceCheck, RepositoryConformanceReport,
    RepositoryConformanceVector, run_repository_conformance,
};
pub use membership::AuthoritativeMembership;
pub use query::{
    GroupMemberCursor, NamespaceCursor, NamespaceRecord, Page, PageLimit, PrincipalKind,
    PrincipalRecord,
};
pub use receipt::{ApplyDisposition, CommandReceipt, EntityKind, EntityReference, LogPosition};
pub use snapshot::{PartitionSnapshotManifest, PreservedVote, restore_partition_snapshot};
pub use verify::{InvariantFinding, InvariantKind, InvariantReport};
pub use volume_head::ConvergedVolumeHead;

/// Authoritative metadata repository owning one identity-bound partition database.
pub struct AuthoritativeRepository {
    database: PartitionDatabase,
}

/// Read boundary used by a consensus authority before accepting a scope mutation.
pub trait ScopeWriteAuthority {
    /// Returns whether this exact local partition owns the scope at the presented route epoch.
    ///
    /// # Errors
    ///
    /// Fails closed when the route is absent or its durable representation is corrupt.
    fn permits_scope_write(
        &self,
        scope_id: ScopeId,
        routing_epoch: u64,
    ) -> Result<bool, RepositoryError>;
}

impl ScopeWriteAuthority for AuthoritativeRepository {
    fn permits_scope_write(
        &self,
        scope_id: ScopeId,
        routing_epoch: u64,
    ) -> Result<bool, RepositoryError> {
        let route = routing::load_scope(self.database.connection(), scope_id)?;
        Ok(route.permits_write(self.database.partition_id(), routing_epoch))
    }
}

impl AuthoritativeMetadataKernel for AuthoritativeRepository {
    fn current_revision(&self) -> Result<Revision, RepositoryError> {
        Self::current_revision(self)
    }

    fn apply_committed(
        &mut self,
        position: LogPosition,
        context: crate::CommandContext,
        command: &crate::AuthoritativeCommand,
    ) -> Result<CommandReceipt, RepositoryError> {
        Self::apply_committed(self, position, context, command)
    }

    fn resolve_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, RepositoryError> {
        Self::resolve_operation(self, operation_id)
    }

    fn check_invariants(&self, limit: PageLimit) -> Result<InvariantReport, RepositoryError> {
        Self::check_invariants(self, limit)
    }
}

impl AuthoritativeRepository {
    /// Wraps one already migrated and identity-verified partition database.
    #[must_use]
    pub const fn new(database: PartitionDatabase) -> Self {
        Self { database }
    }

    /// Returns the currently committed state-machine revision.
    ///
    /// # Errors
    ///
    /// Fails closed if persisted state is absent, malformed or outside the supported range.
    pub fn current_revision(&self) -> Result<Revision, RepositoryError> {
        apply::read_current_revision(&self.database)
    }

    /// Returns one independently validated durable scope route.
    ///
    /// # Errors
    ///
    /// Fails closed when the route is absent or its durable representation is corrupt.
    pub fn scope_route(&self, scope_id: ScopeId) -> Result<ScopeRoute, RepositoryError> {
        routing::load_scope(self.database.connection(), scope_id)
    }

    /// Loads and verifies the exact durable consensus state for one membership epoch.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed, discontinuous, digest-mismatched or stale-epoch state.
    pub fn load_consensus_state(
        &self,
        membership_epoch: u64,
    ) -> Result<meshspan_consensus::DurableCoreState, ConsensusStoreError> {
        consensus::load_state(&self.database, membership_epoch)
    }

    /// Applies one vote/log mutation in a single durable SQLite transaction.
    ///
    /// # Errors
    ///
    /// Rejects stale terms, committed-tail truncation, malformed entries and epoch mismatch.
    pub fn persist_consensus_mutation(
        &mut self,
        membership_epoch: u64,
        mutation: &meshspan_consensus::DurableMutation,
        persisted_at: meshspan_domain::UnixMicros,
    ) -> Result<(), ConsensusStoreError> {
        consensus::persist_mutation(&mut self.database, membership_epoch, mutation, persisted_at)
    }

    /// Applies one already-committed log entry atomically and returns durable evidence.
    ///
    /// # Errors
    ///
    /// Rejects discontinuous log positions, stale revisions, conflicting operation reuse,
    /// unauthorised actors, malformed commands and any violated persisted invariant.
    pub fn apply_committed(
        &mut self,
        position: LogPosition,
        context: crate::CommandContext,
        command: &crate::AuthoritativeCommand,
    ) -> Result<CommandReceipt, RepositoryError> {
        apply::apply_committed(&mut self.database, position, context, command)
    }

    /// Resolves the exact durable result stored for an operation, if present.
    ///
    /// # Errors
    ///
    /// Fails closed if any persisted receipt field is malformed or inconsistent.
    pub fn resolve_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, RepositoryError> {
        receipt::resolve_operation(&self.database, operation_id)
    }

    /// Reads one exact user or group principal.
    ///
    /// # Errors
    ///
    /// Fails closed if stored identity bytes or enum values are malformed.
    pub fn principal(
        &self,
        principal_id: meshspan_domain::PrincipalId,
    ) -> Result<Option<PrincipalRecord>, RepositoryError> {
        query::principal(&self.database, principal_id)
    }

    /// Returns one stable, bounded page of active namespace children.
    ///
    /// # Errors
    ///
    /// Rejects malformed stored identifiers and database failures.
    pub fn namespace_children(
        &self,
        volume_id: meshspan_domain::VolumeId,
        parent_object_id: meshspan_domain::ObjectId,
        after: Option<&NamespaceCursor>,
        limit: PageLimit,
    ) -> Result<Page<NamespaceRecord, NamespaceCursor>, RepositoryError> {
        query::namespace_children(&self.database, volume_id, parent_object_id, after, limit)
    }

    /// Returns the latest replicated globally converged namespace head for one volume.
    ///
    /// # Errors
    ///
    /// Fails closed if any stored identity, digest, sequence or evidence shape is malformed.
    pub fn converged_volume_head(
        &self,
        volume_id: meshspan_domain::VolumeId,
    ) -> Result<Option<ConvergedVolumeHead>, RepositoryError> {
        volume_head::load(&self.database, volume_id)
    }

    /// Returns one stable, bounded page of direct members of a group.
    ///
    /// # Errors
    ///
    /// Rejects malformed stored identifiers and database failures.
    pub fn direct_group_members(
        &self,
        group_id: meshspan_domain::GroupId,
        after: Option<GroupMemberCursor>,
        limit: PageLimit,
    ) -> Result<Page<meshspan_domain::PrincipalId, GroupMemberCursor>, RepositoryError> {
        query::direct_group_members(&self.database, group_id, after, limit)
    }

    /// Returns the authoritative active-voter and admitted-learner projection, if bootstrapped.
    ///
    /// # Errors
    ///
    /// Fails closed on malformed identities, incarnations or unsupported role/state pairings.
    pub fn partition_membership(&self) -> Result<Option<AuthoritativeMembership>, RepositoryError> {
        membership::load(&self.database)
    }

    /// Creates a transactionally consistent SQLite backup and its exact manifest.
    ///
    /// # Errors
    ///
    /// Refuses an existing destination and reports IO, SQLite or state corruption.
    pub fn create_backup(
        &self,
        backup_id: meshspan_domain::BackupId,
        destination: &std::path::Path,
        created_at: meshspan_domain::UnixMicros,
    ) -> Result<PartitionBackupManifest, RepositoryError> {
        backup::create_partition_backup(&self.database, backup_id, destination, created_at)
    }

    /// Creates a complete state-machine snapshot bound to one proved quorum plan.
    ///
    /// # Errors
    ///
    /// Rejects absent/inconsistent consensus state and never overwrites an existing destination.
    pub fn create_snapshot(
        &self,
        snapshot_id: meshspan_domain::SnapshotId,
        destination: &std::path::Path,
        plan: &meshspan_consensus::CompiledQuorumPlan,
        created_at: meshspan_domain::UnixMicros,
    ) -> Result<PartitionSnapshotManifest, RepositoryError> {
        snapshot::create_snapshot(&self.database, snapshot_id, destination, plan, created_at)
    }

    /// Installs the immutable bootstrap plan or verifies the exact existing durable plan.
    ///
    /// # Errors
    ///
    /// Rejects a different existing plan, unsafe record or database failure.
    pub fn initialise_consensus_quorum_plan(
        &mut self,
        plan: &meshspan_consensus::CompiledQuorumPlan,
        updated_at: meshspan_domain::UnixMicros,
    ) -> Result<meshspan_consensus::ActiveQuorumPlan, ConsensusStoreError> {
        quorum_plan::initialise(&mut self.database, plan, updated_at)
    }

    /// Loads and independently re-proves the exact durable stable or joint phase.
    ///
    /// # Errors
    ///
    /// Rejects malformed, corrupt, stale or unproved durable state.
    pub fn load_active_consensus_quorum_plan(
        &self,
    ) -> Result<Option<meshspan_consensus::ActiveQuorumPlan>, ConsensusStoreError> {
        quorum_plan::load(&self.database)
    }

    /// Runs bounded relational/domain checks that go beyond SQLite structural integrity.
    ///
    /// # Errors
    ///
    /// Rejects an invalid finding bound and reports malformed persisted identifiers as corruption.
    pub fn check_invariants(&self, limit: PageLimit) -> Result<InvariantReport, RepositoryError> {
        verify::check_invariants(&self.database, limit)
    }

    /// Returns the underlying database after repository ownership is no longer needed.
    #[must_use]
    pub fn into_database(self) -> PartitionDatabase {
        self.database
    }
}

/// Closed authoritative repository rejection categories.
#[derive(Debug, Error)]
pub enum RepositoryError {
    /// SQLite, migration or integrity machinery rejected the operation.
    #[error("authoritative metadata store failed")]
    Store(#[from] MetadataStoreError),
    /// Direct SQLite access rejected the operation.
    #[error("authoritative metadata transaction failed")]
    Sqlite(#[from] rusqlite::Error),
    /// An operation ID is already committed for different semantic input.
    #[error("operation identity is already bound to different input")]
    OperationConflict,
    /// The supplied log position does not immediately follow applied state.
    #[error("committed log position is stale or discontinuous")]
    InvalidLogPosition,
    /// The compare-and-swap state revision is stale.
    #[error("expected state revision is stale")]
    StaleRevision,
    /// A per-volume converged-head compare-and-swap base is stale.
    #[error("expected converged volume head is stale")]
    StaleVolumeHead,
    /// A command violates a semantic precondition.
    #[error("authoritative command is invalid")]
    InvalidCommand,
    /// A bounded repository or graph limit would be exceeded.
    #[error("authoritative metadata capacity is exceeded")]
    CapacityExceeded,
    /// Persisted bytes or relationships violate the compiled contract.
    #[error("authoritative metadata invariant is corrupt")]
    CorruptState,
    /// A caller supplied an invalid explicit query bound.
    #[error("repository page limit is outside supported bounds")]
    InvalidPageLimit,
    /// Filesystem IO rejected backup creation or verification.
    #[error("metadata backup IO failed")]
    Io(#[from] std::io::Error),
    /// Backup creation never overwrites an existing path.
    #[error("metadata backup destination already exists")]
    BackupDestinationExists,
    /// Backup bytes or their embedded state do not match the supplied manifest.
    #[error("metadata backup does not match its manifest")]
    BackupMismatch,
    /// Snapshot bytes, consensus position, vote or quorum-plan proof do not agree.
    #[error("metadata snapshot does not match its consensus manifest")]
    SnapshotMismatch,
    /// Deterministic internal transaction interruption used by the crash-proof harness.
    #[error("injected authoritative transaction interruption")]
    InjectedFault,
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod volume_head_tests;
