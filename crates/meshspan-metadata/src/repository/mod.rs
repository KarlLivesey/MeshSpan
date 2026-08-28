// SPDX-License-Identifier: GPL-2.0-only

//! Atomic authoritative command application and exact operation resolution.

mod apply;
mod component;
mod group_closure;
mod identity;
mod namespace;
mod receipt;

use meshspan_domain::{OperationId, Revision};
use thiserror::Error;

use crate::{MetadataStoreError, PartitionDatabase};

pub use receipt::{ApplyDisposition, CommandReceipt, EntityKind, EntityReference, LogPosition};

/// Authoritative metadata repository owning one identity-bound partition database.
pub struct AuthoritativeRepository {
    database: PartitionDatabase,
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
    /// A command violates a semantic precondition.
    #[error("authoritative command is invalid")]
    InvalidCommand,
    /// A bounded repository or graph limit would be exceeded.
    #[error("authoritative metadata capacity is exceeded")]
    CapacityExceeded,
    /// Persisted bytes or relationships violate the compiled contract.
    #[error("authoritative metadata invariant is corrupt")]
    CorruptState,
}

#[cfg(test)]
mod tests;
