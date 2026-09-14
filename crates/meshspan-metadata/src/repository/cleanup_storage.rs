// SPDX-License-Identifier: GPL-2.0-only

//! Resolve a wire operation through committed cleanup records, never through a location alone.

use meshspan_domain::OperationId;
use rusqlite::{OptionalExtension as _, params};

use super::{
    AuthoritativeRepository, RepositoryError, VersionCleanupItem, VersionCleanupItemCompletion,
    VersionCleanupPermitAttempt,
};

/// Current exact cleanup evidence for one provider operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupStorageAuthority {
    /// Sealed item, including its authoritative storage owner.
    pub item: VersionCleanupItem,
    /// Most recent committed permit attempt for the item.
    pub attempt: VersionCleanupPermitAttempt,
    /// Exact committed provider tombstone required before physical reclamation.
    pub completion: Option<VersionCleanupItemCompletion>,
}

impl AuthoritativeRepository {
    /// Resolves an exact provider operation to its latest committed cleanup attempt.
    ///
    /// Uses the unique permit-operation index, then the existing inventory/attempt validators.
    /// Unknown or superseded operations return `None`. This does not establish fresh authority,
    /// validate a sender or invoke a provider. The caller must bind it to a fresh read fence
    /// using the same `with_read_view` as its other admission checks.
    ///
    /// # Errors
    /// Rejects inconsistent/unsealed inventory, corrupt evidence and unavailable SQLite reads.
    pub fn version_cleanup_storage_authority(
        &self,
        operation: OperationId,
    ) -> Result<Option<VersionCleanupStorageAuthority>, RepositoryError> {
        let connection = self.database.connection();
        let identity = connection
            .query_row(
                "SELECT cleanup_operation_id, item_index FROM version_cleanup_permit_attempts
             WHERE permit_operation_id = ?1",
                params![operation.as_bytes().as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let Some((cleanup, index)) = identity else {
            return Ok(None);
        };
        let cleanup = OperationId::from_bytes(
            cleanup
                .as_slice()
                .try_into()
                .map_err(|_| RepositoryError::CorruptState)?,
        )
        .map_err(|_| RepositoryError::CorruptState)?;
        let index = u64::try_from(index).map_err(|_| RepositoryError::CorruptState)?;
        let attempt = self
            .version_cleanup_permit_attempt(cleanup, index)?
            .ok_or(RepositoryError::CorruptState)?;
        if attempt.permit.operation_id != operation {
            return Ok(None);
        }
        let item = super::cleanup_inventory::sealed_item(connection, cleanup, index)?.item;
        let completion = self.version_cleanup_item_completion(cleanup, index)?;
        if completion
            .is_some_and(|record| record.permit_attempt_sequence != attempt.attempt_sequence)
        {
            return Err(RepositoryError::CorruptState);
        }
        Ok(Some(VersionCleanupStorageAuthority {
            item,
            attempt,
            completion,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::cleanup_completion_tests::{completion_command, issue, tombstone};
    use super::super::cleanup_inventory_tests::sealed_inventory;
    use super::super::volume_head_tests::context;
    use super::*;
    use crate::{AuthoritativeCommand, LogPosition};
    use meshspan_domain::{Revision, UnixMicros};

    #[test]
    fn storage_lookup_requires_exact_committed_attempt_and_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let fixture = sealed_inventory(&directory.path().join("storage.sqlite3"))?;
        let mut repository = fixture.repository;
        let unknown = OperationId::from_bytes([211; 16])?;
        assert!(
            repository
                .version_cleanup_storage_authority(unknown)?
                .is_none()
        );
        let attempt = issue(
            &mut repository,
            fixture.administrator,
            fixture.cleanup_id,
            0,
            10,
            210,
        )?;
        let read = repository
            .version_cleanup_storage_authority(attempt.permit.operation_id)?
            .ok_or("attempt missing")?;
        assert_eq!(read.attempt, attempt);
        assert_eq!(
            read.item.storage_node_id,
            meshspan_domain::NodeId::from_bytes([15; 16])?
        );
        assert_eq!(read.completion, None);
        let command: AuthoritativeCommand =
            completion_command(fixture.cleanup_id, Revision::new(9), attempt, 0)?;
        repository.apply_committed(
            LogPosition { index: 11, term: 1 },
            context(212, fixture.administrator, 213, 120, Some(10))?,
            &command,
        )?;
        let read = repository
            .version_cleanup_storage_authority(attempt.permit.operation_id)?
            .ok_or("completed attempt missing")?;
        assert_eq!(
            read.completion.ok_or("completion missing")?.receipt,
            tombstone(attempt)
        );
        drop(repository);
        let reopened = AuthoritativeRepository::new(crate::PartitionDatabase::open_existing(
            &directory.path().join("storage.sqlite3"),
            UnixMicros::new(130),
        )?);
        assert_eq!(
            reopened.version_cleanup_storage_authority(attempt.permit.operation_id)?,
            Some(read)
        );
        Ok(())
    }
}
