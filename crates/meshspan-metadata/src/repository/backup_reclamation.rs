// SPDX-License-Identifier: GPL-2.0-only

//! Durable physical-cleanup debt survives provider failure and worker restart.

use meshspan_domain::{BackupDestinationId, BackupId, Revision};
use rusqlite::{Transaction, params};

use super::apply::to_i64;
use super::{
    AuthoritativeRepository, BackupCopyRecord, BackupCopyState, EntityKind, EntityReference,
    MetadataBackupState, Page, PageLimit, RepositoryError, backup_catalogue,
};
use crate::{CommandContext, RecordBackupReclamation};

/// Stable keyset position over exact retired copies awaiting deletion receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupReclamationCursor {
    /// Last scanned generation.
    pub backup_id: BackupId,
    /// Last scanned destination within that generation.
    pub destination_id: BackupDestinationId,
}

impl AuthoritativeRepository {
    /// Lists retired copies without provider-confirmed physical reclamation.
    ///
    /// Callers advance the cursor even after a provider failure and wrap after the final
    /// page, so an unavailable destination cannot starve other cleanup work.
    ///
    /// # Errors
    /// Returns persistence or invalid catalogue errors.
    pub fn pending_backup_reclamations(
        &self,
        after: Option<BackupReclamationCursor>,
        limit: PageLimit,
    ) -> Result<Page<BackupCopyRecord, BackupReclamationCursor>, RepositoryError> {
        let connection = self.database.connection();
        let after_backup = after.map_or([0; 16], |value| value.backup_id.as_bytes());
        let after_destination = after.map_or([0; 16], |value| value.destination_id.as_bytes());
        let mut statement = connection.prepare(
            "SELECT c.backup_id, c.destination_id FROM backup_copies c
             WHERE c.state = 4 AND (c.backup_id, c.destination_id) > (?1, ?2)
               AND NOT EXISTS (SELECT 1 FROM backup_copy_reclamations r
                   WHERE r.backup_id = c.backup_id AND r.destination_id = c.destination_id)
             ORDER BY c.backup_id, c.destination_id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                after_backup.as_slice(),
                after_destination.as_slice(),
                i64::try_from(limit.get()).map_err(|_| RepositoryError::CapacityExceeded)? + 1
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        let mut items = Vec::new();
        for row in rows {
            let (backup, destination) = row?;
            let backup = BackupId::from_bytes(
                backup
                    .try_into()
                    .map_err(|_| RepositoryError::CorruptState)?,
            )
            .map_err(|_| RepositoryError::CorruptState)?;
            let destination = BackupDestinationId::from_bytes(
                destination
                    .try_into()
                    .map_err(|_| RepositoryError::CorruptState)?,
            )
            .map_err(|_| RepositoryError::CorruptState)?;
            items.push(
                backup_catalogue::copy(connection, backup, destination)?
                    .ok_or(RepositoryError::CorruptState)?,
            );
        }
        let has_more = items.len() > limit.get();
        if has_more {
            items.pop();
        }
        let next_cursor = if has_more {
            items.last().map(|copy| BackupReclamationCursor {
                backup_id: copy.backup_id,
                destination_id: copy.destination_id,
            })
        } else {
            None
        };
        Ok(Page {
            items,
            next: next_cursor,
        })
    }
}

pub(super) fn record(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RecordBackupReclamation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let receipt = command.receipt;
    let object = receipt.object;
    let backup = backup_catalogue::backup(transaction, object.backup_id)?
        .ok_or(RepositoryError::InvalidCommand)?;
    let copy = backup_catalogue::copy(transaction, object.backup_id, object.destination_id)?
        .ok_or(RepositoryError::InvalidCommand)?;
    if backup.state != MetadataBackupState::Retired
        || copy.state != BackupCopyState::Retired
        || copy.revision != receipt.retirement_revision
        || receipt.retirement_revision.get() == 0
        || object.provider_generation != copy.provider_generation
        || object.byte_length != copy.byte_length
        || object.digest != copy.copy_digest
    {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO backup_copy_reclamations(backup_id, destination_id, operation_id,
            retirement_revision, provider_generation, byte_length, copy_digest, reclaimed_at, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(backup_id, destination_id) DO NOTHING",
        params![object.backup_id.as_bytes().as_slice(), object.destination_id.as_bytes().as_slice(),
            receipt.operation_id.as_bytes().as_slice(), to_i64(receipt.retirement_revision.get())?,
            to_i64(object.provider_generation)?, to_i64(object.byte_length)?, object.digest.as_slice(),
            context.occurred_at.get(), to_i64(revision.get())?],
    )?;
    let exact: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM backup_copy_reclamations WHERE backup_id = ?1
            AND destination_id = ?2 AND operation_id = ?3 AND retirement_revision = ?4
            AND provider_generation = ?5 AND byte_length = ?6 AND copy_digest = ?7)",
        params![
            object.backup_id.as_bytes().as_slice(),
            object.destination_id.as_bytes().as_slice(),
            receipt.operation_id.as_bytes().as_slice(),
            to_i64(receipt.retirement_revision.get())?,
            to_i64(object.provider_generation)?,
            to_i64(object.byte_length)?,
            object.digest.as_slice()
        ],
        |row| row.get(0),
    )?;
    if !exact {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(EntityReference {
        kind: EntityKind::MetadataBackup,
        id: object.backup_id.as_bytes(),
    })
}
