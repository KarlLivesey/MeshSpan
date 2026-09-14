// SPDX-License-Identifier: GPL-2.0-only

//! One removal projection for admitted history and terminal unadmitted objects.

use meshspan_contracts::{BackupObjectIdentity, BackupObjectReference};
use meshspan_domain::{BackupDestinationId, BackupId, Revision};
use rusqlite::Connection;

use super::super::{
    AuthoritativeRepository, BackupCopyRecord, BackupCopyState, MetadataBackupRunState,
    MetadataBackupState, RepositoryError, backup_catalogue, backup_orphan, backup_run,
};

/// Exact current removal authority, without claiming an admitted recoverable backup exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupReclamationCandidate {
    /// Exact immutable encrypted object owned by this retirement.
    pub object: BackupObjectIdentity,
    /// Provider locator bound to the exact object, never authority by itself.
    pub object_reference: BackupObjectReference,
    /// Immutable authoritative retirement revision used for idempotent removal.
    pub retirement_revision: Revision,
}

impl TryFrom<BackupCopyRecord> for BackupReclamationCandidate {
    type Error = RepositoryError;

    fn try_from(copy: BackupCopyRecord) -> Result<Self, Self::Error> {
        if copy.state != BackupCopyState::Retired
            || copy.revision.get() == 0
            || copy.provider_generation == 0
            || copy.byte_length == 0
            || copy.copy_digest == [0; 32]
        {
            return Err(RepositoryError::CorruptState);
        }
        Ok(Self {
            object: BackupObjectIdentity {
                backup_id: copy.backup_id,
                destination_id: copy.destination_id,
                provider_generation: copy.provider_generation,
                byte_length: copy.byte_length,
                digest: copy.copy_digest,
            },
            object_reference: BackupObjectReference::new(copy.object_reference)
                .map_err(|_| RepositoryError::CorruptState)?,
            retirement_revision: copy.revision,
        })
    }
}

impl AuthoritativeRepository {
    /// Loads current exact retirement authority, including after a lost deletion response.
    ///
    /// Completed reclamation does not remove authority: the exact provider operation may
    /// need replay. All related rows are checked in one short local read view.
    /// # Errors
    /// Rejects contradictory histories, live/unretired state and malformed retained evidence.
    pub fn backup_reclamation_candidate(
        &self,
        backup: BackupId,
        destination: BackupDestinationId,
    ) -> Result<Option<BackupReclamationCandidate>, RepositoryError> {
        self.with_read_view(|view| load(view.database.connection(), backup, destination))?
    }
}

pub(super) fn load(
    connection: &Connection,
    backup: BackupId,
    destination: BackupDestinationId,
) -> Result<Option<BackupReclamationCandidate>, RepositoryError> {
    let retained = backup_orphan::load(connection, backup, destination)?;
    let admitted = backup_catalogue::backup(connection, backup)?;
    let copy = backup_catalogue::copy(connection, backup, destination)?;
    if let Some(retained) = retained {
        let run = backup_run::load(connection, backup)?.ok_or(RepositoryError::CorruptState)?;
        if admitted.is_some()
            || copy.is_some()
            || run.state != MetadataBackupRunState::Incomplete
            || run.revision != retained.command.expected_run_revision
            || run
                .completed_at
                .is_none_or(|instant| instant > retained.retired_at)
            || run.result_digest.is_none_or(|digest| digest == [0; 32])
            || backup_run::live_claim(connection, backup)?.is_some()
        {
            return Err(RepositoryError::CorruptState);
        }
        return Ok(Some(BackupReclamationCandidate {
            object: retained.command.receipt.object,
            object_reference: retained.command.receipt.object_reference,
            retirement_revision: retained.retirement_revision,
        }));
    }
    match (admitted, copy) {
        (Some(backup), Some(copy))
            if backup.state == MetadataBackupState::Retired
                && copy.state == BackupCopyState::Retired =>
        {
            if backup.encrypted_byte_length != copy.byte_length
                || backup.encrypted_digest != copy.copy_digest
            {
                return Err(RepositoryError::CorruptState);
            }
            copy.try_into().map(Some)
        }
        (_, Some(copy)) if copy.state == BackupCopyState::Retired => {
            Err(RepositoryError::CorruptState)
        }
        _ => Ok(None),
    }
}
