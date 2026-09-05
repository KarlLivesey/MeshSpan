// SPDX-License-Identifier: GPL-2.0-only

//! Retention decisions use committed source order and revalidated copy evidence.

use meshspan_domain::{BackupId, PartitionId, Revision};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{
    AuthoritativeRepository, EntityKind, EntityReference, MetadataBackupRecord,
    MetadataBackupRunState, MetadataBackupSchedule, MetadataBackupState, RepositoryError,
    backup_catalogue, backup_run, backup_schedule,
};
use crate::{MAXIMUM_BACKUP_RETENTION_WITNESSES, RetireMetadataBackup};

impl AuthoritativeRepository {
    /// Selects at most one old generation using a bounded newest-generation index scan.
    ///
    /// This is a proposal, not deletion authority. Committing it revalidates all witnesses.
    /// Missing or insufficient current protection conservatively yields no proposal.
    ///
    /// # Errors
    /// Returns storage or malformed-record errors without inventing protection evidence.
    pub fn metadata_backup_retirement_candidate(
        &self,
    ) -> Result<Option<RetireMetadataBackup>, RepositoryError> {
        let connection = self.database.connection();
        let partition = self.database.partition_id();
        let Some(schedule) = backup_schedule::load(connection, partition)? else {
            return Ok(None);
        };
        if !schedule.enabled {
            return Ok(None);
        }
        let mut statement = connection.prepare(
            "SELECT backup_id FROM metadata_backups
             WHERE state = 2 ORDER BY state_revision DESC, backup_id LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::from(schedule.retained_generations)], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let mut identifiers = Vec::new();
        for row in rows {
            let bytes: [u8; 16] = row?.try_into().map_err(|_| RepositoryError::CorruptState)?;
            identifiers
                .push(BackupId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)?);
        }
        if identifiers.len() != usize::from(schedule.retained_generations) {
            return Ok(None);
        }
        let oldest_witness = *identifiers.last().ok_or(RepositoryError::CorruptState)?;
        let boundary = backup_catalogue::backup(connection, oldest_witness)?
            .ok_or(RepositoryError::CorruptState)?;
        let Some(victim_id) = oldest_terminal_generation(connection, boundary.state_revision)?
        else {
            return Ok(None);
        };
        let victim = backup_catalogue::backup(connection, victim_id)?
            .ok_or(RepositoryError::CorruptState)?;
        identifiers.sort_unstable();
        let command = RetireMetadataBackup {
            backup_id: victim_id,
            expected_backup_revision: victim.revision,
            expected_schedule_sequence: schedule.sequence,
            retained_backups: identifiers,
        };
        match validate(connection, partition, &command) {
            Ok(()) => Ok(Some(command)),
            Err(
                RepositoryError::InvalidCommand
                | RepositoryError::StaleMetadataBackupSchedule
                | RepositoryError::StaleRevision,
            ) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

pub(super) fn retire(
    transaction: &Transaction<'_>,
    partition: PartitionId,
    command: &RetireMetadataBackup,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate(transaction, partition, command)?;
    transaction.execute(
        "UPDATE metadata_backups SET state = 3, verified_at = NULL, revision = ?1 WHERE backup_id = ?2",
        params![to_i64(revision.get())?, command.backup_id.as_bytes().as_slice()],
    )?;
    transaction.execute(
        "UPDATE backup_copies SET state = 4, verified_at = NULL, revision = ?1 WHERE backup_id = ?2",
        params![to_i64(revision.get())?, command.backup_id.as_bytes().as_slice()],
    )?;
    Ok(EntityReference {
        kind: EntityKind::MetadataBackup,
        id: command.backup_id.as_bytes(),
    })
}

fn validate(
    connection: &Connection,
    partition: PartitionId,
    command: &RetireMetadataBackup,
) -> Result<(), RepositoryError> {
    let schedule =
        backup_schedule::load(connection, partition)?.ok_or(RepositoryError::InvalidCommand)?;
    if !schedule.enabled || schedule.sequence != command.expected_schedule_sequence {
        return Err(RepositoryError::StaleMetadataBackupSchedule);
    }
    if command.retained_backups.len() != usize::from(schedule.retained_generations)
        || command.retained_backups.len() > MAXIMUM_BACKUP_RETENTION_WITNESSES
        || !command
            .retained_backups
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let victim = terminal_generation(connection, command.backup_id, partition)?;
    if victim.revision != command.expected_backup_revision {
        return Err(RepositoryError::StaleRevision);
    }
    for backup_id in &command.retained_backups {
        let witness = terminal_generation(connection, *backup_id, partition)?;
        if witness.state != MetadataBackupState::Verified
            || witness.state_revision <= victim.state_revision
        {
            return Err(RepositoryError::InvalidCommand);
        }
        require_current_protection(connection, &witness, schedule)?;
    }
    Ok(())
}

fn oldest_terminal_generation(
    connection: &Connection,
    before: Revision,
) -> Result<Option<BackupId>, RepositoryError> {
    // Separate state-prefix seeks prevent SQLite sorting every historical
    // candidate for an IN query. Each seek returns at most one row.
    let mut oldest: Option<(Revision, BackupId)> = None;
    for state in [1, 2] {
        let bytes = connection.query_row(
            "SELECT b.backup_id FROM metadata_backups b JOIN metadata_backup_runs r USING(backup_id)
             WHERE b.state = ?1 AND b.state_revision < ?2 AND r.state IN (4, 5)
             ORDER BY b.state_revision, b.backup_id DESC LIMIT 1",
            params![state, to_i64(before.get())?], |row| row.get::<_, Vec<u8>>(0),
        ).optional()?;
        if let Some(bytes) = bytes {
            let identifier = BackupId::from_bytes(
                bytes
                    .try_into()
                    .map_err(|_| RepositoryError::CorruptState)?,
            )
            .map_err(|_| RepositoryError::CorruptState)?;
            let record = backup_catalogue::backup(connection, identifier)?
                .ok_or(RepositoryError::CorruptState)?;
            let candidate = (record.state_revision, identifier);
            if oldest.is_none_or(|current| candidate < current) {
                oldest = Some(candidate);
            }
        }
    }
    Ok(oldest.map(|(_, identifier)| identifier))
}

fn terminal_generation(
    connection: &Connection,
    backup_id: BackupId,
    partition: PartitionId,
) -> Result<MetadataBackupRecord, RepositoryError> {
    let backup =
        backup_catalogue::backup(connection, backup_id)?.ok_or(RepositoryError::InvalidCommand)?;
    let run = backup_run::load(connection, backup_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if !matches!(
        (backup.state, run.state),
        (
            MetadataBackupState::Verified,
            MetadataBackupRunState::Protected | MetadataBackupRunState::Incomplete
        ) | (
            MetadataBackupState::Recorded,
            MetadataBackupRunState::Incomplete
        )
    ) || backup.partition_id != partition
        || run.partition_id != partition
        || backup_run::live_claim(connection, backup_id)?.is_some()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(backup)
}

fn require_current_protection(
    connection: &Connection,
    backup: &MetadataBackupRecord,
    schedule: MetadataBackupSchedule,
) -> Result<(), RepositoryError> {
    let run =
        backup_run::load(connection, backup.backup_id)?.ok_or(RepositoryError::InvalidCommand)?;
    let evidence = backup_run::protection_evidence(connection, backup.backup_id)?;
    if run.state != MetadataBackupRunState::Protected
        || evidence.verified_copies
            < u64::from(
                schedule
                    .minimum_verified_copies
                    .max(run.minimum_verified_copies),
            )
        || evidence.independent_copies
            < u64::from(
                schedule
                    .minimum_independent_copies
                    .max(run.minimum_independent_copies),
            )
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}
