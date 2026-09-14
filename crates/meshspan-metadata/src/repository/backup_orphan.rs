// SPDX-License-Identifier: GPL-2.0-only

//! Exact retirement authority for provider objects whose generation was never admitted.

use meshspan_domain::{BackupDestinationId, BackupId, Revision, UnixMicros};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{
    AuthoritativeRepository, EntityKind, EntityReference, MetadataBackupRunState, RepositoryError,
    apply::to_i64,
};
use crate::{
    AuthoritativeCommand, BackupDestinationBinding, CommandContext, RetireAbandonedBackupCopy,
};

/// Committed removal authority, not a stored/verified backup or a deletion acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbandonedBackupRetirement {
    /// Immutable exact object and terminal run precondition admitted by consensus.
    pub command: RetireAbandonedBackupCopy,
    /// First committed retirement revision; retries cannot mint replacement authority.
    pub retirement_revision: Revision,
    /// Authority instant when retirement was committed.
    pub retired_at: UnixMicros,
}

impl AuthoritativeRepository {
    /// Loads exact removal authority even after worker loss or destination pause.
    ///
    /// # Errors
    /// Rejects corrupt, substituted or non-canonical retained evidence.
    pub fn abandoned_backup_retirement(
        &self,
        backup: BackupId,
        destination: BackupDestinationId,
    ) -> Result<Option<AbandonedBackupRetirement>, RepositoryError> {
        load(self.database.connection(), backup, destination)
    }
}

pub(super) fn retire(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &RetireAbandonedBackupCopy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let object = value.receipt.object;
    let command = AuthoritativeCommand::RetireAbandonedBackupCopy(value.clone());
    let canonical = crate::encode_authoritative_command(context, &command)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let run = super::backup_run::load(transaction, object.backup_id)?
        .ok_or(RepositoryError::InvalidCommand)?;
    let live_claim = super::backup_run::live_claim(transaction, object.backup_id)?.is_some();
    if run.revision != value.expected_run_revision {
        return Err(RepositoryError::StaleRevision);
    }
    if run.state != MetadataBackupRunState::Incomplete
        || run
            .completed_at
            .is_none_or(|instant| instant > context.occurred_at)
        || run.result_digest.is_none_or(|digest| digest == [0; 32])
        || live_claim
        || super::backup_catalogue::backup(transaction, object.backup_id)?.is_some()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_destination(transaction, value)?;
    if let Some(existing) = load(transaction, object.backup_id, object.destination_id)? {
        if existing.command != *value {
            return Err(RepositoryError::InvalidCommand);
        }
    } else {
        transaction.execute(
            "INSERT INTO abandoned_backup_retirements(backup_id, destination_id, canonical_command, retirement_revision)
             VALUES (?1, ?2, ?3, ?4)",
            params![object.backup_id.as_bytes().as_slice(), object.destination_id.as_bytes().as_slice(), canonical, to_i64(revision.get())?],
        )?;
    }
    Ok(EntityReference {
        kind: EntityKind::MetadataBackup,
        id: object.backup_id.as_bytes(),
    })
}

fn validate_destination(
    connection: &Connection,
    value: &RetireAbandonedBackupCopy,
) -> Result<(), RepositoryError> {
    let object = value.receipt.object;
    let destination = super::backup_catalogue::destination(connection, object.destination_id)?
        .ok_or(RepositoryError::InvalidCommand)?;
    if destination.binding.provider_generation() != object.provider_generation {
        return Err(RepositoryError::StaleRevision);
    }
    // A remote route was committed before IO. A forged receipt cannot redirect retirement
    // to another provider/allocation or change the encrypted identity chosen for that route.
    if matches!(
        destination.binding,
        BackupDestinationBinding::FederatedMesh { .. }
    ) {
        let route_exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM federated_backup_routes WHERE backup_id = ?1 AND destination_id = ?2)",
            params![object.backup_id.as_bytes().as_slice(), object.destination_id.as_bytes().as_slice()], |row| row.get(0),
        )?;
        if !route_exists {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    super::backup_intent::validate_bound_object(connection, object)
}

pub(super) fn record_reclamation(
    transaction: &Transaction<'_>,
    context: CommandContext,
    receipt: meshspan_contracts::BackupDeleteReceipt,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let object = receipt.object;
    transaction.execute(
        "INSERT INTO abandoned_backup_reclamations(backup_id, destination_id, operation_id,
            retirement_revision, provider_generation, byte_length, copy_digest, reclaimed_at, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(backup_id, destination_id) DO NOTHING",
        params![object.backup_id.as_bytes().as_slice(), object.destination_id.as_bytes().as_slice(),
            receipt.operation_id.as_bytes().as_slice(), to_i64(receipt.retirement_revision.get())?,
            to_i64(object.provider_generation)?, to_i64(object.byte_length)?, object.digest.as_slice(),
            context.occurred_at.get(), to_i64(revision.get())?],
    )?;
    let exact: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM abandoned_backup_reclamations WHERE backup_id = ?1
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

pub(super) fn load(
    connection: &Connection,
    backup: BackupId,
    destination: BackupDestinationId,
) -> Result<Option<AbandonedBackupRetirement>, RepositoryError> {
    let row = connection.query_row(
        "SELECT canonical_command, retirement_revision FROM abandoned_backup_retirements WHERE backup_id = ?1 AND destination_id = ?2",
        params![backup.as_bytes().as_slice(), destination.as_bytes().as_slice()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
    ).optional()?;
    row.map(|(bytes, revision)| {
        let decoded = crate::decode_authoritative_command(&bytes)
            .map_err(|_| RepositoryError::CorruptState)?;
        let AuthoritativeCommand::RetireAbandonedBackupCopy(command) = decoded.command else {
            return Err(RepositoryError::CorruptState);
        };
        if command.receipt.object.backup_id != backup
            || command.receipt.object.destination_id != destination
            || decoded.context.occurred_at.get() < 0
            || revision <= 0
            || command.expected_run_revision.get()
                >= u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?
        {
            return Err(RepositoryError::CorruptState);
        }
        Ok(AbandonedBackupRetirement {
            command,
            retirement_revision: Revision::new(
                u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?,
            ),
            retired_at: decoded.context.occurred_at,
        })
    })
    .transpose()
}
