// SPDX-License-Identifier: GPL-2.0-only

//! Replicated upload identity survives a lost worker without claiming provider completion.

mod discovery;

use super::{AuthoritativeRepository, EntityKind, EntityReference, RepositoryError, apply::to_i64};
use crate::{
    AuthoritativeCommand, BackupDestinationState, BackupPublicationIntentRecord,
    BindBackupPublicationIntent, CommandContext,
};
use meshspan_domain::{BackupDestinationId, BackupId, PartitionId, Revision};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

impl AuthoritativeRepository {
    /// Loads the immutable upload identity, including after abandonment or local journal loss.
    /// This is neither proof that bytes exist nor permission to delete them.
    /// # Errors
    /// Rejects corrupt, substituted or non-canonical retained evidence.
    pub fn backup_publication_intent(
        &self,
        backup: BackupId,
        destination: BackupDestinationId,
    ) -> Result<Option<BackupPublicationIntentRecord>, RepositoryError> {
        load(self.database.connection(), backup, destination)
    }
}

pub(super) fn bind(
    transaction: &Transaction<'_>,
    partition: PartitionId,
    context: CommandContext,
    value: &BindBackupPublicationIntent,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let command = AuthoritativeCommand::BindBackupPublicationIntent(*value);
    let bytes = crate::encode_authoritative_command(context, &command)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    super::backup_run::validate_route_claim(
        transaction,
        partition,
        context,
        value.object.backup_id,
        value.claim,
    )?;
    let destination =
        super::backup_catalogue::destination(transaction, value.object.destination_id)?
            .ok_or(RepositoryError::InvalidCommand)?;
    if destination.state != BackupDestinationState::Active
        || destination.revision != value.expected_destination_revision
        || destination.binding.provider_generation() != value.object.provider_generation
    {
        return Err(RepositoryError::StaleRevision);
    }
    if let Some(backup) = super::backup_catalogue::backup(transaction, value.object.backup_id)?
        && (backup.encrypted_byte_length != value.object.byte_length
            || backup.encrypted_digest != value.object.digest)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_bound_object(transaction, value.object)?;
    if let Some(existing) = load(
        transaction,
        value.object.backup_id,
        value.object.destination_id,
    )? {
        if existing.binding.object != value.object
            || existing.binding.store_operation_id != value.store_operation_id
        {
            return Err(RepositoryError::InvalidCommand);
        }
    } else {
        transaction.execute("INSERT INTO backup_publication_intents(backup_id, destination_id, canonical_command, revision) VALUES (?1, ?2, ?3, ?4)",
            params![value.object.backup_id.as_bytes().as_slice(), value.object.destination_id.as_bytes().as_slice(), bytes, to_i64(revision.get())?])?;
    }
    Ok(EntityReference {
        kind: EntityKind::MetadataBackup,
        id: value.object.backup_id.as_bytes(),
    })
}

/// Common immutable-byte fence for publication, admission and retirement.
pub(super) fn validate_bound_object(
    connection: &Connection,
    object: meshspan_contracts::BackupObjectIdentity,
) -> Result<(), RepositoryError> {
    super::federated_backup_route::validate_recorded_object(connection, object)?;
    let first_destination = connection.query_row(
        "SELECT destination_id FROM backup_publication_intents WHERE backup_id = ?1 ORDER BY destination_id LIMIT 1",
        [object.backup_id.as_bytes().as_slice()], |row| row.get::<_, Vec<u8>>(0)).optional()?;
    if let Some(bytes) = first_destination {
        let destination = BackupDestinationId::from_bytes(
            bytes
                .try_into()
                .map_err(|_| RepositoryError::CorruptState)?,
        )
        .map_err(|_| RepositoryError::CorruptState)?;
        let existing = load(connection, object.backup_id, destination)?
            .ok_or(RepositoryError::CorruptState)?;
        if existing.binding.object.byte_length != object.byte_length
            || existing.binding.object.digest != object.digest
        {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    if let Some(existing) = load(connection, object.backup_id, object.destination_id)?
        && existing.binding.object != object
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    backup: BackupId,
    destination: BackupDestinationId,
) -> Result<Option<BackupPublicationIntentRecord>, RepositoryError> {
    let row = connection.query_row("SELECT canonical_command, revision FROM backup_publication_intents WHERE backup_id = ?1 AND destination_id = ?2",
        params![backup.as_bytes().as_slice(), destination.as_bytes().as_slice()], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))).optional()?;
    row.map(|(bytes, revision)| {
        let decoded = crate::decode_authoritative_command(&bytes)
            .map_err(|_| RepositoryError::CorruptState)?;
        let AuthoritativeCommand::BindBackupPublicationIntent(binding) = decoded.command else {
            return Err(RepositoryError::CorruptState);
        };
        if binding.object.backup_id != backup
            || binding.object.destination_id != destination
            || revision <= 0
        {
            return Err(RepositoryError::CorruptState);
        }
        Ok(BackupPublicationIntentRecord {
            binding,
            revision: Revision::new(
                u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?,
            ),
        })
    })
    .transpose()
}
