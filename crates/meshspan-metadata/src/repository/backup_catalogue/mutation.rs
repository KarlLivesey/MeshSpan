// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{BackupDestinationId, BackupId, PartitionId, Revision};
use rusqlite::{OptionalExtension, Transaction, params};

use super::super::apply::to_i64;
use super::super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    BackupDestinationBinding, BackupFailureRelationship, CommandContext,
    ConfigureBackupDestination, MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES, RecordBackupCopy,
    RecordMetadataBackup, VerifyBackupCopy,
};

const DESTINATION_REGISTERED_TARGET: i64 = 1;
const DESTINATION_FEDERATED_MESH: i64 = 2;
const DESTINATION_COMPONENT_PROVIDER: i64 = 3;
const FAILURE_UNKNOWN: i64 = 1;
const FAILURE_OVERLAPPING: i64 = 2;
const FAILURE_INDEPENDENT: i64 = 3;
const DESTINATION_ACTIVE: i64 = 1;
const DESTINATION_PAUSED: i64 = 2;

struct BindingColumns {
    kind: i64,
    target: Option<Vec<u8>>,
    remote_mesh: Option<Vec<u8>>,
    component: Option<Vec<u8>>,
    generation: u64,
}

pub(in crate::repository) fn configure_destination(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ConfigureBackupDestination,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let existing = super::query::destination(transaction, command.destination_id)?;
    let current_revision = existing
        .as_ref()
        .map_or(Revision::new(0), |row| row.revision);
    if command.expected_destination_revision != current_revision {
        return Err(RepositoryError::StaleRevision);
    }
    // Copy receipts resolve through this identity. Rebinding it would orphan older
    // encrypted objects; a different provider must have a new destination identity.
    if existing.as_ref().is_some_and(|row| {
        row.binding != command.binding || row.state == super::BackupDestinationState::Retired
    }) {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_destination_binding(transaction, command.binding)?;
    let binding = binding_columns(command.binding);
    let state = if command.enabled {
        DESTINATION_ACTIVE
    } else {
        DESTINATION_PAUSED
    };
    let changed = transaction.execute(
        "INSERT INTO backup_destinations(
            destination_id, display_name, canonical_name, destination_kind, target_id,
            remote_mesh_id, provider_instance_id, provider_generation, failure_relationship,
            failure_evidence_digest, state, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(destination_id) DO UPDATE SET
            display_name = excluded.display_name,
            canonical_name = excluded.canonical_name,
            destination_kind = excluded.destination_kind,
            target_id = excluded.target_id,
            remote_mesh_id = excluded.remote_mesh_id,
            provider_instance_id = excluded.provider_instance_id,
            provider_generation = excluded.provider_generation,
            failure_relationship = excluded.failure_relationship,
            failure_evidence_digest = excluded.failure_evidence_digest,
            state = excluded.state,
            revision = excluded.revision
         WHERE backup_destinations.state != 3",
        params![
            command.destination_id.as_bytes().as_slice(),
            command.name.display(),
            command.name.canonical(),
            binding.kind,
            binding.target,
            binding.remote_mesh,
            binding.component,
            to_i64(binding.generation)?,
            failure_relationship_code(command.failure_relationship),
            command.failure_evidence_digest.as_slice(),
            state,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    // Explicit edits take ownership; automatic reconciliation deliberately marks
    // its own writes back to automatic within the same enclosing transaction.
    transaction.execute(
        "UPDATE backup_destinations SET configuration_origin = 2 WHERE destination_id = ?1",
        [command.destination_id.as_bytes().as_slice()],
    )?;
    super::super::backup_defaults::invalidate(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::BackupDestination,
        id: command.destination_id.as_bytes(),
    })
}

pub(in crate::repository) fn record_backup(
    transaction: &Transaction<'_>,
    partition_id: PartitionId,
    context: CommandContext,
    command: &RecordMetadataBackup,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_backup_source(transaction, partition_id, command)?;
    validate_initial_copy(transaction, command)?;
    transaction.execute(
        "INSERT INTO metadata_backups(
            backup_id, partition_id, mesh_id, last_log_index, last_log_term, state_revision,
            schema_version, source_byte_length, source_digest, manifest_digest,
            encrypted_byte_length, encrypted_digest, state, created_at, verified_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, ?13, NULL, ?14)",
        params![
            command.backup_id.as_bytes().as_slice(),
            command.partition_id.as_bytes().as_slice(),
            command.mesh_id.as_bytes().as_slice(),
            to_i64(command.last_log_index)?,
            to_i64(command.last_log_term)?,
            to_i64(command.state_revision.get())?,
            i64::from(command.schema_version),
            to_i64(command.source_byte_length)?,
            command.source_digest.as_slice(),
            command.manifest_digest.as_slice(),
            to_i64(command.encrypted_byte_length)?,
            command.encrypted_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO backup_copies(
            backup_id, destination_id, provider_generation, object_reference, byte_length,
            copy_digest, state, stored_at, verified_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, NULL, ?8)",
        params![
            command.backup_id.as_bytes().as_slice(),
            command.initial_copy.destination_id.as_bytes().as_slice(),
            to_i64(command.initial_copy.provider_generation)?,
            command.initial_copy.object_reference,
            to_i64(command.initial_copy.byte_length)?,
            command.initial_copy.copy_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::MetadataBackup,
        id: command.backup_id.as_bytes(),
    })
}

pub(in crate::repository) fn record_copy(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RecordBackupCopy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_object_reference(&command.object_reference)?;
    let expected = expected_copy(transaction, command.backup_id, command.destination_id)?;
    if expected
        != (
            command.provider_generation,
            command.byte_length,
            command.copy_digest,
        )
    {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO backup_copies(
            backup_id, destination_id, provider_generation, object_reference, byte_length,
            copy_digest, state, stored_at, verified_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, NULL, ?8)",
        params![
            command.backup_id.as_bytes().as_slice(),
            command.destination_id.as_bytes().as_slice(),
            to_i64(command.provider_generation)?,
            command.object_reference,
            to_i64(command.byte_length)?,
            command.copy_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::BackupCopy,
        id: command.backup_id.as_bytes(),
    })
}

pub(in crate::repository) fn verify_copy(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: VerifyBackupCopy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let changed = transaction.execute(
        "UPDATE backup_copies
         SET state = 2, verified_at = ?1, revision = ?2
         WHERE backup_id = ?3 AND destination_id = ?4 AND state = 1
           AND provider_generation = ?5 AND copy_digest = ?6",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.backup_id.as_bytes().as_slice(),
            command.destination_id.as_bytes().as_slice(),
            to_i64(command.provider_generation)?,
            command.copy_digest.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(EntityReference {
        kind: EntityKind::BackupCopy,
        id: command.backup_id.as_bytes(),
    })
}

fn validate_destination_binding(
    transaction: &Transaction<'_>,
    binding: BackupDestinationBinding,
) -> Result<(), RepositoryError> {
    let exists: i64 = match binding {
        BackupDestinationBinding::RegisteredTarget {
            target_id,
            target_generation,
        } => transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM storage_targets
             WHERE target_id = ?1 AND current_generation = ?2 AND state < 5)",
            params![target_id.as_bytes().as_slice(), to_i64(target_generation)?],
            |row| row.get(0),
        )?,
        BackupDestinationBinding::FederatedMesh { remote_mesh_id, .. } => transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM federation_relationships
             WHERE remote_mesh_id = ?1 AND state IN (2, 3))",
            [remote_mesh_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?,
        BackupDestinationBinding::ComponentProvider {
            instance_id,
            provider_generation,
        } => transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM component_instances
             WHERE instance_id = ?1 AND active_config_revision = ?2 AND desired_state < 5)",
            params![
                instance_id.as_bytes().as_slice(),
                to_i64(provider_generation)?
            ],
            |row| row.get(0),
        )?,
    };
    if exists == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_backup_source(
    transaction: &Transaction<'_>,
    partition_id: PartitionId,
    command: &RecordMetadataBackup,
) -> Result<(), RepositoryError> {
    if command.partition_id != partition_id
        || command.last_log_index == 0
        || command.last_log_term == 0
        || command.state_revision.get() == 0
        || command.schema_version == 0
        || command.source_byte_length == 0
        || command.encrypted_byte_length == 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let valid: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM meshes m, applied_state a
            WHERE m.mesh_id = ?1 AND a.singleton = 1
              AND a.schema_version = ?2
              AND a.last_log_index = ?3
              AND a.last_log_term = ?4
              AND a.state_revision = ?5
         )",
        params![
            command.mesh_id.as_bytes().as_slice(),
            i64::from(command.schema_version),
            to_i64(command.last_log_index)?,
            to_i64(command.last_log_term)?,
            to_i64(command.state_revision.get())?,
        ],
        |row| row.get(0),
    )?;
    if valid == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_initial_copy(
    transaction: &Transaction<'_>,
    command: &RecordMetadataBackup,
) -> Result<(), RepositoryError> {
    validate_object_reference(&command.initial_copy.object_reference)?;
    if command.initial_copy.byte_length != command.encrypted_byte_length
        || command.initial_copy.copy_digest != command.encrypted_digest
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let generation: Option<i64> = transaction
        .query_row(
            "SELECT provider_generation FROM backup_destinations
             WHERE destination_id = ?1 AND state = 1",
            [command.initial_copy.destination_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if generation.map(parse_u64).transpose()? == Some(command.initial_copy.provider_generation) {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn expected_copy(
    transaction: &Transaction<'_>,
    backup_id: BackupId,
    destination_id: BackupDestinationId,
) -> Result<(u64, u64, [u8; 32]), RepositoryError> {
    transaction
        .query_row(
            "SELECT d.provider_generation, b.encrypted_byte_length, b.encrypted_digest
             FROM metadata_backups b, backup_destinations d
             WHERE b.backup_id = ?1 AND d.destination_id = ?2
               AND b.state IN (1, 2) AND d.state = 1",
            params![
                backup_id.as_bytes().as_slice(),
                destination_id.as_bytes().as_slice()
            ],
            |row| {
                let generation = row.get::<_, i64>(0)?;
                let length = row.get::<_, i64>(1)?;
                let digest = row.get::<_, Vec<u8>>(2)?;
                Ok((generation, length, digest))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)
        .and_then(|(generation, length, digest)| {
            Ok((
                parse_u64(generation)?,
                parse_u64(length)?,
                digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| RepositoryError::CorruptState)?,
            ))
        })
}

fn binding_columns(binding: BackupDestinationBinding) -> BindingColumns {
    match binding {
        BackupDestinationBinding::RegisteredTarget {
            target_id,
            target_generation,
        } => BindingColumns {
            kind: DESTINATION_REGISTERED_TARGET,
            target: Some(target_id.as_bytes().to_vec()),
            remote_mesh: None,
            component: None,
            generation: target_generation,
        },
        BackupDestinationBinding::FederatedMesh {
            remote_mesh_id,
            provider_generation,
        } => BindingColumns {
            kind: DESTINATION_FEDERATED_MESH,
            target: None,
            remote_mesh: Some(remote_mesh_id.as_bytes().to_vec()),
            component: None,
            generation: provider_generation,
        },
        BackupDestinationBinding::ComponentProvider {
            instance_id,
            provider_generation,
        } => BindingColumns {
            kind: DESTINATION_COMPONENT_PROVIDER,
            target: None,
            remote_mesh: None,
            component: Some(instance_id.as_bytes().to_vec()),
            generation: provider_generation,
        },
    }
}

const fn failure_relationship_code(value: BackupFailureRelationship) -> i64 {
    match value {
        BackupFailureRelationship::Unknown => FAILURE_UNKNOWN,
        BackupFailureRelationship::Overlapping => FAILURE_OVERLAPPING,
        BackupFailureRelationship::Independent => FAILURE_INDEPENDENT,
    }
}

fn validate_object_reference(value: &str) -> Result<(), RepositoryError> {
    if value.is_empty()
        || value.len() > MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES
        || value.chars().any(char::is_control)
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
