// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable component instance and configuration persistence.

use meshspan_domain::Revision;
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{AssignComponent, CommandContext, ConfigureComponent, CreateComponent};

const MAXIMUM_CONFIGURATION_BYTES: usize = 16 * 1_024 * 1_024;

pub(super) fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateComponent,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate(command)?;
    let instance = command.instance_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    let stored_revision = to_i64(revision.get())?;
    transaction.execute(
        "INSERT INTO component_instances(
            instance_id, component_kind, display_name, canonical_name, implementation_id,
            contract_major, contract_minor, scope_kind, scope_id, desired_state,
            active_config_revision, created_by, created_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, NULL, 1, 1, ?8, ?9, NULL, ?10)",
        params![
            instance.as_slice(),
            command.component_kind,
            command.name.display(),
            command.name.canonical(),
            command.implementation_id,
            command.contract_major,
            command.contract_minor,
            actor.as_slice(),
            context.occurred_at.get(),
            stored_revision
        ],
    )?;
    transaction.execute(
        "INSERT INTO component_configurations(
            instance_id, config_revision, schema_version, canonical_config, config_digest,
            secret_generation_id, created_by, created_at, state
         ) VALUES (?1, 1, ?2, ?3, ?4, NULL, ?5, ?6, 2)",
        params![
            instance.as_slice(),
            command.schema_version,
            command.canonical_configuration,
            command.configuration_digest.as_slice(),
            actor.as_slice(),
            context.occurred_at.get()
        ],
    )?;
    let updated = transaction.execute(
        "UPDATE meshes SET configuration_revision = ?1, revision = ?1",
        [stored_revision],
    )?;
    if updated != 1 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(EntityReference {
        kind: EntityKind::ComponentInstance,
        id: instance,
    })
}

pub(super) fn configure(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ConfigureComponent,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_configuration(
        command.schema_version,
        &command.canonical_configuration,
        command.configuration_digest,
    )?;
    let instance = command.instance_id.as_bytes();
    let current: Option<i64> = transaction
        .query_row(
            "SELECT active_config_revision FROM component_instances
             WHERE instance_id = ?1 AND retired_at IS NULL",
            [instance.as_slice()],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    let current = current.ok_or(RepositoryError::InvalidCommand)?;
    let next = current
        .checked_add(1)
        .ok_or(RepositoryError::CapacityExceeded)?;
    transaction.execute(
        "UPDATE component_configurations SET state = 4
         WHERE instance_id = ?1 AND state = 2",
        [instance.as_slice()],
    )?;
    let actor = context.actor_principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO component_configurations(
            instance_id, config_revision, schema_version, canonical_config, config_digest,
            secret_generation_id, created_by, created_at, state
         ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, 2)",
        params![
            instance.as_slice(),
            next,
            command.schema_version,
            command.canonical_configuration,
            command.configuration_digest.as_slice(),
            actor.as_slice(),
            context.occurred_at.get()
        ],
    )?;
    let updated = transaction.execute(
        "UPDATE component_instances
         SET active_config_revision = ?1, revision = ?2 WHERE instance_id = ?3",
        params![next, to_i64(revision.get())?, instance.as_slice()],
    )?;
    if updated != 1 {
        return Err(RepositoryError::CorruptState);
    }
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::ComponentInstance,
        id: instance,
    })
}

pub(super) fn assign(
    transaction: &Transaction<'_>,
    command: &AssignComponent,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if !(1..=4).contains(&command.assignment_kind)
        || !(1..=4).contains(&command.desired_state)
        || command.assignment_id == [0; 16]
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let instance = command.instance_id.as_bytes();
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM component_instances
            WHERE instance_id = ?1 AND retired_at IS NULL
         )",
        [instance.as_slice()],
        |row| row.get(0),
    )?;
    if exists != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO component_assignments(
            instance_id, assignment_kind, assignment_id, desired_state, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(instance_id, assignment_kind, assignment_id) DO UPDATE SET
            desired_state = excluded.desired_state, revision = excluded.revision",
        params![
            instance.as_slice(),
            command.assignment_kind,
            command.assignment_id.as_slice(),
            command.desired_state,
            to_i64(revision.get())?
        ],
    )?;
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::ComponentAssignment,
        id: instance,
    })
}

fn validate(command: &CreateComponent) -> Result<(), RepositoryError> {
    command
        .validate_shape(MAXIMUM_CONFIGURATION_BYTES)
        .map_err(|_| RepositoryError::InvalidCommand)
}

fn validate_configuration(
    schema_version: u32,
    canonical_configuration: &[u8],
    configuration_digest: [u8; 32],
) -> Result<(), RepositoryError> {
    let digest: [u8; 32] = Sha256::digest(canonical_configuration).into();
    if schema_version == 0
        || canonical_configuration.len() > MAXIMUM_CONFIGURATION_BYTES
        || digest != configuration_digest
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn update_configuration_revision(
    transaction: &Transaction<'_>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let updated = transaction.execute(
        "UPDATE meshes SET configuration_revision = ?1, revision = ?1",
        [to_i64(revision.get())?],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}
