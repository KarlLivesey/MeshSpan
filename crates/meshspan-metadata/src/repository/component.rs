// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable component instance and configuration persistence.

use meshspan_domain::Revision;
use rusqlite::{Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, CreateComponent};

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

fn validate(command: &CreateComponent) -> Result<(), RepositoryError> {
    let identifier_is_valid = !command.implementation_id.is_empty()
        && command.implementation_id.len() <= 80
        && command
            .implementation_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !command.implementation_id.starts_with('-')
        && !command.implementation_id.ends_with('-');
    let digest: [u8; 32] = Sha256::digest(&command.canonical_configuration).into();
    if !(1..=10).contains(&command.component_kind)
        || command.contract_major == 0
        || command.schema_version == 0
        || command.canonical_configuration.len() > MAXIMUM_CONFIGURATION_BYTES
        || digest != command.configuration_digest
        || !identifier_is_valid
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}
