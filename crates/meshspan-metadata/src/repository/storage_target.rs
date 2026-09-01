// SPDX-License-Identifier: GPL-2.0-only

//! First authoritative generation of one registered storage target.

use meshspan_domain::{HostId, MeshId, NodeId, PrincipalId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::component;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, RegisterStorageTarget, StorageUsageLimit};

const ACTIVE_TARGET_STATE: u8 = 1;
const ACTIVE_GENERATION_STATE: u8 = 1;
const SYSTEM_MANAGE_RIGHT: i64 = 1;

/// Current authoritative identities needed to register one node-local storage target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageTargetRegistrationContext {
    /// Sole owning mesh.
    pub mesh_id: MeshId,
    /// Active local node.
    pub node_id: NodeId,
    /// Active host containing the node.
    pub host_id: HostId,
    /// Deterministically selected active system manager authorising local appliance configuration.
    pub actor_principal_id: PrincipalId,
}

pub(super) fn registration_context(
    database: &crate::PartitionDatabase,
    node_id: NodeId,
    now: UnixMicros,
) -> Result<Option<StorageTargetRegistrationContext>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT m.mesh_id, n.node_id, n.host_id,
                    (SELECT rg.principal_id FROM role_grants rg
                     JOIN roles r USING(role_id)
                     JOIN principals p ON p.principal_id = rg.principal_id
                     WHERE p.state = 1 AND (r.system_rights & ?1) = ?1
                       AND (rg.valid_from IS NULL OR rg.valid_from <= ?2)
                       AND (rg.valid_until IS NULL OR rg.valid_until > ?2)
                       AND rg.activation_policy_id IS NULL
                     ORDER BY rg.principal_id LIMIT 1)
             FROM meshes m
             JOIN nodes n ON n.node_id = ?3 AND n.state = 2 AND n.retired_at IS NULL
             JOIN hosts h ON h.host_id = n.host_id AND h.state = 1 AND h.retired_at IS NULL
             WHERE (SELECT COUNT(*) FROM meshes) = 1",
            params![
                SYSTEM_MANAGE_RIGHT,
                now.get(),
                node_id.as_bytes().as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((mesh, node, host, actor)) = stored else {
        return Ok(None);
    };
    let Some(actor) = actor else {
        return Ok(None);
    };
    let context = StorageTargetRegistrationContext {
        mesh_id: MeshId::from_bytes(exact_identifier(mesh)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        node_id: NodeId::from_bytes(exact_identifier(node)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        host_id: HostId::from_bytes(exact_identifier(host)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        actor_principal_id: PrincipalId::from_bytes(exact_identifier(actor)?)
            .map_err(|_| RepositoryError::CorruptState)?,
    };
    if context.node_id == node_id {
        Ok(Some(context))
    } else {
        Err(RepositoryError::CorruptState)
    }
}

pub(super) fn register(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RegisterStorageTarget,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let (usage_limit_kind, usage_limit_value) = validate(command)?;
    let target = command.target_id.as_bytes();
    let node = command.node_id.as_bytes();
    let host = command.host_id.as_bytes();
    component::create(transaction, context, &command.provider, revision)?;
    let provider = command.provider.instance_id.as_bytes();
    let stored_revision = to_i64(revision.get())?;
    transaction.execute(
        "INSERT INTO storage_targets(
            target_id, node_id, host_id, provider_instance_id, display_name, canonical_name,
            state, current_generation, usage_limit_kind, usage_limit_value, admitted_at,
            draining_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, NULL, ?12)",
        params![
            target.as_slice(),
            node.as_slice(),
            host.as_slice(),
            provider.as_slice(),
            command.name.display(),
            command.name.canonical(),
            ACTIVE_TARGET_STATE,
            to_i64(command.generation)?,
            usage_limit_kind,
            usage_limit_value,
            context.occurred_at.get(),
            stored_revision,
        ],
    )?;
    transaction.execute(
        "INSERT INTO target_generations(
            target_id, generation, marker_fingerprint, backing_device_fingerprint,
            filesystem_fingerprint, activated_at, retired_at, state, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8)",
        params![
            target.as_slice(),
            to_i64(command.generation)?,
            command.marker_fingerprint.as_slice(),
            command
                .backing_device_fingerprint
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            command
                .filesystem_fingerprint
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            context.occurred_at.get(),
            ACTIVE_GENERATION_STATE,
            stored_revision,
        ],
    )?;
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::StorageTarget,
        id: target,
    })
}

fn validate(command: &RegisterStorageTarget) -> Result<(u8, i64), RepositoryError> {
    command
        .usage_limit
        .validate()
        .map_err(|_| RepositoryError::InvalidCommand)?;
    if command.provider.component_kind != 1
        || command.generation == 0
        || command.marker_fingerprint == [0; 32]
        || command.backing_device_fingerprint == Some([0; 32])
        || command.filesystem_fingerprint == Some([0; 32])
    {
        return Err(RepositoryError::InvalidCommand);
    }
    match command.usage_limit {
        StorageUsageLimit::Percent(value) => Ok((1, i64::from(value))),
        StorageUsageLimit::Bytes(value) => Ok((2, to_i64(value)?)),
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

fn exact_identifier(value: Vec<u8>) -> Result<[u8; 16], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
