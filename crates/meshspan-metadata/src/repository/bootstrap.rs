// SPDX-License-Identifier: GPL-2.0-only

//! Atomic creation of the first mesh, authority, administrator and voter.

use meshspan_domain::Revision;
use meshspan_secret_envelope::WrappingPublicKey;
use rusqlite::{Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError, authentication_policy, identity};
use crate::{BootstrapAppliance, BootstrapMesh, CommandContext};

const PRINCIPAL_USER: u8 = 1;
const ALL_SYSTEM_RIGHTS: u16 = 255;

pub(super) fn bootstrap(
    transaction: &Transaction<'_>,
    partition_id: [u8; 16],
    context: CommandContext,
    command: &BootstrapMesh,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    identity::insert_principal(
        transaction,
        command.administrator_id,
        PRINCIPAL_USER,
        &command.administrator_name,
        context,
        revision,
    )?;
    let administrator = command.administrator_id.as_bytes();
    transaction.execute(
        "INSERT INTO users(principal_id, primary_email) VALUES (?1, NULL)",
        [administrator.as_slice()],
    )?;
    let mesh = persist_mesh(transaction, context, command, revision)?;
    persist_initial_topology(transaction, partition_id, context, command, revision)?;
    persist_administrator_role(transaction, context, command, revision)?;
    authentication_policy::bootstrap_defaults(
        transaction,
        command.administrator_id,
        context.occurred_at,
        revision,
    )?;
    Ok(EntityReference {
        kind: EntityKind::Mesh,
        id: mesh,
    })
}

pub(super) fn bootstrap_appliance(
    transaction: &Transaction<'_>,
    partition_id: [u8; 16],
    context: CommandContext,
    command: &BootstrapAppliance,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.authentication.principal_id != command.mesh.administrator_id
        || command.node_wrapping_key.node_id != command.mesh.node_id
        || command.node_certificate.certificate_der.is_empty()
        || command.node_certificate.certificate_fingerprint
            != <[u8; 32]>::from(Sha256::digest(&command.node_certificate.certificate_der))
        || command.node_certificate.certificate_valid_until <= context.occurred_at
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let node_recipient = WrappingPublicKey::from_bytes(command.node_wrapping_key.public_key)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let recovery_recipient = WrappingPublicKey::from_bytes(command.recovery.public_wrapping_key)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let mesh = bootstrap(transaction, partition_id, context, &command.mesh, revision)?;
    persist_initial_node_certificate(transaction, context, command, revision)?;
    super::authentication_method_creation::create(
        transaction,
        context,
        &command.authentication,
        revision,
    )?;
    super::recovery_authority::insert_bootstrap(
        transaction,
        context,
        command.mesh.mesh_id,
        &command.recovery,
        revision,
    )?;
    super::node_wrapping_key::register(transaction, context, command.node_wrapping_key, revision)?;
    super::secret_generation::commit_initial_storage_permit_key(
        transaction,
        context,
        command.mesh.mesh_id,
        node_recipient,
        recovery_recipient,
        &command.storage_permit_key_generation,
        revision,
    )?;
    super::secret_generation::commit_initial_authentication_root_key(
        transaction,
        context,
        command.mesh.mesh_id,
        node_recipient,
        recovery_recipient,
        &command.authentication_root_key_generation,
        revision,
    )?;
    super::secret_generation::commit_initial_online_authority_key(
        transaction,
        context,
        command.mesh.mesh_id,
        node_recipient,
        recovery_recipient,
        &command.online_authority_key_generation,
        revision,
    )?;
    Ok(mesh)
}

fn persist_initial_node_certificate(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &BootstrapAppliance,
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO node_certificates(
            node_id, generation, certificate_der, certificate_fingerprint, valid_from,
            valid_until, state, revision
         ) VALUES (?1, 1, ?2, ?3, ?4, ?5, 1, ?6)",
        params![
            command.mesh.node_id.as_bytes().as_slice(),
            command.node_certificate.certificate_der,
            command.node_certificate.certificate_fingerprint.as_slice(),
            context.occurred_at.get(),
            command.node_certificate.certificate_valid_until.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn persist_mesh(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &BootstrapMesh,
    revision: Revision,
) -> Result<[u8; 16], RepositoryError> {
    let mesh = command.mesh_id.as_bytes();
    let stored_revision = to_i64(revision.get())?;
    transaction.execute(
        "INSERT INTO meshes(
            mesh_id, display_name, canonical_name, created_at, configuration_revision,
            identity_revision, namespace_revision, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5, ?5)",
        params![
            mesh.as_slice(),
            command.mesh_name.display(),
            command.mesh_name.canonical(),
            context.occurred_at.get(),
            stored_revision
        ],
    )?;
    Ok(mesh)
}

fn persist_initial_topology(
    transaction: &Transaction<'_>,
    partition_id: [u8; 16],
    context: CommandContext,
    command: &BootstrapMesh,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let stored_revision = to_i64(revision.get())?;
    let host = command.host_id.as_bytes();
    transaction.execute(
        "INSERT INTO hosts(
            host_id, display_name, canonical_name, state, created_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, 1, ?4, NULL, ?5)",
        params![
            host.as_slice(),
            command.host_name.display(),
            command.host_name.canonical(),
            context.occurred_at.get(),
            stored_revision
        ],
    )?;
    let node = command.node_id.as_bytes();
    transaction.execute(
        "INSERT INTO nodes(
            node_id, host_id, display_name, canonical_name, state, current_incarnation,
            admitted_at, activated_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, ?4, 2, 1, ?5, ?5, NULL, ?6)",
        params![
            node.as_slice(),
            host.as_slice(),
            command.node_name.display(),
            command.node_name.canonical(),
            context.occurred_at.get(),
            stored_revision
        ],
    )?;
    transaction.execute(
        "INSERT INTO metadata_partitions(
            partition_id, partition_kind, display_name, state, routing_epoch,
            current_membership_revision, created_at, retired_at, revision
         ) VALUES (?1, 1, ?2, 1, 1, 1, ?3, NULL, ?4)",
        params![
            partition_id.as_slice(),
            command.partition_name.display(),
            context.occurred_at.get(),
            stored_revision
        ],
    )?;
    transaction.execute(
        "INSERT INTO partition_voters(
            partition_id, node_id, membership_revision, member_role, state, revision
         ) VALUES (?1, ?2, 1, 1, 1, ?3)",
        params![partition_id.as_slice(), node.as_slice(), stored_revision],
    )?;
    for role_code in [1_u8, 2, 3] {
        transaction.execute(
            "INSERT INTO node_roles(node_id, role_code, revision) VALUES (?1, ?2, ?3)",
            params![node.as_slice(), role_code, stored_revision],
        )?;
    }
    Ok(())
}

fn persist_administrator_role(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &BootstrapMesh,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let stored_revision = to_i64(revision.get())?;
    let administrator = command.administrator_id.as_bytes();
    let role = command.administrator_role_id.as_bytes();
    transaction.execute(
        "INSERT INTO roles(
            role_id, display_name, canonical_name, system_rights, created_at, revision
         ) VALUES (?1, 'System administrators', 'system administrators', ?2, ?3, ?4)",
        params![
            role.as_slice(),
            ALL_SYSTEM_RIGHTS,
            context.occurred_at.get(),
            stored_revision
        ],
    )?;
    transaction.execute(
        "INSERT INTO role_grants(
            role_id, principal_id, valid_from, valid_until, activation_policy_id,
            created_by, created_at, revision
         ) VALUES (?1, ?2, NULL, NULL, NULL, ?2, ?3, ?4)",
        params![
            role.as_slice(),
            administrator.as_slice(),
            context.occurred_at.get(),
            stored_revision
        ],
    )?;
    Ok(())
}
