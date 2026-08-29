// SPDX-License-Identifier: GPL-2.0-only

//! Namespace and immutable multi-principal owner-set mutations.

use std::collections::BTreeSet;

use meshspan_domain::{OwnerSet, PrincipalId, Revision};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    CommandContext, CreateObject, CreateVolume, NamespaceObjectKind, ReplaceObjectOwners,
    SetObjectGrantInheritance,
};

const MAXIMUM_OWNERS: usize = 1_024;
const DEFAULT_RETENTION_MICROS: i64 = 2_592_000_000_000;

pub(super) fn create_volume(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateVolume,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    persist_owner_set(
        transaction,
        context,
        command.owner_set_id.as_bytes(),
        command.owners.as_slice(),
        revision,
    )?;
    let volume = command.volume_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    let stored_revision = to_i64(revision.get())?;
    transaction.execute(
        "INSERT INTO volumes(
            volume_id, display_name, canonical_name, state, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
        params![
            volume.as_slice(),
            command.name.display(),
            command.name.canonical(),
            actor.as_slice(),
            context.occurred_at.get(),
            stored_revision
        ],
    )?;
    transaction.execute(
        "INSERT INTO version_retention_policy_revisions(
            volume_id, policy_sequence, history_enabled, minimum_age_micros,
            maximum_age_micros, minimum_versions, reclaim_mode, soft_minimum_breakable,
            conflict_minimum_age_micros, configured_by, configured_at, revision
         ) VALUES (?1, 1, 1, ?2, NULL, NULL, 1, 1, ?2, ?3, ?4, ?5)",
        params![
            volume.as_slice(),
            DEFAULT_RETENTION_MICROS,
            actor.as_slice(),
            context.occurred_at.get(),
            stored_revision,
        ],
    )?;
    let root = command.root_object_id.as_bytes();
    let owners = command.owner_set_id.as_bytes();
    transaction.execute(
        "INSERT INTO namespace_objects(
            object_id, volume_id, parent_object_id, object_kind, display_name, canonical_name,
            owner_set_id, state, created_by, created_at, revision
         ) VALUES (?1, ?2, NULL, 1, '', '', ?3, 1, ?4, ?5, ?6)",
        params![
            root.as_slice(),
            volume.as_slice(),
            owners.as_slice(),
            actor.as_slice(),
            context.occurred_at.get(),
            stored_revision
        ],
    )?;
    update_namespace_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::Volume,
        id: volume,
    })
}

pub(super) fn create_object(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateObject,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.name.display().len() > 255 || command.name.canonical().len() > 255 {
        return Err(RepositoryError::InvalidCommand);
    }
    let parent = command.parent_object_id.as_bytes();
    let expected_volume = command.volume_id.as_bytes();
    let parent_volume: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT volume_id FROM namespace_objects
             WHERE object_id = ?1 AND object_kind = 1 AND state = 1",
            [parent.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if parent_volume.as_deref() != Some(expected_volume.as_slice()) {
        return Err(RepositoryError::InvalidCommand);
    }
    persist_owner_set(
        transaction,
        context,
        command.owner_set_id.as_bytes(),
        command.owners.as_slice(),
        revision,
    )?;
    let object = command.object_id.as_bytes();
    let owners = command.owner_set_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO namespace_objects(
            object_id, volume_id, parent_object_id, object_kind, display_name, canonical_name,
            owner_set_id, state, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10)",
        params![
            object.as_slice(),
            expected_volume.as_slice(),
            parent.as_slice(),
            object_kind(command.kind),
            command.name.display(),
            command.name.canonical(),
            owners.as_slice(),
            actor.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?
        ],
    )?;
    update_namespace_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::NamespaceObject,
        id: object,
    })
}

pub(super) fn replace_object_owners(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ReplaceObjectOwners,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let object = command.object_id.as_bytes();
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM namespace_objects WHERE object_id = ?1 AND state = 1
         )",
        [object.as_slice()],
        |row| row.get(0),
    )?;
    if exists != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    persist_owner_set(
        transaction,
        context,
        command.owner_set_id.as_bytes(),
        command.owners.as_slice(),
        revision,
    )?;
    let owner_set = command.owner_set_id.as_bytes();
    let updated = transaction.execute(
        "UPDATE namespace_objects SET owner_set_id = ?1, revision = ?2
         WHERE object_id = ?3 AND state = 1",
        params![
            owner_set.as_slice(),
            to_i64(revision.get())?,
            object.as_slice()
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::CorruptState);
    }
    update_namespace_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::NamespaceObject,
        id: object,
    })
}

pub(super) fn set_grant_inheritance(
    transaction: &Transaction<'_>,
    command: SetObjectGrantInheritance,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let object = command.object_id.as_bytes();
    let updated = transaction.execute(
        "UPDATE namespace_objects
         SET stop_parent_grant_inheritance = ?1, revision = ?2
         WHERE object_id = ?3 AND object_kind = 1 AND state = 1",
        params![
            u8::from(command.stop_parent_grants),
            to_i64(revision.get())?,
            object.as_slice(),
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    let updated_mesh = transaction.execute(
        "UPDATE meshes
         SET identity_revision = ?1, namespace_revision = ?1, revision = ?1",
        [to_i64(revision.get())?],
    )?;
    if updated_mesh != 1 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(EntityReference {
        kind: EntityKind::NamespaceObject,
        id: object,
    })
}

fn persist_owner_set(
    transaction: &Transaction<'_>,
    context: CommandContext,
    owner_set_id: [u8; 16],
    owners: &[PrincipalId],
    revision: Revision,
) -> Result<(), RepositoryError> {
    let unique: BTreeSet<PrincipalId> = owners.iter().copied().collect();
    if unique.len() != owners.len() || owners.len() > MAXIMUM_OWNERS {
        return Err(RepositoryError::InvalidCommand);
    }
    OwnerSet::new(unique.clone(), revision).map_err(|_| RepositoryError::InvalidCommand)?;
    validate_active_principals(transaction, &unique)?;
    let actor = context.actor_principal_id.as_bytes();
    let stored_revision = to_i64(revision.get())?;
    transaction.execute(
        "INSERT INTO owner_sets(owner_set_id, created_by, created_at, revision)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            owner_set_id.as_slice(),
            actor.as_slice(),
            context.occurred_at.get(),
            stored_revision
        ],
    )?;
    for owner in unique {
        let owner = owner.as_bytes();
        transaction.execute(
            "INSERT INTO object_owners(
                owner_set_id, owner_principal_id, assigned_by, assigned_at, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                owner_set_id.as_slice(),
                owner.as_slice(),
                actor.as_slice(),
                context.occurred_at.get(),
                stored_revision
            ],
        )?;
    }
    Ok(())
}

fn validate_active_principals(
    transaction: &Transaction<'_>,
    principals: &BTreeSet<PrincipalId>,
) -> Result<(), RepositoryError> {
    for principal in principals {
        let identifier = principal.as_bytes();
        let active: i64 = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM principals WHERE principal_id = ?1 AND state = 1
             )",
            [identifier.as_slice()],
            |row| row.get(0),
        )?;
        if active != 1 {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    Ok(())
}

pub(super) fn update_namespace_revision(
    transaction: &Transaction<'_>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let updated = transaction.execute(
        "UPDATE meshes SET namespace_revision = ?1, revision = ?1",
        [to_i64(revision.get())?],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

const fn object_kind(kind: NamespaceObjectKind) -> u8 {
    match kind {
        NamespaceObjectKind::Folder => 1,
        NamespaceObjectKind::File => 2,
    }
}
