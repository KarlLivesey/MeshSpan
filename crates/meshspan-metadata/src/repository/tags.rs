// SPDX-License-Identifier: GPL-2.0-only

//! Descriptive principal/object tags with deliberately no authority semantics.

use meshspan_domain::{Revision, TagId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, CreateTag, TagTarget};

pub(super) fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateTag,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.name.display().chars().count() > 128
        || command.name.canonical().chars().count() > 128
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let tag = command.tag_id.as_bytes();
    transaction.execute(
        "INSERT INTO tags(tag_id, display_name, canonical_name, created_by, created_at, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            tag.as_slice(),
            command.name.display(),
            command.name.canonical(),
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::Tag,
        id: tag,
    })
}

pub(super) fn attach(
    transaction: &Transaction<'_>,
    context: CommandContext,
    tag_id: TagId,
    target: TagTarget,
) -> Result<EntityReference, RepositoryError> {
    verify_tag(transaction, tag_id)?;
    let target_id = target_id(target);
    let tag = tag_id.as_bytes();
    let actor = context.actor_principal_id.as_bytes();
    match target {
        TagTarget::Principal(_) => {
            verify_active(transaction, "principals", "principal_id", &target_id)?;
            ensure_detached(
                transaction,
                "principal_tags",
                "principal_id",
                target_id,
                tag_id,
            )?;
            transaction.execute(
                "INSERT INTO principal_tags(principal_id, tag_id, assigned_by, assigned_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    target_id.as_slice(),
                    tag.as_slice(),
                    actor.as_slice(),
                    context.occurred_at.get(),
                ],
            )?;
        }
        TagTarget::Object(_) => {
            verify_active(transaction, "namespace_objects", "object_id", &target_id)?;
            ensure_detached(transaction, "object_tags", "object_id", target_id, tag_id)?;
            transaction.execute(
                "INSERT INTO object_tags(object_id, tag_id, assigned_by, assigned_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    target_id.as_slice(),
                    tag.as_slice(),
                    actor.as_slice(),
                    context.occurred_at.get(),
                ],
            )?;
        }
    }
    Ok(EntityReference {
        kind: EntityKind::TagAttachment,
        id: target_id,
    })
}

pub(super) fn detach(
    transaction: &Transaction<'_>,
    tag_id: TagId,
    target: TagTarget,
) -> Result<EntityReference, RepositoryError> {
    let target_id = target_id(target);
    let changed = match target {
        TagTarget::Principal(_) => transaction.execute(
            "DELETE FROM principal_tags WHERE principal_id = ?1 AND tag_id = ?2",
            params![target_id.as_slice(), tag_id.as_bytes().as_slice()],
        )?,
        TagTarget::Object(_) => transaction.execute(
            "DELETE FROM object_tags WHERE object_id = ?1 AND tag_id = ?2",
            params![target_id.as_slice(), tag_id.as_bytes().as_slice()],
        )?,
    };
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(EntityReference {
        kind: EntityKind::TagAttachment,
        id: target_id,
    })
}

fn verify_tag(transaction: &Transaction<'_>, tag_id: TagId) -> Result<(), RepositoryError> {
    let exists = transaction
        .query_row(
            "SELECT 1 FROM tags WHERE tag_id = ?1",
            [tag_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if exists == Some(1) {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn verify_active(
    transaction: &Transaction<'_>,
    table: &str,
    identity_column: &str,
    identity: &[u8; 16],
) -> Result<(), RepositoryError> {
    let sql = format!("SELECT 1 FROM {table} WHERE {identity_column} = ?1 AND state = 1");
    let exists = transaction
        .query_row(&sql, [identity.as_slice()], |row| row.get::<_, i64>(0))
        .optional()?;
    if exists == Some(1) {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn ensure_detached(
    transaction: &Transaction<'_>,
    table: &str,
    identity_column: &str,
    identity: [u8; 16],
    tag_id: TagId,
) -> Result<(), RepositoryError> {
    let sql = format!("SELECT 1 FROM {table} WHERE {identity_column} = ?1 AND tag_id = ?2");
    let exists = transaction
        .query_row(
            &sql,
            params![identity.as_slice(), tag_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if exists.is_none() {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

const fn target_id(target: TagTarget) -> [u8; 16] {
    match target {
        TagTarget::Principal(principal_id) => principal_id.as_bytes(),
        TagTarget::Object(object_id) => object_id.as_bytes(),
    }
}
