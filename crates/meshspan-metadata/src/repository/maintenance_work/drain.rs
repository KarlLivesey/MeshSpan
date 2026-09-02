// SPDX-License-Identifier: GPL-2.0-only

//! Atomic admission of one storage-target evacuation.

use meshspan_work::{DrainScope, WorkSubject};
use rusqlite::{Transaction, params};

use super::{entity_exists, queue, to_i64};
use crate::repository::{EntityKind, EntityReference, RepositoryError};
use crate::{BeginStorageTargetDrain, CommandContext};

const ACTIVE_TARGET: i64 = 1;
const DRAINING_TARGET: i64 = 3;
const ACTIVE_GENERATION: i64 = 1;
const DRAIN_EVACUATING: i64 = 1;

pub(crate) fn begin_target(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: BeginStorageTargetDrain,
    revision: meshspan_domain::Revision,
) -> Result<EntityReference, RepositoryError> {
    let WorkSubject::Drain(DrainScope::Target {
        target_id,
        target_generation,
    }) = value.work.subject
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    if !target_is_writable_generation(transaction, target_id, target_generation)? {
        return Err(RepositoryError::InvalidCommand);
    }
    queue(transaction, context, value.work, revision)?;
    transaction.execute(
        "INSERT INTO storage_target_drains(
            work_id, target_id, target_generation, allow_temporary_degraded, cleanup_requested,
            state, requested_by, requested_at, safe_at, completed_at, safety_evidence_digest,
            revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, NULL, ?9)",
        params![
            value.work.work_id.as_bytes().as_slice(),
            target_id.as_bytes().as_slice(),
            to_i64(target_generation)?,
            i64::from(value.allow_temporary_degraded),
            i64::from(value.cleanup_requested),
            DRAIN_EVACUATING,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE storage_targets
         SET state = ?1, draining_at = ?2, revision = ?3
         WHERE target_id = ?4 AND current_generation = ?5 AND state = ?6
           AND draining_at IS NULL AND retired_at IS NULL",
        params![
            DRAINING_TARGET,
            context.occurred_at.get(),
            to_i64(revision.get())?,
            target_id.as_bytes().as_slice(),
            to_i64(target_generation)?,
            ACTIVE_TARGET,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    let mesh_changed = transaction.execute(
        "UPDATE meshes SET configuration_revision = ?1, revision = ?1",
        [to_i64(revision.get())?],
    )?;
    if mesh_changed != 1 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(EntityReference {
        kind: EntityKind::StorageTarget,
        id: target_id.as_bytes(),
    })
}

fn target_is_writable_generation(
    transaction: &Transaction<'_>,
    target_id: meshspan_domain::TargetId,
    generation: u64,
) -> Result<bool, RepositoryError> {
    if !entity_exists(
        transaction,
        "storage_targets",
        "target_id",
        target_id.as_bytes(),
        Some("state = 1 AND draining_at IS NULL AND retired_at IS NULL"),
    )? {
        return Ok(false);
    }
    Ok(transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM target_generations
            WHERE target_id = ?1 AND generation = ?2 AND state = ?3 AND retired_at IS NULL
         )",
        params![
            target_id.as_bytes().as_slice(),
            to_i64(generation)?,
            ACTIVE_GENERATION,
        ],
        |row| row.get::<_, i64>(0),
    )? == 1)
}
