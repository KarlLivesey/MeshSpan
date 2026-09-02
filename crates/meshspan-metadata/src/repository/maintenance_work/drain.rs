// SPDX-License-Identifier: GPL-2.0-only

//! Atomic admission of one storage-target evacuation.

use meshspan_work::{DrainScope, WorkSubject};
use rusqlite::{Transaction, params};
use sha2::{Digest, Sha256};

use super::{
    entity, entity_exists, load_job_for_transition, queue, require_live_claim, to_i64,
    validate_worker,
};
use crate::repository::{EntityKind, EntityReference, RepositoryError};
use crate::{AttestStorageTargetDrain, BeginStorageTargetDrain, CommandContext};

const ACTIVE_TARGET: i64 = 1;
const DRAINING_TARGET: i64 = 3;
const ACTIVE_GENERATION: i64 = 1;
const DRAIN_EVACUATING: i64 = 1;
const DRAIN_SAFE: i64 = 2;
const PARTICIPANT_PENDING: i64 = 1;
const PARTICIPANT_ATTESTED: i64 = 2;

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
    snapshot_gateways(transaction, value.work.work_id, revision)?;
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

pub(crate) fn attest_target(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: AttestStorageTargetDrain,
    revision: meshspan_domain::Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_worker(transaction, value.worker_node_id, value.worker_incarnation)?;
    require_live_claim(
        transaction,
        context,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    validate_attestation_subject(transaction, value, revision)?;
    let changed = transaction.execute(
        "UPDATE storage_target_drain_participants
         SET state = ?1, attestation_operation_id = ?2, observed_authority_revision = ?3,
             empty_catalogue_digest = ?4, attested_at = ?5, revision = ?6
         WHERE work_id = ?7 AND node_id = ?8 AND node_incarnation = ?9 AND state = ?10",
        params![
            PARTICIPANT_ATTESTED,
            context.operation_id.as_bytes().as_slice(),
            to_i64(value.observed_authority_revision.get())?,
            value.empty_catalogue_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
            value.work_id.as_bytes().as_slice(),
            value.worker_node_id.as_bytes().as_slice(),
            to_i64(value.worker_incarnation)?,
            PARTICIPANT_PENDING,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    finish_if_fully_attested(transaction, context, value, revision)?;
    Ok(entity(value.work_id))
}

fn validate_attestation_subject(
    transaction: &Transaction<'_>,
    value: AttestStorageTargetDrain,
    revision: meshspan_domain::Revision,
) -> Result<(), RepositoryError> {
    if value.observed_authority_revision == meshspan_domain::Revision::ZERO
        || value.observed_authority_revision >= revision
        || value.empty_catalogue_digest
            != empty_target_drain_catalogue_digest(
                value.target_id,
                value.target_generation,
                value.observed_authority_revision,
            )
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let WorkSubject::Drain(DrainScope::Target {
        target_id,
        target_generation,
    }) = load_job_for_transition(transaction, value.work_id)?.subject
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    let drain_revision = transaction
        .query_row(
            "SELECT revision FROM storage_target_drains
             WHERE work_id = ?1 AND target_id = ?2 AND target_generation = ?3 AND state = ?4",
            params![
                value.work_id.as_bytes().as_slice(),
                value.target_id.as_bytes().as_slice(),
                to_i64(value.target_generation)?,
                DRAIN_EVACUATING,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RepositoryError::InvalidCommand,
            other => RepositoryError::Sqlite(other),
        })?;
    if target_id == value.target_id
        && target_generation == value.target_generation
        && value.observed_authority_revision.get()
            >= u64::try_from(drain_revision).map_err(|_| RepositoryError::CorruptState)?
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn finish_if_fully_attested(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: AttestStorageTargetDrain,
    revision: meshspan_domain::Revision,
) -> Result<(), RepositoryError> {
    let counts = transaction.query_row(
        "SELECT count(*), sum(state = ?1)
         FROM storage_target_drain_participants WHERE work_id = ?2",
        params![PARTICIPANT_ATTESTED, value.work_id.as_bytes().as_slice()],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    if counts.0 <= 0 || counts.1 < 0 || counts.1 > counts.0 {
        return Err(RepositoryError::CorruptState);
    }
    if counts.0 != counts.1 {
        return Ok(());
    }
    let evidence_digest = complete_attestation_digest(transaction, value.work_id)?;
    let changed = transaction.execute(
        "UPDATE storage_target_drains
         SET state = ?1, safe_at = ?2, safety_evidence_digest = ?3, revision = ?4
         WHERE work_id = ?5 AND state = ?6 AND safe_at IS NULL
           AND safety_evidence_digest IS NULL",
        params![
            DRAIN_SAFE,
            context.occurred_at.get(),
            evidence_digest.as_slice(),
            to_i64(revision.get())?,
            value.work_id.as_bytes().as_slice(),
            DRAIN_EVACUATING,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::CorruptState);
    }
    transaction.execute(
        "INSERT INTO storage_target_drain_effects(
            effect_operation_id, work_id, participant_count, safety_evidence_digest,
            committed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            context.operation_id.as_bytes().as_slice(),
            value.work_id.as_bytes().as_slice(),
            counts.0,
            evidence_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn complete_attestation_digest(
    transaction: &Transaction<'_>,
    work_id: meshspan_domain::WorkId,
) -> Result<[u8; 32], RepositoryError> {
    let mut statement = transaction.prepare(
        "SELECT node_id, node_incarnation, observed_authority_revision, empty_catalogue_digest
         FROM storage_target_drain_participants
         WHERE work_id = ?1 AND state = ?2 ORDER BY node_id",
    )?;
    let rows = statement.query_map(
        params![work_id.as_bytes().as_slice(), PARTICIPANT_ATTESTED],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        },
    )?;
    let mut digest = Sha256::new();
    digest.update(b"meshspan.storage-target-drain.complete.v1\0");
    digest.update(work_id.as_bytes());
    for row in rows {
        let (node_id, incarnation, observed_revision, empty_digest) = row?;
        if node_id.len() != 16
            || empty_digest.len() != 32
            || incarnation <= 0
            || observed_revision <= 0
        {
            return Err(RepositoryError::CorruptState);
        }
        digest.update(node_id);
        digest.update(incarnation.to_be_bytes());
        digest.update(observed_revision.to_be_bytes());
        digest.update(empty_digest);
    }
    Ok(digest.finalize().into())
}

/// Canonical proof identity for an empty current-route scan on one target generation.
#[must_use]
pub fn empty_target_drain_catalogue_digest(
    target_id: meshspan_domain::TargetId,
    target_generation: u64,
    observed_authority_revision: meshspan_domain::Revision,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.storage-target-drain.empty-catalogue.v1\0");
    digest.update(target_id.as_bytes());
    digest.update(target_generation.to_be_bytes());
    digest.update(observed_authority_revision.get().to_be_bytes());
    digest.finalize().into()
}

fn snapshot_gateways(
    transaction: &Transaction<'_>,
    work_id: meshspan_domain::WorkId,
    revision: meshspan_domain::Revision,
) -> Result<(), RepositoryError> {
    let inserted = transaction.execute(
        "INSERT INTO storage_target_drain_participants(
            work_id, node_id, node_incarnation, state, attestation_operation_id,
            observed_authority_revision, empty_catalogue_digest, attested_at, revision
         )
         SELECT ?1, node.node_id, node.current_incarnation, 1, NULL, NULL, NULL, NULL, ?2
         FROM nodes node
         WHERE node.state IN (1, 2) AND (
             EXISTS(
                 SELECT 1 FROM node_roles role
                 WHERE role.node_id = node.node_id AND role.role_code = 2
             )
             OR (
                 NOT EXISTS(SELECT 1 FROM node_roles role WHERE role.node_id = node.node_id)
                 AND EXISTS(
                     SELECT 1 FROM partition_voters voter
                     WHERE voter.node_id = node.node_id AND voter.state IN (1, 2)
                 )
             )
         )",
        params![work_id.as_bytes().as_slice(), to_i64(revision.get())?,],
    )?;
    if inserted == 0 {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
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
