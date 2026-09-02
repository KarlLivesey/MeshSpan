// SPDX-License-Identifier: GPL-2.0-only

//! Immutable summaries for complete, fenced storage-target scrub passes.

use meshspan_domain::{OperationId, Revision, TargetId, UnixMicros, WorkId};
use meshspan_work::WorkSubject;
use rusqlite::{OptionalExtension, Transaction, params};

use super::{
    current_generation, entity, load_job_for_transition, nonnegative, positive, require_live_claim,
    to_i64, validate_worker,
};
use crate::repository::{EntityReference, RepositoryError};
use crate::{CommandContext, CommitScrubPass};

/// Authoritative evidence that one complete target-generation scrub pass finished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrubPassEffectRecord {
    /// Committed effect operation linked by work completion.
    pub effect_operation_id: OperationId,
    /// Claimed scrub job that authorised this pass.
    pub work_id: WorkId,
    /// Exact storage target inspected.
    pub target_id: TargetId,
    /// Exact target generation inspected.
    pub target_generation: u64,
    /// Total classified observations.
    pub observation_count: u64,
    /// Bytes independently read and digested.
    pub verified_bytes: u64,
    /// Exact outcome totals ordered as healthy, missing, corrupt, unreadable, unexpected, deferred.
    pub outcome_counts: [u64; 6],
    /// Canonical digest over the complete ordered evidence stream.
    pub evidence_digest: [u8; 32],
    /// Authoritative commit instant.
    pub committed_at: UnixMicros,
    /// Authoritative effect revision.
    pub revision: Revision,
}

pub(super) fn commit(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: CommitScrubPass,
    revision: Revision,
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
    validate_subject(transaction, value)?;
    insert_effect(transaction, context, value, revision)?;
    Ok(entity(value.work_id))
}

fn validate_subject(
    transaction: &Transaction<'_>,
    value: CommitScrubPass,
) -> Result<(), RepositoryError> {
    let WorkSubject::Scrub {
        target_id,
        target_generation,
    } = load_job_for_transition(transaction, value.work_id)?.subject
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    let classified = value
        .healthy_count
        .checked_add(value.missing_count)
        .and_then(|count| count.checked_add(value.corrupt_count))
        .and_then(|count| count.checked_add(value.unreadable_count))
        .and_then(|count| count.checked_add(value.unexpected_count))
        .and_then(|count| count.checked_add(value.deferred_count));
    if target_id != value.target_id
        || target_generation != value.target_generation
        || classified != Some(value.observation_count)
        || value.evidence_digest == [0; 32]
        || !current_generation(
            transaction,
            "storage_targets",
            "target_id",
            "current_generation",
            value.target_id.as_bytes(),
            value.target_generation,
        )?
    {
        return Err(RepositoryError::InvalidCommand);
    }
    for count in [
        value.observation_count,
        value.verified_bytes,
        value.healthy_count,
        value.missing_count,
        value.corrupt_count,
        value.unreadable_count,
        value.unexpected_count,
        value.deferred_count,
    ] {
        to_i64(count)?;
    }
    Ok(())
}

fn insert_effect(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: CommitScrubPass,
    revision: Revision,
) -> Result<(), RepositoryError> {
    if transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM maintenance_scrub_effects WHERE work_id = ?1)",
        [value.work_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )? != 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO maintenance_scrub_effects(
            effect_operation_id, work_id, claim_generation, worker_node_id, worker_incarnation,
            fence, target_id, target_generation, observation_count, verified_bytes,
            healthy_count, missing_count, corrupt_count, unreadable_count, unexpected_count,
            deferred_count, evidence_digest, committed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                   ?15, ?16, ?17, ?18, ?19)",
        params![
            context.operation_id.as_bytes().as_slice(),
            value.work_id.as_bytes().as_slice(),
            to_i64(value.claim_generation)?,
            value.worker_node_id.as_bytes().as_slice(),
            to_i64(value.worker_incarnation)?,
            to_i64(value.fence)?,
            value.target_id.as_bytes().as_slice(),
            to_i64(value.target_generation)?,
            to_i64(value.observation_count)?,
            to_i64(value.verified_bytes)?,
            to_i64(value.healthy_count)?,
            to_i64(value.missing_count)?,
            to_i64(value.corrupt_count)?,
            to_i64(value.unreadable_count)?,
            to_i64(value.unexpected_count)?,
            to_i64(value.deferred_count)?,
            value.evidence_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

pub(super) fn load(
    connection: &rusqlite::Connection,
    effect_operation_id: OperationId,
) -> Result<Option<ScrubPassEffectRecord>, RepositoryError> {
    connection
        .query_row(
            "SELECT work_id, target_id, target_generation, observation_count, verified_bytes,
                    healthy_count, missing_count, corrupt_count, unreadable_count,
                    unexpected_count, deferred_count, evidence_digest, committed_at, revision
             FROM maintenance_scrub_effects WHERE effect_operation_id = ?1",
            [effect_operation_id.as_bytes().as_slice()],
            |row| {
                Ok(ScrubPassEffectRecord {
                    effect_operation_id,
                    work_id: WorkId::from_bytes(exact_sql(row.get(0)?)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    target_id: TargetId::from_bytes(exact_sql(row.get(1)?)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    target_generation: positive_sql(row.get(2)?)?,
                    observation_count: nonnegative_sql(row.get(3)?)?,
                    verified_bytes: nonnegative_sql(row.get(4)?)?,
                    outcome_counts: [
                        nonnegative_sql(row.get(5)?)?,
                        nonnegative_sql(row.get(6)?)?,
                        nonnegative_sql(row.get(7)?)?,
                        nonnegative_sql(row.get(8)?)?,
                        nonnegative_sql(row.get(9)?)?,
                        nonnegative_sql(row.get(10)?)?,
                    ],
                    evidence_digest: exact_sql(row.get(11)?)?,
                    committed_at: UnixMicros::new(row.get(12)?),
                    revision: Revision::new(positive_sql(row.get(13)?)?),
                })
            },
        )
        .optional()?
        .map(validate_record)
        .transpose()
}

fn validate_record(value: ScrubPassEffectRecord) -> Result<ScrubPassEffectRecord, RepositoryError> {
    let classified = value
        .outcome_counts
        .into_iter()
        .try_fold(0_u64, u64::checked_add);
    if classified == Some(value.observation_count) && value.evidence_digest != [0; 32] {
        Ok(value)
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn exact_sql<const LENGTH: usize>(value: Vec<u8>) -> rusqlite::Result<[u8; LENGTH]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn positive_sql(value: i64) -> rusqlite::Result<u64> {
    positive(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn nonnegative_sql(value: i64) -> rusqlite::Result<u64> {
    nonnegative(value).map_err(|_| rusqlite::Error::InvalidQuery)
}
