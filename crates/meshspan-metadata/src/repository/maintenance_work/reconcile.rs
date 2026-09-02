// SPDX-License-Identifier: GPL-2.0-only

//! Immutable completion evidence for returning-target inventory reconciliation.

use meshspan_work::WorkSubject;
use rusqlite::{Transaction, params};

use super::{
    current_generation, entity, load_job_for_transition, require_live_claim, to_i64,
    validate_worker,
};
use crate::repository::{EntityReference, RepositoryError};
use crate::{CommandContext, CommitTargetReconciliation};

pub(super) fn commit(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: CommitTargetReconciliation,
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
    validate_subject(transaction, value)?;
    if transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM maintenance_reconciliation_effects WHERE work_id = ?1)",
        [value.work_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )? != 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO maintenance_reconciliation_effects(
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
    Ok(entity(value.work_id))
}

fn validate_subject(
    transaction: &Transaction<'_>,
    value: CommitTargetReconciliation,
) -> Result<(), RepositoryError> {
    let WorkSubject::Reconcile {
        target_id,
        target_generation,
    } = load_job_for_transition(transaction, value.work_id)?.subject
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    let classified = [
        value.healthy_count,
        value.missing_count,
        value.corrupt_count,
        value.unreadable_count,
        value.unexpected_count,
        value.deferred_count,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add);
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
