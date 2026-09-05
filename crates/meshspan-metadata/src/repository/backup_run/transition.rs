// SPDX-License-Identifier: GPL-2.0-only

//! Atomic state transitions for metadata-backup runs and their schedules.

use meshspan_domain::{BackupId, PartitionId, Revision};
use rusqlite::{Transaction, params};
use sha2::{Digest, Sha256};

use super::query::{active_claim, run_head};
use super::{CLAIM_ACTIVE, CLAIM_SUPERSEDED, MetadataBackupRunClaimRecord, RUN_CLAIMED};
use crate::repository::RepositoryError;
use crate::repository::apply::to_i64;
use crate::{CommandContext, MetadataBackupRunCompletion};

pub(super) fn supersede(
    transaction: &Transaction<'_>,
    context: CommandContext,
    backup_id: BackupId,
    claim: MetadataBackupRunClaimRecord,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let digest = superseded_digest(claim);
    let changed = transaction.execute(
        "UPDATE metadata_backup_run_claims
         SET state = ?1, finished_at = ?2, result_digest = ?3, revision = ?4
         WHERE backup_id = ?5 AND claim_generation = ?6 AND state = ?7",
        params![
            CLAIM_SUPERSEDED,
            context.occurred_at.get(),
            digest.as_slice(),
            to_i64(revision.get())?,
            backup_id.as_bytes().as_slice(),
            to_i64(claim.claim.claim_generation)?,
            CLAIM_ACTIVE,
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn finish_incomplete_claim(
    transaction: &Transaction<'_>,
    context: CommandContext,
    backup_id: BackupId,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let Some(claim) = active_claim(transaction, backup_id)? else {
        return Ok(());
    };
    if claim.lease_expires_at > context.occurred_at {
        return Err(RepositoryError::InvalidCommand);
    }
    supersede(transaction, context, backup_id, claim, revision)
}

pub(super) fn finish_protected_claim(
    transaction: &Transaction<'_>,
    context: CommandContext,
    backup_id: BackupId,
    result_digest: [u8; 32],
    revision: Revision,
) -> Result<(), RepositoryError> {
    let claim = active_claim(transaction, backup_id)?.ok_or(RepositoryError::InvalidCommand)?;
    let changed = transaction.execute(
        "UPDATE metadata_backup_run_claims
         SET state = ?1, finished_at = ?2, result_digest = ?3, revision = ?4
         WHERE backup_id = ?5 AND claim_generation = ?6 AND state = ?7",
        params![
            super::CLAIM_COMPLETE,
            context.occurred_at.get(),
            result_digest.as_slice(),
            to_i64(revision.get())?,
            backup_id.as_bytes().as_slice(),
            to_i64(claim.claim.claim_generation)?,
            CLAIM_ACTIVE,
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn mark_backup_verified(
    transaction: &Transaction<'_>,
    context: CommandContext,
    backup_id: BackupId,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let changed = transaction.execute(
        "UPDATE metadata_backups
         SET state = 2, verified_at = COALESCE(verified_at, ?1), revision = ?2
         WHERE backup_id = ?3 AND state IN (1, 2)",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            backup_id.as_bytes().as_slice(),
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn mark_backup_incomplete(
    transaction: &Transaction<'_>,
    context: CommandContext,
    backup_id: BackupId,
    verified_copies: u64,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata_backups WHERE backup_id = ?1)",
        [backup_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Ok(());
    }
    let (state, verified_at) = if verified_copies == 0 {
        // An unsuccessful verification is not deletion authority. Keep the
        // admitted bytes until retention atomically retires the generation and
        // every copy against sufficient newer protected generations.
        (1, None)
    } else {
        (2, Some(context.occurred_at.get()))
    };
    let changed = transaction.execute(
        "UPDATE metadata_backups
         SET state = ?1, verified_at = COALESCE(verified_at, ?2), revision = ?3
         WHERE backup_id = ?4 AND state IN (1, 2)",
        params![
            state,
            verified_at,
            to_i64(revision.get())?,
            backup_id.as_bytes().as_slice(),
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn advance_schedule(
    transaction: &Transaction<'_>,
    context: CommandContext,
    partition_id: PartitionId,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let interval = transaction.query_row(
        "SELECT interval_micros FROM metadata_backup_schedule_heads WHERE partition_id = ?1",
        [partition_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )?;
    let next_due = context
        .occurred_at
        .get()
        .checked_add(interval)
        .ok_or(RepositoryError::CapacityExceeded)?;
    let changed = transaction.execute(
        "UPDATE metadata_backup_schedule_heads SET next_due_at = ?1, revision = ?2
         WHERE partition_id = ?3",
        params![
            next_due,
            to_i64(revision.get())?,
            partition_id.as_bytes().as_slice(),
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn update_run_state(
    transaction: &Transaction<'_>,
    backup_id: BackupId,
    current_states: &[i64],
    next_state: i64,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let current = run_head(transaction, backup_id)?;
    if !current_states.contains(&current.state) {
        return Err(RepositoryError::InvalidCommand);
    }
    let changed = transaction.execute(
        "UPDATE metadata_backup_runs SET state = ?1, revision = ?2
         WHERE backup_id = ?3 AND state = ?4",
        params![
            next_state,
            to_i64(revision.get())?,
            backup_id.as_bytes().as_slice(),
            current.state,
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn update_run_revision(
    transaction: &Transaction<'_>,
    backup_id: BackupId,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let changed = transaction.execute(
        "UPDATE metadata_backup_runs SET revision = ?1
         WHERE backup_id = ?2 AND state IN (?3, ?4)",
        params![
            to_i64(revision.get())?,
            backup_id.as_bytes().as_slice(),
            RUN_CLAIMED,
            super::RUN_RECORDED,
        ],
    )?;
    exactly_one(changed)
}

pub(super) fn completion_digest(value: MetadataBackupRunCompletion) -> [u8; 32] {
    match value {
        MetadataBackupRunCompletion::Protected { result_digest }
        | MetadataBackupRunCompletion::Incomplete { result_digest } => result_digest,
    }
}

pub(super) fn exactly_one(changed: usize) -> Result<(), RepositoryError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn superseded_digest(value: MetadataBackupRunClaimRecord) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.metadata-backup-claim-superseded.v1\0");
    digest.update(value.backup_id.as_bytes());
    digest.update(value.claim.claim_generation.to_be_bytes());
    digest.update(value.claim.worker_node_id.as_bytes());
    digest.update(value.claim.worker_incarnation.to_be_bytes());
    digest.update(value.claim.fence.to_be_bytes());
    digest.update(value.lease_expires_at.get().to_be_bytes());
    digest.finalize().into()
}
