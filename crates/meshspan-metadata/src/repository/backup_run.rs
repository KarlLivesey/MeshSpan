// SPDX-License-Identifier: GPL-2.0-only

//! Fenced execution and honest terminal state for automatic metadata backups.

mod query;
mod transition;

use meshspan_domain::{BackupId, PartitionId, Revision, UnixMicros};
use rusqlite::{Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError, acme};
use crate::{
    ClaimMetadataBackupRun, CommandContext, CompleteMetadataBackupRun, MetadataBackupRunClaim,
    MetadataBackupRunCompletion, RecordMetadataBackup, RenewMetadataBackupRun,
};
use query::{active_claim, latest_claim_generation, require_live_claim, run_head};
use transition::{
    advance_schedule, completion_digest, exactly_one, finish_incomplete_claim,
    mark_backup_incomplete, mark_backup_verified, supersede, update_run_revision, update_run_state,
};

const RUN_QUEUED: i64 = 1;
const RUN_CLAIMED: i64 = 2;
const RUN_RECORDED: i64 = 3;
const RUN_PROTECTED: i64 = 4;
const RUN_INCOMPLETE: i64 = 5;
const CLAIM_ACTIVE: i64 = 1;
const CLAIM_SUPERSEDED: i64 = 2;
const CLAIM_COMPLETE: i64 = 3;
const MAXIMUM_CLAIM_MICROS: i64 = 30 * 60 * 1_000_000;

/// Durable lifecycle of one automatic metadata-backup occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataBackupRunState {
    /// Due work exists but has no active worker.
    Queued,
    /// One exact node incarnation owns a live production lease.
    Claimed,
    /// Encrypted bytes and their first provider receipt are authoritative.
    Recorded,
    /// The configured verified/independent-copy thresholds were met.
    Protected,
    /// The occurrence terminated without meeting its configured thresholds.
    Incomplete,
}

/// Current durable state of one automatic metadata-backup occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataBackupRun {
    /// Stable generation identity.
    pub backup_id: BackupId,
    /// Source partition.
    pub partition_id: PartitionId,
    /// Exact schedule policy selected for the run.
    pub schedule_sequence: u64,
    /// Monotonic occurrence number within the partition.
    pub run_sequence: u64,
    /// Exact occurrence instant.
    pub scheduled_for: UnixMicros,
    /// Required verified-copy count captured at queue time.
    pub minimum_verified_copies: u8,
    /// Required independent verified-copy count captured at queue time.
    pub minimum_independent_copies: u8,
    /// Current authoritative lifecycle.
    pub state: MetadataBackupRunState,
    /// Terminal instant, when complete.
    pub completed_at: Option<UnixMicros>,
    /// Terminal evidence digest, when complete.
    pub result_digest: Option<[u8; 32]>,
    /// Latest authoritative revision affecting the run.
    pub revision: Revision,
}

/// Current live claim over one backup occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataBackupRunClaimRecord {
    /// Claimed generation.
    pub backup_id: BackupId,
    /// Exact worker authority.
    pub claim: MetadataBackupRunClaim,
    /// Authority-agreed lease end.
    pub lease_expires_at: UnixMicros,
    /// Latest authoritative revision affecting the claim.
    pub revision: Revision,
}

/// Canonical evidence for the currently usable verified-copy set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataBackupProtectionEvidence {
    /// Backup generation whose copies were evaluated.
    pub backup_id: BackupId,
    /// Verified copies using each destination's current provider generation.
    pub verified_copies: u64,
    /// Verified copies whose destination declares independent failure boundaries.
    pub independent_copies: u64,
    /// Domain-separated digest of the complete ordered evidence set.
    pub digest: [u8; 32],
}

pub(super) fn claim(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: ClaimMetadataBackupRun,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_lease(context.occurred_at, command.lease_expires_at)?;
    acme::validate_worker(
        transaction,
        command.claim.worker_node_id,
        command.claim.worker_incarnation,
    )?;
    let run = run_head(transaction, command.backup_id)?;
    let active = active_claim(transaction, command.backup_id)?;
    match (run.state, active) {
        (RUN_QUEUED, None) => {}
        (RUN_CLAIMED, Some(current)) if current.lease_expires_at <= context.occurred_at => {
            supersede(transaction, context, command.backup_id, current, revision)?;
        }
        _ => return Err(RepositoryError::InvalidCommand),
    }
    let next_generation = latest_claim_generation(transaction, command.backup_id)?
        .checked_add(1)
        .ok_or(RepositoryError::CapacityExceeded)?;
    if command.claim.claim_generation != next_generation
        || command.claim.worker_incarnation == 0
        || command.claim.fence == 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO metadata_backup_run_claims(
            backup_id, claim_generation, worker_node_id, worker_incarnation, fence,
            claimed_at, lease_expires_at, state, finished_at, result_digest, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, ?9)",
        params![
            command.backup_id.as_bytes().as_slice(),
            to_i64(command.claim.claim_generation)?,
            command.claim.worker_node_id.as_bytes().as_slice(),
            to_i64(command.claim.worker_incarnation)?,
            to_i64(command.claim.fence)?,
            context.occurred_at.get(),
            command.lease_expires_at.get(),
            CLAIM_ACTIVE,
            to_i64(revision.get())?,
        ],
    )?;
    update_run_state(
        transaction,
        command.backup_id,
        &[RUN_QUEUED, RUN_CLAIMED],
        RUN_CLAIMED,
        revision,
    )?;
    Ok(run_entity(command.backup_id))
}

pub(super) fn renew(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RenewMetadataBackupRun,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_lease(context.occurred_at, command.lease_expires_at)?;
    acme::validate_worker(
        transaction,
        command.claim.worker_node_id,
        command.claim.worker_incarnation,
    )?;
    let current = require_live_claim(transaction, context, command.backup_id, command.claim)?;
    if command.lease_expires_at <= current.lease_expires_at {
        return Err(RepositoryError::InvalidCommand);
    }
    let changed = transaction.execute(
        "UPDATE metadata_backup_run_claims SET lease_expires_at = ?1, revision = ?2
         WHERE backup_id = ?3 AND claim_generation = ?4 AND state = ?5",
        params![
            command.lease_expires_at.get(),
            to_i64(revision.get())?,
            command.backup_id.as_bytes().as_slice(),
            to_i64(command.claim.claim_generation)?,
            CLAIM_ACTIVE,
        ],
    )?;
    exactly_one(changed)?;
    update_run_revision(transaction, command.backup_id, revision)?;
    Ok(run_entity(command.backup_id))
}

pub(super) fn validate_admission(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RecordMetadataBackup,
) -> Result<(), RepositoryError> {
    let run = run_head(transaction, command.backup_id)?;
    if run.state != RUN_CLAIMED || run.partition_id != command.partition_id {
        return Err(RepositoryError::InvalidCommand);
    }
    require_live_claim(transaction, context, command.backup_id, command.claim).map(|_| ())
}

pub(super) fn mark_admitted(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RecordMetadataBackup,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let changed = transaction.execute(
        "UPDATE metadata_backup_run_claims
         SET state = ?1, finished_at = ?2, result_digest = ?3, revision = ?4
         WHERE backup_id = ?5 AND claim_generation = ?6 AND state = ?7",
        params![
            CLAIM_COMPLETE,
            context.occurred_at.get(),
            command.encrypted_digest.as_slice(),
            to_i64(revision.get())?,
            command.backup_id.as_bytes().as_slice(),
            to_i64(command.claim.claim_generation)?,
            CLAIM_ACTIVE,
        ],
    )?;
    exactly_one(changed)?;
    update_run_state(
        transaction,
        command.backup_id,
        &[RUN_CLAIMED],
        RUN_RECORDED,
        revision,
    )
}

pub(super) fn complete(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: CompleteMetadataBackupRun,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let run = run_head(transaction, command.backup_id)?;
    let evidence = query::protection_evidence(transaction, command.backup_id)?;
    if completion_digest(command.outcome) != evidence.digest {
        return Err(RepositoryError::InvalidCommand);
    }
    let protected = evidence.verified_copies >= u64::from(run.minimum_verified_copies)
        && evidence.independent_copies >= u64::from(run.minimum_independent_copies);
    let terminal_state = match command.outcome {
        MetadataBackupRunCompletion::Protected { .. } if run.state == RUN_RECORDED && protected => {
            mark_backup_verified(transaction, context, command.backup_id, revision)?;
            RUN_PROTECTED
        }
        MetadataBackupRunCompletion::Incomplete { .. }
            if matches!(run.state, RUN_QUEUED | RUN_CLAIMED | RUN_RECORDED) && !protected =>
        {
            finish_incomplete_claim(transaction, context, command.backup_id, revision)?;
            mark_backup_incomplete(
                transaction,
                context,
                command.backup_id,
                evidence.verified_copies,
                revision,
            )?;
            RUN_INCOMPLETE
        }
        _ => return Err(RepositoryError::InvalidCommand),
    };
    let result_digest = completion_digest(command.outcome);
    let changed = transaction.execute(
        "UPDATE metadata_backup_runs
         SET state = ?1, completed_at = ?2, result_digest = ?3, revision = ?4
         WHERE backup_id = ?5 AND state = ?6",
        params![
            terminal_state,
            context.occurred_at.get(),
            result_digest.as_slice(),
            to_i64(revision.get())?,
            command.backup_id.as_bytes().as_slice(),
            run.state,
        ],
    )?;
    exactly_one(changed)?;
    advance_schedule(transaction, context, run.partition_id, revision)?;
    Ok(run_entity(command.backup_id))
}

pub(super) fn load(
    connection: &rusqlite::Connection,
    backup_id: BackupId,
) -> Result<Option<MetadataBackupRun>, RepositoryError> {
    query::load(connection, backup_id)
}

pub(super) fn live_claim(
    connection: &rusqlite::Connection,
    backup_id: BackupId,
) -> Result<Option<MetadataBackupRunClaimRecord>, RepositoryError> {
    query::live_claim(connection, backup_id)
}

pub(super) fn unfinished(
    connection: &rusqlite::Connection,
    partition_id: PartitionId,
) -> Result<Option<MetadataBackupRun>, RepositoryError> {
    query::unfinished(connection, partition_id)
}

pub(super) fn protection_evidence(
    connection: &rusqlite::Connection,
    backup_id: BackupId,
) -> Result<MetadataBackupProtectionEvidence, RepositoryError> {
    query::protection_evidence(connection, backup_id)
}

fn validate_lease(now: UnixMicros, expires_at: UnixMicros) -> Result<(), RepositoryError> {
    let lifetime = expires_at
        .get()
        .checked_sub(now.get())
        .ok_or(RepositoryError::InvalidCommand)?;
    if now.get() < 0 || lifetime == 0 || lifetime > MAXIMUM_CLAIM_MICROS {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn run_entity(backup_id: BackupId) -> EntityReference {
    EntityReference {
        kind: EntityKind::MetadataBackupRun,
        id: backup_id.as_bytes(),
    }
}
