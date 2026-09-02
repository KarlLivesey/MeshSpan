// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative restart-safe progress for one bounded volume rebalance scan.

use meshspan_domain::{OperationId, Revision, VolumeId, WorkId};
use meshspan_work::WorkSubject;
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::{entity, load_job_for_transition, require_live_claim, to_i64, validate_worker};
use crate::repository::RepositoryError;
use crate::{CommandContext, CommitRebalanceScanPage, RebalanceScanCursor};

const SCAN_ACTIVE: i64 = 1;
const SCAN_COMPLETE: i64 = 2;

/// Exact durable progress of one volume rebalance scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RebalanceScanProgress {
    /// Rebalance job being scanned.
    pub work_id: WorkId,
    /// Volume bound into the job.
    pub volume_id: VolumeId,
    /// Configuration revision evaluated by the job.
    pub topology_revision: Revision,
    /// Last committed keyset position, if another page remains.
    pub cursor: Option<RebalanceScanCursor>,
    /// Total complete stripes examined.
    pub scanned_stripes: u64,
    /// Total strict improvements admitted to repair.
    pub queued_repairs: u64,
    /// Newer configuration which made this scan obsolete.
    pub superseded_by_revision: Option<Revision>,
    /// Chained digest of every committed scan page.
    pub evidence_digest: [u8; 32],
    /// Whether a terminal effect has been committed.
    pub complete: bool,
    /// Latest authoritative revision of the scan.
    pub revision: Revision,
}

pub(crate) fn commit_page(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: CommitRebalanceScanPage,
    revision: Revision,
) -> Result<crate::repository::EntityReference, RepositoryError> {
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
    let previous = load(transaction, value.work_id)?;
    validate_progression(previous, value)?;
    let scanned_stripes = previous.map_or(0, |progress| progress.scanned_stripes);
    let queued_repairs = previous.map_or(0, |progress| progress.queued_repairs);
    let scanned_stripes = scanned_stripes
        .checked_add(u64::from(value.scanned_stripes))
        .ok_or(RepositoryError::CapacityExceeded)?;
    let queued_repairs = queued_repairs
        .checked_add(u64::from(value.queued_repairs))
        .ok_or(RepositoryError::CapacityExceeded)?;
    let evidence_digest = scan_evidence_digest(previous, value);
    persist_progress(
        transaction,
        context,
        value,
        revision,
        scanned_stripes,
        queued_repairs,
        evidence_digest,
    )?;
    Ok(entity(value.work_id))
}

pub(super) fn load(
    connection: &rusqlite::Connection,
    work_id: WorkId,
) -> Result<Option<RebalanceScanProgress>, RepositoryError> {
    let stored = connection
        .query_row(
            "SELECT volume_id, topology_revision, cursor_publication_operation_id,
                    cursor_stripe_index, scanned_stripes, queued_repairs,
                    superseded_by_revision, evidence_digest, state, revision
             FROM maintenance_rebalance_scans WHERE work_id = ?1",
            [work_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(|stored| decode_progress(work_id, stored))
        .transpose()
}

type StoredProgress = (
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Option<i64>,
    i64,
    i64,
    Option<i64>,
    Vec<u8>,
    i64,
    i64,
);

fn decode_progress(
    work_id: WorkId,
    stored: StoredProgress,
) -> Result<RebalanceScanProgress, RepositoryError> {
    let cursor = match (stored.2, stored.3) {
        (Some(operation), Some(stripe_index)) => Some(RebalanceScanCursor {
            publication_operation_id: OperationId::from_bytes(exact(operation)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            stripe_index: nonnegative(stripe_index)?,
        }),
        (None, None) => None,
        _ => return Err(RepositoryError::CorruptState),
    };
    let topology_revision = positive_revision(stored.1)?;
    let superseded_by_revision = stored.6.map(positive_revision).transpose()?;
    let complete = match stored.8 {
        SCAN_ACTIVE => false,
        SCAN_COMPLETE => true,
        _ => return Err(RepositoryError::CorruptState),
    };
    if superseded_by_revision
        .is_some_and(|superseded| !complete || superseded <= topology_revision || cursor.is_some())
        || (!complete && cursor.is_none())
        || stored.7 == vec![0; 32]
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(RebalanceScanProgress {
        work_id,
        volume_id: VolumeId::from_bytes(exact(stored.0)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        topology_revision,
        cursor,
        scanned_stripes: nonnegative(stored.4)?,
        queued_repairs: nonnegative(stored.5)?,
        superseded_by_revision,
        evidence_digest: exact(stored.7)?,
        complete,
        revision: positive_revision(stored.9)?,
    })
}

fn validate_subject(
    transaction: &Transaction<'_>,
    value: CommitRebalanceScanPage,
) -> Result<(), RepositoryError> {
    let WorkSubject::Rebalance {
        volume_id,
        topology_revision,
    } = load_job_for_transition(transaction, value.work_id)?.subject
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    let configuration_revision = transaction.query_row(
        "SELECT configuration_revision FROM meshes LIMIT 2",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let configuration_revision = positive_revision(configuration_revision)?;
    let supersession_valid = value.superseded_by_revision.is_some_and(|superseded| {
        superseded == configuration_revision
            && superseded > topology_revision
            && value.page_digest != [0; 32]
    });
    let page_valid = value.superseded_by_revision.is_none()
        && topology_revision == configuration_revision
        && value.page_digest != [0; 32]
        && value.queued_repairs <= value.scanned_stripes
        && value.next.is_none_or(|next| {
            value.scanned_stripes > 0 && value.after.is_none_or(|after| next > after)
        });
    if volume_id == value.volume_id
        && topology_revision == value.topology_revision
        && (supersession_valid || page_valid)
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_progression(
    previous: Option<RebalanceScanProgress>,
    value: CommitRebalanceScanPage,
) -> Result<(), RepositoryError> {
    if previous.is_some_and(|progress| {
        progress.complete
            || progress.volume_id != value.volume_id
            || progress.topology_revision != value.topology_revision
            || progress.cursor != value.after
    }) || (previous.is_none() && value.after.is_some())
        || value.superseded_by_revision.is_some_and(|_| {
            value.scanned_stripes != 0 || value.queued_repairs != 0 || value.next.is_some()
        })
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the complete cumulative scan checkpoint is explicit"
)]
fn persist_progress(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: CommitRebalanceScanPage,
    revision: Revision,
    scanned_stripes: u64,
    queued_repairs: u64,
    evidence_digest: [u8; 32],
) -> Result<(), RepositoryError> {
    let state = if value.next.is_some() {
        SCAN_ACTIVE
    } else {
        SCAN_COMPLETE
    };
    transaction.execute(
        "INSERT INTO maintenance_rebalance_scans(
            work_id, volume_id, topology_revision, cursor_publication_operation_id,
            cursor_stripe_index, scanned_stripes, queued_repairs, superseded_by_revision,
            evidence_digest, state, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(work_id) DO UPDATE SET
            cursor_publication_operation_id = excluded.cursor_publication_operation_id,
            cursor_stripe_index = excluded.cursor_stripe_index,
            scanned_stripes = excluded.scanned_stripes,
            queued_repairs = excluded.queued_repairs,
            superseded_by_revision = excluded.superseded_by_revision,
            evidence_digest = excluded.evidence_digest, state = excluded.state,
            revision = excluded.revision",
        params![
            value.work_id.as_bytes().as_slice(),
            value.volume_id.as_bytes().as_slice(),
            to_i64(value.topology_revision.get())?,
            value
                .next
                .map(|cursor| cursor.publication_operation_id.as_bytes().to_vec()),
            value
                .next
                .map(|cursor| to_i64(cursor.stripe_index))
                .transpose()?,
            to_i64(scanned_stripes)?,
            to_i64(queued_repairs)?,
            value
                .superseded_by_revision
                .map(Revision::get)
                .map(to_i64)
                .transpose()?,
            evidence_digest.as_slice(),
            state,
            to_i64(revision.get())?,
        ],
    )?;
    if state == SCAN_COMPLETE {
        transaction.execute(
            "INSERT INTO maintenance_rebalance_effects(
                effect_operation_id, work_id, scanned_stripes, queued_repairs,
                superseded_by_revision, evidence_digest, committed_at, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                context.operation_id.as_bytes().as_slice(),
                value.work_id.as_bytes().as_slice(),
                to_i64(scanned_stripes)?,
                to_i64(queued_repairs)?,
                value
                    .superseded_by_revision
                    .map(Revision::get)
                    .map(to_i64)
                    .transpose()?,
                evidence_digest.as_slice(),
                context.occurred_at.get(),
                to_i64(revision.get())?,
            ],
        )?;
    }
    Ok(())
}

fn scan_evidence_digest(
    previous: Option<RebalanceScanProgress>,
    value: CommitRebalanceScanPage,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.rebalance-scan.evidence.v1\0");
    digest.update(value.work_id.as_bytes());
    digest.update(value.volume_id.as_bytes());
    digest.update(value.topology_revision.get().to_be_bytes());
    digest.update(previous.map_or([0; 32], |progress| progress.evidence_digest));
    digest.update(value.page_digest);
    digest.update(value.scanned_stripes.to_be_bytes());
    digest.update(value.queued_repairs.to_be_bytes());
    digest.update([u8::from(value.next.is_none())]);
    if let Some(revision) = value.superseded_by_revision {
        digest.update(revision.get().to_be_bytes());
    }
    digest.finalize().into()
}

fn exact<const LENGTH: usize>(value: Vec<u8>) -> Result<[u8; LENGTH], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn nonnegative(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn positive_revision(value: i64) -> Result<Revision, RepositoryError> {
    let value = nonnegative(value)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(Revision::new(value))
    }
}
