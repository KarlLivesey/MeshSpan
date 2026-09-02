// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe local progress for one bounded storage-target scrub cycle.

use meshspan_domain::{TargetId, UnixMicros, WorkId};
use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;

use crate::LocalDatabase;

const MAXIMUM_CURSOR_BYTES: usize = 512;

/// Exact durable continuation and accumulated evidence for one scrub job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalScrubProgress {
    /// Authoritative maintenance job being executed.
    pub work_id: WorkId,
    /// Exact local target.
    pub target_id: TargetId,
    /// Exact target generation; path reuse cannot inherit progress.
    pub target_generation: u64,
    /// Opaque provider cursor for the next page, or `None` at the cycle start/end.
    pub next_cursor: Option<Vec<u8>>,
    /// Number of complete pages already included in the rolling evidence.
    pub page_index: u64,
    /// Total observations accumulated across committed local pages.
    pub observation_count: u64,
    /// Total bytes independently read and digested.
    pub verified_bytes: u64,
    /// Outcomes ordered as healthy, missing, corrupt, unreadable, unexpected and deferred.
    pub outcome_counts: [u64; 6],
    /// Rolling digest after the latest committed page, or zero before the first page.
    pub rolling_evidence_digest: [u8; 32],
    /// Whether the provider returned the end of the inventory cycle.
    pub complete: bool,
    /// Local observation time of cycle completion.
    pub completed_at: Option<UnixMicros>,
    /// Last local update time.
    pub updated_at: UnixMicros,
    /// Compare-and-set local journal revision.
    pub revision: u64,
}

/// Complete next state calculated from one validated provider page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalScrubProgressUpdate {
    /// Opaque continuation returned by the provider; `None` completes the cycle.
    pub next_cursor: Option<Vec<u8>>,
    /// Accumulated observation total including the new page.
    pub observation_count: u64,
    /// Accumulated verified-byte total including the new page.
    pub verified_bytes: u64,
    /// Accumulated outcome totals including the new page.
    pub outcome_counts: [u64; 6],
    /// Rolling evidence digest including the new page.
    pub rolling_evidence_digest: [u8; 32],
}

/// Closed local scrub journal failures.
#[derive(Debug, Error)]
pub enum LocalScrubProgressError {
    /// SQLite or durable IO failed.
    #[error("local scrub progress database operation failed")]
    Sqlite(#[from] rusqlite::Error),
    /// Input was malformed, non-monotonic or contradicted its durable identity.
    #[error("local scrub progress input was invalid")]
    Invalid,
    /// A different writer advanced this exact progress record.
    #[error("local scrub progress changed concurrently")]
    Conflict,
    /// Persisted local progress contradicted its schema-level invariants.
    #[error("local scrub progress was corrupt")]
    Corrupt,
}

impl LocalDatabase {
    /// Loads or creates the initial continuation for one exact scrub job and target generation.
    ///
    /// # Errors
    ///
    /// Rejects identity reuse, malformed generations, corrupt persisted state or SQLite failure.
    pub fn load_or_create_scrub_progress(
        &mut self,
        work_id: WorkId,
        target_id: TargetId,
        target_generation: u64,
        now: UnixMicros,
    ) -> Result<LocalScrubProgress, LocalScrubProgressError> {
        if target_generation == 0 {
            return Err(LocalScrubProgressError::Invalid);
        }
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT OR IGNORE INTO local_maintenance_scrub_progress(
                work_id, target_id, target_generation, next_cursor, page_index,
                observation_count, verified_bytes, healthy_count, missing_count, corrupt_count,
                unreadable_count, unexpected_count, deferred_count, rolling_evidence_digest,
                complete, completed_at, updated_at, revision
             ) VALUES (?1, ?2, ?3, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?4, 0, NULL, ?5, 1)",
            params![
                work_id.as_bytes().as_slice(),
                target_id.as_bytes().as_slice(),
                to_i64(target_generation)?,
                [0_u8; 32].as_slice(),
                now.get(),
            ],
        )?;
        let progress = load(&transaction, work_id)?.ok_or(LocalScrubProgressError::Corrupt)?;
        if progress.target_id != target_id || progress.target_generation != target_generation {
            return Err(LocalScrubProgressError::Invalid);
        }
        transaction.commit()?;
        Ok(progress)
    }

    /// Advances one page by exact local compare-and-set, resolving an exact replay idempotently.
    ///
    /// # Errors
    ///
    /// Rejects stale writers, invalid cursors, non-monotonic counters, digest reuse, updates after
    /// completion, integer overflow and SQLite failure.
    pub fn advance_scrub_progress(
        &mut self,
        expected: &LocalScrubProgress,
        update: &LocalScrubProgressUpdate,
        now: UnixMicros,
    ) -> Result<LocalScrubProgress, LocalScrubProgressError> {
        validate_update(expected, update, now)?;
        let revision = expected
            .revision
            .checked_add(1)
            .ok_or(LocalScrubProgressError::Invalid)?;
        let page_index = expected
            .page_index
            .checked_add(1)
            .ok_or(LocalScrubProgressError::Invalid)?;
        let complete = update.next_cursor.is_none();
        let completed_at = complete.then_some(now);
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE local_maintenance_scrub_progress
             SET next_cursor = ?1, page_index = ?2, observation_count = ?3,
                 verified_bytes = ?4, healthy_count = ?5, missing_count = ?6,
                 corrupt_count = ?7, unreadable_count = ?8, unexpected_count = ?9,
                 deferred_count = ?10, rolling_evidence_digest = ?11, complete = ?12,
                 completed_at = ?13, updated_at = ?14, revision = ?15
             WHERE work_id = ?16 AND target_id = ?17 AND target_generation = ?18
               AND revision = ?19 AND complete = 0",
            params![
                update.next_cursor.as_deref(),
                to_i64(page_index)?,
                to_i64(update.observation_count)?,
                to_i64(update.verified_bytes)?,
                to_i64(update.outcome_counts[0])?,
                to_i64(update.outcome_counts[1])?,
                to_i64(update.outcome_counts[2])?,
                to_i64(update.outcome_counts[3])?,
                to_i64(update.outcome_counts[4])?,
                to_i64(update.outcome_counts[5])?,
                update.rolling_evidence_digest.as_slice(),
                i64::from(complete),
                completed_at.map(UnixMicros::get),
                now.get(),
                to_i64(revision)?,
                expected.work_id.as_bytes().as_slice(),
                expected.target_id.as_bytes().as_slice(),
                to_i64(expected.target_generation)?,
                to_i64(expected.revision)?,
            ],
        )?;
        let stored =
            load(&transaction, expected.work_id)?.ok_or(LocalScrubProgressError::Corrupt)?;
        if changed == 0 && !matches_update(&stored, expected, update, now) {
            return Err(LocalScrubProgressError::Conflict);
        }
        if changed > 1 {
            return Err(LocalScrubProgressError::Corrupt);
        }
        transaction.commit()?;
        Ok(stored)
    }
}

fn validate_update(
    expected: &LocalScrubProgress,
    update: &LocalScrubProgressUpdate,
    now: UnixMicros,
) -> Result<(), LocalScrubProgressError> {
    let classified = update
        .outcome_counts
        .into_iter()
        .try_fold(0_u64, u64::checked_add);
    if expected.complete
        || expected.target_generation == 0
        || expected.revision == 0
        || now < expected.updated_at
        || update.next_cursor.as_ref().is_some_and(|cursor| {
            cursor.is_empty()
                || cursor.len() > MAXIMUM_CURSOR_BYTES
                || expected.next_cursor.as_ref() == Some(cursor)
        })
        || update.observation_count <= expected.observation_count
        || update.verified_bytes < expected.verified_bytes
        || update
            .outcome_counts
            .iter()
            .zip(expected.outcome_counts)
            .any(|(next, previous)| *next < previous)
        || classified != Some(update.observation_count)
        || update.rolling_evidence_digest == [0; 32]
        || update.rolling_evidence_digest == expected.rolling_evidence_digest
    {
        Err(LocalScrubProgressError::Invalid)
    } else {
        Ok(())
    }
}

fn matches_update(
    stored: &LocalScrubProgress,
    expected: &LocalScrubProgress,
    update: &LocalScrubProgressUpdate,
    now: UnixMicros,
) -> bool {
    stored.work_id == expected.work_id
        && stored.target_id == expected.target_id
        && stored.target_generation == expected.target_generation
        && stored.revision == expected.revision.saturating_add(1)
        && stored.page_index == expected.page_index.saturating_add(1)
        && stored.next_cursor == update.next_cursor
        && stored.observation_count == update.observation_count
        && stored.verified_bytes == update.verified_bytes
        && stored.outcome_counts == update.outcome_counts
        && stored.rolling_evidence_digest == update.rolling_evidence_digest
        && stored.complete == update.next_cursor.is_none()
        && stored.completed_at == update.next_cursor.is_none().then_some(now)
        && stored.updated_at == now
}

fn load(
    connection: &rusqlite::Connection,
    work_id: WorkId,
) -> Result<Option<LocalScrubProgress>, LocalScrubProgressError> {
    connection
        .query_row(
            "SELECT target_id, target_generation, next_cursor, page_index, observation_count,
                    verified_bytes, healthy_count, missing_count, corrupt_count, unreadable_count,
                    unexpected_count, deferred_count, rolling_evidence_digest, complete,
                    completed_at, updated_at, revision
             FROM local_maintenance_scrub_progress WHERE work_id = ?1",
            [work_id.as_bytes().as_slice()],
            |row| decode(row, work_id),
        )
        .optional()
        .map_err(Into::into)
}

fn decode(row: &Row<'_>, work_id: WorkId) -> rusqlite::Result<LocalScrubProgress> {
    decode_inner(row, work_id).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_inner(
    row: &Row<'_>,
    work_id: WorkId,
) -> Result<LocalScrubProgress, LocalScrubProgressError> {
    let complete = boolean(row.get(13)?)?;
    let completed_at = row.get::<_, Option<i64>>(14)?.map(UnixMicros::new);
    let progress = LocalScrubProgress {
        work_id,
        target_id: TargetId::from_bytes(exact(row.get(0)?)?)
            .map_err(|_| LocalScrubProgressError::Corrupt)?,
        target_generation: positive(row.get(1)?)?,
        next_cursor: row.get(2)?,
        page_index: nonnegative(row.get(3)?)?,
        observation_count: nonnegative(row.get(4)?)?,
        verified_bytes: nonnegative(row.get(5)?)?,
        outcome_counts: [
            nonnegative(row.get(6)?)?,
            nonnegative(row.get(7)?)?,
            nonnegative(row.get(8)?)?,
            nonnegative(row.get(9)?)?,
            nonnegative(row.get(10)?)?,
            nonnegative(row.get(11)?)?,
        ],
        rolling_evidence_digest: exact(row.get(12)?)?,
        complete,
        completed_at,
        updated_at: UnixMicros::new(row.get(15)?),
        revision: positive(row.get(16)?)?,
    };
    validate_stored(&progress)?;
    Ok(progress)
}

fn validate_stored(progress: &LocalScrubProgress) -> Result<(), LocalScrubProgressError> {
    let classified = progress
        .outcome_counts
        .into_iter()
        .try_fold(0_u64, u64::checked_add);
    let initial = progress.page_index == 0
        && progress.observation_count == 0
        && progress.verified_bytes == 0
        && progress.outcome_counts == [0; 6]
        && progress.rolling_evidence_digest == [0; 32]
        && progress.next_cursor.is_none()
        && !progress.complete;
    let advanced = progress.page_index > 0
        && progress.observation_count > 0
        && progress.rolling_evidence_digest != [0; 32];
    if classified != Some(progress.observation_count)
        || progress
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAXIMUM_CURSOR_BYTES)
        || progress.complete != progress.completed_at.is_some()
        || (progress.complete && progress.next_cursor.is_some())
        || (!initial && !advanced)
    {
        Err(LocalScrubProgressError::Corrupt)
    } else {
        Ok(())
    }
}

fn boolean(value: i64) -> Result<bool, LocalScrubProgressError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(LocalScrubProgressError::Corrupt),
    }
}

fn exact<const LENGTH: usize>(value: Vec<u8>) -> Result<[u8; LENGTH], LocalScrubProgressError> {
    value
        .try_into()
        .map_err(|_| LocalScrubProgressError::Corrupt)
}

fn positive(value: i64) -> Result<u64, LocalScrubProgressError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(LocalScrubProgressError::Corrupt)
}

fn nonnegative(value: i64) -> Result<u64, LocalScrubProgressError> {
    u64::try_from(value).map_err(|_| LocalScrubProgressError::Corrupt)
}

fn to_i64(value: u64) -> Result<i64, LocalScrubProgressError> {
    i64::try_from(value).map_err(|_| LocalScrubProgressError::Invalid)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn progress_is_identity_bound_monotonic_and_replay_safe()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let node_id = meshspan_domain::NodeId::from_bytes([1; 16])?;
        let mut database = LocalDatabase::open(
            &directory.path().join("local.sqlite3"),
            node_id,
            UnixMicros::new(1),
        )?;
        let work_id = WorkId::from_bytes([2; 16])?;
        let target_id = TargetId::from_bytes([3; 16])?;
        let initial =
            database.load_or_create_scrub_progress(work_id, target_id, 4, UnixMicros::new(2))?;
        let first = LocalScrubProgressUpdate {
            next_cursor: Some(vec![1, 2, 3]),
            observation_count: 2,
            verified_bytes: 20,
            outcome_counts: [1, 1, 0, 0, 0, 0],
            rolling_evidence_digest: [5; 32],
        };
        let advanced = database.advance_scrub_progress(&initial, &first, UnixMicros::new(3))?;
        assert_eq!(advanced.page_index, 1);
        assert_eq!(advanced.next_cursor, first.next_cursor);
        assert!(!advanced.complete);
        assert_eq!(
            database.advance_scrub_progress(&initial, &first, UnixMicros::new(3))?,
            advanced
        );

        let complete = LocalScrubProgressUpdate {
            next_cursor: None,
            observation_count: 3,
            verified_bytes: 30,
            outcome_counts: [2, 1, 0, 0, 0, 0],
            rolling_evidence_digest: [6; 32],
        };
        let finished = database.advance_scrub_progress(&advanced, &complete, UnixMicros::new(4))?;
        assert!(finished.complete);
        assert_eq!(finished.completed_at, Some(UnixMicros::new(4)));
        assert!(matches!(
            database.advance_scrub_progress(&finished, &complete, UnixMicros::new(5)),
            Err(LocalScrubProgressError::Invalid)
        ));
        assert!(matches!(
            database.load_or_create_scrub_progress(
                work_id,
                TargetId::from_bytes([7; 16])?,
                4,
                UnixMicros::new(5),
            ),
            Err(LocalScrubProgressError::Invalid)
        ));
        Ok(())
    }
}
