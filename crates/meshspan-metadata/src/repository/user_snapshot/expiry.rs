// SPDX-License-Identifier: GPL-2.0-only

//! Indexed age/count expiry selection and exact count-eligibility validation.

use meshspan_domain::{Revision, SnapshotId, UnixMicros, VolumeId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{identifier, parse_u64};
use crate::PartitionDatabase;
use crate::SnapshotExpiryReason;
use crate::repository::{Page, PageLimit, RepositoryError};

/// Stable seek cursor for automatic snapshot-expiry candidates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotExpiryCursor {
    revision: Revision,
    snapshot_id: SnapshotId,
}

/// One independently revalidated automatic snapshot-expiry candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotExpiryCandidate {
    /// Active unprotected snapshot selected by current retention state.
    pub snapshot_id: SnapshotId,
    /// Owning volume.
    pub volume_id: VolumeId,
    /// Exact snapshot revision required by the expiry command.
    pub revision: Revision,
    /// Deadline or schedule occurrence that made the snapshot eligible.
    pub eligible_at: UnixMicros,
    /// Exact automatic policy reason.
    pub reason: SnapshotExpiryReason,
}

pub(super) fn count_eligible(
    transaction: &Transaction<'_>,
    snapshot_id: SnapshotId,
) -> Result<bool, RepositoryError> {
    let stored: Option<(i64, i64, Option<i64>, i64)> = transaction
        .query_row(
            "SELECT sr.run_sequence, h.run_sequence, h.retention_count,
                    CASE WHEN r.volume_id = h.volume_id
                               AND r.interval_micros = h.interval_micros
                               AND r.retention_count IS h.retention_count
                               AND r.retention_duration_micros IS h.retention_duration_micros
                               AND r.enabled = h.enabled
                               AND (SELECT count(*) FROM snapshot_schedule_revisions c
                                    WHERE c.schedule_id = h.schedule_id) = h.schedule_sequence
                               AND (SELECT min(c.schedule_sequence)
                                    FROM snapshot_schedule_revisions c
                                    WHERE c.schedule_id = h.schedule_id) = 1
                               AND (SELECT max(c.schedule_sequence)
                                    FROM snapshot_schedule_revisions c
                                    WHERE c.schedule_id = h.schedule_id) = h.schedule_sequence
                               AND NOT EXISTS(
                                   SELECT 1 FROM snapshot_schedule_revisions c
                                   WHERE c.schedule_id = h.schedule_id
                                     AND c.volume_id != h.volume_id)
                               AND (SELECT count(*) FROM snapshot_schedule_runs x
                                    WHERE x.schedule_id = h.schedule_id) = h.run_sequence
                               AND coalesce((SELECT max(x.run_sequence)
                                             FROM snapshot_schedule_runs x
                                             WHERE x.schedule_id = h.schedule_id), 0)
                                   = h.run_sequence
                         THEN 1 ELSE 0 END
             FROM snapshot_schedule_runs sr
             JOIN snapshot_schedule_heads h ON h.schedule_id = sr.schedule_id
             LEFT JOIN snapshot_schedule_revisions r
               ON r.schedule_id = h.schedule_id
              AND r.schedule_sequence = h.schedule_sequence
             WHERE sr.snapshot_id = ?1",
            [snapshot_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((run_sequence, current_sequence, retention_count, valid)) = stored else {
        return Ok(false);
    };
    if valid != 1 {
        return Err(RepositoryError::CorruptState);
    }
    let Some(retention_count) = retention_count else {
        return Ok(false);
    };
    let retained_boundary = current_sequence
        .checked_sub(retention_count)
        .unwrap_or_default();
    Ok(run_sequence > 0 && run_sequence <= retained_boundary)
}

pub(crate) fn due(
    database: &PartitionDatabase,
    now: UnixMicros,
    after: Option<&SnapshotExpiryCursor>,
    limit: PageLimit,
) -> Result<Page<SnapshotExpiryCandidate, SnapshotExpiryCursor>, RepositoryError> {
    let lower_revision = after.map_or(0, |cursor| cursor.revision.get());
    let lower_id = after.map_or([0; 16], |cursor| cursor.snapshot_id.as_bytes());
    let row_limit = i64::try_from(
        limit
            .get()
            .checked_add(1)
            .ok_or(RepositoryError::InvalidPageLimit)?,
    )
    .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let mut statement = database.connection().prepare(
        "WITH candidates AS (
             SELECT vs.snapshot_id, vs.volume_id, vs.revision,
                    vs.expires_at AS eligible_at, 2 AS reason_code, 1 AS valid
             FROM volume_snapshots vs INDEXED BY snapshot_expiry_by_revision
             WHERE vs.state = 1 AND vs.protected_from_expiry = 0
               AND vs.expires_at IS NOT NULL AND vs.expires_at <= ?1
             UNION ALL
             SELECT vs.snapshot_id, vs.volume_id, vs.revision,
                    sr.scheduled_for AS eligible_at, 3 AS reason_code,
                    CASE WHEN r.volume_id = h.volume_id
                               AND r.interval_micros = h.interval_micros
                               AND r.retention_count IS h.retention_count
                               AND r.retention_duration_micros IS h.retention_duration_micros
                               AND r.enabled = h.enabled
                               AND (SELECT count(*) FROM snapshot_schedule_revisions c
                                    WHERE c.schedule_id = h.schedule_id) = h.schedule_sequence
                               AND (SELECT min(c.schedule_sequence)
                                    FROM snapshot_schedule_revisions c
                                    WHERE c.schedule_id = h.schedule_id) = 1
                               AND (SELECT max(c.schedule_sequence)
                                    FROM snapshot_schedule_revisions c
                                    WHERE c.schedule_id = h.schedule_id) = h.schedule_sequence
                               AND NOT EXISTS(
                                   SELECT 1 FROM snapshot_schedule_revisions c
                                   WHERE c.schedule_id = h.schedule_id
                                     AND c.volume_id != h.volume_id)
                               AND (SELECT count(*) FROM snapshot_schedule_runs x
                                    WHERE x.schedule_id = h.schedule_id) = h.run_sequence
                               AND coalesce((SELECT max(x.run_sequence)
                                             FROM snapshot_schedule_runs x
                                             WHERE x.schedule_id = h.schedule_id), 0)
                                   = h.run_sequence
                         THEN 1 ELSE 0 END AS valid
             FROM snapshot_schedule_runs sr INDEXED BY snapshot_schedule_runs_by_sequence
             JOIN snapshot_schedule_heads h ON h.schedule_id = sr.schedule_id
             LEFT JOIN snapshot_schedule_revisions r
               ON r.schedule_id = h.schedule_id
              AND r.schedule_sequence = h.schedule_sequence
             JOIN volume_snapshots vs ON vs.snapshot_id = sr.snapshot_id
             WHERE vs.state = 1 AND vs.protected_from_expiry = 0
               AND h.retention_count IS NOT NULL
               AND sr.run_sequence <= h.run_sequence - h.retention_count
               AND (vs.expires_at IS NULL OR vs.expires_at > ?1)
         )
         SELECT snapshot_id, volume_id, revision, eligible_at, reason_code, valid
         FROM candidates
         WHERE (revision, snapshot_id) > (?2, ?3)
         ORDER BY revision, snapshot_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            now.get(),
            to_i64(lower_revision)?,
            lower_id.as_slice(),
            row_limit
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for stored in rows {
        let stored = stored?;
        items.push(decode(&stored)?);
    }
    let next = (items.len() > limit.get()).then(|| {
        let last = items[limit.get() - 1];
        SnapshotExpiryCursor {
            revision: last.revision,
            snapshot_id: last.snapshot_id,
        }
    });
    items.truncate(limit.get());
    Ok(Page { items, next })
}

fn decode(
    stored: &(Vec<u8>, Vec<u8>, i64, i64, i64, i64),
) -> Result<SnapshotExpiryCandidate, RepositoryError> {
    if stored.5 != 1 {
        return Err(RepositoryError::CorruptState);
    }
    let reason = match stored.4 {
        2 => SnapshotExpiryReason::RetentionAge,
        3 => SnapshotExpiryReason::RetentionCount,
        _ => return Err(RepositoryError::CorruptState),
    };
    Ok(SnapshotExpiryCandidate {
        snapshot_id: identifier(&stored.0, SnapshotId::from_bytes)?,
        volume_id: identifier(&stored.1, VolumeId::from_bytes)?,
        revision: Revision::new(parse_u64(stored.2)?),
        eligible_at: UnixMicros::new(stored.3),
        reason,
    })
}

fn to_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::InvalidPageLimit)
}
