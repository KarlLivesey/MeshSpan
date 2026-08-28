// SPDX-License-Identifier: GPL-2.0-only

//! Independently validated point reads and indexed due-schedule pagination.

use meshspan_domain::{DurationMicros, Revision, SnapshotScheduleId, UnixMicros, VolumeId};
use rusqlite::{OptionalExtension, params};

use super::{duration, identifier, parse_u32, parse_u64};
use crate::PartitionDatabase;
use crate::repository::{Page, PageLimit, RepositoryError};

type StoredSchedule = (
    Vec<u8>,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    i64,
    i64,
    i64,
    i64,
);

/// Stable seek cursor for schedules ordered by their next due instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotScheduleCursor {
    next_due_at: UnixMicros,
    schedule_id: SnapshotScheduleId,
}

/// One independently validated current snapshot schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotSchedule {
    /// Stable schedule identity.
    pub schedule_id: SnapshotScheduleId,
    /// Volume captured by each occurrence.
    pub volume_id: VolumeId,
    /// Monotonic immutable configuration sequence.
    pub sequence: u64,
    /// Positive interval between occurrences.
    pub interval: DurationMicros,
    /// Optional count of newest schedule snapshots retained.
    pub retention_count: Option<u32>,
    /// Optional age after which schedule snapshots become expirable.
    pub retention_duration: Option<DurationMicros>,
    /// Whether the schedule may execute.
    pub enabled: bool,
    /// Next authoritative occurrence.
    pub next_due_at: UnixMicros,
    /// Last authoritative state revision affecting the schedule head.
    pub revision: Revision,
}

pub(crate) fn load(
    database: &PartitionDatabase,
    schedule_id: SnapshotScheduleId,
) -> Result<Option<SnapshotSchedule>, RepositoryError> {
    database
        .connection()
        .query_row(
            "SELECT h.volume_id, h.schedule_sequence, h.interval_micros, h.retention_count,
                    h.retention_duration_micros, h.enabled, h.next_due_at, h.revision,
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
                         THEN 1 ELSE 0 END
             FROM snapshot_schedule_heads h
             LEFT JOIN snapshot_schedule_revisions r
               ON r.schedule_id = h.schedule_id
              AND r.schedule_sequence = h.schedule_sequence
             WHERE h.schedule_id = ?1",
            [schedule_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()?
        .map(|stored| decode(schedule_id, &stored))
        .transpose()
}

pub(crate) fn due(
    database: &PartitionDatabase,
    now: UnixMicros,
    after: Option<&SnapshotScheduleCursor>,
    limit: PageLimit,
) -> Result<Page<SnapshotSchedule, SnapshotScheduleCursor>, RepositoryError> {
    let lower_due = after.map_or(i64::MIN, |cursor| cursor.next_due_at.get());
    let lower_id = after.map_or([0; 16], |cursor| cursor.schedule_id.as_bytes());
    let row_limit = i64::try_from(
        limit
            .get()
            .checked_add(1)
            .ok_or(RepositoryError::InvalidPageLimit)?,
    )
    .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let mut statement = database.connection().prepare(
        "SELECT h.schedule_id, h.volume_id, h.schedule_sequence, h.interval_micros,
                h.retention_count, h.retention_duration_micros, h.enabled, h.next_due_at,
                h.revision,
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
                     THEN 1 ELSE 0 END
         FROM snapshot_schedule_heads h INDEXED BY snapshot_schedule_heads_due
         LEFT JOIN snapshot_schedule_revisions r
           ON r.schedule_id = h.schedule_id AND r.schedule_sequence = h.schedule_sequence
         WHERE h.enabled = 1 AND h.next_due_at <= ?1
           AND (h.next_due_at, h.schedule_id) > (?2, ?3)
         ORDER BY h.next_due_at, h.schedule_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![now.get(), lower_due, lower_id.as_slice(), row_limit],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
            ))
        },
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for stored in rows {
        let stored = stored?;
        let schedule_id = identifier(&stored.0, SnapshotScheduleId::from_bytes)?;
        let schedule = (
            stored.1, stored.2, stored.3, stored.4, stored.5, stored.6, stored.7, stored.8,
            stored.9,
        );
        items.push(decode(schedule_id, &schedule)?);
    }
    let next = (items.len() > limit.get()).then(|| {
        let last = items[limit.get() - 1];
        SnapshotScheduleCursor {
            next_due_at: last.next_due_at,
            schedule_id: last.schedule_id,
        }
    });
    items.truncate(limit.get());
    Ok(Page { items, next })
}

fn decode(
    schedule_id: SnapshotScheduleId,
    stored: &StoredSchedule,
) -> Result<SnapshotSchedule, RepositoryError> {
    if (stored.5 != 0 && stored.5 != 1) || stored.8 != 1 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(SnapshotSchedule {
        schedule_id,
        volume_id: identifier(&stored.0, VolumeId::from_bytes)?,
        sequence: parse_u64(stored.1)?,
        interval: duration(stored.2)?,
        retention_count: stored.3.map(parse_u32).transpose()?,
        retention_duration: stored.4.map(duration).transpose()?,
        enabled: stored.5 == 1,
        next_due_at: UnixMicros::new(stored.6),
        revision: Revision::new(parse_u64(stored.7)?),
    })
}
