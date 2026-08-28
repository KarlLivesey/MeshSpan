// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative fixed-interval snapshot schedules and exact due execution.

use meshspan_domain::{DurationMicros, Revision, SnapshotScheduleId, UnixMicros, VolumeId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError, user_snapshot};
use crate::{CommandContext, ConfigureSnapshotSchedule, CreateVolumeSnapshot, RunSnapshotSchedule};

type StoredRunHead = (i64, Vec<u8>, i64, Option<i64>, i64, i64, i64, i64);
mod query;

pub use query::{SnapshotSchedule, SnapshotScheduleCursor};
pub(super) use query::{due, load};

struct ScheduleRunHead {
    sequence: u64,
    volume_id: VolumeId,
    interval: i64,
    retention_duration: Option<i64>,
    enabled: bool,
    next_due_at: i64,
    run_sequence: u64,
}

pub(super) fn configure(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: ConfigureSnapshotSchedule,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_configuration(command)?;
    let current: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT schedule_sequence, volume_id FROM snapshot_schedule_heads
             WHERE schedule_id = ?1",
            [command.schedule_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let sequence = next_sequence(current.as_ref(), command)?;
    transaction.execute(
        "INSERT INTO snapshot_schedule_revisions(
            schedule_id, schedule_sequence, volume_id, interval_micros,
            retention_count, retention_duration_micros, enabled, next_due_at,
            configured_by, configured_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        schedule_parameters(context, command, sequence, revision)?,
    )?;
    if current.is_none() {
        transaction.execute(
            "INSERT INTO snapshot_schedule_heads(
                schedule_id, schedule_sequence, volume_id, interval_micros,
                retention_count, retention_duration_micros, enabled, next_due_at, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            head_parameters(command, sequence, revision)?,
        )?;
    } else {
        let updated = transaction.execute(
            "UPDATE snapshot_schedule_heads SET
                schedule_sequence = ?1, interval_micros = ?2, retention_count = ?3,
                retention_duration_micros = ?4, enabled = ?5, next_due_at = ?6,
                revision = ?7
             WHERE schedule_id = ?8 AND schedule_sequence = ?9 AND volume_id = ?10",
            params![
                to_i64(sequence)?,
                duration_i64(command.interval)?,
                command.retention_count.map(i64::from),
                command.retention_duration.map(duration_i64).transpose()?,
                command.enabled,
                command.next_due_at.get(),
                to_i64(revision.get())?,
                command.schedule_id.as_bytes().as_slice(),
                to_i64(command.expected_schedule_sequence)?,
                command.volume_id.as_bytes().as_slice(),
            ],
        )?;
        if updated != 1 {
            return Err(RepositoryError::StaleSnapshotSchedule);
        }
    }
    Ok(EntityReference {
        kind: EntityKind::SnapshotSchedule,
        id: command.schedule_id.as_bytes(),
    })
}

pub(super) fn run(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RunSnapshotSchedule,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let Some(head) = load_run_head(transaction, command.schedule_id)? else {
        return Err(RepositoryError::InvalidCommand);
    };
    if head.sequence != command.expected_schedule_sequence {
        return Err(RepositoryError::StaleSnapshotSchedule);
    }
    if !head.enabled
        || head.next_due_at != command.scheduled_for.get()
        || head.next_due_at > context.occurred_at.get()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let expires_at = head
        .retention_duration
        .map(|duration| expiry_at(context.occurred_at, duration))
        .transpose()?;
    let entity = user_snapshot::create(
        transaction,
        context,
        &CreateVolumeSnapshot {
            snapshot_id: command.snapshot_id,
            volume_id: head.volume_id,
            namespace_commit_id: command.namespace_commit_id,
            name: command.name.clone(),
            expires_at,
            protected_from_expiry: false,
        },
        revision,
    )?;
    let following_due = following_due(head.next_due_at, head.interval, context.occurred_at.get())?;
    let run_sequence = head
        .run_sequence
        .checked_add(1)
        .ok_or(RepositoryError::CapacityExceeded)?;
    let updated = transaction.execute(
        "UPDATE snapshot_schedule_heads
         SET next_due_at = ?1, run_sequence = ?2, revision = ?3
         WHERE schedule_id = ?4 AND schedule_sequence = ?5
           AND next_due_at = ?6 AND run_sequence = ?7",
        params![
            following_due,
            to_i64(run_sequence)?,
            to_i64(revision.get())?,
            command.schedule_id.as_bytes().as_slice(),
            to_i64(head.sequence)?,
            head.next_due_at,
            to_i64(head.run_sequence)?,
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::StaleSnapshotSchedule);
    }
    transaction.execute(
        "INSERT INTO snapshot_schedule_runs(
            schedule_id, schedule_sequence, scheduled_for, snapshot_id,
            operation_id, created_at, revision, run_sequence
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            command.schedule_id.as_bytes().as_slice(),
            to_i64(head.sequence)?,
            head.next_due_at,
            command.snapshot_id.as_bytes().as_slice(),
            context.operation_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
            to_i64(run_sequence)?,
        ],
    )?;
    Ok(entity)
}

fn load_run_head(
    transaction: &Transaction<'_>,
    schedule_id: SnapshotScheduleId,
) -> Result<Option<ScheduleRunHead>, RepositoryError> {
    let stored: Option<StoredRunHead> = transaction
        .query_row(
            "SELECT h.schedule_sequence, h.volume_id, h.interval_micros,
                    h.retention_duration_micros, h.enabled, h.next_due_at, h.run_sequence,
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
                               AND (SELECT count(*) FROM snapshot_schedule_runs sr
                                    WHERE sr.schedule_id = h.schedule_id) = h.run_sequence
                               AND coalesce((SELECT max(sr.run_sequence)
                                             FROM snapshot_schedule_runs sr
                                             WHERE sr.schedule_id = h.schedule_id), 0)
                                   = h.run_sequence
                         THEN 1 ELSE 0 END
             FROM snapshot_schedule_heads h
             LEFT JOIN snapshot_schedule_revisions r
               ON r.schedule_id = h.schedule_id
              AND r.schedule_sequence = h.schedule_sequence
             WHERE h.schedule_id = ?1",
            [schedule_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    stored.map(|value| decode_run_head(&value)).transpose()
}

fn decode_run_head(stored: &StoredRunHead) -> Result<ScheduleRunHead, RepositoryError> {
    if stored.7 != 1 || !matches!(stored.4, 0 | 1) || stored.2 <= 0 {
        return Err(RepositoryError::CorruptState);
    }
    if stored.3.is_some_and(|duration| duration <= 0) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(ScheduleRunHead {
        sequence: parse_u64(stored.0)?,
        volume_id: identifier(&stored.1, VolumeId::from_bytes)?,
        interval: stored.2,
        retention_duration: stored.3,
        enabled: stored.4 == 1,
        next_due_at: stored.5,
        run_sequence: parse_u64(stored.6)?,
    })
}

fn validate_configuration(command: ConfigureSnapshotSchedule) -> Result<(), RepositoryError> {
    if command.interval.get() == 0
        || command.retention_count == Some(0)
        || command
            .retention_duration
            .is_some_and(|duration| duration.get() == 0)
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn next_sequence(
    current: Option<&(i64, Vec<u8>)>,
    command: ConfigureSnapshotSchedule,
) -> Result<u64, RepositoryError> {
    let Some((sequence, volume)) = current else {
        return if command.expected_schedule_sequence == 0 {
            Ok(1)
        } else {
            Err(RepositoryError::StaleSnapshotSchedule)
        };
    };
    if parse_u64(*sequence)? != command.expected_schedule_sequence {
        return Err(RepositoryError::StaleSnapshotSchedule);
    }
    if identifier(volume, VolumeId::from_bytes)? != command.volume_id {
        return Err(RepositoryError::InvalidCommand);
    }
    command
        .expected_schedule_sequence
        .checked_add(1)
        .ok_or(RepositoryError::CapacityExceeded)
}

fn following_due(current: i64, interval: i64, now: i64) -> Result<i64, RepositoryError> {
    let elapsed = now
        .checked_sub(current)
        .ok_or(RepositoryError::InvalidCommand)?;
    let steps = elapsed
        .checked_div(interval)
        .and_then(|value| value.checked_add(1))
        .ok_or(RepositoryError::CapacityExceeded)?;
    current
        .checked_add(
            interval
                .checked_mul(steps)
                .ok_or(RepositoryError::CapacityExceeded)?,
        )
        .ok_or(RepositoryError::CapacityExceeded)
}

fn expiry_at(now: UnixMicros, duration: i64) -> Result<UnixMicros, RepositoryError> {
    if duration <= 0 {
        return Err(RepositoryError::CorruptState);
    }
    now.get()
        .checked_add(duration)
        .map(UnixMicros::new)
        .ok_or(RepositoryError::CapacityExceeded)
}

fn schedule_parameters(
    context: CommandContext,
    command: ConfigureSnapshotSchedule,
    sequence: u64,
    revision: Revision,
) -> Result<rusqlite::ParamsFromIter<Vec<rusqlite::types::Value>>, RepositoryError> {
    Ok(rusqlite::params_from_iter(vec![
        command.schedule_id.as_bytes().to_vec().into(),
        to_i64(sequence)?.into(),
        command.volume_id.as_bytes().to_vec().into(),
        duration_i64(command.interval)?.into(),
        command.retention_count.map(i64::from).into(),
        command
            .retention_duration
            .map(duration_i64)
            .transpose()?
            .into(),
        command.enabled.into(),
        command.next_due_at.get().into(),
        context.actor_principal_id.as_bytes().to_vec().into(),
        context.occurred_at.get().into(),
        to_i64(revision.get())?.into(),
    ]))
}

fn head_parameters(
    command: ConfigureSnapshotSchedule,
    sequence: u64,
    revision: Revision,
) -> Result<rusqlite::ParamsFromIter<Vec<rusqlite::types::Value>>, RepositoryError> {
    Ok(rusqlite::params_from_iter(vec![
        command.schedule_id.as_bytes().to_vec().into(),
        to_i64(sequence)?.into(),
        command.volume_id.as_bytes().to_vec().into(),
        duration_i64(command.interval)?.into(),
        command.retention_count.map(i64::from).into(),
        command
            .retention_duration
            .map(duration_i64)
            .transpose()?
            .into(),
        command.enabled.into(),
        command.next_due_at.get().into(),
        to_i64(revision.get())?.into(),
    ]))
}

fn identifier<T>(
    bytes: &[u8],
    constructor: fn([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, RepositoryError> {
    constructor(
        bytes
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn duration_i64(value: DurationMicros) -> Result<i64, RepositoryError> {
    i64::try_from(value.get()).map_err(|_| RepositoryError::CapacityExceeded)
}

fn duration(value: i64) -> Result<DurationMicros, RepositoryError> {
    parse_u64(value).map(DurationMicros::new)
}

fn parse_u32(value: i64) -> Result<u32, RepositoryError> {
    u32::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
