// SPDX-License-Identifier: GPL-2.0-only

//! Replicated automatic metadata-backup policy and due-run materialisation.

use meshspan_domain::{BackupId, DurationMicros, PartitionId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, ConfigureMetadataBackupSchedule, QueueMetadataBackupRun};

const RUN_QUEUED: i64 = 1;

type StoredSchedule = (i64, i64, i64, i64, i64, i64, i64, i64);

/// Current automatic metadata-backup policy for one partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataBackupSchedule {
    /// Partition whose committed state is protected.
    pub partition_id: PartitionId,
    /// Monotonic immutable policy sequence.
    pub sequence: u64,
    /// Delay between completed attempts.
    pub interval: DurationMicros,
    /// Number of newest usable generations retained.
    pub retained_generations: u16,
    /// Verified copies required for a protected generation.
    pub minimum_verified_copies: u8,
    /// Required verified copies on independently declared destinations.
    pub minimum_independent_copies: u8,
    /// Whether a due run may be created.
    pub enabled: bool,
    /// Next authoritative due instant.
    pub next_due_at: UnixMicros,
    /// Number of runs materialised by this schedule.
    pub run_sequence: u64,
    /// Latest authoritative revision affecting the head.
    pub revision: Revision,
}

/// One durable due occurrence awaiting fenced execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataBackupRun {
    /// Stable generation identity.
    pub backup_id: BackupId,
    /// Source partition.
    pub partition_id: PartitionId,
    /// Exact schedule policy selected for the run.
    pub schedule_sequence: u64,
    /// Monotonic run number within the partition.
    pub run_sequence: u64,
    /// Exact occurrence instant.
    pub scheduled_for: UnixMicros,
    /// Latest authoritative revision affecting the run.
    pub revision: Revision,
}

pub(super) fn configure(
    transaction: &Transaction<'_>,
    partition_id: PartitionId,
    context: CommandContext,
    command: ConfigureMetadataBackupSchedule,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_configuration(partition_id, context, command)?;
    let current = schedule_head(transaction, partition_id)?;
    let sequence = next_sequence(current.as_ref(), command.expected_schedule_sequence)?;
    transaction.execute(
        "INSERT INTO metadata_backup_schedule_revisions(
            partition_id, schedule_sequence, interval_micros, retained_generations,
            minimum_verified_copies, minimum_independent_copies, enabled, next_due_at,
            configured_by, configured_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            partition_id.as_bytes().as_slice(),
            to_i64(sequence)?,
            to_i64(command.interval.get())?,
            i64::from(command.retained_generations),
            i64::from(command.minimum_verified_copies),
            i64::from(command.minimum_independent_copies),
            command.enabled,
            command.next_due_at.get(),
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    write_head(
        transaction,
        partition_id,
        command,
        sequence,
        revision,
        current,
    )?;
    Ok(EntityReference {
        kind: EntityKind::MetadataBackupSchedule,
        id: partition_id.as_bytes(),
    })
}

pub(super) fn queue(
    transaction: &Transaction<'_>,
    partition_id: PartitionId,
    context: CommandContext,
    command: QueueMetadataBackupRun,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.partition_id != partition_id {
        return Err(RepositoryError::InvalidCommand);
    }
    let schedule =
        load_from_connection(transaction, partition_id)?.ok_or(RepositoryError::InvalidCommand)?;
    validate_due(context, command, schedule)?;
    let unfinished: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata_backup_runs
         WHERE partition_id = ?1 AND state IN (1, 2, 3))",
        [partition_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if unfinished != 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let run_sequence = schedule
        .run_sequence
        .checked_add(1)
        .ok_or(RepositoryError::CapacityExceeded)?;
    transaction.execute(
        "INSERT INTO metadata_backup_runs(
            backup_id, partition_id, schedule_sequence, run_sequence, scheduled_for,
            interval_micros, retained_generations, minimum_verified_copies,
            minimum_independent_copies, state, operation_id, created_at, completed_at,
            result_digest, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, NULL, ?13)",
        params![
            command.backup_id.as_bytes().as_slice(),
            partition_id.as_bytes().as_slice(),
            to_i64(schedule.sequence)?,
            to_i64(run_sequence)?,
            command.scheduled_for.get(),
            to_i64(schedule.interval.get())?,
            i64::from(schedule.retained_generations),
            i64::from(schedule.minimum_verified_copies),
            i64::from(schedule.minimum_independent_copies),
            RUN_QUEUED,
            context.operation_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE metadata_backup_schedule_heads SET run_sequence = ?1, revision = ?2
         WHERE partition_id = ?3 AND schedule_sequence = ?4 AND run_sequence = ?5",
        params![
            to_i64(run_sequence)?,
            to_i64(revision.get())?,
            partition_id.as_bytes().as_slice(),
            to_i64(schedule.sequence)?,
            to_i64(schedule.run_sequence)?,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::StaleMetadataBackupSchedule);
    }
    Ok(EntityReference {
        kind: EntityKind::MetadataBackupRun,
        id: command.backup_id.as_bytes(),
    })
}

pub(super) fn load(
    connection: &rusqlite::Connection,
    partition_id: PartitionId,
) -> Result<Option<MetadataBackupSchedule>, RepositoryError> {
    load_from_connection(connection, partition_id)
}

pub(super) fn due(
    connection: &rusqlite::Connection,
    partition_id: PartitionId,
    now: UnixMicros,
) -> Result<Option<MetadataBackupSchedule>, RepositoryError> {
    let schedule = load_from_connection(connection, partition_id)?;
    let unfinished: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata_backup_runs
         WHERE partition_id = ?1 AND state IN (1, 2, 3))",
        [partition_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    Ok(schedule.filter(|value| value.enabled && value.next_due_at <= now && unfinished == 0))
}

pub(super) fn run(
    connection: &rusqlite::Connection,
    backup_id: BackupId,
) -> Result<Option<MetadataBackupRun>, RepositoryError> {
    connection
        .query_row(
            "SELECT partition_id, schedule_sequence, run_sequence, scheduled_for, revision,
                    state, completed_at, result_digest
             FROM metadata_backup_runs WHERE backup_id = ?1",
            [backup_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                ))
            },
        )
        .optional()?
        .map(|stored| {
            if stored.5 != RUN_QUEUED || stored.6.is_some() || stored.7.is_some() {
                return Err(RepositoryError::CorruptState);
            }
            Ok(MetadataBackupRun {
                backup_id,
                partition_id: partition_identifier(&stored.0)?,
                schedule_sequence: parse_u64(stored.1)?,
                run_sequence: parse_u64(stored.2)?,
                scheduled_for: UnixMicros::new(stored.3),
                revision: Revision::new(parse_u64(stored.4)?),
            })
        })
        .transpose()
}

fn load_from_connection(
    connection: &rusqlite::Connection,
    partition_id: PartitionId,
) -> Result<Option<MetadataBackupSchedule>, RepositoryError> {
    connection
        .query_row(
            "SELECT h.schedule_sequence, h.interval_micros, h.retained_generations,
                    h.minimum_verified_copies, h.minimum_independent_copies, h.enabled,
                    h.next_due_at, h.run_sequence, h.revision,
                    CASE WHEN r.interval_micros = h.interval_micros
                              AND r.retained_generations = h.retained_generations
                              AND r.minimum_verified_copies = h.minimum_verified_copies
                              AND r.minimum_independent_copies = h.minimum_independent_copies
                              AND r.enabled = h.enabled
                              AND r.next_due_at = h.next_due_at
                              AND (SELECT count(*) FROM metadata_backup_schedule_revisions c
                                   WHERE c.partition_id = h.partition_id) = h.schedule_sequence
                         THEN 1 ELSE 0 END
             FROM metadata_backup_schedule_heads h
             LEFT JOIN metadata_backup_schedule_revisions r
               ON r.partition_id = h.partition_id
              AND r.schedule_sequence = h.schedule_sequence
             WHERE h.partition_id = ?1",
            [partition_id.as_bytes().as_slice()],
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
                    row.get(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?
        .map(|stored| decode_schedule(partition_id, stored))
        .transpose()
}

fn decode_schedule(
    partition_id: PartitionId,
    stored: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64),
) -> Result<MetadataBackupSchedule, RepositoryError> {
    if stored.9 != 1 || !matches!(stored.5, 0 | 1) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(MetadataBackupSchedule {
        partition_id,
        sequence: parse_u64(stored.0)?,
        interval: DurationMicros::new(parse_u64(stored.1)?),
        retained_generations: u16::try_from(stored.2).map_err(|_| RepositoryError::CorruptState)?,
        minimum_verified_copies: u8::try_from(stored.3)
            .map_err(|_| RepositoryError::CorruptState)?,
        minimum_independent_copies: u8::try_from(stored.4)
            .map_err(|_| RepositoryError::CorruptState)?,
        enabled: stored.5 == 1,
        next_due_at: UnixMicros::new(stored.6),
        run_sequence: parse_u64(stored.7)?,
        revision: Revision::new(parse_u64(stored.8)?),
    })
}

fn validate_configuration(
    partition_id: PartitionId,
    context: CommandContext,
    command: ConfigureMetadataBackupSchedule,
) -> Result<(), RepositoryError> {
    if command.partition_id != partition_id
        || command.interval.get() == 0
        || command.retained_generations == 0
        || command.minimum_verified_copies == 0
        || command.minimum_independent_copies > command.minimum_verified_copies
        || command.next_due_at < context.occurred_at
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_due(
    context: CommandContext,
    command: QueueMetadataBackupRun,
    schedule: MetadataBackupSchedule,
) -> Result<(), RepositoryError> {
    if !schedule.enabled
        || schedule.sequence != command.expected_schedule_sequence
        || schedule.next_due_at != command.scheduled_for
        || schedule.next_due_at > context.occurred_at
    {
        Err(RepositoryError::StaleMetadataBackupSchedule)
    } else {
        Ok(())
    }
}

fn next_sequence(current: Option<&StoredSchedule>, expected: u64) -> Result<u64, RepositoryError> {
    match current {
        None if expected == 0 => Ok(1),
        Some(value) if parse_u64(value.0)? == expected => expected
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded),
        None | Some(_) => Err(RepositoryError::StaleMetadataBackupSchedule),
    }
}

fn schedule_head(
    transaction: &Transaction<'_>,
    partition_id: PartitionId,
) -> Result<Option<StoredSchedule>, RepositoryError> {
    transaction
        .query_row(
            "SELECT schedule_sequence, interval_micros, retained_generations,
                    minimum_verified_copies, minimum_independent_copies, enabled,
                    next_due_at, run_sequence
             FROM metadata_backup_schedule_heads WHERE partition_id = ?1",
            [partition_id.as_bytes().as_slice()],
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
        .optional()
        .map_err(Into::into)
}

fn write_head(
    transaction: &Transaction<'_>,
    partition_id: PartitionId,
    command: ConfigureMetadataBackupSchedule,
    sequence: u64,
    revision: Revision,
    current: Option<StoredSchedule>,
) -> Result<(), RepositoryError> {
    let run_sequence = current.map_or(0, |value| value.7);
    transaction.execute(
        "INSERT INTO metadata_backup_schedule_heads(
            partition_id, schedule_sequence, interval_micros, retained_generations,
            minimum_verified_copies, minimum_independent_copies, enabled, next_due_at,
            run_sequence, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(partition_id) DO UPDATE SET
            schedule_sequence = excluded.schedule_sequence,
            interval_micros = excluded.interval_micros,
            retained_generations = excluded.retained_generations,
            minimum_verified_copies = excluded.minimum_verified_copies,
            minimum_independent_copies = excluded.minimum_independent_copies,
            enabled = excluded.enabled, next_due_at = excluded.next_due_at,
            revision = excluded.revision",
        params![
            partition_id.as_bytes().as_slice(),
            to_i64(sequence)?,
            to_i64(command.interval.get())?,
            i64::from(command.retained_generations),
            i64::from(command.minimum_verified_copies),
            i64::from(command.minimum_independent_copies),
            command.enabled,
            command.next_due_at.get(),
            run_sequence,
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn partition_identifier(value: &[u8]) -> Result<PartitionId, RepositoryError> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    PartitionId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
