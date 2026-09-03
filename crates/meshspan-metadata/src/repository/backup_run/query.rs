// SPDX-License-Identifier: GPL-2.0-only

//! Strict reconstruction of metadata-backup run and claim state.

use meshspan_domain::{BackupId, NodeId, PartitionId, Revision, UnixMicros};
use rusqlite::{Connection, OptionalExtension, params};

use super::{
    CLAIM_ACTIVE, MetadataBackupRun, MetadataBackupRunClaimRecord, MetadataBackupRunState,
    RUN_CLAIMED, RUN_INCOMPLETE, RUN_PROTECTED, RUN_QUEUED, RUN_RECORDED,
};
use crate::{CommandContext, MetadataBackupRunClaim};

use crate::repository::RepositoryError;

#[derive(Clone, Copy)]
pub(super) struct RunHead {
    pub(super) partition_id: PartitionId,
    pub(super) state: i64,
    pub(super) minimum_verified_copies: u8,
    pub(super) minimum_independent_copies: u8,
}

pub(super) fn load(
    connection: &Connection,
    backup_id: BackupId,
) -> Result<Option<MetadataBackupRun>, RepositoryError> {
    connection
        .query_row(
            "SELECT partition_id, schedule_sequence, run_sequence, scheduled_for,
                    minimum_verified_copies, minimum_independent_copies, state,
                    completed_at, result_digest, revision
             FROM metadata_backup_runs WHERE backup_id = ?1",
            [backup_id.as_bytes().as_slice()],
            decode_run,
        )
        .optional()?
        .map(|stored| build_run(backup_id, stored))
        .transpose()
}

pub(super) fn live_claim(
    connection: &Connection,
    backup_id: BackupId,
) -> Result<Option<MetadataBackupRunClaimRecord>, RepositoryError> {
    active_claim(connection, backup_id)
}

pub(super) fn unfinished(
    connection: &Connection,
    partition_id: PartitionId,
) -> Result<Option<MetadataBackupRun>, RepositoryError> {
    let stored = connection
        .query_row(
            "SELECT backup_id FROM metadata_backup_runs
             WHERE partition_id = ?1 AND state IN (?2, ?3, ?4)",
            params![
                partition_id.as_bytes().as_slice(),
                RUN_QUEUED,
                RUN_CLAIMED,
                RUN_RECORDED,
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    stored
        .map(|bytes| backup_identifier(&bytes))
        .transpose()?
        .map(|backup_id| load(connection, backup_id)?.ok_or(RepositoryError::CorruptState))
        .transpose()
}

pub(super) fn run_head(
    connection: &Connection,
    backup_id: BackupId,
) -> Result<RunHead, RepositoryError> {
    connection
        .query_row(
            "SELECT partition_id, state, minimum_verified_copies,
                    minimum_independent_copies
             FROM metadata_backup_runs WHERE backup_id = ?1",
            [backup_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)
        .and_then(|stored| {
            Ok(RunHead {
                partition_id: partition_identifier(&stored.0)?,
                state: decode_state_code(stored.1)?,
                minimum_verified_copies: u8::try_from(stored.2)
                    .map_err(|_| RepositoryError::CorruptState)?,
                minimum_independent_copies: u8::try_from(stored.3)
                    .map_err(|_| RepositoryError::CorruptState)?,
            })
        })
}

pub(super) fn active_claim(
    connection: &Connection,
    backup_id: BackupId,
) -> Result<Option<MetadataBackupRunClaimRecord>, RepositoryError> {
    connection
        .query_row(
            "SELECT claim_generation, worker_node_id, worker_incarnation, fence,
                    lease_expires_at, revision
             FROM metadata_backup_run_claims WHERE backup_id = ?1 AND state = ?2",
            params![backup_id.as_bytes().as_slice(), CLAIM_ACTIVE],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?
        .map(|stored| build_claim(backup_id, &stored))
        .transpose()
}

pub(super) fn require_live_claim(
    connection: &Connection,
    context: CommandContext,
    backup_id: BackupId,
    claim: MetadataBackupRunClaim,
) -> Result<MetadataBackupRunClaimRecord, RepositoryError> {
    let current = active_claim(connection, backup_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if current.claim == claim && current.lease_expires_at > context.occurred_at {
        Ok(current)
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

pub(super) fn latest_claim_generation(
    connection: &Connection,
    backup_id: BackupId,
) -> Result<u64, RepositoryError> {
    let generation = connection.query_row(
        "SELECT coalesce(max(claim_generation), 0)
         FROM metadata_backup_run_claims WHERE backup_id = ?1",
        [backup_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )?;
    parse_u64(generation)
}

pub(super) fn verified_copy_counts(
    connection: &Connection,
    backup_id: BackupId,
) -> Result<(u64, u64), RepositoryError> {
    let stored = connection.query_row(
        "SELECT count(*),
                coalesce(sum(CASE WHEN d.failure_relationship = 3 THEN 1 ELSE 0 END), 0)
         FROM backup_copies c JOIN backup_destinations d USING(destination_id)
         WHERE c.backup_id = ?1 AND c.state = 2 AND d.state IN (1, 2)",
        [backup_id.as_bytes().as_slice()],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok((parse_u64(stored.0)?, parse_u64(stored.1)?))
}

type StoredRun = (
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<Vec<u8>>,
    i64,
);

type StoredClaim = (i64, Vec<u8>, i64, i64, i64, i64);

fn decode_run(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRun> {
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
        row.get(9)?,
    ))
}

fn build_run(backup_id: BackupId, stored: StoredRun) -> Result<MetadataBackupRun, RepositoryError> {
    let state = decode_state(stored.6)?;
    let terminal = matches!(
        state,
        MetadataBackupRunState::Protected | MetadataBackupRunState::Incomplete
    );
    let result_digest = stored.8.map(|value| digest32(&value)).transpose()?;
    if terminal != (stored.7.is_some() && result_digest.is_some()) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(MetadataBackupRun {
        backup_id,
        partition_id: partition_identifier(&stored.0)?,
        schedule_sequence: parse_u64(stored.1)?,
        run_sequence: parse_u64(stored.2)?,
        scheduled_for: UnixMicros::new(stored.3),
        minimum_verified_copies: u8::try_from(stored.4)
            .map_err(|_| RepositoryError::CorruptState)?,
        minimum_independent_copies: u8::try_from(stored.5)
            .map_err(|_| RepositoryError::CorruptState)?,
        state,
        completed_at: stored.7.map(UnixMicros::new),
        result_digest,
        revision: Revision::new(parse_u64(stored.9)?),
    })
}

fn build_claim(
    backup_id: BackupId,
    stored: &StoredClaim,
) -> Result<MetadataBackupRunClaimRecord, RepositoryError> {
    Ok(MetadataBackupRunClaimRecord {
        backup_id,
        claim: MetadataBackupRunClaim {
            claim_generation: parse_u64(stored.0)?,
            worker_node_id: node_identifier(&stored.1)?,
            worker_incarnation: parse_u64(stored.2)?,
            fence: parse_u64(stored.3)?,
        },
        lease_expires_at: UnixMicros::new(stored.4),
        revision: Revision::new(parse_u64(stored.5)?),
    })
}

fn decode_state(value: i64) -> Result<MetadataBackupRunState, RepositoryError> {
    match value {
        RUN_QUEUED => Ok(MetadataBackupRunState::Queued),
        RUN_CLAIMED => Ok(MetadataBackupRunState::Claimed),
        RUN_RECORDED => Ok(MetadataBackupRunState::Recorded),
        RUN_PROTECTED => Ok(MetadataBackupRunState::Protected),
        RUN_INCOMPLETE => Ok(MetadataBackupRunState::Incomplete),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn decode_state_code(value: i64) -> Result<i64, RepositoryError> {
    decode_state(value).map(|_| value)
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn partition_identifier(value: &[u8]) -> Result<PartitionId, RepositoryError> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    PartitionId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)
}

fn backup_identifier(value: &[u8]) -> Result<BackupId, RepositoryError> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    BackupId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)
}

fn node_identifier(value: &[u8]) -> Result<NodeId, RepositoryError> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    NodeId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)
}

fn digest32(value: &[u8]) -> Result<[u8; 32], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
