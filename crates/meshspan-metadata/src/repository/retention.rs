// SPDX-License-Identifier: GPL-2.0-only

//! Immutable per-volume file-version retention policy revisions.

use meshspan_domain::{DurationMicros, Revision, UnixMicros, VolumeId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, ConfigureVersionRetention, PartitionDatabase, RetentionReclaimMode};

type StoredPolicy = (
    i64,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    i64,
    i64,
    i64,
    i64,
    i64,
);

/// Current independently validated file-version retention policy for one volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionRetentionPolicy {
    /// Volume governed by this policy.
    pub volume_id: VolumeId,
    /// Monotonic immutable policy sequence.
    pub sequence: u64,
    /// Whether future superseded versions enter ordinary history.
    pub history_enabled: bool,
    /// Ordinary minimum retention age.
    pub minimum_age: DurationMicros,
    /// Optional maximum retention age.
    pub maximum_age: Option<DurationMicros>,
    /// Optional count of newest historical versions retained.
    pub minimum_versions: Option<u32>,
    /// Reclamation trigger after reachability guards pass.
    pub reclaim_mode: RetentionReclaimMode,
    /// Whether critical pressure may break the ordinary minimum.
    pub soft_minimum_breakable: bool,
    /// Mandatory safety age for acknowledged conflict alternatives.
    pub conflict_minimum_age: DurationMicros,
    /// Authoritative configuration instant.
    pub configured_at: UnixMicros,
    /// Replicated state revision that selected this policy.
    pub revision: Revision,
}

pub(super) fn configure(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: ConfigureVersionRetention,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate(command)?;
    let current: Option<i64> = transaction
        .query_row(
            "SELECT policy_sequence FROM version_retention_policy_revisions
             WHERE volume_id = ?1 ORDER BY policy_sequence DESC LIMIT 1",
            [command.volume_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let current = current.ok_or(RepositoryError::InvalidCommand)?;
    if parse_u64(current)? != command.expected_policy_sequence {
        return Err(RepositoryError::StaleRetentionPolicy);
    }
    let sequence = command
        .expected_policy_sequence
        .checked_add(1)
        .ok_or(RepositoryError::CapacityExceeded)?;
    transaction.execute(
        "INSERT INTO version_retention_policy_revisions(
            volume_id, policy_sequence, history_enabled, minimum_age_micros,
            maximum_age_micros, minimum_versions, reclaim_mode, soft_minimum_breakable,
            conflict_minimum_age_micros, configured_by, configured_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            command.volume_id.as_bytes().as_slice(),
            to_i64(sequence)?,
            command.history_enabled,
            duration_i64(command.minimum_age)?,
            command.maximum_age.map(duration_i64).transpose()?,
            command.minimum_versions.map(i64::from),
            mode_code(command.reclaim_mode),
            command.soft_minimum_breakable,
            duration_i64(command.conflict_minimum_age)?,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::Volume,
        id: command.volume_id.as_bytes(),
    })
}

fn validate(command: ConfigureVersionRetention) -> Result<(), RepositoryError> {
    if command.expected_policy_sequence == 0
        || command.minimum_versions == Some(0)
        || command
            .maximum_age
            .is_some_and(|maximum| maximum < command.minimum_age)
        || command.conflict_minimum_age < command.minimum_age
        || command.reclaim_mode == RetentionReclaimMode::AfterMaximumAge
            && command.maximum_age.is_none()
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

pub(super) fn load(
    database: &PartitionDatabase,
    volume_id: VolumeId,
) -> Result<Option<VersionRetentionPolicy>, RepositoryError> {
    let stored: Option<StoredPolicy> = database
        .connection()
        .query_row(
            "SELECT policy_sequence, history_enabled, minimum_age_micros,
                    maximum_age_micros, minimum_versions, reclaim_mode,
                    soft_minimum_breakable, conflict_minimum_age_micros,
                    configured_at, revision
             FROM version_retention_policy_revisions WHERE volume_id = ?1
             ORDER BY policy_sequence DESC LIMIT 1",
            [volume_id.as_bytes().as_slice()],
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
                    row.get(9)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let policy = decode(volume_id, stored)?;
    let count: i64 = database.connection().query_row(
        "SELECT count(*) FROM version_retention_policy_revisions WHERE volume_id = ?1",
        [volume_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if policy.sequence != parse_u64(count)? {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(policy))
}

fn decode(
    volume_id: VolumeId,
    stored: StoredPolicy,
) -> Result<VersionRetentionPolicy, RepositoryError> {
    let sequence = parse_u64(stored.0)?;
    if !matches!(stored.1, 0 | 1) || !matches!(stored.6, 0 | 1) {
        return Err(RepositoryError::CorruptState);
    }
    let minimum_versions = stored
        .4
        .map(|value| u32::try_from(value).map_err(|_| RepositoryError::CorruptState))
        .transpose()?;
    if minimum_versions == Some(0) {
        return Err(RepositoryError::CorruptState);
    }
    let policy = VersionRetentionPolicy {
        volume_id,
        sequence,
        history_enabled: stored.1 == 1,
        minimum_age: duration(stored.2)?,
        maximum_age: stored.3.map(duration).transpose()?,
        minimum_versions,
        reclaim_mode: parse_mode(stored.5)?,
        soft_minimum_breakable: stored.6 == 1,
        conflict_minimum_age: duration(stored.7)?,
        configured_at: UnixMicros::new(stored.8),
        revision: Revision::new(parse_u64(stored.9)?),
    };
    if policy
        .maximum_age
        .is_some_and(|maximum| maximum < policy.minimum_age)
        || policy.conflict_minimum_age < policy.minimum_age
        || policy.reclaim_mode == RetentionReclaimMode::AfterMaximumAge
            && policy.maximum_age.is_none()
    {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(policy)
    }
}

const fn mode_code(mode: RetentionReclaimMode) -> u8 {
    match mode {
        RetentionReclaimMode::UnderPressure => 1,
        RetentionReclaimMode::AfterMaximumAge => 2,
        RetentionReclaimMode::EagerAfterMinimumAge => 3,
    }
}

fn parse_mode(value: i64) -> Result<RetentionReclaimMode, RepositoryError> {
    match value {
        1 => Ok(RetentionReclaimMode::UnderPressure),
        2 => Ok(RetentionReclaimMode::AfterMaximumAge),
        3 => Ok(RetentionReclaimMode::EagerAfterMinimumAge),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn duration_i64(value: DurationMicros) -> Result<i64, RepositoryError> {
    i64::try_from(value.get()).map_err(|_| RepositoryError::CapacityExceeded)
}

fn duration(value: i64) -> Result<DurationMicros, RepositoryError> {
    parse_u64(value).map(DurationMicros::new)
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
