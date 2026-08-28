// SPDX-License-Identifier: GPL-2.0-only

//! Durable history classification and bounded preliminary version reclamation selection.

use meshspan_domain::{
    BranchId, ContentManifestId, DurationMicros, FileVersionId, ObjectId, UnixMicros, VolumeId,
};
use rusqlite::{Connection, Transaction, params};
use thiserror::Error;

use crate::publication::{FilePublication, PublicationError};

const MAXIMUM_PAGE_SIZE: usize = 4_096;

/// Trigger governing when ordinary historical versions become preliminary candidates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionReclaimMode {
    /// Select only while storage pressure is reported.
    UnderPressure,
    /// Select after the configured maximum age without requiring pressure.
    AfterMaximumAge,
    /// Select eagerly after the ordinary minimum age.
    EagerAfterMinimumAge,
}

/// Current local capacity pressure used only for preliminary selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionRetentionPressure {
    /// No storage pressure.
    None,
    /// Normal pressure permits reclaiming versions beyond the ordinary minimum.
    Pressure,
    /// Critical pressure may break a configured soft minimum as a last resort.
    Critical,
}

/// Exact authoritative policy fields needed by local candidate selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionRetentionSelectionPolicy {
    sequence: u64,
    minimum_age: DurationMicros,
    maximum_age: Option<DurationMicros>,
    minimum_versions: u32,
    reclaim_mode: VersionReclaimMode,
    soft_minimum_breakable: bool,
    conflict_minimum_age: DurationMicros,
}

impl VersionRetentionSelectionPolicy {
    /// Constructs a validated immutable selection view of one replicated policy revision.
    ///
    /// # Errors
    ///
    /// Rejects a zero sequence, unrepresentable ages, inverted bounds, or maximum-age mode
    /// without a maximum.
    pub fn new(
        sequence: u64,
        minimum_age: DurationMicros,
        maximum_age: Option<DurationMicros>,
        minimum_versions: Option<u32>,
        reclaim_mode: VersionReclaimMode,
        soft_minimum_breakable: bool,
        conflict_minimum_age: DurationMicros,
    ) -> Result<Self, VersionRetentionError> {
        if sequence == 0
            || i64::try_from(sequence).is_err()
            || minimum_versions == Some(0)
            || maximum_age.is_some_and(|maximum| maximum < minimum_age)
            || conflict_minimum_age < minimum_age
            || reclaim_mode == VersionReclaimMode::AfterMaximumAge && maximum_age.is_none()
            || duration_i64(minimum_age).is_none()
            || maximum_age.is_some_and(|age| duration_i64(age).is_none())
            || duration_i64(conflict_minimum_age).is_none()
        {
            return Err(VersionRetentionError::InvalidPolicy);
        }
        Ok(Self {
            sequence,
            minimum_age,
            maximum_age,
            minimum_versions: minimum_versions.unwrap_or(0),
            reclaim_mode,
            soft_minimum_breakable,
            conflict_minimum_age,
        })
    }

    /// Replicated immutable policy sequence bound to every returned candidate.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Bounded page size for one independently validated selection query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionRetentionPageLimit(usize);

impl VersionRetentionPageLimit {
    /// Creates a non-zero page bound no larger than the implementation ceiling.
    ///
    /// # Errors
    ///
    /// Rejects zero and excessive limits.
    pub const fn new(value: usize) -> Result<Self, VersionRetentionError> {
        if value == 0 || value > MAXIMUM_PAGE_SIZE {
            Err(VersionRetentionError::InvalidLimit)
        } else {
            Ok(Self(value))
        }
    }
}

/// Stable seek cursor ordered by supersession time then immutable version identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionRetentionCursor {
    superseded_at: UnixMicros,
    branch_id: BranchId,
    version_id: FileVersionId,
}

/// Why one version passed preliminary retention selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionRetentionCandidateReason {
    /// Ordinary history was disabled when this version was superseded.
    HistoryDisabled,
    /// The configured maximum age elapsed.
    MaximumAge,
    /// Normal pressure selected a version beyond its minimum retention.
    Pressure,
    /// Critical pressure exercised the explicit soft-minimum escape hatch.
    CriticalPressure,
    /// The mandatory conflict-alternative safety age elapsed.
    ConflictSafetyElapsed,
    /// Eager policy selected a version beyond its ordinary minimum age.
    MinimumAge,
}

/// One bounded preliminary candidate; physical cleanup still requires reachability authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionRetentionCandidate {
    /// Immutable historical file version.
    pub version_id: FileVersionId,
    /// Version that superseded this one on its original branch.
    pub superseded_by_version_id: FileVersionId,
    /// Original writable branch.
    pub branch_id: BranchId,
    /// Volume containing the logical file.
    pub volume_id: VolumeId,
    /// Stable logical file identity.
    pub object_id: ObjectId,
    /// Immutable content manifest selected by the version.
    pub manifest_id: ContentManifestId,
    /// Logical bytes represented by the version.
    pub logical_length: u64,
    /// Authoritative instant at which the version stopped being current.
    pub superseded_at: UnixMicros,
    /// Exact policy sequence used for selection.
    pub policy_sequence: u64,
    /// Policy sequence that classified this version when it was superseded.
    pub supersession_policy_sequence: u64,
    /// Typed reason the version became eligible for a reachability proof.
    pub reason: VersionRetentionCandidateReason,
}

/// One stable candidate page and an optional cursor only when another item exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionRetentionCandidatePage {
    /// Oldest-first candidates.
    pub items: Vec<VersionRetentionCandidate>,
    /// Cursor for the next page, absent at the end.
    pub next: Option<VersionRetentionCursor>,
}

/// Stable retention selection failures.
#[derive(Debug, Error)]
pub enum VersionRetentionError {
    /// Policy fields are inconsistent or cannot be represented safely by SQLite.
    #[error("file-version retention policy is invalid")]
    InvalidPolicy,
    /// Requested page size is zero or exceeds the fixed allocation ceiling.
    #[error("file-version retention page limit is invalid")]
    InvalidLimit,
    /// Durable history classification or file-version state is malformed.
    #[error("file-version retention state is corrupt")]
    Corrupt,
    /// SQLite persistence or query failed.
    #[error("file-version retention database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

pub(crate) fn record_supersession(
    transaction: &Transaction<'_>,
    publication: FilePublication,
) -> Result<(), PublicationError> {
    let Some(previous) = publication.expected_current_version_id else {
        return Ok(());
    };
    let stored: (Vec<u8>, Vec<u8>, i64) = transaction.query_row(
        "SELECT volume_id, object_id, created_at
         FROM file_versions WHERE version_id = ?1",
        [previous.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if stored.0.as_slice() != publication.volume_id.as_bytes()
        || stored.1.as_slice() != publication.object_id.as_bytes()
        || stored.2 > publication.created_at.get()
    {
        return Err(PublicationError::Corrupt);
    }
    transaction.execute(
        "INSERT INTO file_version_history(
            branch_id, version_id, superseded_by_version_id, superseded_at,
            ordinary_history_enabled, policy_sequence
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            publication.branch_id.as_bytes().as_slice(),
            previous.as_bytes().as_slice(),
            publication.version_id.as_bytes().as_slice(),
            publication.created_at.get(),
            publication.retain_superseded_history,
            i64::try_from(publication.retention_policy_sequence)
                .map_err(|_| PublicationError::InvalidInput)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn record_conflict_protection(
    transaction: &Transaction<'_>,
    version_id: FileVersionId,
    observed_at: UnixMicros,
) -> Result<(), PublicationError> {
    let created_at: i64 = transaction.query_row(
        "SELECT created_at FROM file_versions WHERE version_id = ?1",
        [version_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if observed_at.get() < created_at {
        return Err(PublicationError::Corrupt);
    }
    transaction.execute(
        "INSERT INTO file_version_conflict_protections(version_id, first_observed_at)
         VALUES (?1, ?2)
         ON CONFLICT(version_id) DO UPDATE SET
             first_observed_at = min(first_observed_at, excluded.first_observed_at)",
        params![version_id.as_bytes().as_slice(), observed_at.get()],
    )?;
    Ok(())
}

pub(crate) fn select_candidates(
    connection: &Connection,
    volume_id: VolumeId,
    policy: VersionRetentionSelectionPolicy,
    pressure: VersionRetentionPressure,
    now: UnixMicros,
    after: Option<VersionRetentionCursor>,
    limit: VersionRetentionPageLimit,
) -> Result<VersionRetentionCandidatePage, VersionRetentionError> {
    let minimum_cutoff = cutoff(now, policy.minimum_age)?;
    let maximum_cutoff = policy.maximum_age.map(|age| cutoff(now, age)).transpose()?;
    let conflict_cutoff = cutoff(now, policy.conflict_minimum_age)?;
    let ordinary_cutoff = ordinary_cutoff(policy, pressure, now, minimum_cutoff, maximum_cutoff);
    let row_limit = i64::try_from(
        limit
            .0
            .checked_add(1)
            .ok_or(VersionRetentionError::InvalidLimit)?,
    )
    .map_err(|_| VersionRetentionError::InvalidLimit)?;
    let rows = load_candidate_rows(
        connection,
        CandidateQuery {
            volume_id,
            after,
            now: now.get(),
            conflict_cutoff,
            minimum_versions: policy.minimum_versions,
            ordinary_cutoff,
            row_limit,
        },
    )?;
    let mut items = Vec::with_capacity(limit.0.saturating_add(1));
    for row in &rows {
        items.push(decode_candidate(
            row,
            policy,
            pressure,
            minimum_cutoff,
            maximum_cutoff,
        )?);
    }
    let next = (items.len() > limit.0).then(|| {
        let last = items[limit.0 - 1];
        VersionRetentionCursor {
            superseded_at: last.superseded_at,
            branch_id: last.branch_id,
            version_id: last.version_id,
        }
    });
    items.truncate(limit.0);
    Ok(VersionRetentionCandidatePage { items, next })
}

#[derive(Clone, Copy)]
struct CandidateQuery {
    volume_id: VolumeId,
    after: Option<VersionRetentionCursor>,
    now: i64,
    conflict_cutoff: i64,
    minimum_versions: u32,
    ordinary_cutoff: Option<i64>,
    row_limit: i64,
}

fn load_candidate_rows(
    connection: &Connection,
    query: CandidateQuery,
) -> Result<Vec<StoredCandidate>, VersionRetentionError> {
    let after_time = query.after.map(|cursor| cursor.superseded_at.get());
    let after_branch = query
        .after
        .map_or([0; 16], |cursor| cursor.branch_id.as_bytes());
    let after_id = query
        .after
        .map_or([0; 16], |cursor| cursor.version_id.as_bytes());
    let mut statement = connection.prepare(
        "WITH historical AS (
            SELECT versions.version_id, history.superseded_by_version_id,
                   history.branch_id, versions.volume_id, versions.object_id,
                   versions.manifest_id, versions.logical_length, history.superseded_at,
                   history.ordinary_history_enabled, history.policy_sequence,
                   conflicts.first_observed_at,
                   versions.created_at AS version_created_at,
                   successors.branch_id AS successor_branch_id,
                   successors.volume_id AS successor_volume_id,
                   successors.object_id AS successor_object_id,
                   successors.created_at AS successor_created_at,
                   sum(CASE
                       WHEN history.ordinary_history_enabled = 1
                        AND conflicts.first_observed_at IS NULL THEN 1 ELSE 0
                   END) OVER (
                       PARTITION BY history.branch_id, versions.object_id
                       ORDER BY history.superseded_at DESC, versions.version_id DESC
                   ) AS ordinary_history_rank
            FROM file_versions AS versions
            JOIN file_version_history AS history USING(version_id)
            JOIN file_versions AS successors
              ON successors.version_id = history.superseded_by_version_id
            LEFT JOIN file_version_conflict_protections AS conflicts USING(version_id)
            WHERE versions.volume_id = ?1
              AND NOT EXISTS (
                  SELECT 1 FROM branch_files AS heads
                  WHERE heads.current_version_id = versions.version_id
              )
        )
        SELECT version_id, superseded_by_version_id, branch_id, volume_id, object_id,
               manifest_id, logical_length, superseded_at, ordinary_history_enabled,
               policy_sequence, first_observed_at, version_created_at, successor_branch_id,
               successor_volume_id, successor_object_id, successor_created_at
        FROM historical
        WHERE (?2 IS NULL OR (superseded_at, branch_id, version_id) > (?2, ?3, ?4))
          AND superseded_at <= ?5
          AND (
              (first_observed_at IS NOT NULL AND first_observed_at <= ?6)
              OR
              (first_observed_at IS NULL AND (
                  ordinary_history_enabled = 0
                  OR (ordinary_history_rank > ?7 AND ?8 IS NOT NULL AND superseded_at <= ?8)
              ))
          )
        ORDER BY superseded_at, branch_id, version_id LIMIT ?9",
    )?;
    let rows = statement.query_map(
        params![
            query.volume_id.as_bytes().as_slice(),
            after_time,
            after_branch.as_slice(),
            after_id.as_slice(),
            query.now,
            query.conflict_cutoff,
            i64::from(query.minimum_versions),
            query.ordinary_cutoff,
            query.row_limit,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, Vec<u8>>(13)?,
                row.get::<_, Vec<u8>>(14)?,
                row.get::<_, i64>(15)?,
            ))
        },
    )?;
    let mut stored = Vec::new();
    for row in rows {
        stored.push(row?);
    }
    Ok(stored)
}

type StoredCandidate = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
);

fn decode_candidate(
    stored: &StoredCandidate,
    policy: VersionRetentionSelectionPolicy,
    pressure: VersionRetentionPressure,
    minimum_cutoff: i64,
    maximum_cutoff: Option<i64>,
) -> Result<VersionRetentionCandidate, VersionRetentionError> {
    if !matches!(stored.8, 0 | 1)
        || stored.9 <= 0
        || stored.6 < 0
        || stored.11 > stored.7
        || stored.15 != stored.7
        || stored.10.is_some_and(|observed| observed < stored.11)
        || stored.2 != stored.12
        || stored.3 != stored.13
        || stored.4 != stored.14
    {
        return Err(VersionRetentionError::Corrupt);
    }
    let superseded_at = UnixMicros::new(stored.7);
    let reason = if stored.10.is_some() {
        VersionRetentionCandidateReason::ConflictSafetyElapsed
    } else if stored.8 == 0 {
        VersionRetentionCandidateReason::HistoryDisabled
    } else if maximum_cutoff.is_some_and(|cutoff| superseded_at.get() <= cutoff) {
        VersionRetentionCandidateReason::MaximumAge
    } else {
        match (policy.reclaim_mode, pressure) {
            (VersionReclaimMode::AfterMaximumAge, _) => VersionRetentionCandidateReason::MaximumAge,
            (VersionReclaimMode::EagerAfterMinimumAge, _) => {
                VersionRetentionCandidateReason::MinimumAge
            }
            (VersionReclaimMode::UnderPressure, VersionRetentionPressure::Critical)
                if policy.soft_minimum_breakable && superseded_at.get() > minimum_cutoff =>
            {
                VersionRetentionCandidateReason::CriticalPressure
            }
            (VersionReclaimMode::UnderPressure, _) => VersionRetentionCandidateReason::Pressure,
        }
    };
    let version_id = identifier(&stored.0, FileVersionId::from_bytes)?;
    let superseded_by_version_id = identifier(&stored.1, FileVersionId::from_bytes)?;
    if version_id == superseded_by_version_id {
        return Err(VersionRetentionError::Corrupt);
    }
    Ok(VersionRetentionCandidate {
        version_id,
        superseded_by_version_id,
        branch_id: identifier(&stored.2, BranchId::from_bytes)?,
        volume_id: identifier(&stored.3, VolumeId::from_bytes)?,
        object_id: identifier(&stored.4, ObjectId::from_bytes)?,
        manifest_id: identifier(&stored.5, ContentManifestId::from_bytes)?,
        logical_length: u64::try_from(stored.6).map_err(|_| VersionRetentionError::Corrupt)?,
        superseded_at,
        policy_sequence: policy.sequence,
        supersession_policy_sequence: u64::try_from(stored.9)
            .map_err(|_| VersionRetentionError::Corrupt)?,
        reason,
    })
}

fn ordinary_cutoff(
    policy: VersionRetentionSelectionPolicy,
    pressure: VersionRetentionPressure,
    now: UnixMicros,
    minimum_cutoff: i64,
    maximum_cutoff: Option<i64>,
) -> Option<i64> {
    match policy.reclaim_mode {
        VersionReclaimMode::AfterMaximumAge => maximum_cutoff,
        VersionReclaimMode::EagerAfterMinimumAge => Some(minimum_cutoff),
        VersionReclaimMode::UnderPressure => match pressure {
            VersionRetentionPressure::None => maximum_cutoff,
            VersionRetentionPressure::Critical if policy.soft_minimum_breakable => Some(now.get()),
            VersionRetentionPressure::Pressure | VersionRetentionPressure::Critical => {
                Some(minimum_cutoff)
            }
        },
    }
}

fn cutoff(now: UnixMicros, age: DurationMicros) -> Result<i64, VersionRetentionError> {
    let age = duration_i64(age).ok_or(VersionRetentionError::InvalidPolicy)?;
    now.get()
        .checked_sub(age)
        .ok_or(VersionRetentionError::InvalidPolicy)
}

fn duration_i64(value: DurationMicros) -> Option<i64> {
    i64::try_from(value.get()).ok()
}

fn identifier<T>(
    bytes: &[u8],
    constructor: fn([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, VersionRetentionError> {
    constructor(
        bytes
            .try_into()
            .map_err(|_| VersionRetentionError::Corrupt)?,
    )
    .map_err(|_| VersionRetentionError::Corrupt)
}
