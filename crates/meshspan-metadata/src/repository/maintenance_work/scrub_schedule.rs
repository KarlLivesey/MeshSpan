// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic admission candidates for periodic full-byte storage verification.

use meshspan_domain::{DurationMicros, NodeId, TargetId, UnixMicros};
use rusqlite::{Row, params};

use super::{MAXIMUM_READY_PAGE_ITEMS, positive};
use crate::repository::RepositoryError;

const ACTIVE_TARGET_STATE: i64 = 1;
const ACTIVE_GENERATION_STATE: i64 = 1;
const ACTIVE_NODE_STATE: i64 = 2;
const ACTIVE_HOST_STATE: i64 = 1;

/// Stable seek position in target-identity order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DueStorageScrubCursor {
    target_id: TargetId,
}

impl DueStorageScrubCursor {
    /// Reconstructs one validated continuation position.
    #[must_use]
    pub const fn new(target_id: TargetId) -> Self {
        Self { target_id }
    }

    /// Returns the last target included in the previous page.
    #[must_use]
    pub const fn target_id(self) -> TargetId {
        self.target_id
    }
}

/// One exact local target generation requiring a periodic scrub cycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DueStorageScrub {
    /// Stable storage target identity.
    pub target_id: TargetId,
    /// Exact current generation; path reuse cannot inherit this work.
    pub target_generation: u64,
    /// Stable deadline that made this generation overdue.
    pub due_at: UnixMicros,
    /// Last complete scrub effect, or `None` when this generation has never completed one.
    pub last_completed_at: Option<UnixMicros>,
}

/// One bounded page of overdue local target generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DueStorageScrubPage {
    /// Candidates ordered by stable target identity.
    pub targets: Vec<DueStorageScrub>,
    /// Continuation after the final returned target when another candidate exists.
    pub next: Option<DueStorageScrubCursor>,
}

pub(super) fn due_page(
    connection: &rusqlite::Connection,
    node_id: NodeId,
    now: UnixMicros,
    maximum_verification_age: DurationMicros,
    after: Option<DueStorageScrubCursor>,
    limit: usize,
) -> Result<DueStorageScrubPage, RepositoryError> {
    if maximum_verification_age.get() == 0 || limit == 0 || limit > MAXIMUM_READY_PAGE_ITEMS {
        return Err(RepositoryError::InvalidCommand);
    }
    let age = i64::try_from(maximum_verification_age.get())
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let cutoff = now
        .get()
        .checked_sub(age)
        .ok_or(RepositoryError::InvalidCommand)?;
    let after_id = after.map_or([0_u8; 16], |cursor| cursor.target_id.as_bytes());
    let mut statement = connection.prepare(
        "SELECT st.target_id, st.current_generation, st.admitted_at, latest.completed_at
         FROM storage_targets st
         JOIN target_generations generation
           ON generation.target_id = st.target_id
          AND generation.generation = st.current_generation
         JOIN nodes node ON node.node_id = st.node_id
         JOIN hosts host ON host.host_id = st.host_id
         LEFT JOIN (
             SELECT target_id, target_generation, MAX(committed_at) AS completed_at
             FROM maintenance_scrub_effects
             GROUP BY target_id, target_generation
         ) latest ON latest.target_id = st.target_id
                 AND latest.target_generation = st.current_generation
         WHERE st.node_id = ?1
           AND st.state = ?2 AND st.draining_at IS NULL AND st.retired_at IS NULL
           AND generation.state = ?3 AND generation.retired_at IS NULL
           AND node.state = ?4 AND node.retired_at IS NULL
           AND host.state = ?5 AND host.retired_at IS NULL
           AND COALESCE(latest.completed_at, st.admitted_at) <= ?6
           AND st.target_id > ?7
         ORDER BY st.target_id
         LIMIT ?8",
    )?;
    let rows = statement.query_map(
        params![
            node_id.as_bytes().as_slice(),
            ACTIVE_TARGET_STATE,
            ACTIVE_GENERATION_STATE,
            ACTIVE_NODE_STATE,
            ACTIVE_HOST_STATE,
            cutoff,
            after_id.as_slice(),
            i64::try_from(limit.saturating_add(1))
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| decode_candidate(row, maximum_verification_age),
    )?;
    let mut targets = rows.collect::<Result<Vec<_>, _>>()?;
    let next = if targets.len() > limit {
        targets.pop();
        targets
            .last()
            .map(|target| DueStorageScrubCursor::new(target.target_id))
    } else {
        None
    };
    Ok(DueStorageScrubPage { targets, next })
}

fn decode_candidate(
    row: &Row<'_>,
    maximum_verification_age: DurationMicros,
) -> rusqlite::Result<DueStorageScrub> {
    decode_candidate_inner(row, maximum_verification_age).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_candidate_inner(
    row: &Row<'_>,
    maximum_verification_age: DurationMicros,
) -> Result<DueStorageScrub, RepositoryError> {
    let target_id =
        TargetId::from_bytes(exact(row.get(0)?)?).map_err(|_| RepositoryError::CorruptState)?;
    let admitted_at = UnixMicros::new(row.get(2)?);
    let last_completed_at = row.get::<_, Option<i64>>(3)?.map(UnixMicros::new);
    let due_at = last_completed_at
        .unwrap_or(admitted_at)
        .checked_add(maximum_verification_age)
        .ok_or(RepositoryError::CorruptState)?;
    Ok(DueStorageScrub {
        target_id,
        target_generation: positive(row.get(1)?)?,
        due_at,
        last_completed_at,
    })
}

fn exact<const LENGTH: usize>(value: Vec<u8>) -> Result<[u8; LENGTH], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
