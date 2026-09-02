// SPDX-License-Identifier: GPL-2.0-only

//! Unified read model for target, node and shared-failure-group drains.

use meshspan_domain::{FaultGroupId, NodeId, PrincipalId, Revision, TargetId, UnixMicros, WorkId};
use meshspan_work::DrainScope;
use rusqlite::{Row, params};

use super::super::{Page, PageLimit, RepositoryError};
use crate::PartitionDatabase;

const TARGET_SCOPE: i64 = 1;
const NODE_SCOPE: i64 = 2;
const FAULT_GROUP_SCOPE: i64 = 3;

/// Publicly useful lifecycle shared by every storage-drain scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageDrainState {
    /// New placement is fenced while protected bytes evacuate.
    Evacuating,
    /// An evacuated node is leaving consensus membership.
    MembershipFenced,
    /// The exact scope has durable evidence that it may be detached.
    SafeToDetach,
}

/// One independently decoded durable drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageDrainRecord {
    /// Stable drain/work identity.
    pub drain_id: WorkId,
    /// Generation-fenced target, node incarnation or shared-failure group.
    pub scope: DrainScope,
    /// Whether temporary policy debt is accepted once recoverability is proved.
    pub allow_temporary_degraded: bool,
    /// Whether physical cleanup was requested after safe completion.
    pub cleanup_requested: bool,
    /// Principal which requested the drain.
    pub requested_by: PrincipalId,
    /// Authoritative admission instant.
    pub requested_at: UnixMicros,
    /// Current authoritative lifecycle.
    pub state: StorageDrainState,
    /// Terminal safe instant, when present.
    pub safe_at: Option<UnixMicros>,
    /// Latest authoritative revision.
    pub revision: Revision,
}

/// Opaque keyset fields for a newest-first drain page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageDrainCursor {
    requested_at: UnixMicros,
    scope_order: u8,
    drain_id: WorkId,
}

impl StorageDrainCursor {
    /// Reconstructs a cursor after the public codec has validated every field.
    #[must_use]
    pub const fn new(requested_at: UnixMicros, scope_order: u8, drain_id: WorkId) -> Self {
        Self {
            requested_at,
            scope_order,
            drain_id,
        }
    }

    /// Returns the request instant seek field.
    #[must_use]
    pub const fn requested_at(self) -> UnixMicros {
        self.requested_at
    }

    /// Returns the stable scope ordering field.
    #[must_use]
    pub const fn scope_order(self) -> u8 {
        self.scope_order
    }

    /// Returns the stable drain identity seek field.
    #[must_use]
    pub const fn drain_id(self) -> WorkId {
        self.drain_id
    }
}

/// One newest-first drain page.
pub type StorageDrainStatusPage = Page<StorageDrainRecord, StorageDrainCursor>;

pub(crate) fn load(
    database: &PartitionDatabase,
    drain_id: WorkId,
) -> Result<Option<StorageDrainRecord>, RepositoryError> {
    let sql = format!("{} WHERE drain_id = ?1 LIMIT 2", inventory_query());
    let mut statement = database.connection().prepare(&sql)?;
    let mut records = statement
        .query_map([drain_id.as_bytes().as_slice()], decode_record)?
        .collect::<Result<Vec<_>, _>>()?;
    match records.len() {
        0 => Ok(None),
        1 => Ok(records.pop()),
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(crate) fn page(
    database: &PartitionDatabase,
    after: Option<StorageDrainCursor>,
    limit: PageLimit,
) -> Result<StorageDrainStatusPage, RepositoryError> {
    let after_time = after.map_or(i64::MAX, |cursor| cursor.requested_at.get());
    let after_scope = after.map_or(i64::MAX, |cursor| i64::from(cursor.scope_order));
    let after_id = after.map_or([u8::MAX; 16], |cursor| cursor.drain_id.as_bytes());
    let row_limit = limit
        .get()
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(RepositoryError::InvalidPageLimit)?;
    let sql = format!(
        "{} WHERE requested_at < ?1
             OR (requested_at = ?1 AND scope_kind < ?2)
             OR (requested_at = ?1 AND scope_kind = ?2 AND drain_id < ?3)
         ORDER BY requested_at DESC, scope_kind DESC, drain_id DESC LIMIT ?4",
        inventory_query()
    );
    let mut statement = database.connection().prepare(&sql)?;
    let mut records = statement
        .query_map(
            params![after_time, after_scope, after_id.as_slice(), row_limit],
            decode_record,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let next = if records.len() > limit.get() {
        records.pop();
        records.last().map(|record| {
            StorageDrainCursor::new(
                record.requested_at,
                scope_order(record.scope),
                record.drain_id,
            )
        })
    } else {
        None
    };
    Ok(Page {
        items: records,
        next,
    })
}

fn inventory_query() -> &'static str {
    "WITH drain_inventory AS (
        SELECT work_id AS drain_id, 1 AS scope_kind, target_id AS scope_id,
               target_generation AS scope_generation, allow_temporary_degraded,
               cleanup_requested, state, requested_by, requested_at, safe_at, revision
        FROM storage_target_drains
        UNION ALL
        SELECT drain_id, scope_kind + 1, scope_id, scope_incarnation,
               allow_temporary_degraded, cleanup_requested, state, requested_by,
               requested_at, safe_at, revision
        FROM storage_scope_drains
     )
     SELECT drain_id, scope_kind, scope_id, scope_generation,
            allow_temporary_degraded, cleanup_requested, state, requested_by,
            requested_at, safe_at, revision
     FROM drain_inventory"
}

fn decode_record(row: &Row<'_>) -> rusqlite::Result<StorageDrainRecord> {
    let drain_id = WorkId::from_bytes(bytes::<16>(row, 0)?)
        .map_err(|_| invalid(0, "invalid drain identity"))?;
    let scope_kind = row.get::<_, i64>(1)?;
    let scope_id = bytes::<16>(row, 2)?;
    let generation = row.get::<_, Option<i64>>(3)?;
    let scope = decode_scope(scope_kind, scope_id, generation)?;
    let state_code = row.get::<_, i64>(6)?;
    let state = decode_state(scope_kind, state_code)?;
    let requested_at = UnixMicros::new(row.get(8)?);
    let safe_at = row.get::<_, Option<i64>>(9)?.map(UnixMicros::new);
    if (state == StorageDrainState::SafeToDetach) != safe_at.is_some() {
        return Err(invalid(9, "contradictory safe instant"));
    }
    Ok(StorageDrainRecord {
        drain_id,
        scope,
        allow_temporary_degraded: boolean(row, 4)?,
        cleanup_requested: boolean(row, 5)?,
        requested_by: PrincipalId::from_bytes(bytes::<16>(row, 7)?)
            .map_err(|_| invalid(7, "invalid requesting principal"))?,
        requested_at,
        state,
        safe_at,
        revision: Revision::new(positive(row, 10)?),
    })
}

fn decode_scope(kind: i64, id: [u8; 16], generation: Option<i64>) -> rusqlite::Result<DrainScope> {
    match (kind, generation) {
        (TARGET_SCOPE, Some(value)) => Ok(DrainScope::Target {
            target_id: TargetId::from_bytes(id).map_err(|_| invalid(2, "invalid target"))?,
            target_generation: positive_value(value, 3)?,
        }),
        (NODE_SCOPE, Some(value)) => Ok(DrainScope::Node {
            node_id: NodeId::from_bytes(id).map_err(|_| invalid(2, "invalid node"))?,
            node_incarnation: positive_value(value, 3)?,
        }),
        (FAULT_GROUP_SCOPE, None) => Ok(DrainScope::FaultGroup {
            fault_group_id: FaultGroupId::from_bytes(id)
                .map_err(|_| invalid(2, "invalid fault group"))?,
        }),
        _ => Err(invalid(1, "invalid drain scope")),
    }
}

fn decode_state(kind: i64, state: i64) -> rusqlite::Result<StorageDrainState> {
    match (kind, state) {
        (TARGET_SCOPE | NODE_SCOPE | FAULT_GROUP_SCOPE, 1) => Ok(StorageDrainState::Evacuating),
        (NODE_SCOPE, 2) => Ok(StorageDrainState::MembershipFenced),
        (TARGET_SCOPE, 2) | (NODE_SCOPE | FAULT_GROUP_SCOPE, 3) => {
            Ok(StorageDrainState::SafeToDetach)
        }
        _ => Err(invalid(6, "invalid drain state")),
    }
}

const fn scope_order(scope: DrainScope) -> u8 {
    match scope {
        DrainScope::Target { .. } => 1,
        DrainScope::Node { .. } => 2,
        DrainScope::FaultGroup { .. } => 3,
    }
}

fn boolean(row: &Row<'_>, index: usize) -> rusqlite::Result<bool> {
    match row.get::<_, i64>(index)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid(index, "invalid boolean")),
    }
}

fn positive(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    positive_value(row.get(index)?, index)
}

fn positive_value(value: i64, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid(index, "expected positive integer"))
}

fn bytes<const N: usize>(row: &Row<'_>, index: usize) -> rusqlite::Result<[u8; N]> {
    row.get::<_, Vec<u8>>(index)?
        .try_into()
        .map_err(|_| invalid(index, "invalid byte length"))
}

fn invalid(index: usize, message: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Blob,
        std::io::Error::new(std::io::ErrorKind::InvalidData, message).into(),
    )
}
