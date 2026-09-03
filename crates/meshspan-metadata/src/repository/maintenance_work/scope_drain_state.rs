// SPDX-License-Identifier: GPL-2.0-only

//! Durable scope-drain projection, next-action planning and safety evidence.

use meshspan_consensus::ActiveQuorumPlan;
use meshspan_domain::{FaultGroupId, NodeId, PrincipalId, Revision, TargetId, UnixMicros, WorkId};
use meshspan_work::DrainScope;
use rusqlite::{OptionalExtension, Row, params};
use sha2::{Digest, Sha256};

use super::super::{Page, PageLimit, RepositoryError};
use super::scope_drain::{
    ACTIVE_TARGET, DRAIN_EVACUATING, DRAIN_MEMBERSHIP_FENCED, DRAIN_SAFE, DRAINING_TARGET,
    FAULT_GROUP_SCOPE, NODE_SCOPE, StorageScopeDrainAction, StorageScopeDrainCursor,
    StorageScopeDrainRecord, StorageScopeDrainState, scope_identifier,
};
use crate::PartitionDatabase;

const TARGET_DRAIN_SAFE: i64 = 2;

pub(crate) fn load(
    database: &PartitionDatabase,
    drain_id: WorkId,
) -> Result<Option<StorageScopeDrainRecord>, RepositoryError> {
    load_record(database.connection(), drain_id)
}

pub(crate) fn next_action(
    database: &PartitionDatabase,
    drain_id: WorkId,
) -> Result<Option<StorageScopeDrainAction>, RepositoryError> {
    let record =
        load_record(database.connection(), drain_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if record.state == StorageScopeDrainState::SafeToDetach {
        return Ok(None);
    }
    let targets = target_states(database.connection(), &record)?;
    for target in &targets {
        match target.drain_state {
            None if target.target_state == ACTIVE_TARGET => {
                return Ok(Some(StorageScopeDrainAction::BeginTarget {
                    drain_id,
                    target_id: target.target_id,
                    target_generation: target.target_generation,
                    allow_temporary_degraded: record.allow_temporary_degraded,
                    cleanup_requested: record.cleanup_requested,
                    requested_by: record.requested_by,
                    requested_at: record.requested_at,
                }));
            }
            None => return Ok(None),
            Some(state) if state < TARGET_DRAIN_SAFE => return Ok(None),
            Some(_) if target.safety_evidence_digest.is_none() => {
                return Err(RepositoryError::CorruptState);
            }
            Some(_) => {}
        }
    }
    match (record.state, record.scope) {
        (
            StorageScopeDrainState::Evacuating,
            DrainScope::Node {
                node_id,
                node_incarnation,
            },
        ) if membership_can_retire_node(database.connection(), node_id)? => {
            Ok(Some(StorageScopeDrainAction::FenceNodeMembership {
                drain_id,
                node_id,
                node_incarnation,
                requested_by: record.requested_by,
                requested_at: record.requested_at,
            }))
        }
        (StorageScopeDrainState::Evacuating, DrainScope::FaultGroup { .. })
        | (StorageScopeDrainState::MembershipFenced, DrainScope::Node { .. })
            if !scope_node_is_consensus_member(database.connection(), record.scope)? =>
        {
            Ok(Some(StorageScopeDrainAction::Complete {
                drain_id,
                safety_evidence_digest: completion_evidence(database.connection(), &record)?,
                requested_by: record.requested_by,
                requested_at: record.requested_at,
            }))
        }
        _ => Ok(None),
    }
}

pub(crate) fn pending_page(
    database: &PartitionDatabase,
    after: Option<StorageScopeDrainCursor>,
    limit: PageLimit,
) -> Result<Page<StorageScopeDrainRecord, StorageScopeDrainCursor>, RepositoryError> {
    let after_time = after.map_or(i64::MIN, |cursor| cursor.requested_at().get());
    let after_id = after.map_or([0; 16], |cursor| cursor.drain_id().as_bytes());
    let row_limit = limit
        .get()
        .checked_add(1)
        .ok_or(RepositoryError::InvalidPageLimit)?;
    let mut statement = database.connection().prepare(
        "SELECT scope_kind, scope_id, scope_incarnation, allow_temporary_degraded,
                cleanup_requested, state, requested_by, requested_at, revision, drain_id
         FROM storage_scope_drains
         WHERE state < 3 AND (requested_at > ?1 OR (requested_at = ?1 AND drain_id > ?2))
         ORDER BY requested_at, drain_id LIMIT ?3",
    )?;
    let mut records = statement
        .query_map(
            params![
                after_time,
                after_id.as_slice(),
                i64::try_from(row_limit).map_err(|_| RepositoryError::InvalidPageLimit)?
            ],
            decode_pending_record,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let next = if records.len() > limit.get() {
        records.pop();
        records
            .last()
            .map(|record| StorageScopeDrainCursor::new(record.requested_at, record.drain_id))
    } else {
        None
    };
    Ok(Page {
        items: records,
        next,
    })
}

pub(super) fn all_targets_safe(
    connection: &rusqlite::Connection,
    record: &StorageScopeDrainRecord,
) -> Result<bool, RepositoryError> {
    Ok(target_states(connection, record)?.iter().all(|target| {
        target
            .drain_state
            .is_some_and(|state| state >= TARGET_DRAIN_SAFE)
            && target.safety_evidence_digest.is_some()
    }))
}

pub(super) fn membership_can_retire_node(
    connection: &rusqlite::Connection,
    node_id: NodeId,
) -> Result<bool, RepositoryError> {
    let blocked = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM partition_voters retiring
            WHERE retiring.node_id = ?1 AND retiring.state IN (1, 2)
              AND retiring.member_role = 1
              AND NOT EXISTS(
                SELECT 1 FROM partition_voters survivor
                WHERE survivor.partition_id = retiring.partition_id
                  AND survivor.node_id != retiring.node_id
                  AND survivor.member_role = 1 AND survivor.state = 1)
         )",
        [node_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(blocked == 0)
}

pub(super) fn scope_node_is_consensus_member(
    connection: &rusqlite::Connection,
    scope: DrainScope,
) -> Result<bool, RepositoryError> {
    let DrainScope::Node { node_id, .. } = scope else {
        return Ok(false);
    };
    let encoded = connection
        .query_row(
            "SELECT canonical_plan FROM consensus_active_quorum_plan WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(encoded) = encoded else {
        return Err(RepositoryError::CorruptState);
    };
    let plan = ActiveQuorumPlan::decode(&encoded).map_err(|_| RepositoryError::CorruptState)?;
    Ok(plan.members().contains(&node_id))
}

pub(super) fn completion_evidence(
    connection: &rusqlite::Connection,
    record: &StorageScopeDrainRecord,
) -> Result<[u8; 32], RepositoryError> {
    let targets = target_states(connection, record)?;
    if !targets.iter().all(|target| {
        target
            .drain_state
            .is_some_and(|state| state >= TARGET_DRAIN_SAFE)
            && target.safety_evidence_digest.is_some()
    }) {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut digest = Sha256::new();
    digest.update(b"meshspan.storage-scope-drain-safe.v1");
    digest.update(record.drain_id.as_bytes());
    digest.update(WorkSubjectBytes::new(record.scope));
    digest.update([u8::from(record.allow_temporary_degraded)]);
    digest.update([u8::from(record.cleanup_requested)]);
    for target in targets {
        digest.update(target.target_id.as_bytes());
        digest.update(target.target_generation.to_be_bytes());
        digest.update(
            target
                .safety_evidence_digest
                .ok_or(RepositoryError::CorruptState)?,
        );
    }
    if let DrainScope::Node { .. } = record.scope {
        let encoded = connection.query_row(
            "SELECT canonical_plan FROM consensus_active_quorum_plan WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let plan = ActiveQuorumPlan::decode(&encoded).map_err(|_| RepositoryError::CorruptState)?;
        digest.update(plan.proof_digest());
    }
    Ok(digest.finalize().into())
}

pub(super) fn load_record(
    connection: &rusqlite::Connection,
    drain_id: WorkId,
) -> Result<Option<StorageScopeDrainRecord>, RepositoryError> {
    connection
        .query_row(
            "SELECT scope_kind, scope_id, scope_incarnation, allow_temporary_degraded,
                    cleanup_requested, state, requested_by, requested_at, revision
             FROM storage_scope_drains WHERE drain_id = ?1",
            [drain_id.as_bytes().as_slice()],
            |row| decode_record(row, drain_id),
        )
        .optional()
        .map_err(Into::into)
}

fn target_states(
    connection: &rusqlite::Connection,
    record: &StorageScopeDrainRecord,
) -> Result<Vec<TargetDrainState>, RepositoryError> {
    let query = match record.scope {
        DrainScope::Node { .. } => {
            "SELECT st.target_id, st.current_generation, st.state, d.state,
                    d.safety_evidence_digest
             FROM storage_targets st
             LEFT JOIN storage_target_drains d
               ON d.target_id = st.target_id AND d.target_generation = st.current_generation
             WHERE st.node_id = ?1 AND st.state != 5 AND st.retired_at IS NULL
             ORDER BY st.target_id"
        }
        DrainScope::FaultGroup { .. } => {
            "SELECT st.target_id, st.current_generation, st.state, d.state,
                    d.safety_evidence_digest
             FROM storage_targets st
             JOIN host_fault_group_memberships hfg ON hfg.host_id = st.host_id
             LEFT JOIN storage_target_drains d
               ON d.target_id = st.target_id AND d.target_generation = st.current_generation
             WHERE hfg.group_id = ?1 AND st.state != 5 AND st.retired_at IS NULL
             ORDER BY st.target_id"
        }
        DrainScope::Target { .. } => return Err(RepositoryError::CorruptState),
    };
    let mut statement = connection.prepare(query)?;
    let rows = statement.query_map([scope_identifier(record.scope).as_slice()], decode_target)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn decode_target(row: &Row<'_>) -> rusqlite::Result<TargetDrainState> {
    let target_id = row.get::<_, Vec<u8>>(0)?;
    let exact: [u8; 16] = target_id
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let target_id = TargetId::from_bytes(exact).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let generation = row.get::<_, i64>(1)?;
    let target_generation = u64::try_from(generation)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)?;
    let target_state = row.get::<_, i64>(2)?;
    if !matches!(target_state, ACTIVE_TARGET | DRAINING_TARGET | 2 | 4) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let drain_state = row.get::<_, Option<i64>>(3)?;
    if drain_state.is_some_and(|state| !(1..=3).contains(&state)) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let safety_evidence_digest = row
        .get::<_, Option<Vec<u8>>>(4)?
        .map(|bytes| bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()?;
    Ok(TargetDrainState {
        target_id,
        target_generation,
        target_state,
        drain_state,
        safety_evidence_digest,
    })
}

fn decode_record(row: &Row<'_>, drain_id: WorkId) -> rusqlite::Result<StorageScopeDrainRecord> {
    let scope_id: Vec<u8> = row.get(1)?;
    let scope_id: [u8; 16] = scope_id
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let scope = match (row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(2)?) {
        (NODE_SCOPE, Some(incarnation)) if incarnation > 0 => DrainScope::Node {
            node_id: NodeId::from_bytes(scope_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
            node_incarnation: u64::try_from(incarnation)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        },
        (FAULT_GROUP_SCOPE, None) => DrainScope::FaultGroup {
            fault_group_id: FaultGroupId::from_bytes(scope_id)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        },
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let allow_temporary_degraded = strict_bool(row.get(3)?)?;
    let cleanup_requested = strict_bool(row.get(4)?)?;
    let state = match row.get::<_, i64>(5)? {
        DRAIN_EVACUATING => StorageScopeDrainState::Evacuating,
        DRAIN_MEMBERSHIP_FENCED if matches!(scope, DrainScope::Node { .. }) => {
            StorageScopeDrainState::MembershipFenced
        }
        DRAIN_SAFE => StorageScopeDrainState::SafeToDetach,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let requested_by: Vec<u8> = row.get(6)?;
    let requested_by: [u8; 16] = requested_by
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let requested_by =
        PrincipalId::from_bytes(requested_by).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let revision = row.get::<_, i64>(8)?;
    let revision = u64::try_from(revision)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)?;
    Ok(StorageScopeDrainRecord {
        drain_id,
        scope,
        allow_temporary_degraded,
        cleanup_requested,
        requested_by,
        requested_at: UnixMicros::new(row.get(7)?),
        state,
        revision: Revision::new(revision),
    })
}

fn decode_pending_record(row: &Row<'_>) -> rusqlite::Result<StorageScopeDrainRecord> {
    let drain_id: Vec<u8> = row.get(9)?;
    let drain_id: [u8; 16] = drain_id
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let drain_id = WorkId::from_bytes(drain_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    decode_record(row, drain_id)
}

struct WorkSubjectBytes(Vec<u8>);

impl WorkSubjectBytes {
    fn new(scope: DrainScope) -> Self {
        Self(meshspan_work::WorkSubject::Drain(scope).encode())
    }
}

impl AsRef<[u8]> for WorkSubjectBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

struct TargetDrainState {
    target_id: TargetId,
    target_generation: u64,
    target_state: i64,
    drain_state: Option<i64>,
    safety_evidence_digest: Option<[u8; 32]>,
}

fn strict_bool(value: i64) -> rusqlite::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
