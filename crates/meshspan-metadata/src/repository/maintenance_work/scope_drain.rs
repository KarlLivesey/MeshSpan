// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative node and fault-group drains composed from ordinary target evacuations.

use meshspan_consensus::ActiveQuorumPlan;
use meshspan_domain::{FaultGroupId, NodeId, PrincipalId, Revision, TargetId, UnixMicros, WorkId};
use meshspan_work::DrainScope;
use rusqlite::{OptionalExtension, Row, Transaction, params};
use sha2::{Digest, Sha256};

use super::super::apply::to_i64;
use super::super::{EntityKind, EntityReference, Page, PageLimit, RepositoryError};
use crate::{
    BeginStorageScopeDrain, CommandContext, CompleteStorageScopeDrain,
    FenceStorageNodeDrainMembership, PartitionDatabase,
};

const NODE_SCOPE: i64 = 1;
const FAULT_GROUP_SCOPE: i64 = 2;
const DRAIN_EVACUATING: i64 = 1;
const DRAIN_MEMBERSHIP_FENCED: i64 = 2;
const DRAIN_SAFE: i64 = 3;
const ACTIVE_NODE: i64 = 2;
const DRAINING_NODE: i64 = 3;
const ACTIVE_GROUP: i64 = 1;
const DRAINING_GROUP: i64 = 2;
const ACTIVE_TARGET: i64 = 1;
const DRAINING_TARGET: i64 = 3;
const TARGET_DRAIN_SAFE: i64 = 2;

/// One authoritative scope drain awaiting bounded coordinator work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageScopeDrainRecord {
    /// Stable scope-drain identity.
    pub drain_id: WorkId,
    /// Exact node incarnation or fault group fenced by this drain.
    pub scope: DrainScope,
    /// Whether reduced desired protection is accepted after recoverability is proved.
    pub allow_temporary_degraded: bool,
    /// Whether child target drains request physical cleanup.
    pub cleanup_requested: bool,
    /// Principal who requested the drain.
    pub requested_by: PrincipalId,
    /// Authoritative request instant.
    pub requested_at: UnixMicros,
    /// Current replicated lifecycle.
    pub state: StorageScopeDrainState,
    /// Latest authoritative revision.
    pub revision: Revision,
}

/// Stable keyset cursor over live scope drains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageScopeDrainCursor {
    requested_at: UnixMicros,
    drain_id: WorkId,
}

impl StorageScopeDrainCursor {
    /// Reconstructs a validated internal scheduling cursor.
    #[must_use]
    pub const fn new(requested_at: UnixMicros, drain_id: WorkId) -> Self {
        Self {
            requested_at,
            drain_id,
        }
    }

    /// Returns the authoritative request instant at the seek boundary.
    #[must_use]
    pub const fn requested_at(self) -> UnixMicros {
        self.requested_at
    }

    /// Returns the stable drain identity at the seek boundary.
    #[must_use]
    pub const fn drain_id(self) -> WorkId {
        self.drain_id
    }
}

/// Replicated lifecycle of one node or fault-group drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageScopeDrainState {
    /// New placement is fenced while ordinary target drains evacuate bytes.
    Evacuating,
    /// A node's target proofs are safe and consensus membership retirement is underway.
    MembershipFenced,
    /// Every target is safe and the scope may be detached.
    SafeToDetach,
}

/// Unique next action for one scope drain; absent means existing work must converge first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageScopeDrainAction {
    /// Begin the ordinary target drain for one not-yet-admitted target.
    BeginTarget {
        /// Parent scope drain.
        drain_id: WorkId,
        /// Exact current target generation.
        target_id: TargetId,
        /// Exact current target generation.
        target_generation: u64,
        /// Inherited temporary-degradation policy.
        allow_temporary_degraded: bool,
        /// Inherited cleanup policy.
        cleanup_requested: bool,
        /// Original requesting principal.
        requested_by: PrincipalId,
        /// Stable parent request instant used by every idempotent coordinator replay.
        requested_at: UnixMicros,
    },
    /// Fence an evacuated node from metadata membership.
    FenceNodeMembership {
        /// Parent scope drain.
        drain_id: WorkId,
        /// Exact node being retired.
        node_id: NodeId,
        /// Incarnation captured at drain admission.
        node_incarnation: u64,
        /// Original requesting principal.
        requested_by: PrincipalId,
        /// Stable parent request instant used by every idempotent coordinator replay.
        requested_at: UnixMicros,
    },
    /// Commit the final safe-to-detach evidence.
    Complete {
        /// Parent scope drain.
        drain_id: WorkId,
        /// Exact evidence digest independently recomputed during apply.
        safety_evidence_digest: [u8; 32],
        /// Original requesting principal.
        requested_by: PrincipalId,
        /// Stable parent request instant used by every idempotent coordinator replay.
        requested_at: UnixMicros,
    },
}

pub(crate) fn begin(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: BeginStorageScopeDrain,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let (scope_kind, scope_id, scope_incarnation) = validate_new_scope(transaction, value.scope)?;
    reject_overlapping_scope(transaction, value.scope)?;
    validate_existing_child_policies(transaction, value)?;
    transaction.execute(
        "INSERT INTO storage_scope_drains(
            drain_id, scope_kind, scope_id, scope_incarnation, allow_temporary_degraded,
            cleanup_requested, state, requested_by, requested_at, membership_fenced_at,
            safe_at, safety_evidence_digest, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, NULL, ?10)",
        params![
            value.drain_id.as_bytes().as_slice(),
            scope_kind,
            scope_id.as_slice(),
            scope_incarnation.map(to_i64).transpose()?,
            i64::from(value.allow_temporary_degraded),
            i64::from(value.cleanup_requested),
            DRAIN_EVACUATING,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    if scope_kind == FAULT_GROUP_SCOPE {
        let changed = transaction.execute(
            "UPDATE fault_groups SET state = ?1, revision = ?2
             WHERE group_id = ?3 AND state = ?4",
            params![
                DRAINING_GROUP,
                to_i64(revision.get())?,
                scope_id.as_slice(),
                ACTIVE_GROUP,
            ],
        )?;
        require_one(changed)?;
    }
    bump_configuration_revision(transaction, revision)?;
    Ok(entity(value.drain_id))
}

pub(crate) fn fence_node_membership(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: FenceStorageNodeDrainMembership,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let record =
        load_record(transaction, value.drain_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if record.state != StorageScopeDrainState::Evacuating
        || record.scope
            != (DrainScope::Node {
                node_id: value.node_id,
                node_incarnation: value.node_incarnation,
            })
        || !all_targets_safe(transaction, &record)?
        || !membership_can_retire_node(transaction, value.node_id)?
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let changed = transaction.execute(
        "UPDATE nodes SET state = ?1, revision = ?2
         WHERE node_id = ?3 AND current_incarnation = ?4 AND state = ?5",
        params![
            DRAINING_NODE,
            to_i64(revision.get())?,
            value.node_id.as_bytes().as_slice(),
            to_i64(value.node_incarnation)?,
            ACTIVE_NODE,
        ],
    )?;
    require_one(changed)?;
    transaction.execute(
        "UPDATE partition_voters SET state = 3, revision = ?1
         WHERE node_id = ?2 AND state IN (1, 2)",
        params![to_i64(revision.get())?, value.node_id.as_bytes().as_slice(),],
    )?;
    let changed = transaction.execute(
        "UPDATE storage_scope_drains
         SET state = ?1, membership_fenced_at = ?2, revision = ?3
         WHERE drain_id = ?4 AND state = ?5",
        params![
            DRAIN_MEMBERSHIP_FENCED,
            context.occurred_at.get(),
            to_i64(revision.get())?,
            value.drain_id.as_bytes().as_slice(),
            DRAIN_EVACUATING,
        ],
    )?;
    require_one(changed)?;
    bump_configuration_revision(transaction, revision)?;
    Ok(entity(value.drain_id))
}

pub(crate) fn complete(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: CompleteStorageScopeDrain,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let record =
        load_record(transaction, value.drain_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if record.state == StorageScopeDrainState::SafeToDetach
        || !all_targets_safe(transaction, &record)?
        || completion_evidence(transaction, &record)? != value.safety_evidence_digest
        || matches!(record.scope, DrainScope::Node { .. })
            && (record.state != StorageScopeDrainState::MembershipFenced
                || scope_node_is_consensus_member(transaction, record.scope)?)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let changed = transaction.execute(
        "UPDATE storage_scope_drains
         SET state = ?1, safe_at = ?2, safety_evidence_digest = ?3, revision = ?4
         WHERE drain_id = ?5 AND state = ?6",
        params![
            DRAIN_SAFE,
            context.occurred_at.get(),
            value.safety_evidence_digest.as_slice(),
            to_i64(revision.get())?,
            value.drain_id.as_bytes().as_slice(),
            state_code(record.state),
        ],
    )?;
    require_one(changed)?;
    Ok(entity(value.drain_id))
}

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
    let after_time = after.map_or(i64::MIN, |cursor| cursor.requested_at.get());
    let after_id = after.map_or([0; 16], |cursor| cursor.drain_id.as_bytes());
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

fn validate_new_scope(
    transaction: &Transaction<'_>,
    scope: DrainScope,
) -> Result<(i64, [u8; 16], Option<u64>), RepositoryError> {
    match scope {
        DrainScope::Node {
            node_id,
            node_incarnation,
        } if node_incarnation > 0 => {
            let valid = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM nodes
                 WHERE node_id = ?1 AND current_incarnation = ?2 AND state = ?3
                   AND retired_at IS NULL)",
                params![
                    node_id.as_bytes().as_slice(),
                    to_i64(node_incarnation)?,
                    ACTIVE_NODE,
                ],
                |row| row.get::<_, i64>(0),
            )? == 1;
            valid
                .then_some((NODE_SCOPE, node_id.as_bytes(), Some(node_incarnation)))
                .ok_or(RepositoryError::InvalidCommand)
        }
        DrainScope::FaultGroup { fault_group_id } => {
            let valid = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM fault_groups WHERE group_id = ?1 AND state = ?2)",
                params![fault_group_id.as_bytes().as_slice(), ACTIVE_GROUP],
                |row| row.get::<_, i64>(0),
            )? == 1;
            valid
                .then_some((FAULT_GROUP_SCOPE, fault_group_id.as_bytes(), None))
                .ok_or(RepositoryError::InvalidCommand)
        }
        DrainScope::Target { .. } | DrainScope::Node { .. } => Err(RepositoryError::InvalidCommand),
    }
}

fn reject_overlapping_scope(
    transaction: &Transaction<'_>,
    scope: DrainScope,
) -> Result<(), RepositoryError> {
    let overlap = match scope {
        DrainScope::Node { node_id, .. } => transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM storage_scope_drains d
                WHERE (
                    (d.scope_kind = 1 AND d.scope_id = ?1)
                    OR (d.scope_kind = 2 AND EXISTS(
                        SELECT 1 FROM nodes n
                        JOIN host_fault_group_memberships hfg ON hfg.host_id = n.host_id
                        WHERE n.node_id = ?1 AND hfg.group_id = d.scope_id)))
             )",
            [node_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )?,
        DrainScope::FaultGroup { fault_group_id } => transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM storage_scope_drains d
                WHERE (
                    (d.scope_kind = 2 AND d.scope_id = ?1)
                    OR (d.scope_kind = 1 AND EXISTS(
                        SELECT 1 FROM nodes n
                        JOIN host_fault_group_memberships hfg ON hfg.host_id = n.host_id
                        WHERE n.node_id = d.scope_id AND hfg.group_id = ?1)))
             )",
            [fault_group_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )?,
        DrainScope::Target { .. } => return Err(RepositoryError::InvalidCommand),
    };
    if overlap == 0 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_existing_child_policies(
    transaction: &Transaction<'_>,
    value: BeginStorageScopeDrain,
) -> Result<(), RepositoryError> {
    let query = target_query(value.scope, true);
    let mismatch = transaction.query_row(
        &query,
        params![
            scope_identifier(value.scope).as_slice(),
            i64::from(value.allow_temporary_degraded),
            i64::from(value.cleanup_requested),
        ],
        |row| row.get::<_, i64>(0),
    )?;
    if mismatch == 0 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn all_targets_safe(
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

fn membership_can_retire_node(
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

fn scope_node_is_consensus_member(
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

fn completion_evidence(
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

fn load_record(
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

fn target_query(scope: DrainScope, mismatch_only: bool) -> String {
    let join = if matches!(scope, DrainScope::FaultGroup { .. }) {
        "JOIN host_fault_group_memberships hfg ON hfg.host_id = st.host_id"
    } else {
        ""
    };
    let scope_column = if matches!(scope, DrainScope::FaultGroup { .. }) {
        "hfg.group_id"
    } else {
        "st.node_id"
    };
    let mismatch = if mismatch_only {
        "AND (d.allow_temporary_degraded != ?2 OR d.cleanup_requested != ?3)"
    } else {
        ""
    };
    format!(
        "SELECT count(*) FROM storage_targets st {join}
         JOIN storage_target_drains d
           ON d.target_id = st.target_id AND d.target_generation = st.current_generation
         WHERE {scope_column} = ?1 AND st.state != 5 AND st.retired_at IS NULL {mismatch}"
    )
}

const fn scope_identifier(scope: DrainScope) -> [u8; 16] {
    match scope {
        DrainScope::Node { node_id, .. } => node_id.as_bytes(),
        DrainScope::FaultGroup { fault_group_id } => fault_group_id.as_bytes(),
        DrainScope::Target { target_id, .. } => target_id.as_bytes(),
    }
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

const fn state_code(state: StorageScopeDrainState) -> i64 {
    match state {
        StorageScopeDrainState::Evacuating => DRAIN_EVACUATING,
        StorageScopeDrainState::MembershipFenced => DRAIN_MEMBERSHIP_FENCED,
        StorageScopeDrainState::SafeToDetach => DRAIN_SAFE,
    }
}

fn strict_bool(value: i64) -> rusqlite::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn require_one(changed: usize) -> Result<(), RepositoryError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn bump_configuration_revision(
    transaction: &Transaction<'_>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let changed = transaction.execute(
        "UPDATE meshes SET configuration_revision = ?1, revision = ?1",
        [to_i64(revision.get())?],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn entity(drain_id: WorkId) -> EntityReference {
    EntityReference {
        kind: EntityKind::MaintenanceWork,
        id: drain_id.as_bytes(),
    }
}
