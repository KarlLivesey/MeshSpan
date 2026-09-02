// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative node and fault-group drains composed from ordinary target evacuations.

use meshspan_domain::{NodeId, PrincipalId, Revision, TargetId, UnixMicros, WorkId};
use meshspan_work::DrainScope;
use rusqlite::{Transaction, params};

use super::super::apply::to_i64;
use super::super::{EntityKind, EntityReference, RepositoryError};
use super::scope_drain_state::{
    all_targets_safe, completion_evidence, load_record, membership_can_retire_node,
    scope_node_is_consensus_member,
};
use crate::{
    BeginStorageScopeDrain, CommandContext, CompleteStorageScopeDrain,
    FenceStorageNodeDrainMembership,
};

pub(crate) use super::scope_drain_state::{load, next_action, pending_page};

pub(super) const NODE_SCOPE: i64 = 1;
pub(super) const FAULT_GROUP_SCOPE: i64 = 2;
pub(super) const DRAIN_EVACUATING: i64 = 1;
pub(super) const DRAIN_MEMBERSHIP_FENCED: i64 = 2;
pub(super) const DRAIN_SAFE: i64 = 3;
const ACTIVE_NODE: i64 = 2;
const DRAINING_NODE: i64 = 3;
const ACTIVE_GROUP: i64 = 1;
const DRAINING_GROUP: i64 = 2;
pub(super) const ACTIVE_TARGET: i64 = 1;
pub(super) const DRAINING_TARGET: i64 = 3;

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

pub(super) const fn scope_identifier(scope: DrainScope) -> [u8; 16] {
    match scope {
        DrainScope::Node { node_id, .. } => node_id.as_bytes(),
        DrainScope::FaultGroup { fault_group_id } => fault_group_id.as_bytes(),
        DrainScope::Target { target_id, .. } => target_id.as_bytes(),
    }
}

const fn state_code(state: StorageScopeDrainState) -> i64 {
    match state {
        StorageScopeDrainState::Evacuating => DRAIN_EVACUATING,
        StorageScopeDrainState::MembershipFenced => DRAIN_MEMBERSHIP_FENCED,
        StorageScopeDrainState::SafeToDetach => DRAIN_SAFE,
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
