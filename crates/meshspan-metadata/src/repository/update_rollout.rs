// SPDX-License-Identifier: GPL-2.0-only

//! Durable update progression. Actual readiness and process replacement belong to the daemon.

use meshspan_domain::{Revision, WorkId};
use rusqlite::{Connection, Transaction, params};
use sha2::{Digest as _, Sha256};

use super::{EntityKind, EntityReference, RepositoryError, apply::to_i64};
use crate::{
    AdvanceUpdateNode, CommandContext, ConfigureUpdateSigner, ControlUpdateRollout,
    StartUpdateRollout, UpdateNodePhase, UpdateRolloutControl, authenticate_update_manifest,
};

pub(super) fn execute(
    tx: &Transaction<'_>,
    context: CommandContext,
    command: &crate::AuthoritativeCommand,
    revision: Revision,
) -> Option<Result<EntityReference, RepositoryError>> {
    use crate::AuthoritativeCommand;
    Some(match command {
        AuthoritativeCommand::ConfigureUpdateSigner(value) => configure_signer(tx, value, revision),
        AuthoritativeCommand::StartUpdateRollout(value) => start(tx, context, value, revision),
        AuthoritativeCommand::AdvanceUpdateNode(value) => advance(tx, context, value, revision),
        AuthoritativeCommand::ControlUpdateRollout(value) => control(tx, *value, revision),
        AuthoritativeCommand::PublishUpdateArtifact(value) => {
            super::update_artifact::publish(tx, value, revision)
        }
        _ => return None,
    })
}

fn configure_signer(
    tx: &Transaction<'_>,
    value: &ConfigureUpdateSigner,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    meshspan_certificates::NodePublicIdentity::from_sec1(&value.public_key)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let current = signer(tx, value.signer_id)?;
    if current.as_ref().map_or(0, |row| row.sequence) != value.expected_sequence {
        return Err(RepositoryError::StaleRevision);
    }
    if current
        .as_ref()
        .is_some_and(|row| row.public_key != value.public_key)
    {
        // New keys get new identities. Existing rollout signatures must remain verifiable.
        return Err(RepositoryError::InvalidCommand);
    }
    if current.is_none() {
        let count: i64 =
            tx.query_row("SELECT count(*) FROM update_signers", [], |row| row.get(0))?;
        if count >= 64 {
            return Err(RepositoryError::CapacityExceeded);
        }
    }
    let next = to_i64(
        value
            .expected_sequence
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)?,
    )?;
    tx.execute(
        "INSERT INTO update_signers(signer_id, sequence, public_key, enabled, revision)
        VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(signer_id) DO UPDATE SET
        sequence=excluded.sequence, enabled=excluded.enabled, revision=excluded.revision",
        params![
            value.signer_id.as_bytes().as_slice(),
            next,
            value.public_key.as_slice(),
            value.enabled,
            to_i64(revision.get())?
        ],
    )?;
    if !value.enabled {
        tx.execute(
            "UPDATE update_rollouts SET state=2, sequence=sequence+1, revision=?1
            WHERE signer_id=?2 AND state=1",
            params![
                to_i64(revision.get())?,
                value.signer_id.as_bytes().as_slice()
            ],
        )?;
    }
    Ok(EntityReference {
        kind: EntityKind::UpdateSigner,
        id: value.signer_id.as_bytes(),
    })
}

fn start(
    tx: &Transaction<'_>,
    context: CommandContext,
    value: &StartUpdateRollout,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let trust = signer(tx, value.signer_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if !trust.enabled || trust.sequence != value.signer_sequence {
        return Err(RepositoryError::StaleRevision);
    }
    let manifest =
        authenticate_update_manifest(&value.manifest, &value.signature, &trust.public_key)
            .map_err(|_| RepositoryError::InvalidCommand)?;
    if !manifest.accepts_partition(crate::migration::PARTITION_SCHEMA_VERSION, 1) {
        return Err(RepositoryError::InvalidCommand);
    }
    let occupied: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM update_rollouts WHERE state IN (1,2))",
        [],
        |row| row.get(0),
    )?;
    if occupied || context.occurred_at.get() < 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let digest: [u8; 32] = Sha256::digest(&value.manifest).into();
    tx.execute("INSERT INTO update_rollouts(rollout_id,signer_id,signer_sequence,manifest,
        manifest_digest,signature,allow_service_interruption,state,sequence,created_by,created_at,revision)
        VALUES (?1,?2,?3,?4,?5,?6,?7,1,1,?8,?9,?10)", params![
        value.rollout_id.as_bytes().as_slice(), value.signer_id.as_bytes().as_slice(),
        to_i64(value.signer_sequence)?, value.manifest, digest.as_slice(), value.signature,
        value.allow_service_interruption, context.actor_principal_id.as_bytes().as_slice(),
        context.occurred_at.get(), to_i64(revision.get())?])?;
    let inserted = tx.execute(
        "INSERT INTO update_rollout_nodes(rollout_id,node_id,incarnation,
        phase,restart_pending,sequence,target,evidence_digest,observed_at,revision)
        SELECT ?1,node_id,current_incarnation,1,0,1,NULL,NULL,NULL,?2
        FROM nodes WHERE state=2 AND retired_at IS NULL",
        params![
            value.rollout_id.as_bytes().as_slice(),
            to_i64(revision.get())?
        ],
    )?;
    if inserted == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(rollout_entity(value.rollout_id))
}

fn advance(
    tx: &Transaction<'_>,
    context: CommandContext,
    value: &AdvanceUpdateNode,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let rollout = load(tx, value.rollout_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if !matches!(
        rollout.state,
        UpdateRolloutState::Running | UpdateRolloutState::Paused
    ) || value.evidence_digest == [0; 32]
        || context.occurred_at.get() < 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let previous =
        node(tx, value.rollout_id, value.node_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if previous.sequence != value.expected_sequence || previous.incarnation != value.incarnation {
        return Err(RepositoryError::StaleRevision);
    }
    let still_assigned: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes
        WHERE node_id=?1 AND current_incarnation=?2 AND state=2 AND retired_at IS NULL)",
        params![
            value.node_id.as_bytes().as_slice(),
            to_i64(value.incarnation)?
        ],
        |row| row.get(0),
    )?;
    if !still_assigned {
        return Err(RepositoryError::StaleRevision);
    }
    rollout
        .manifest
        .artifact(&value.target)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    if previous
        .target
        .as_ref()
        .is_some_and(|target| target != &value.target)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_transition(tx, &rollout, &previous, value.phase)?;
    if value.phase == UpdateNodePhase::Restarting {
        super::update_restart::admit(tx, context, &rollout, value)?;
    } else if value.restart_readiness.is_some() {
        return Err(RepositoryError::InvalidCommand);
    }
    let restart_pending = match value.phase {
        UpdateNodePhase::Restarting => true,
        UpdateNodePhase::Failed => previous.restart_pending,
        UpdateNodePhase::Verified | UpdateNodePhase::Staged | UpdateNodePhase::Pending => false,
    };
    tx.execute(
        "UPDATE update_rollout_nodes SET phase=?1,restart_pending=?2,sequence=sequence+1,
        target=?3,evidence_digest=?4,observed_at=?5,revision=?6 WHERE rollout_id=?7 AND node_id=?8",
        params![
            value.phase as u8,
            restart_pending,
            value.target,
            value.evidence_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
            value.rollout_id.as_bytes().as_slice(),
            value.node_id.as_bytes().as_slice()
        ],
    )?;
    let next_state = if value.phase == UpdateNodePhase::Failed {
        2
    } else if !has_unverified(tx, value.rollout_id)? {
        3
    } else {
        rollout.state as u8
    };
    tx.execute(
        "UPDATE update_rollouts SET state=?1,sequence=sequence+1,revision=?2 WHERE rollout_id=?3",
        params![
            next_state,
            to_i64(revision.get())?,
            value.rollout_id.as_bytes().as_slice()
        ],
    )?;
    Ok(rollout_entity(value.rollout_id))
}

fn validate_transition(
    tx: &Connection,
    rollout: &UpdateRolloutRecord,
    previous: &UpdateNodeRecord,
    next: UpdateNodePhase,
) -> Result<(), RepositoryError> {
    let valid = match next {
        UpdateNodePhase::Pending => false,
        UpdateNodePhase::Staged => {
            previous.phase == UpdateNodePhase::Pending && !previous.restart_pending
        }
        UpdateNodePhase::Restarting => {
            previous.phase == UpdateNodePhase::Staged
                && rollout.state == UpdateRolloutState::Running
        }
        UpdateNodePhase::Verified => {
            previous.restart_pending
                && matches!(
                    previous.phase,
                    UpdateNodePhase::Restarting | UpdateNodePhase::Failed
                )
        }
        UpdateNodePhase::Failed => {
            previous.phase != UpdateNodePhase::Verified && previous.phase != UpdateNodePhase::Failed
        }
    };
    if !valid {
        return Err(RepositoryError::InvalidCommand);
    }
    if next == UpdateNodePhase::Restarting {
        let trust = signer(tx, rollout.signer_id)?.ok_or(RepositoryError::CorruptState)?;
        let busy: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM update_rollout_nodes
            WHERE rollout_id=?1 AND (restart_pending=1 OR phase IN (1,5)))",
            [rollout.rollout_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if !trust.enabled || busy {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    Ok(())
}

fn control(
    tx: &Transaction<'_>,
    value: ControlUpdateRollout,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let current = load(tx, value.rollout_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if current.sequence != value.expected_sequence {
        return Err(RepositoryError::StaleRevision);
    }
    let active_restart: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM update_rollout_nodes
        WHERE rollout_id=?1 AND restart_pending=1)",
        [value.rollout_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let next = match (current.state, value.action) {
        (UpdateRolloutState::Running, UpdateRolloutControl::Pause) => 2,
        (UpdateRolloutState::Paused, UpdateRolloutControl::Resume) => {
            let trust = signer(tx, current.signer_id)?.ok_or(RepositoryError::CorruptState)?;
            if !trust.enabled {
                return Err(RepositoryError::InvalidCommand);
            }
            // An ambiguous restart stays exclusive and resumes probing, never blind replacement.
            tx.execute("UPDATE update_rollout_nodes SET phase=CASE WHEN restart_pending=1 THEN 3 ELSE 1 END,
                sequence=sequence+1, revision=?1 WHERE rollout_id=?2 AND phase=5",
                params![to_i64(revision.get())?, value.rollout_id.as_bytes().as_slice()])?;
            1
        }
        (
            UpdateRolloutState::Running | UpdateRolloutState::Paused,
            UpdateRolloutControl::Cancel,
        ) if !active_restart => 4,
        _ => return Err(RepositoryError::InvalidCommand),
    };
    tx.execute(
        "UPDATE update_rollouts SET state=?1,sequence=sequence+1,revision=?2 WHERE rollout_id=?3",
        params![
            next,
            to_i64(revision.get())?,
            value.rollout_id.as_bytes().as_slice()
        ],
    )?;
    Ok(rollout_entity(value.rollout_id))
}

fn has_unverified(tx: &Connection, id: WorkId) -> Result<bool, RepositoryError> {
    Ok(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM update_rollout_nodes WHERE rollout_id=?1 AND phase!=4)",
        [id.as_bytes().as_slice()],
        |row| row.get(0),
    )?)
}

fn rollout_entity(id: WorkId) -> EntityReference {
    EntityReference {
        kind: EntityKind::UpdateRollout,
        id: id.as_bytes(),
    }
}

use super::update_rollout_queries::{load, node, signer};
use crate::{UpdateNodeRecord, UpdateRolloutRecord, UpdateRolloutState};
