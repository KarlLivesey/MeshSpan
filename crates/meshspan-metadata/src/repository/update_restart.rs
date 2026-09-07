// SPDX-License-Identifier: GPL-2.0-only

//! Root-quorum and gateway admission from fresh, authenticated coordinator probes.
//!
//! The daemon remains responsible for acquiring the observations through authenticated peers,
//! checking workload/protection readiness and retaining the bound evidence before this command.

use super::{RepositoryError, apply::to_i64};
use crate::{AdvanceUpdateNode, CommandContext, UpdateRestartReadiness, UpdateRolloutRecord};
use meshspan_consensus::{ActiveQuorumPlan, QuorumFamily};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::BTreeSet;

pub(super) fn admit(
    tx: &Connection,
    context: CommandContext,
    rollout: &UpdateRolloutRecord,
    command: &AdvanceUpdateNode,
) -> Result<(), RepositoryError> {
    let proof = command
        .restart_readiness
        .as_ref()
        .ok_or(RepositoryError::InvalidCommand)?;
    validate_proof(proof, context)?;
    let encoded: Option<Vec<u8>> = tx
        .query_row(
            "SELECT canonical_plan FROM consensus_active_quorum_plan
        WHERE singleton=1 AND length(canonical_plan)<=65536",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let plan = ActiveQuorumPlan::decode(&encoded.ok_or(RepositoryError::InvalidCommand)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    if plan.proof_digest() != proof.quorum_plan_digest {
        return Err(RepositoryError::StaleRevision);
    }
    let applied: i64 = tx.query_row(
        "SELECT last_log_index FROM applied_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let mut ready = BTreeSet::new();
    let mut gateway_available = false;
    for node in &proof.ready_nodes {
        if node.node_id == command.node_id
            || node.incarnation == 0
            || to_i64(node.applied_index)? < applied
        {
            return Err(RepositoryError::StaleRevision);
        }
        let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM nodes n
            WHERE n.node_id=?1 AND n.current_incarnation=?2 AND n.state=2 AND n.retired_at IS NULL
            AND NOT EXISTS(SELECT 1 FROM update_rollout_nodes u WHERE u.node_id=n.node_id AND u.rollout_id=?3 AND u.restart_pending=1))",
            params![node.node_id.as_bytes().as_slice(),to_i64(node.incarnation)?,command.rollout_id.as_bytes().as_slice()], |row|row.get(0))?;
        if !valid {
            return Err(RepositoryError::StaleRevision);
        }
        ready.insert(node.node_id);
        let gateway: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM node_roles WHERE node_id=?1 AND role_code=2)",
            [node.node_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        gateway_available |= gateway;
    }
    let safe = gateway_available
        && !plan.eligible_leaders().is_disjoint(&ready)
        && [
            QuorumFamily::Election,
            QuorumFamily::Commit,
            QuorumFamily::Read,
        ]
        .into_iter()
        .all(|family| plan.satisfies(family, &ready));
    if !safe && !rollout.allow_service_interruption {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn validate_proof(
    proof: &UpdateRestartReadiness,
    context: CommandContext,
) -> Result<(), RepositoryError> {
    let age = context
        .occurred_at
        .get()
        .checked_sub(proof.observed_at.get())
        .ok_or(RepositoryError::InvalidCommand)?;
    if !(0..=30_000_000).contains(&age)
        || proof.observed_at.get() < 0
        || proof.ready_nodes.len() > 19
        || proof
            .ready_nodes
            .windows(2)
            .any(|pair| pair[0].node_id >= pair[1].node_id)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}
