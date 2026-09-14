// SPDX-License-Identifier: GPL-2.0-only

//! Automatic sequential installation for explicitly interruption-allowed rollouts.
//! Uninterrupted installation additionally needs workload and delegated-group proofs.

use super::{
    UpdateError, UpdateMutation, UpdateService, identifier, installation::UpdateProcessControl,
    staging::retain_evidence,
};
use crate::IdentityAdministrator;
use meshspan_domain::{Clock as _, OperationId, uuid_v8};
use meshspan_metadata::{
    AdvanceUpdateNode, AuthoritativeCommand, EntityKind, UpdateNodePhase, UpdateRolloutRecord,
    UpdateRolloutState,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::path::Path;

impl UpdateService {
    /// Runs inside the one owned updater job. Preparing and restarting are separate
    /// committed turns, so a crash cannot skip preparation or release its reservation.
    pub(super) async fn stage_and_coordinate(
        &self,
        record: &UpdateRolloutRecord,
        directory: &Path,
        control: &UpdateProcessControl,
        network: &crate::private_consensus_runtime::PrivateConsensusRuntime,
    ) -> Result<(), UpdateError> {
        self.stage_pending(record, directory)?;
        if record.state != UpdateRolloutState::Running {
            return Ok(());
        }
        let reader = self.authority.reader();
        let counts = reader
            .update_progress_counts(record.rollout_id)
            .map_err(|_| UpdateError::Unavailable)?;
        if counts.pending != 0 || counts.failed != 0 || counts.unresolved_restarts != 0 {
            return Ok(());
        }
        let Some(node) = reader
            .update_restart_candidate(record.rollout_id)
            .map_err(|_| UpdateError::Unavailable)?
        else {
            return Ok(());
        };
        if node.node_id != self.gateway.node_id || node.incarnation != self.gateway.incarnation {
            return Ok(());
        }
        let observed = control.observe().await?;
        let plan = reader
            .load_active_consensus_quorum_plan()
            .map_err(|_| UpdateError::Unavailable)?
            .ok_or(UpdateError::Unavailable)?;
        if observed.node_id != node.node_id
            || observed.partition_id != reader.partition_id()
            || observed.plan_digest != plan.proof_digest()
            || node
                .preparation_log_index
                .is_some_and(|barrier| observed.applied_index < barrier)
        {
            return Err(UpdateError::Unavailable);
        }
        let Some(phase) = next_phase(node.phase, record.allow_service_interruption) else {
            return Ok(());
        };
        let target = node.target.as_deref().ok_or(UpdateError::Failed)?;
        let readiness = if phase == UpdateNodePhase::Restarting {
            Some(
                crate::update_readiness::probe_surviving_voters(
                    network.network().map_err(|()| UpdateError::Unavailable)?,
                    record.rollout_id,
                    &node,
                    &plan,
                )
                .await
                .map_err(|()| UpdateError::Unavailable)?,
            )
        } else {
            None
        };
        let now = crate::OperatingSystemClock.now();
        let witnesses: Vec<_> = readiness.iter().flat_map(|proof| &proof.ready_nodes).map(|peer| json!({
            "node_id": identifier(peer.node_id.as_bytes()), "incarnation": peer.incarnation, "applied_index": peer.applied_index,
        })).collect();
        // Missing peers remain absent; interruption consent never creates evidence.
        let bytes = serde_json::to_vec(&json!({
            "phase": phase as u8, "rollout_id": identifier(record.rollout_id.as_bytes()),
            "node_id": identifier(node.node_id.as_bytes()), "incarnation": node.incarnation,
            "expected_sequence": node.sequence, "preparation_log_index": node.preparation_log_index,
            "quorum_plan_digest": plan.proof_digest(), "observed_at": now.get(),
            "applied_index": observed.applied_index, "allow_service_interruption": record.allow_service_interruption,
            "ready_nodes": witnesses,
        }))
        .map_err(|_| UpdateError::Failed)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        retain_evidence(directory, &bytes, &digest)?;
        let operation = OperationId::from_bytes(uuid_v8(
            digest[..16].try_into().map_err(|_| UpdateError::Failed)?,
        ))
        .map_err(|_| UpdateError::Failed)?;
        self.submit(
            IdentityAdministrator {
                principal_id: record.created_by,
                now,
            },
            &UpdateMutation {
                operation_id: meshspan_api_contract::OperationId::parse(
                    &identifier(operation.as_bytes()).0,
                )
                .ok_or(UpdateError::Failed)?,
                resource_id: identifier(record.rollout_id.as_bytes()),
                entity_kind: EntityKind::UpdateRollout,
                command: AuthoritativeCommand::AdvanceUpdateNode(AdvanceUpdateNode {
                    rollout_id: record.rollout_id,
                    node_id: node.node_id,
                    incarnation: node.incarnation,
                    expected_sequence: node.sequence,
                    phase,
                    target: target.to_owned(),
                    evidence_digest: digest,
                    restart_readiness: readiness,
                }),
            },
        )?;
        Ok(())
    }
}

fn next_phase(phase: UpdateNodePhase, allow_interruption: bool) -> Option<UpdateNodePhase> {
    match phase {
        UpdateNodePhase::Staged => Some(UpdateNodePhase::Preparing),
        UpdateNodePhase::Preparing if allow_interruption => Some(UpdateNodePhase::Restarting),
        // Local content scans alone are not all-scope restart authority.
        UpdateNodePhase::Preparing
        | UpdateNodePhase::Pending
        | UpdateNodePhase::Restarting
        | UpdateNodePhase::Verified
        | UpdateNodePhase::Failed => None,
    }
}
