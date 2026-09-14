// SPDX-License-Identifier: GPL-2.0-only

//! Consume one committed restart reservation; never create restart authority from local health.

use super::{UpdateError, UpdateService, identifier, staging::retain_evidence};
use crate::{
    update_artifact_store::UpdateArtifactStore, update_installation::InstallSelection,
    update_readiness::UpdateReadiness,
};
use meshspan_metadata::{UpdateNodePhase, UpdateNodeRecord, UpdateRolloutRecord};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::path::Path;

pub(crate) struct UpdateProcessControl {
    restart: tokio::sync::mpsc::UnboundedSender<()>,
    readiness: UpdateReadiness,
    pub(super) filesystem: crate::NativeFilesystemRuntime,
}

impl UpdateProcessControl {
    pub(super) fn workload_status(&self) -> super::UpdateWorkloadStatus {
        self.readiness.workload_status.clone()
    }

    pub(super) async fn observe(
        &self,
    ) -> Result<meshspan_cluster::MetadataAuthorityObservation, UpdateError> {
        self.readiness
            .local_ready()
            .await
            .map_err(|()| UpdateError::Unavailable)
    }

    pub(crate) const fn new(
        restart: tokio::sync::mpsc::UnboundedSender<()>,
        readiness: UpdateReadiness,
        filesystem: crate::NativeFilesystemRuntime,
    ) -> Self {
        Self {
            restart,
            readiness,
            filesystem,
        }
    }
}

impl UpdateService {
    /// Caller is the sole owned updater job, including all filesystem and hashing work.
    pub(super) async fn install_admitted(
        &self,
        record: &UpdateRolloutRecord,
        directory: &Path,
        control: &UpdateProcessControl,
    ) -> Result<bool, UpdateError> {
        let Some(node) = self
            .authority
            .reader()
            .update_rollout_node(record.rollout_id, self.gateway.node_id)
            .map_err(|_| UpdateError::Unavailable)?
        else {
            return Ok(false);
        };
        if !node.restart_pending
            || node.incarnation != self.gateway.incarnation
            || !matches!(
                node.phase,
                UpdateNodePhase::Restarting | UpdateNodePhase::Failed
            )
        {
            return Ok(false);
        }
        if let Some(selection) =
            InstallSelection::load(directory).map_err(|_| UpdateError::Failed)?
            && selection.matches(record, &node)
            && selection
                .current_process(directory)
                .map_err(|_| UpdateError::Failed)?
        {
            self.verify_installation(record, &node, directory, &selection, control)
                .await?;
            return Ok(true);
        }
        if node.phase == UpdateNodePhase::Failed {
            return Ok(true);
        }
        // Revocation blocks a not-yet-started replacement, but cannot prevent a
        // previously admitted, already-running image from reporting verified above.
        self.candidate(record.rollout_id)?;
        let signer = self
            .authority
            .reader()
            .update_signers()
            .map_err(|_| UpdateError::Unavailable)?
            .into_iter()
            .find(|signer| signer.signer_id == record.signer_id && signer.enabled)
            .ok_or(UpdateError::Conflict)?;
        let target = crate::update_candidate::local_target().map_err(|_| UpdateError::Failed)?;
        let executable = UpdateArtifactStore::open(directory)
            .map_err(|_| UpdateError::Failed)?
            .executable(&record.manifest, target)
            .map_err(|_| UpdateError::Failed)?;
        if crate::update_runtime_info::probe(&executable, &record.manifest).is_err() {
            let bytes = serde_json::to_vec(&json!({
                "phase": "restart_probe_failed",
                "rollout_id": identifier(record.rollout_id.as_bytes()),
                "node_id": identifier(node.node_id.as_bytes()),
                "incarnation": node.incarnation,
                "sequence": node.sequence,
            }))
            .map_err(|_| UpdateError::Failed)?;
            let digest = Sha256::digest(&bytes).into();
            retain_evidence(directory, &bytes, &digest)?;
            self.checkpoint(record, &node, UpdateNodePhase::Failed, target, digest)?;
            return Ok(true);
        }
        let revision = self
            .authority
            .reader()
            .current_revision()
            .map_err(|_| UpdateError::Unavailable)?
            .get();
        InstallSelection::new(record, &node, &signer, revision)
            .map_err(|_| UpdateError::Failed)?
            .save(directory)
            .map_err(|_| UpdateError::Failed)?;
        control
            .restart
            .send(())
            .map_err(|_| UpdateError::Unavailable)?;
        Ok(true)
    }

    async fn verify_installation(
        &self,
        record: &UpdateRolloutRecord,
        node: &UpdateNodeRecord,
        directory: &Path,
        selection: &InstallSelection,
        control: &UpdateProcessControl,
    ) -> Result<(), UpdateError> {
        let observed = control
            .readiness
            .local_ready()
            .await
            .map_err(|()| UpdateError::Unavailable)?;
        if observed.node_id != self.gateway.node_id
            || observed.partition_id != self.authority.reader().partition_id()
            || self
                .authority
                .reader()
                .current_revision()
                .map_err(|_| UpdateError::Unavailable)?
                .get()
                < selection.minimum_revision
        {
            return Err(UpdateError::Unavailable);
        }
        let report = crate::update_runtime_info::report().map_err(|_| UpdateError::Failed)?;
        crate::update_runtime_info::validate(&report, &record.manifest)
            .map_err(|_| UpdateError::Failed)?;
        let target = crate::update_candidate::local_target().map_err(|_| UpdateError::Failed)?;
        let artifact = record
            .manifest
            .artifact(target)
            .map_err(|_| UpdateError::Failed)?;
        let bytes = serde_json::to_vec(&json!({
            "phase": "installed",
            "rollout_id": identifier(record.rollout_id.as_bytes()),
            "node_id": identifier(node.node_id.as_bytes()),
            "incarnation": node.incarnation,
            "sequence": node.sequence,
            "restart_sequence": selection.restart_sequence,
            "minimum_revision": selection.minimum_revision,
            "applied_index": observed.applied_index,
            "committed_index": observed.commit_index,
            "sha256": artifact.sha256,
            "runtime": report,
        }))
        .map_err(|_| UpdateError::Failed)?;
        let digest = Sha256::digest(&bytes).into();
        retain_evidence(directory, &bytes, &digest)?;
        self.checkpoint(record, node, UpdateNodePhase::Verified, target, digest)
    }
}
