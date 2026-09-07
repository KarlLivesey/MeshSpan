// SPDX-License-Identifier: GPL-2.0-only

//! Local executable admission and retained evidence precede a replicated node checkpoint.

use super::{UpdateError, UpdateMutation, UpdateService, identifier};
use crate::{
    IdentityAdministrator,
    protected_file::{self, PublishMode},
    update_artifact_store::UpdateArtifactStore,
};
use meshspan_domain::{Clock as _, OperationId, uuid_v8};
use meshspan_metadata::{
    AdvanceUpdateNode, AuthoritativeCommand, EntityKind, UpdateNodePhase, UpdateNodeRecord,
    UpdateRolloutRecord, UpdateRolloutState,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::path::Path;

impl UpdateService {
    /// Runs only in the updater's owned blocking worker. Pausing stops new probes.
    pub(super) fn stage_pending(
        &self,
        record: &UpdateRolloutRecord,
        directory: &Path,
    ) -> Result<(), UpdateError> {
        if record.state != UpdateRolloutState::Running {
            return Ok(());
        }
        let Some(node) = self
            .authority
            .reader()
            .update_rollout_node(record.rollout_id, self.gateway.node_id)
            .map_err(|_| UpdateError::Unavailable)?
        else {
            return Ok(());
        };
        if node.incarnation != self.gateway.incarnation || node.phase != UpdateNodePhase::Pending {
            return Ok(());
        }
        let target = crate::update_candidate::local_target().map_err(|_| UpdateError::Failed)?;
        let store = UpdateArtifactStore::open(directory).map_err(|_| UpdateError::Failed)?;
        // Missing or corrupt bytes are not executable-probe evidence. The distribution
        // owner handles transfer errors; only authenticated bytes may reach the child.
        let executable = store
            .executable(&record.manifest, target)
            .map_err(|_| UpdateError::Failed)?;
        let result = crate::update_runtime_info::probe(&executable, &record.manifest);
        let phase = if result.is_ok() {
            UpdateNodePhase::Staged
        } else {
            UpdateNodePhase::Failed
        };
        let evidence = json!({
            "format":1, "rollout_id":identifier(record.rollout_id.as_bytes()),
            "node_id":identifier(node.node_id.as_bytes()), "incarnation":node.incarnation,
            "expected_sequence":node.sequence, "manifest_sha256":crate::update_candidate::hex(&Sha256::digest(&record.canonical_manifest)),
            "target":target, "accepted":result.is_ok(), "runtime":result.ok(),
        });
        let bytes = serde_json::to_vec(&evidence).map_err(|_| UpdateError::Failed)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        retain_evidence(directory, &bytes, &digest)?;
        self.checkpoint(record, &node, phase, target, digest)
    }

    fn checkpoint(
        &self,
        record: &UpdateRolloutRecord,
        node: &UpdateNodeRecord,
        phase: UpdateNodePhase,
        target: &str,
        digest: [u8; 32],
    ) -> Result<(), UpdateError> {
        let operation = OperationId::from_bytes(uuid_v8(
            digest[..16].try_into().map_err(|_| UpdateError::Failed)?,
        ))
        .map_err(|_| UpdateError::Failed)?;
        let operation_id =
            meshspan_api_contract::OperationId::parse(&identifier(operation.as_bytes()).0)
                .ok_or(UpdateError::Failed)?;
        self.submit(
            IdentityAdministrator {
                principal_id: record.created_by,
                now: crate::OperatingSystemClock.now(),
            },
            &UpdateMutation {
                operation_id,
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
                    restart_readiness: None,
                }),
            },
        )?;
        Ok(())
    }
}

fn retain_evidence(directory: &Path, bytes: &[u8], digest: &[u8; 32]) -> Result<(), UpdateError> {
    let directory =
        crate::daemon_local_state::ensure_private_directory(&directory.join("update-evidence"))
            .map_err(|_| UpdateError::Failed)?;
    let name = crate::update_candidate::hex(digest);
    let file = directory.join(format!("{name}.json"));
    match protected_file::publish(&file, bytes, PublishMode::Create) {
        Ok(()) => Ok(()),
        Err(protected_file::ProtectedFileError::Exists) => {
            let previous =
                protected_file::read_bounded(&file, 1, 16_384).map_err(|_| UpdateError::Failed)?;
            if previous.as_slice() == bytes {
                Ok(())
            } else {
                Err(UpdateError::Failed)
            }
        }
        Err(_) => Err(UpdateError::Failed),
    }
}
