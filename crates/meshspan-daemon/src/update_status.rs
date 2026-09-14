// SPDX-License-Identifier: GPL-2.0-only

use crate::update_service::{UpdateError, identifier};
use meshspan_api_contract::{UpdateProgress, UpdateRolloutStatus, UpdateState};
use meshspan_metadata::{UpdateProgressCounts, UpdateRolloutRecord, UpdateRolloutState};

pub(crate) fn rollout(
    record: &UpdateRolloutRecord,
    counts: UpdateProgressCounts,
) -> Result<UpdateRolloutStatus, UpdateError> {
    Ok(UpdateRolloutStatus {
        artifacts: record
            .manifest
            .artifacts()
            .map_err(|_| UpdateError::Failed)?
            .into_iter()
            .map(
                |(target, artifact)| meshspan_api_contract::UpdateArtifactDescriptor {
                    target,
                    byte_length: artifact.size,
                    sha256: artifact.sha256,
                },
            )
            .collect(),
        rollout_id: identifier(record.rollout_id.as_bytes()),
        signer_id: identifier(record.signer_id.as_bytes()),
        version: record
            .manifest
            .version()
            .map_err(|_| UpdateError::Failed)?
            .to_owned(),
        source_commit: record
            .manifest
            .source_commit()
            .map_err(|_| UpdateError::Failed)?
            .to_owned(),
        sequence: record.sequence,
        state: match record.state {
            UpdateRolloutState::Running => UpdateState::Running,
            UpdateRolloutState::Paused => UpdateState::Paused,
            UpdateRolloutState::Completed => UpdateState::Completed,
            UpdateRolloutState::Cancelled => UpdateState::Cancelled,
        },
        allow_service_interruption: record.allow_service_interruption,
        progress: UpdateProgress {
            pending: counts.pending.to_string(),
            staged: counts.staged.to_string(),
            restarting: counts.restarting.to_string(),
            verified: counts.verified.to_string(),
            failed: counts.failed.to_string(),
            unresolved_restarts: counts.unresolved_restarts.to_string(),
        },
    })
}
