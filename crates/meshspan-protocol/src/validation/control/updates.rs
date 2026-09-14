// SPDX-License-Identifier: GPL-2.0-only

//! Bounds for fresh update observations; authentication and quorum admission are separate.

use super::super::{valid_digest, valid_identifier};
use crate::{
    framing::WireContractError,
    v1::{
        ProbeUpdateReadiness, UpdateReadinessResult, UpdateWorkloadObservation, UpdateWorkloadState,
    },
};

pub(super) fn request(value: &ProbeUpdateReadiness) -> Result<(), WireContractError> {
    valid_identifier(&value.rollout_id)?;
    valid_digest(&value.quorum_plan_digest)
}

pub(super) fn response(value: &UpdateReadinessResult) -> Result<(), WireContractError> {
    valid_identifier(&value.rollout_id)?;
    valid_identifier(&value.node_id)?;
    valid_digest(&value.quorum_plan_digest)?;
    if value.incarnation == 0
        || value.applied_index > value.committed_index
        || value.observed_at_unix_micros <= 0
        || value.runtime_report.is_empty()
        || value.runtime_report.len() > 8192
    {
        return Err(WireContractError::InvalidMessage);
    }
    if let Some(scan) = &value.local_content_scan {
        workload(scan, value)?;
    }
    Ok(())
}

fn workload(
    value: &UpdateWorkloadObservation,
    parent: &UpdateReadinessResult,
) -> Result<(), WireContractError> {
    valid_identifier(&value.excluded_node_id)?;
    if let Some(volume) = &value.current_volume_id {
        valid_identifier(volume)?;
    }
    let state = UpdateWorkloadState::try_from(value.state)
        .map_err(|_| WireContractError::InvalidMessage)?;
    if value.excluded_node_incarnation == 0
        || value.preparation_sequence == 0
        || value.preparation_log_index == 0
        || value.preparation_log_index > parent.applied_index
        || value.metadata_revision == 0
        || value.observed_at_unix_micros <= 0
        || value.observed_at_unix_micros > parent.observed_at_unix_micros
        || state == UpdateWorkloadState::Unspecified
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}
