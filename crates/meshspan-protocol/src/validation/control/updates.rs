// SPDX-License-Identifier: GPL-2.0-only

//! Bounds for fresh update observations; authentication and quorum admission are separate.

use super::super::{valid_digest, valid_identifier};
use crate::{
    framing::WireContractError,
    v1::{ProbeUpdateReadiness, UpdateReadinessResult},
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
    Ok(())
}
