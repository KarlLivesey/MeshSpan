// SPDX-License-Identifier: GPL-2.0-only

//! Consensus and snapshot message validation.

use crate::framing::{WireContractError, WireLimits};
use crate::v1::{
    AppendRequest, AppendResponse, SnapshotBegin, SnapshotChunk, SnapshotFinish, SnapshotResult,
    VoteRequest, VoteResponse,
};

use super::{
    valid_count, valid_digest, valid_identifier, valid_nonempty_bytes, validate_payload,
    validate_position, validate_wire_error,
};

pub(super) fn vote_request(value: &VoteRequest) -> Result<(), WireContractError> {
    valid_identifier(&value.candidate_node_id)?;
    valid_digest(&value.quorum_plan_digest)?;
    validate_position(value.last_log.as_ref(), true)?;
    if value.term == 0 || value.candidate_incarnation == 0 || value.membership_epoch == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn vote_response(value: &VoteResponse) -> Result<(), WireContractError> {
    valid_digest(&value.quorum_plan_digest)?;
    if value.term == 0 || value.membership_epoch == 0 {
        return Err(WireContractError::InvalidMessage);
    }
    validate_conditional_error(value.granted, value.rejection.as_ref())
}

pub(super) fn append_request(
    value: &AppendRequest,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.leader_node_id)?;
    valid_digest(&value.previous_digest)?;
    valid_digest(&value.quorum_plan_digest)?;
    validate_position(value.previous.as_ref(), true)?;
    valid_count(value.entries.len(), limits, true)?;
    for entry in &value.entries {
        validate_position(entry.position.as_ref(), false)?;
        valid_identifier(&entry.operation_id)?;
        valid_digest(&entry.command_digest)?;
        validate_payload(entry.command.as_ref(), limits)?;
    }
    if value.term == 0
        || value.leader_incarnation == 0
        || value.membership_epoch == 0
        || value.read_barrier_id == Some(0)
    {
        return Err(WireContractError::InvalidMessage);
    }
    validate_entry_order(value)
}

pub(super) fn append_response(value: &AppendResponse) -> Result<(), WireContractError> {
    valid_digest(&value.quorum_plan_digest)?;
    if value.term == 0
        || value.next_index_hint == 0
        || value.membership_epoch == 0
        || value.read_barrier_id == Some(0)
    {
        return Err(WireContractError::InvalidMessage);
    }
    validate_conditional_error(value.accepted, value.rejection.as_ref())
}

pub(super) fn snapshot_begin(
    value: &SnapshotBegin,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.snapshot_id)?;
    valid_digest(&value.digest)?;
    valid_digest(&value.quorum_plan_digest)?;
    valid_nonempty_bytes(&value.quorum_plan, limits.maximum_control_bytes())?;
    validate_position(value.included_position.as_ref(), false)?;
    if value.state_revision == 0
        || value.total_bytes == 0
        || value.format_version == 0
        || value.membership_epoch == 0
    {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn snapshot_chunk(
    value: &SnapshotChunk,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.snapshot_id)?;
    valid_nonempty_bytes(&value.bytes, limits.maximum_control_bytes())?;
    valid_digest(&value.chunk_digest)
}

pub(super) fn snapshot_finish(value: &SnapshotFinish) -> Result<(), WireContractError> {
    valid_identifier(&value.snapshot_id)?;
    valid_digest(&value.digest)?;
    if value.total_bytes == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn snapshot_result(value: &SnapshotResult) -> Result<(), WireContractError> {
    valid_identifier(&value.snapshot_id)?;
    if value.installed {
        validate_position(value.included_position.as_ref(), false)?;
        if value.error.is_some() {
            return Err(WireContractError::InvalidMessage);
        }
    } else {
        validate_wire_error(
            value
                .error
                .as_ref()
                .ok_or(WireContractError::InvalidMessage)?,
        )?;
    }
    Ok(())
}

fn validate_conditional_error(
    accepted: bool,
    error: Option<&crate::v1::WireError>,
) -> Result<(), WireContractError> {
    match (accepted, error) {
        (true, None) => Ok(()),
        (false, Some(error)) => validate_wire_error(error),
        _ => Err(WireContractError::InvalidMessage),
    }
}

fn validate_entry_order(value: &AppendRequest) -> Result<(), WireContractError> {
    let mut expected_index = value
        .previous
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?
        .index
        .checked_add(1)
        .ok_or(WireContractError::InvalidMessage)?;
    for entry in &value.entries {
        let position = entry
            .position
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?;
        if position.index != expected_index || position.term > value.term {
            return Err(WireContractError::InvalidMessage);
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(WireContractError::InvalidMessage)?;
    }
    Ok(())
}
