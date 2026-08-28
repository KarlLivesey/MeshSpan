// SPDX-License-Identifier: GPL-2.0-only

//! Semantic validation for generated hostile-input structures.

mod connection;
mod consensus;
mod control;
mod data;

use crate::framing::{WireContractError, WireLimits};
use crate::v1::control_envelope::Message;
use crate::v1::{
    ControlEnvelope, DataControlEnvelope, DataFrame, ErrorCode, LogPosition, OperationOutcome,
    OperationResult, RequestHeader, ShardIdentity, VersionedPayload, WireError,
};

const IDENTIFIER_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;

pub(crate) fn validate_control_envelope(
    envelope: &ControlEnvelope,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    let message = envelope
        .message
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    if message_requires_header(message) {
        validate_header(
            envelope
                .header
                .as_ref()
                .ok_or(WireContractError::InvalidMessage)?,
        )?;
    } else if let Some(header) = &envelope.header {
        validate_header(header)?;
    }
    validate_message(message, limits)
}

pub(crate) fn validate_data_frame(
    frame: &DataFrame,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_nonempty_bytes(&frame.bytes, limits.maximum_data_frame_bytes())
}

pub(crate) fn validate_data_control_envelope(
    envelope: &DataControlEnvelope,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    data::message(
        envelope
            .message
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?,
        limits,
    )
}

fn message_requires_header(message: &Message) -> bool {
    !matches!(
        message,
        Message::NodeHello(_)
            | Message::NodeWelcome(_)
            | Message::Ping(_)
            | Message::Pong(_)
            | Message::GoAway(_)
            | Message::ProtocolError(_)
    )
}

pub(super) fn validate_header(header: &RequestHeader) -> Result<(), WireContractError> {
    let version = header
        .version
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    if version.major != 1
        || header.routing_epoch == 0
        || header.sender_incarnation == 0
        || header.deadline_unix_micros <= 0
        || !is_identifier(&header.mesh_id)
        || !is_identifier(&header.partition_id)
        || !is_identifier(&header.sender_node_id)
        || !is_identifier(&header.request_id)
        || !is_identifier(&header.operation_id)
        || !is_identifier(&header.trace_id)
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

fn validate_message(message: &Message, limits: WireLimits) -> Result<(), WireContractError> {
    match message {
        Message::NodeHello(value) => connection::hello(value, limits),
        Message::NodeWelcome(value) => connection::welcome(value, limits),
        Message::Ping(value) => connection::ping(value),
        Message::Pong(value) => connection::pong(value),
        Message::GoAway(value) => connection::go_away(value),
        Message::ProtocolError(value) => connection::protocol_error(value),
        Message::VoteRequest(value) => consensus::vote_request(value),
        Message::VoteResponse(value) => consensus::vote_response(value),
        Message::AppendRequest(value) => consensus::append_request(value, limits),
        Message::AppendResponse(value) => consensus::append_response(value),
        Message::SnapshotBegin(value) => consensus::snapshot_begin(value, limits),
        Message::SnapshotChunk(value) => consensus::snapshot_chunk(value, limits),
        Message::SnapshotFinish(value) => consensus::snapshot_finish(value),
        Message::SnapshotResult(value) => consensus::snapshot_result(value),
        other => control::message(other, limits),
    }
}

pub(super) fn validate_payload(
    value: Option<&VersionedPayload>,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    let payload = value.ok_or(WireContractError::InvalidMessage)?;
    if payload.format_version == 0 {
        return Err(WireContractError::InvalidMessage);
    }
    valid_optional_bytes(&payload.canonical_bytes, limits.maximum_control_bytes())
}

pub(super) fn validate_payloads(
    values: &[VersionedPayload],
    limits: WireLimits,
    allow_empty: bool,
) -> Result<(), WireContractError> {
    valid_count(values.len(), limits, allow_empty)?;
    for value in values {
        validate_payload(Some(value), limits)?;
    }
    Ok(())
}

pub(super) fn validate_operation_result(
    result: Option<&OperationResult>,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    let result = result.ok_or(WireContractError::InvalidMessage)?;
    let outcome = OperationOutcome::try_from(result.outcome)
        .map_err(|_| WireContractError::InvalidMessage)?;
    if outcome == OperationOutcome::Unspecified {
        return Err(WireContractError::InvalidMessage);
    }
    if let Some(error) = &result.error {
        validate_wire_error(error)?;
    }
    if let Some(payload) = &result.result {
        validate_payload(Some(payload), limits)?;
    }
    if !result.result_digest.is_empty() {
        valid_digest(&result.result_digest)?;
    }
    Ok(())
}

pub(super) fn validate_wire_error(error: &WireError) -> Result<(), WireContractError> {
    let code = ErrorCode::try_from(error.code).map_err(|_| WireContractError::InvalidMessage)?;
    if code == ErrorCode::Unspecified
        || error.diagnostic_code == 0
        || error.retry_after_micros == Some(0)
    {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn validate_position(
    position: Option<&LogPosition>,
    allow_origin: bool,
) -> Result<(), WireContractError> {
    let position = position.ok_or(WireContractError::InvalidMessage)?;
    let has_zero = position.term == 0 || position.index == 0;
    let mismatched_origin = (position.term == 0) != (position.index == 0);
    if (!allow_origin && has_zero) || mismatched_origin {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn validate_shard(shard: Option<&ShardIdentity>) -> Result<(), WireContractError> {
    let shard = shard.ok_or(WireContractError::InvalidMessage)?;
    valid_digest(&shard.manifest_digest)?;
    if shard.generation == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn valid_digests(
    values: &[Vec<u8>],
    limits: WireLimits,
    allow_empty: bool,
) -> Result<(), WireContractError> {
    valid_count(values.len(), limits, allow_empty)?;
    for value in values {
        valid_digest(value)?;
    }
    Ok(())
}

pub(super) fn valid_identifiers(
    values: &[Vec<u8>],
    limits: WireLimits,
    allow_empty: bool,
) -> Result<(), WireContractError> {
    valid_count(values.len(), limits, allow_empty)?;
    for value in values {
        valid_identifier(value)?;
    }
    Ok(())
}

pub(super) fn valid_page_limit(value: u32, limits: WireLimits) -> Result<(), WireContractError> {
    let value = usize::try_from(value).map_err(|_| WireContractError::InvalidMessage)?;
    if value == 0 || value > limits.maximum_items() {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn valid_text(value: &str, limits: WireLimits) -> Result<(), WireContractError> {
    if value.is_empty()
        || value.len() > limits.maximum_text_bytes()
        || value.chars().any(char::is_control)
    {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn valid_count(
    value: usize,
    limits: WireLimits,
    allow_empty: bool,
) -> Result<(), WireContractError> {
    if (!allow_empty && value == 0) || value > limits.maximum_items() {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn valid_identifier(value: &[u8]) -> Result<(), WireContractError> {
    if is_identifier(value) {
        Ok(())
    } else {
        Err(WireContractError::InvalidMessage)
    }
}

pub(super) fn valid_digest(value: &[u8]) -> Result<(), WireContractError> {
    if value.len() == DIGEST_BYTES {
        Ok(())
    } else {
        Err(WireContractError::InvalidMessage)
    }
}

pub(super) fn valid_nonempty_bytes(value: &[u8], maximum: usize) -> Result<(), WireContractError> {
    if value.is_empty() || value.len() > maximum {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn valid_optional_bytes(value: &[u8], maximum: usize) -> Result<(), WireContractError> {
    if value.len() > maximum {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn is_identifier(value: &[u8]) -> bool {
    value.len() == IDENTIFIER_BYTES && value.iter().any(|byte| *byte != 0)
}
