// SPDX-License-Identifier: GPL-2.0-only

//! Private shard-stream control-message validation.

use crate::framing::{WireContractError, WireLimits};
use crate::v1::data_control_envelope::Message;
use crate::v1::{GetShardHeader, OperationOutcome, PutShardReady, VersionedPayload};

use super::{
    valid_digest, valid_identifier, valid_nonempty_bytes, validate_header,
    validate_operation_result, validate_payload, validate_shard, validate_wire_error,
};

pub(super) fn message(value: &Message, limits: WireLimits) -> Result<(), WireContractError> {
    match value {
        Message::PutShardBegin(value) => {
            validate_header(
                value
                    .header
                    .as_ref()
                    .ok_or(WireContractError::InvalidMessage)?,
            )?;
            validate_target(&value.target_id, value.target_generation)?;
            validate_shard(value.shard.as_ref())?;
            nonzero(value.declared_length)?;
            valid_digest(&value.declared_digest)?;
            valid_nonempty_bytes(&value.write_capability, limits.maximum_control_bytes())
        }
        Message::PutShardReady(value) => put_ready(value, limits),
        Message::PutShardFinish(value) => {
            nonzero(value.final_length)?;
            valid_digest(&value.final_digest)
        }
        Message::PutShardResult(value) => {
            validate_operation_result(value.result.as_ref(), limits)?;
            validate_mutation_receipt(value.result.as_ref(), value.receipt.as_ref(), limits)
        }
        Message::GetShardRequest(value) => {
            validate_header(
                value
                    .header
                    .as_ref()
                    .ok_or(WireContractError::InvalidMessage)?,
            )?;
            validate_target(&value.target_id, value.target_generation)?;
            validate_shard(value.shard.as_ref())?;
            valid_nonempty_bytes(&value.read_capability, limits.maximum_control_bytes())
        }
        Message::GetShardHeader(value) => get_header(value, limits),
        Message::GetShardResult(value) => validate_operation_result(value.result.as_ref(), limits),
        Message::DeleteShardRequest(value) => {
            validate_header(
                value
                    .header
                    .as_ref()
                    .ok_or(WireContractError::InvalidMessage)?,
            )?;
            validate_target(&value.target_id, value.target_generation)?;
            validate_shard(value.shard.as_ref())?;
            validate_payload(value.removal_permit.as_ref(), limits)
        }
        Message::DeleteShardResult(value) => {
            validate_operation_result(value.result.as_ref(), limits)?;
            validate_mutation_receipt(value.result.as_ref(), value.receipt.as_ref(), limits)
        }
        Message::ValidateRemoval(value) => {
            validate_header(
                value
                    .header
                    .as_ref()
                    .ok_or(WireContractError::InvalidMessage)?,
            )?;
            validate_target(&value.target_id, value.target_generation)?;
            validate_shard(value.shard.as_ref())?;
            valid_digest(&value.permit_digest)
        }
    }
}

fn validate_mutation_receipt(
    result: Option<&crate::v1::OperationResult>,
    receipt: Option<&VersionedPayload>,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    let outcome =
        OperationOutcome::try_from(result.ok_or(WireContractError::InvalidMessage)?.outcome)
            .map_err(|_| WireContractError::InvalidMessage)?;
    match outcome {
        OperationOutcome::Durable => validate_payload(receipt, limits),
        OperationOutcome::Rejected | OperationOutcome::Stale | OperationOutcome::Failed
            if receipt.is_none() =>
        {
            Ok(())
        }
        _ => Err(WireContractError::InvalidMessage),
    }
}

fn put_ready(value: &PutShardReady, limits: WireLimits) -> Result<(), WireContractError> {
    if value.maximum_frame_bytes == 0
        || value.maximum_frame_bytes
            > u64::try_from(limits.maximum_data_frame_bytes())
                .map_err(|_| WireContractError::InvalidMessage)?
    {
        return Err(WireContractError::InvalidMessage);
    }
    match &value.rejection {
        Some(error) if value.reservation.is_empty() => validate_wire_error(error),
        None => valid_nonempty_bytes(&value.reservation, limits.maximum_control_bytes()),
        Some(_) => Err(WireContractError::InvalidMessage),
    }
}

fn get_header(value: &GetShardHeader, limits: WireLimits) -> Result<(), WireContractError> {
    if let Some(error) = &value.rejection {
        validate_wire_error(error)?;
        if value.shard.is_some() || value.length != 0 || !value.digest.is_empty() {
            return Err(WireContractError::InvalidMessage);
        }
        return Ok(());
    }
    validate_shard(value.shard.as_ref())?;
    nonzero(value.length)?;
    valid_digest(&value.digest)?;
    if value.maximum_frame_bytes == 0
        || value.maximum_frame_bytes
            > u64::try_from(limits.maximum_data_frame_bytes())
                .map_err(|_| WireContractError::InvalidMessage)?
    {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn validate_target(target_id: &[u8], generation: u64) -> Result<(), WireContractError> {
    valid_identifier(target_id)?;
    nonzero(generation)
}

const fn nonzero(value: u64) -> Result<(), WireContractError> {
    if value == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}
