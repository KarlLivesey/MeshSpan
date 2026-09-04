// SPDX-License-Identifier: GPL-2.0-only

//! Private shard-stream control-message validation.

mod backup;

use crate::framing::{WireContractError, WireLimits};
use crate::v1::data_control_envelope::Message;
use crate::v1::{
    GetShardHeader, OperationOutcome, PutShardReady, ScrubShardRequest, ScrubShardResult,
    VersionedPayload,
};

use super::{
    valid_digest, valid_identifier, valid_nonempty_bytes, validate_header,
    validate_operation_result, validate_payload, validate_shard, validate_wire_error,
};

pub(super) fn message(value: &Message, limits: WireLimits) -> Result<(), WireContractError> {
    match value {
        Message::PutShardBegin(value) => put_begin(value, limits),
        Message::PutShardReady(value) => put_ready(value, limits),
        Message::PutShardFinish(value) => {
            nonzero(value.final_length)?;
            valid_digest(&value.final_digest)
        }
        Message::PutShardResult(value) => {
            validate_operation_result(value.result.as_ref(), limits)?;
            validate_mutation_receipt(value.result.as_ref(), value.receipt.as_ref(), limits)
        }
        Message::GetShardRequest(value) => get_request(value, limits),
        Message::GetShardHeader(value) => get_header(value, limits),
        Message::GetShardResult(value) => validate_operation_result(value.result.as_ref(), limits),
        Message::ScrubShardRequest(value) => scrub_request(value, limits),
        Message::ScrubShardResult(value) => scrub_result(value, limits),
        Message::DeleteShardRequest(value) => delete_request(value, limits),
        Message::DeleteShardResult(value) => {
            validate_operation_result(value.result.as_ref(), limits)?;
            validate_mutation_receipt(value.result.as_ref(), value.receipt.as_ref(), limits)
        }
        Message::ReclaimShardRequest(value) => reclaim_request(value, limits),
        Message::ReclaimShardResult(value) => {
            validate_operation_result(value.result.as_ref(), limits)?;
            validate_mutation_receipt(value.result.as_ref(), value.receipt.as_ref(), limits)
        }
        Message::ValidateRemoval(value) => validate_removal(value),
        Message::StoreBackupBegin(_)
        | Message::StoreBackupReady(_)
        | Message::StoreBackupFinish(_)
        | Message::StoreBackupResult(_)
        | Message::ReadBackupRequest(_)
        | Message::ReadBackupHeader(_)
        | Message::ReadBackupResult(_)
        | Message::VerifyBackupRequest(_)
        | Message::VerifyBackupResult(_)
        | Message::DeleteBackupRequest(_)
        | Message::DeleteBackupResult(_) => backup::message(value, limits),
    }
}

fn put_begin(
    value: &crate::v1::PutShardBegin,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    validate_required_header(value.header.as_ref())?;
    validate_target(&value.target_id, value.target_generation)?;
    validate_shard(value.shard.as_ref())?;
    nonzero(value.declared_length)?;
    valid_digest(&value.declared_digest)?;
    valid_nonempty_bytes(&value.write_capability, limits.maximum_control_bytes())?;
    optional_digest(&value.federation_capability_digest)
}

fn get_request(
    value: &crate::v1::GetShardRequest,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    validate_required_header(value.header.as_ref())?;
    validate_target(&value.target_id, value.target_generation)?;
    validate_shard(value.shard.as_ref())?;
    valid_nonempty_bytes(&value.read_capability, limits.maximum_control_bytes())?;
    optional_digest(&value.federation_capability_digest)
}

fn delete_request(
    value: &crate::v1::DeleteShardRequest,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    validate_required_header(value.header.as_ref())?;
    validate_target(&value.target_id, value.target_generation)?;
    validate_shard(value.shard.as_ref())?;
    validate_removal_authority(
        value.removal_permit.as_ref(),
        &value.federation_capability,
        limits,
    )?;
    correlated_federation_digest(
        &value.federation_capability,
        &value.federation_capability_digest,
    )
}

fn reclaim_request(
    value: &crate::v1::ReclaimShardRequest,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    validate_required_header(value.header.as_ref())?;
    validate_target(&value.target_id, value.target_generation)?;
    validate_shard(value.shard.as_ref())?;
    validate_payload(value.tombstone_receipt.as_ref(), limits)?;
    optional_bytes(&value.federation_capability, limits)?;
    correlated_federation_digest(
        &value.federation_capability,
        &value.federation_capability_digest,
    )
}

fn validate_removal(value: &crate::v1::ValidateRemoval) -> Result<(), WireContractError> {
    validate_required_header(value.header.as_ref())?;
    validate_target(&value.target_id, value.target_generation)?;
    validate_shard(value.shard.as_ref())?;
    valid_digest(&value.permit_digest)
}

fn validate_required_header(
    value: Option<&crate::v1::RequestHeader>,
) -> Result<(), WireContractError> {
    validate_header(value.ok_or(WireContractError::InvalidMessage)?)
}

fn scrub_request(value: &ScrubShardRequest, limits: WireLimits) -> Result<(), WireContractError> {
    validate_header(
        value
            .header
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?,
    )?;
    validate_target(&value.target_id, value.target_generation)?;
    validate_shard(value.shard.as_ref())?;
    valid_nonempty_bytes(&value.federation_capability, limits.maximum_control_bytes())?;
    correlated_federation_digest(
        &value.federation_capability,
        &value.federation_capability_digest,
    )
}

fn scrub_result(value: &ScrubShardResult, limits: WireLimits) -> Result<(), WireContractError> {
    validate_operation_result(value.result.as_ref(), limits)?;
    validate_observation(value.result.as_ref(), value.observation.as_ref(), limits)
}

fn validate_observation(
    result: Option<&crate::v1::OperationResult>,
    observation: Option<&VersionedPayload>,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    validate_mutation_receipt(result, observation, limits)
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

fn optional_digest(value: &[u8]) -> Result<(), WireContractError> {
    if value.is_empty() {
        Ok(())
    } else {
        valid_digest(value)
    }
}

fn validate_removal_authority(
    local_permit: Option<&VersionedPayload>,
    federation_permit: &[u8],
    limits: WireLimits,
) -> Result<(), WireContractError> {
    match (local_permit, federation_permit.is_empty()) {
        (Some(permit), true) => validate_payload(Some(permit), limits),
        (None, false) => valid_nonempty_bytes(federation_permit, limits.maximum_control_bytes()),
        _ => Err(WireContractError::InvalidMessage),
    }
}

fn optional_bytes(value: &[u8], limits: WireLimits) -> Result<(), WireContractError> {
    if value.is_empty() {
        Ok(())
    } else {
        valid_nonempty_bytes(value, limits.maximum_control_bytes())
    }
}

fn correlated_federation_digest(
    capability: &[u8],
    capability_digest: &[u8],
) -> Result<(), WireContractError> {
    if capability.is_empty() == capability_digest.is_empty() {
        optional_digest(capability_digest)
    } else {
        Err(WireContractError::InvalidMessage)
    }
}
