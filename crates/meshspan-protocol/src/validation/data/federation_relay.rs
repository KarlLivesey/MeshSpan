// SPDX-License-Identifier: GPL-2.0-only

//! Structural relay validation; signatures, current peers and receipts need runtime checks.

use super::super::federation::backup;
use super::super::{valid_digest, valid_identifier, validate_header};
use crate::{
    WireContractError, WireLimits, decode_federation_frame,
    v1::{
        ForwardFederatedBackupReady, ForwardFederatedBackupRequest, ForwardFederatedBackupResult,
        federation_envelope::Message,
    },
};

pub(super) fn request(
    value: &ForwardFederatedBackupRequest,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    let header = value
        .header
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    validate_header(header)?;
    valid_identifier(&value.provider_node_id)?;
    super::backup::validate_maximum_frame_bytes(value.maximum_frame_bytes, limits)?;
    let decoded = decode_federation_frame(&value.request, limits)?;
    let request = decoded.as_inner();
    let original = request
        .header
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    let Some(Message::ExecuteBackup(execution)) = request.message.as_ref() else {
        return Err(WireContractError::InvalidMessage);
    };
    let permit = execution
        .permit
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    let scope = permit
        .scope
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    if value.provider_node_id != scope.provider_node_id
        || header.mesh_id != scope.provider_mesh_id
        || header.request_id != original.request_id
        || header.operation_id != original.operation_id
        || header.trace_id != original.trace_id
        || header.deadline_unix_micros > original.deadline_unix_micros
        || header.deadline_unix_micros > permit.expires_at_unix_micros
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

pub(super) fn ready(
    value: &ForwardFederatedBackupReady,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_digest(&value.request_digest)?;
    let ready = value
        .ready
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    if !ready.signature.is_empty() {
        return Err(WireContractError::InvalidMessage);
    }
    backup::ready_payload(ready, limits)
}

pub(super) fn result(
    value: &ForwardFederatedBackupResult,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_digest(&value.request_digest)?;
    let result = value
        .result
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    if !result.signature.is_empty() {
        return Err(WireContractError::InvalidMessage);
    }
    backup::result_payload(result, limits).map(|_| ())
}
