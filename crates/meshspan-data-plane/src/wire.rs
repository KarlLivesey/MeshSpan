// SPDX-License-Identifier: GPL-2.0-only

//! Exact conversions between generated private-wire records and provider contracts.

use meshspan_contracts::{
    ContractError, ContractVersion, ReclamationReceipt, RemovalPermit, RequestContext,
    ShardIdentity, ShardReceipt, TombstoneReceipt,
};
use meshspan_domain::{OperationId, Revision, UnixMicros};
use meshspan_protocol::v1::{
    ErrorCode, OperationOutcome, OperationResult, RequestHeader, VersionedPayload, WireError,
};

use crate::DataPlaneError;
use crate::capability::{
    decode_reclamation_receipt, decode_removal_permit, decode_shard_receipt,
    decode_tombstone_receipt, encode_reclamation_receipt, encode_removal_permit,
    encode_shard_receipt, encode_tombstone_receipt,
};

pub(crate) const RECEIPT_FORMAT_VERSION: u32 = 1;
const DIAGNOSTIC_PROVIDER_REJECTION: u32 = 1;

pub(crate) fn request_context(
    header: &RequestHeader,
    revision: Revision,
) -> Result<RequestContext, DataPlaneError> {
    request_context_with_revision(header, Some(revision))
}

pub(crate) fn request_context_without_revision(
    header: &RequestHeader,
) -> Result<RequestContext, DataPlaneError> {
    request_context_with_revision(header, None)
}

fn request_context_with_revision(
    header: &RequestHeader,
    expected_revision: Option<Revision>,
) -> Result<RequestContext, DataPlaneError> {
    let version = header
        .version
        .as_ref()
        .ok_or(DataPlaneError::InvalidMessage)?;
    if version.major != 1 || version.minor != 0 {
        return Err(DataPlaneError::InvalidMessage);
    }
    let operation_bytes: [u8; 16] = header
        .operation_id
        .as_slice()
        .try_into()
        .map_err(|_| DataPlaneError::InvalidMessage)?;
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes(operation_bytes)
            .map_err(|_| DataPlaneError::InvalidMessage)?,
        deadline: UnixMicros::new(header.deadline_unix_micros),
        expected_revision,
    })
}

pub(crate) fn shard(
    value: &meshspan_protocol::v1::ShardIdentity,
) -> Result<ShardIdentity, DataPlaneError> {
    Ok(ShardIdentity {
        manifest_digest: value
            .manifest_digest
            .as_slice()
            .try_into()
            .map_err(|_| DataPlaneError::InvalidMessage)?,
        stripe_index: value.stripe_index,
        shard_index: u16::try_from(value.shard_index)
            .map_err(|_| DataPlaneError::InvalidMessage)?,
        generation: value.generation,
    })
}

pub(crate) fn wire_shard(value: ShardIdentity) -> meshspan_protocol::v1::ShardIdentity {
    meshspan_protocol::v1::ShardIdentity {
        manifest_digest: value.manifest_digest.to_vec(),
        stripe_index: value.stripe_index,
        shard_index: u32::from(value.shard_index),
        generation: value.generation,
    }
}

pub(crate) fn durable_result() -> OperationResult {
    OperationResult {
        outcome: OperationOutcome::Durable.into(),
        committed_revision: None,
        error: None,
        result: None,
        result_digest: Vec::new(),
    }
}

pub(crate) fn rejected_result(error: ContractError) -> OperationResult {
    OperationResult {
        outcome: match error {
            ContractError::Stale => OperationOutcome::Stale,
            ContractError::Unavailable | ContractError::InternalContract => {
                OperationOutcome::Failed
            }
            _ => OperationOutcome::Rejected,
        }
        .into(),
        committed_revision: None,
        error: Some(wire_error(error)),
        result: None,
        result_digest: Vec::new(),
    }
}

pub(crate) fn wire_error(error: ContractError) -> WireError {
    WireError {
        code: error_code(error).into(),
        diagnostic_code: DIAGNOSTIC_PROVIDER_REJECTION,
        retry_after_micros: None,
    }
}

pub(crate) fn require_durable(result: Option<&OperationResult>) -> Result<(), DataPlaneError> {
    let result = result.ok_or(DataPlaneError::InvalidMessage)?;
    let outcome =
        OperationOutcome::try_from(result.outcome).map_err(|_| DataPlaneError::InvalidMessage)?;
    if outcome == OperationOutcome::Durable && result.error.is_none() {
        return Ok(());
    }
    let error = result
        .error
        .as_ref()
        .ok_or(DataPlaneError::InvalidMessage)?;
    let code = ErrorCode::try_from(error.code).map_err(|_| DataPlaneError::InvalidMessage)?;
    Err(DataPlaneError::Remote(code))
}

pub(crate) fn remote_rejection(error: &WireError) -> Result<DataPlaneError, DataPlaneError> {
    let code = ErrorCode::try_from(error.code).map_err(|_| DataPlaneError::InvalidMessage)?;
    Ok(DataPlaneError::Remote(code))
}

pub(crate) fn receipt_payload(receipt: ShardReceipt) -> VersionedPayload {
    VersionedPayload {
        format_version: RECEIPT_FORMAT_VERSION,
        canonical_bytes: encode_shard_receipt(receipt),
    }
}

pub(crate) fn receipt(value: Option<&VersionedPayload>) -> Result<ShardReceipt, DataPlaneError> {
    let value = value.ok_or(DataPlaneError::InvalidMessage)?;
    if value.format_version != RECEIPT_FORMAT_VERSION {
        return Err(DataPlaneError::InvalidMessage);
    }
    decode_shard_receipt(&value.canonical_bytes).map_err(Into::into)
}

pub(crate) fn removal_permit_payload(permit: RemovalPermit) -> VersionedPayload {
    VersionedPayload {
        format_version: RECEIPT_FORMAT_VERSION,
        canonical_bytes: encode_removal_permit(permit),
    }
}

pub(crate) fn removal_permit(
    value: Option<&VersionedPayload>,
) -> Result<RemovalPermit, DataPlaneError> {
    let value = versioned_payload(value)?;
    decode_removal_permit(&value.canonical_bytes).map_err(Into::into)
}

pub(crate) fn tombstone_receipt_payload(receipt: TombstoneReceipt) -> VersionedPayload {
    VersionedPayload {
        format_version: RECEIPT_FORMAT_VERSION,
        canonical_bytes: encode_tombstone_receipt(receipt),
    }
}

pub(crate) fn tombstone_receipt(
    value: Option<&VersionedPayload>,
) -> Result<TombstoneReceipt, DataPlaneError> {
    let value = versioned_payload(value)?;
    decode_tombstone_receipt(&value.canonical_bytes).map_err(Into::into)
}

pub(crate) fn reclamation_receipt_payload(receipt: ReclamationReceipt) -> VersionedPayload {
    VersionedPayload {
        format_version: RECEIPT_FORMAT_VERSION,
        canonical_bytes: encode_reclamation_receipt(receipt),
    }
}

pub(crate) fn reclamation_receipt(
    value: Option<&VersionedPayload>,
) -> Result<ReclamationReceipt, DataPlaneError> {
    let value = versioned_payload(value)?;
    decode_reclamation_receipt(&value.canonical_bytes).map_err(Into::into)
}

fn versioned_payload(
    value: Option<&VersionedPayload>,
) -> Result<&VersionedPayload, DataPlaneError> {
    let value = value.ok_or(DataPlaneError::InvalidMessage)?;
    if value.format_version == RECEIPT_FORMAT_VERSION {
        Ok(value)
    } else {
        Err(DataPlaneError::InvalidMessage)
    }
}

const fn error_code(error: ContractError) -> ErrorCode {
    match error {
        ContractError::InvalidInput => ErrorCode::Invalid,
        ContractError::Unauthorized => ErrorCode::Unauthorised,
        ContractError::Stale => ErrorCode::Stale,
        ContractError::Conflict => ErrorCode::Conflict,
        ContractError::UnsupportedVersion => ErrorCode::Unsupported,
        ContractError::NotFound => ErrorCode::NotFound,
        ContractError::ResourceExhausted => ErrorCode::Exhausted,
        ContractError::Corrupt => ErrorCode::Corrupt,
        ContractError::DeadlineExceeded => ErrorCode::Deadline,
        ContractError::Unavailable => ErrorCode::Unavailable,
        ContractError::InternalContract => ErrorCode::InternalContract,
    }
}
