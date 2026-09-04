// SPDX-License-Identifier: GPL-2.0-only

//! Exact conversions between remote-backup wire records and provider contracts.

use meshspan_contracts::{
    BackupDeleteReceipt, BackupObjectIdentity, BackupObjectReceipt, BackupReadReceipt,
    BackupReadRequest, BackupVerifyRequest, ContractVersion, RequestContext,
};
use meshspan_domain::{BackupDestinationId, BackupId, OperationId, Revision, UnixMicros};
use meshspan_protocol::v1::{
    ErrorCode, OperationOutcome, OperationResult, RequestHeader, WireError,
};

use crate::BackupPlaneError;

const DIAGNOSTIC_PROVIDER_REJECTION: u32 = 2;

pub(crate) fn request_context(
    header: &RequestHeader,
    revision: Revision,
) -> Result<RequestContext, BackupPlaneError> {
    let version = header
        .version
        .as_ref()
        .ok_or(BackupPlaneError::InvalidMessage)?;
    let operation_id = operation_id(&header.operation_id)?;
    if version.major != 1 || version.minor != 0 {
        return Err(BackupPlaneError::InvalidMessage);
    }
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id,
        deadline: UnixMicros::new(header.deadline_unix_micros),
        expected_revision: Some(revision),
    })
}

pub(crate) fn object(
    value: &meshspan_protocol::v1::BackupObjectIdentity,
) -> Result<BackupObjectIdentity, BackupPlaneError> {
    Ok(BackupObjectIdentity {
        backup_id: identifier(&value.backup_id).and_then(|bytes| {
            BackupId::from_bytes(bytes).map_err(|_| BackupPlaneError::InvalidMessage)
        })?,
        destination_id: identifier(&value.destination_id).and_then(|bytes| {
            BackupDestinationId::from_bytes(bytes).map_err(|_| BackupPlaneError::InvalidMessage)
        })?,
        provider_generation: value.provider_generation,
        byte_length: value.byte_length,
        digest: digest(&value.digest)?,
    })
}

pub(crate) fn wire_object(
    value: BackupObjectIdentity,
) -> meshspan_protocol::v1::BackupObjectIdentity {
    meshspan_protocol::v1::BackupObjectIdentity {
        backup_id: value.backup_id.as_bytes().to_vec(),
        destination_id: value.destination_id.as_bytes().to_vec(),
        provider_generation: value.provider_generation,
        byte_length: value.byte_length,
        digest: value.digest.to_vec(),
    }
}

pub(crate) fn object_receipt(
    value: &meshspan_protocol::v1::BackupObjectReceipt,
) -> Result<BackupObjectReceipt, BackupPlaneError> {
    Ok(BackupObjectReceipt {
        operation_id: operation_id(&value.operation_id)?,
        object: object(
            value
                .object
                .as_ref()
                .ok_or(BackupPlaneError::InvalidMessage)?,
        )?,
        object_reference: meshspan_contracts::BackupObjectReference::new(
            value.object_reference.clone(),
        )
        .map_err(|_| BackupPlaneError::InvalidMessage)?,
    })
}

pub(crate) fn wire_object_receipt(
    value: &BackupObjectReceipt,
) -> meshspan_protocol::v1::BackupObjectReceipt {
    meshspan_protocol::v1::BackupObjectReceipt {
        operation_id: value.operation_id.as_bytes().to_vec(),
        object: Some(wire_object(value.object)),
        object_reference: value.object_reference.as_str().to_owned(),
    }
}

pub(crate) fn read_receipt(
    value: &meshspan_protocol::v1::BackupReadReceipt,
) -> Result<BackupReadReceipt, BackupPlaneError> {
    Ok(BackupReadReceipt {
        operation_id: operation_id(&value.operation_id)?,
        byte_length: value.byte_length,
        digest: digest(&value.digest)?,
    })
}

pub(crate) fn wire_read_receipt(
    value: BackupReadReceipt,
) -> meshspan_protocol::v1::BackupReadReceipt {
    meshspan_protocol::v1::BackupReadReceipt {
        operation_id: value.operation_id.as_bytes().to_vec(),
        byte_length: value.byte_length,
        digest: value.digest.to_vec(),
    }
}

pub(crate) fn delete_receipt(
    value: &meshspan_protocol::v1::BackupDeleteReceipt,
) -> Result<BackupDeleteReceipt, BackupPlaneError> {
    Ok(BackupDeleteReceipt {
        operation_id: operation_id(&value.operation_id)?,
        object: object(
            value
                .object
                .as_ref()
                .ok_or(BackupPlaneError::InvalidMessage)?,
        )?,
        retirement_revision: Revision::new(value.retirement_revision),
    })
}

pub(crate) fn wire_delete_receipt(
    value: BackupDeleteReceipt,
) -> meshspan_protocol::v1::BackupDeleteReceipt {
    meshspan_protocol::v1::BackupDeleteReceipt {
        operation_id: value.operation_id.as_bytes().to_vec(),
        object: Some(wire_object(value.object)),
        retirement_revision: value.retirement_revision.get(),
    }
}

pub(crate) fn read_request_parts(
    context: RequestContext,
    object: BackupObjectIdentity,
    object_reference: String,
) -> Result<BackupReadRequest, BackupPlaneError> {
    Ok(BackupReadRequest {
        context,
        object,
        object_reference: meshspan_contracts::BackupObjectReference::new(object_reference)
            .map_err(|_| BackupPlaneError::InvalidMessage)?,
    })
}

pub(crate) fn verify_request_parts(
    context: RequestContext,
    object: BackupObjectIdentity,
    object_reference: String,
) -> Result<BackupVerifyRequest, BackupPlaneError> {
    Ok(BackupVerifyRequest {
        context,
        object,
        object_reference: meshspan_contracts::BackupObjectReference::new(object_reference)
            .map_err(|_| BackupPlaneError::InvalidMessage)?,
    })
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

pub(crate) fn rejected_result(error: meshspan_contracts::ContractError) -> OperationResult {
    OperationResult {
        outcome: match error {
            meshspan_contracts::ContractError::Stale => OperationOutcome::Stale,
            meshspan_contracts::ContractError::Unavailable
            | meshspan_contracts::ContractError::InternalContract => OperationOutcome::Failed,
            _ => OperationOutcome::Rejected,
        }
        .into(),
        committed_revision: None,
        error: Some(wire_error(error)),
        result: None,
        result_digest: Vec::new(),
    }
}

pub(crate) fn wire_error(error: meshspan_contracts::ContractError) -> WireError {
    WireError {
        code: error_code(error).into(),
        diagnostic_code: DIAGNOSTIC_PROVIDER_REJECTION,
        retry_after_micros: None,
    }
}

pub(crate) fn require_durable(result: Option<&OperationResult>) -> Result<(), BackupPlaneError> {
    let result = result.ok_or(BackupPlaneError::InvalidMessage)?;
    let outcome =
        OperationOutcome::try_from(result.outcome).map_err(|_| BackupPlaneError::InvalidMessage)?;
    if outcome == OperationOutcome::Durable && result.error.is_none() {
        return Ok(());
    }
    let error = result
        .error
        .as_ref()
        .ok_or(BackupPlaneError::InvalidMessage)?;
    Err(remote_rejection(error)?)
}

pub(crate) fn remote_rejection(error: &WireError) -> Result<BackupPlaneError, BackupPlaneError> {
    let code = ErrorCode::try_from(error.code).map_err(|_| BackupPlaneError::InvalidMessage)?;
    Ok(BackupPlaneError::Remote(code))
}

fn operation_id(value: &[u8]) -> Result<OperationId, BackupPlaneError> {
    OperationId::from_bytes(identifier(value)?).map_err(|_| BackupPlaneError::InvalidMessage)
}

fn identifier(value: &[u8]) -> Result<[u8; 16], BackupPlaneError> {
    value
        .try_into()
        .map_err(|_| BackupPlaneError::InvalidMessage)
}

fn digest(value: &[u8]) -> Result<[u8; 32], BackupPlaneError> {
    value
        .try_into()
        .map_err(|_| BackupPlaneError::InvalidMessage)
}

const fn error_code(error: meshspan_contracts::ContractError) -> ErrorCode {
    match error {
        meshspan_contracts::ContractError::InvalidInput => ErrorCode::Invalid,
        meshspan_contracts::ContractError::Unauthorized => ErrorCode::Unauthorised,
        meshspan_contracts::ContractError::Stale => ErrorCode::Stale,
        meshspan_contracts::ContractError::Conflict => ErrorCode::Conflict,
        meshspan_contracts::ContractError::UnsupportedVersion => ErrorCode::Unsupported,
        meshspan_contracts::ContractError::NotFound => ErrorCode::NotFound,
        meshspan_contracts::ContractError::ResourceExhausted => ErrorCode::Exhausted,
        meshspan_contracts::ContractError::Corrupt => ErrorCode::Corrupt,
        meshspan_contracts::ContractError::DeadlineExceeded => ErrorCode::Deadline,
        meshspan_contracts::ContractError::Unavailable => ErrorCode::Unavailable,
        meshspan_contracts::ContractError::InternalContract => ErrorCode::InternalContract,
    }
}
