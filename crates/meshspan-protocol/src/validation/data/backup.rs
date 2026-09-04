// SPDX-License-Identifier: GPL-2.0-only

//! Remote metadata-backup provider control-message validation.

use crate::framing::{WireContractError, WireLimits};
use crate::v1::data_control_envelope::Message;
use crate::v1::{
    BackupDeleteReceipt, BackupObjectIdentity, BackupObjectReceipt, BackupReadReceipt,
    DeleteBackupRequest, OperationOutcome, ReadBackupHeader, ReadBackupRequest, StoreBackupBegin,
    StoreBackupReady, VerifyBackupRequest,
};

use super::super::{
    valid_digest, valid_identifier, valid_nonempty_bytes, validate_header,
    validate_operation_result, validate_wire_error,
};
use super::nonzero;

const MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES: usize = 2_048;

pub(super) fn message(value: &Message, limits: WireLimits) -> Result<(), WireContractError> {
    match value {
        Message::StoreBackupBegin(value) => store_begin(value),
        Message::StoreBackupReady(value) => store_ready(value, limits),
        Message::StoreBackupFinish(value) => {
            nonzero(value.final_length)?;
            valid_nonzero_digest(&value.final_digest)
        }
        Message::StoreBackupResult(value) => {
            validate_operation_result(value.result.as_ref(), limits)?;
            validate_object_outcome(value.result.as_ref(), value.receipt.as_ref(), limits)
        }
        Message::ReadBackupRequest(value) => read_request(value, limits),
        Message::ReadBackupHeader(value) => read_header(value, limits),
        Message::ReadBackupResult(value) => {
            validate_operation_result(value.result.as_ref(), limits)?;
            validate_read_outcome(value.result.as_ref(), value.receipt.as_ref())
        }
        Message::VerifyBackupRequest(value) => verify_request(value, limits),
        Message::VerifyBackupResult(value) => {
            validate_operation_result(value.result.as_ref(), limits)?;
            validate_object_outcome(value.result.as_ref(), value.receipt.as_ref(), limits)
        }
        Message::DeleteBackupRequest(value) => delete_request(value, limits),
        Message::DeleteBackupResult(value) => {
            validate_operation_result(value.result.as_ref(), limits)?;
            validate_delete_outcome(value.result.as_ref(), value.receipt.as_ref())
        }
        _ => Err(WireContractError::InvalidMessage),
    }
}

fn store_begin(value: &StoreBackupBegin) -> Result<(), WireContractError> {
    validate_required_header(value.header.as_ref())?;
    validate_object(value.object.as_ref())?;
    nonzero(value.authority_revision)
}

fn store_ready(value: &StoreBackupReady, limits: WireLimits) -> Result<(), WireContractError> {
    match &value.rejection {
        Some(error) if value.reservation.is_empty() && value.maximum_frame_bytes == 0 => {
            validate_wire_error(error)
        }
        None => {
            valid_nonempty_bytes(&value.reservation, limits.maximum_control_bytes())?;
            validate_maximum_frame_bytes(value.maximum_frame_bytes, limits)
        }
        Some(_) => Err(WireContractError::InvalidMessage),
    }
}

fn read_request(value: &ReadBackupRequest, limits: WireLimits) -> Result<(), WireContractError> {
    validate_required_header(value.header.as_ref())?;
    validate_object(value.object.as_ref())?;
    validate_reference(&value.object_reference, limits)?;
    nonzero(value.authority_revision)
}

fn verify_request(
    value: &VerifyBackupRequest,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    validate_required_header(value.header.as_ref())?;
    validate_object(value.object.as_ref())?;
    validate_reference(&value.object_reference, limits)?;
    nonzero(value.authority_revision)
}

fn delete_request(
    value: &DeleteBackupRequest,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    validate_required_header(value.header.as_ref())?;
    validate_object(value.object.as_ref())?;
    validate_reference(&value.object_reference, limits)?;
    nonzero(value.retirement_revision)
}

fn read_header(value: &ReadBackupHeader, limits: WireLimits) -> Result<(), WireContractError> {
    match &value.rejection {
        Some(error)
            if value.byte_length == 0
                && value.digest.is_empty()
                && value.maximum_frame_bytes == 0 =>
        {
            validate_wire_error(error)
        }
        None => {
            nonzero(value.byte_length)?;
            valid_nonzero_digest(&value.digest)?;
            validate_maximum_frame_bytes(value.maximum_frame_bytes, limits)
        }
        Some(_) => Err(WireContractError::InvalidMessage),
    }
}

fn validate_object(value: Option<&BackupObjectIdentity>) -> Result<(), WireContractError> {
    let object = value.ok_or(WireContractError::InvalidMessage)?;
    valid_identifier(&object.backup_id)?;
    valid_identifier(&object.destination_id)?;
    nonzero(object.provider_generation)?;
    nonzero(object.byte_length)?;
    valid_nonzero_digest(&object.digest)
}

fn validate_object_receipt(
    value: Option<&BackupObjectReceipt>,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    let receipt = value.ok_or(WireContractError::InvalidMessage)?;
    valid_identifier(&receipt.operation_id)?;
    validate_object(receipt.object.as_ref())?;
    validate_reference(&receipt.object_reference, limits)
}

fn validate_read_receipt(value: Option<&BackupReadReceipt>) -> Result<(), WireContractError> {
    let receipt = value.ok_or(WireContractError::InvalidMessage)?;
    valid_identifier(&receipt.operation_id)?;
    nonzero(receipt.byte_length)?;
    valid_nonzero_digest(&receipt.digest)
}

fn validate_delete_receipt(value: Option<&BackupDeleteReceipt>) -> Result<(), WireContractError> {
    let receipt = value.ok_or(WireContractError::InvalidMessage)?;
    valid_identifier(&receipt.operation_id)?;
    validate_object(receipt.object.as_ref())?;
    nonzero(receipt.retirement_revision)
}

fn validate_object_outcome(
    result: Option<&crate::v1::OperationResult>,
    receipt: Option<&BackupObjectReceipt>,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    validate_outcome(result, receipt, |receipt| {
        validate_object_receipt(receipt, limits)
    })
}

fn validate_read_outcome(
    result: Option<&crate::v1::OperationResult>,
    receipt: Option<&BackupReadReceipt>,
) -> Result<(), WireContractError> {
    validate_outcome(result, receipt, validate_read_receipt)
}

fn validate_delete_outcome(
    result: Option<&crate::v1::OperationResult>,
    receipt: Option<&BackupDeleteReceipt>,
) -> Result<(), WireContractError> {
    validate_outcome(result, receipt, validate_delete_receipt)
}

fn validate_outcome<T>(
    result: Option<&crate::v1::OperationResult>,
    receipt: Option<&T>,
    validate_receipt: impl FnOnce(Option<&T>) -> Result<(), WireContractError>,
) -> Result<(), WireContractError> {
    let outcome =
        OperationOutcome::try_from(result.ok_or(WireContractError::InvalidMessage)?.outcome)
            .map_err(|_| WireContractError::InvalidMessage)?;
    match outcome {
        OperationOutcome::Durable => validate_receipt(receipt),
        OperationOutcome::Rejected | OperationOutcome::Stale | OperationOutcome::Failed
            if receipt.is_none() =>
        {
            Ok(())
        }
        _ => Err(WireContractError::InvalidMessage),
    }
}

fn validate_required_header(
    value: Option<&crate::v1::RequestHeader>,
) -> Result<(), WireContractError> {
    validate_header(value.ok_or(WireContractError::InvalidMessage)?)
}

fn validate_reference(value: &str, limits: WireLimits) -> Result<(), WireContractError> {
    let maximum = limits
        .maximum_text_bytes()
        .min(MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES);
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn validate_maximum_frame_bytes(value: u64, limits: WireLimits) -> Result<(), WireContractError> {
    let maximum = u64::try_from(limits.maximum_data_frame_bytes())
        .map_err(|_| WireContractError::InvalidMessage)?;
    if value == 0 || value > maximum {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn valid_nonzero_digest(value: &[u8]) -> Result<(), WireContractError> {
    valid_digest(value)?;
    if value.iter().all(|byte| *byte == 0) {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}
