// SPDX-License-Identifier: GPL-2.0-only

//! Remote backup verification and exact retirement clients.

use meshspan_contracts::{
    BackupDeleteReceipt, BackupDeleteRequest, BackupObjectReceipt, BackupVerifyRequest,
    validate_backup_delete_request, validate_backup_verify_request,
};
use meshspan_domain::UnixMicros;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DataControlEnvelope, DeleteBackupRequest as WireDeleteBackupRequest, RequestHeader,
    VerifyBackupRequest as WireVerifyBackupRequest,
};
use meshspan_transport::{StreamKind, open_stream, receive_data_control, send_data_control};

use super::validate_invocation;
use crate::BackupPlaneError;
use crate::backup_wire::{delete_receipt, object_receipt, require_durable, wire_object};

/// Independently verifies one exact encrypted backup on a remote provider.
///
/// # Errors
///
/// Rejects invalid authority, transport failure, a typed rejection or substituted evidence.
pub async fn verify_backup(
    connection: &quinn::Connection,
    header: RequestHeader,
    request: &BackupVerifyRequest,
    limits: WireLimits,
    observed_at: UnixMicros,
) -> Result<BackupObjectReceipt, BackupPlaneError> {
    validate_backup_verify_request(request, observed_at)
        .map_err(|_| BackupPlaneError::InvalidMessage)?;
    let authority_revision = validate_invocation(&header, request.context)?;
    let response = exchange(
        connection,
        Message::VerifyBackupRequest(WireVerifyBackupRequest {
            header: Some(header),
            object: Some(wire_object(request.object)),
            object_reference: request.object_reference.as_str().to_owned(),
            authority_revision: authority_revision.get(),
        }),
        limits,
    )
    .await?;
    let Message::VerifyBackupResult(response) = response else {
        return Err(BackupPlaneError::InvalidMessage);
    };
    require_durable(response.result.as_ref())?;
    let receipt = object_receipt(
        response
            .receipt
            .as_ref()
            .ok_or(BackupPlaneError::InvalidMessage)?,
    )?;
    if receipt.operation_id == request.context.operation_id
        && receipt.object == request.object
        && receipt.object_reference == request.object_reference
    {
        Ok(receipt)
    } else {
        Err(BackupPlaneError::InvalidMessage)
    }
}

/// Deletes only one exact authority-retired backup from a remote provider.
///
/// # Errors
///
/// Rejects location-only or stale authority, transport failure, a typed rejection or substituted
/// removal evidence.
pub async fn delete_backup(
    connection: &quinn::Connection,
    header: RequestHeader,
    request: &BackupDeleteRequest,
    limits: WireLimits,
    observed_at: UnixMicros,
) -> Result<BackupDeleteReceipt, BackupPlaneError> {
    validate_backup_delete_request(request, observed_at)
        .map_err(|_| BackupPlaneError::InvalidMessage)?;
    let retirement_revision = validate_invocation(&header, request.context)?;
    if retirement_revision != request.retirement_revision {
        return Err(BackupPlaneError::InvalidMessage);
    }
    let response = exchange(
        connection,
        Message::DeleteBackupRequest(WireDeleteBackupRequest {
            header: Some(header),
            object: Some(wire_object(request.object)),
            object_reference: request.object_reference.as_str().to_owned(),
            retirement_revision: request.retirement_revision.get(),
        }),
        limits,
    )
    .await?;
    let Message::DeleteBackupResult(response) = response else {
        return Err(BackupPlaneError::InvalidMessage);
    };
    require_durable(response.result.as_ref())?;
    let receipt = delete_receipt(
        response
            .receipt
            .as_ref()
            .ok_or(BackupPlaneError::InvalidMessage)?,
    )?;
    if receipt.operation_id == request.context.operation_id
        && receipt.object == request.object
        && receipt.retirement_revision == request.retirement_revision
    {
        Ok(receipt)
    } else {
        Err(BackupPlaneError::InvalidMessage)
    }
}

async fn exchange(
    connection: &quinn::Connection,
    message: Message,
    limits: WireLimits,
) -> Result<Message, BackupPlaneError> {
    let (mut send, mut receive) = open_stream(connection, StreamKind::Data).await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(message),
        },
        limits,
    )
    .await?;
    send.finish()
        .map_err(meshspan_transport::TransportError::from)?;
    receive_data_control(&mut receive, limits)
        .await?
        .into_inner()
        .message
        .ok_or(BackupPlaneError::InvalidMessage)
}
