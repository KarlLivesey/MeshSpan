// SPDX-License-Identifier: GPL-2.0-only

//! Remote exact-backup read client.

use meshspan_contracts::{BackupReadReceipt, BackupReadRequest, validate_backup_read_request};
use meshspan_domain::UnixMicros;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DataControlEnvelope, ReadBackupRequest as WireReadBackupRequest, RequestHeader,
};
use meshspan_transport::{
    StreamKind, open_stream, receive_data_control, receive_data_frame, send_data_control,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::validate_invocation;
use crate::BackupPlaneError;
use crate::backup_wire::{read_receipt, remote_rejection, require_durable, wire_object};

/// Streams one exact encrypted backup from an authenticated remote provider.
///
/// # Errors
///
/// Rejects invalid local authority, transport failure, a typed remote rejection, frame
/// discontinuity, length/digest drift or a substituted completion receipt.
pub async fn read_backup<Destination>(
    connection: &quinn::Connection,
    header: RequestHeader,
    request: &BackupReadRequest,
    destination: &mut Destination,
    limits: WireLimits,
    observed_at: UnixMicros,
) -> Result<BackupReadReceipt, BackupPlaneError>
where
    Destination: AsyncWrite + Unpin + ?Sized,
{
    validate_backup_read_request(request, observed_at)
        .map_err(|_| BackupPlaneError::InvalidMessage)?;
    let authority_revision = validate_invocation(&header, request.context)?;
    let (mut send, mut receive) = open_stream(connection, StreamKind::Data).await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(Message::ReadBackupRequest(WireReadBackupRequest {
                header: Some(header),
                object: Some(wire_object(request.object)),
                object_reference: request.object_reference.as_str().to_owned(),
                authority_revision: authority_revision.get(),
            })),
        },
        limits,
    )
    .await?;
    send.finish()
        .map_err(meshspan_transport::TransportError::from)?;
    let response = receive_data_control(&mut receive, limits)
        .await?
        .into_inner();
    let Message::ReadBackupHeader(response) =
        response.message.ok_or(BackupPlaneError::InvalidMessage)?
    else {
        return Err(BackupPlaneError::InvalidMessage);
    };
    if let Some(error) = response.rejection.as_ref() {
        return Err(remote_rejection(error)?);
    }
    if response.byte_length != request.object.byte_length
        || response.digest.as_slice() != request.object.digest
        || response.maximum_frame_bytes == 0
        || response.maximum_frame_bytes > limits.maximum_data_frame_bytes() as u64
    {
        return Err(BackupPlaneError::InvalidMessage);
    }
    receive_source(
        &mut receive,
        destination,
        request,
        limits,
        response.byte_length,
    )
    .await
}

async fn receive_source<Destination>(
    receive: &mut quinn::RecvStream,
    destination: &mut Destination,
    request: &BackupReadRequest,
    limits: WireLimits,
    expected_length: u64,
) -> Result<BackupReadReceipt, BackupPlaneError>
where
    Destination: AsyncWrite + Unpin + ?Sized,
{
    let mut received = 0_u64;
    let mut digest = Sha256::new();
    while received < expected_length {
        let frame = receive_data_frame(receive, limits).await?.into_inner();
        if frame.offset != received {
            return Err(BackupPlaneError::InvalidMessage);
        }
        received = received
            .checked_add(frame.bytes.len() as u64)
            .ok_or(BackupPlaneError::InvalidMessage)?;
        if received > expected_length {
            return Err(BackupPlaneError::InvalidMessage);
        }
        digest.update(&frame.bytes);
        destination.write_all(&frame.bytes).await?;
    }
    destination.flush().await?;
    let response = receive_data_control(receive, limits).await?.into_inner();
    let Message::ReadBackupResult(response) =
        response.message.ok_or(BackupPlaneError::InvalidMessage)?
    else {
        return Err(BackupPlaneError::InvalidMessage);
    };
    require_durable(response.result.as_ref())?;
    let receipt = read_receipt(
        response
            .receipt
            .as_ref()
            .ok_or(BackupPlaneError::InvalidMessage)?,
    )?;
    let digest: [u8; 32] = digest.finalize().into();
    if received == request.object.byte_length
        && digest == request.object.digest
        && receipt.operation_id == request.context.operation_id
        && receipt.byte_length == request.object.byte_length
        && receipt.digest == request.object.digest
    {
        Ok(receipt)
    } else {
        Err(BackupPlaneError::InvalidMessage)
    }
}
