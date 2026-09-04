// SPDX-License-Identifier: GPL-2.0-only

//! Remote exact-backup store client.

use meshspan_contracts::{BackupObjectReceipt, BackupStoreRequest, validate_backup_store_request};
use meshspan_domain::UnixMicros;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DataControlEnvelope, DataFrame, RequestHeader, StoreBackupBegin, StoreBackupFinish,
};
use meshspan_transport::{
    StreamKind, open_stream, receive_data_control, send_data_control, send_data_frame,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::validate_invocation;
use crate::BackupPlaneError;
use crate::backup_wire::{object_receipt, remote_rejection, require_durable, wire_object};

/// Streams one exact encrypted backup to an authenticated remote provider.
///
/// # Errors
///
/// Rejects invalid local authority, source length/digest drift, transport failure, a typed remote
/// rejection or a durable receipt that does not exactly match the request.
pub async fn store_backup<Source>(
    connection: &quinn::Connection,
    header: RequestHeader,
    request: BackupStoreRequest,
    source: &mut Source,
    limits: WireLimits,
    observed_at: UnixMicros,
) -> Result<BackupObjectReceipt, BackupPlaneError>
where
    Source: AsyncRead + Unpin + ?Sized,
{
    validate_backup_store_request(request, observed_at)
        .map_err(|_| BackupPlaneError::InvalidMessage)?;
    let authority_revision = validate_invocation(&header, request.context)?;
    let (mut send, mut receive) = open_stream(connection, StreamKind::Data).await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(Message::StoreBackupBegin(StoreBackupBegin {
                header: Some(header),
                object: Some(wire_object(request.object)),
                authority_revision: authority_revision.get(),
            })),
        },
        limits,
    )
    .await?;
    let ready = receive_data_control(&mut receive, limits)
        .await?
        .into_inner();
    let Message::StoreBackupReady(ready) = ready.message.ok_or(BackupPlaneError::InvalidMessage)?
    else {
        return Err(BackupPlaneError::InvalidMessage);
    };
    if let Some(error) = ready.rejection.as_ref() {
        return Err(remote_rejection(error)?);
    }
    let frame_bytes = validate_frame_bound(ready.maximum_frame_bytes, limits)?;
    send_source(&mut send, source, request, frame_bytes, limits).await?;
    send.finish()
        .map_err(meshspan_transport::TransportError::from)?;
    let result = receive_data_control(&mut receive, limits)
        .await?
        .into_inner();
    let Message::StoreBackupResult(result) =
        result.message.ok_or(BackupPlaneError::InvalidMessage)?
    else {
        return Err(BackupPlaneError::InvalidMessage);
    };
    require_durable(result.result.as_ref())?;
    let receipt = object_receipt(
        result
            .receipt
            .as_ref()
            .ok_or(BackupPlaneError::InvalidMessage)?,
    )?;
    if receipt.operation_id == request.context.operation_id && receipt.object == request.object {
        Ok(receipt)
    } else {
        Err(BackupPlaneError::InvalidMessage)
    }
}

async fn send_source<Source>(
    send: &mut quinn::SendStream,
    source: &mut Source,
    request: BackupStoreRequest,
    frame_bytes: usize,
    limits: WireLimits,
) -> Result<(), BackupPlaneError>
where
    Source: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = vec![0_u8; frame_bytes];
    let mut offset = 0_u64;
    let mut digest = Sha256::new();
    while offset < request.object.byte_length {
        let remaining = usize::try_from(request.object.byte_length - offset)
            .unwrap_or(usize::MAX)
            .min(frame_bytes);
        let read = source.read(&mut buffer[..remaining]).await?;
        if read == 0 {
            return Err(BackupPlaneError::InvalidMessage);
        }
        digest.update(&buffer[..read]);
        send_data_frame(
            send,
            &DataFrame {
                offset,
                bytes: buffer[..read].to_vec(),
            },
            limits,
        )
        .await?;
        offset = offset
            .checked_add(read as u64)
            .ok_or(BackupPlaneError::InvalidMessage)?;
    }
    let mut excess = [0_u8; 1];
    if source.read(&mut excess).await? != 0 {
        return Err(BackupPlaneError::InvalidMessage);
    }
    let digest: [u8; 32] = digest.finalize().into();
    if digest != request.object.digest {
        return Err(BackupPlaneError::InvalidMessage);
    }
    send_data_control(
        send,
        &DataControlEnvelope {
            message: Some(Message::StoreBackupFinish(StoreBackupFinish {
                final_length: offset,
                final_digest: digest.to_vec(),
            })),
        },
        limits,
    )
    .await?;
    Ok(())
}

fn validate_frame_bound(value: u64, limits: WireLimits) -> Result<usize, BackupPlaneError> {
    let value = usize::try_from(value).map_err(|_| BackupPlaneError::InvalidMessage)?;
    if value == 0 || value > limits.maximum_data_frame_bytes() {
        Err(BackupPlaneError::InvalidMessage)
    } else {
        Ok(value)
    }
}
