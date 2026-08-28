// SPDX-License-Identifier: GPL-2.0-only

//! Client side of exact remote shard put and get streams.

use meshspan_contracts::{BoundedBytes, ShardReadPermit, ShardReceipt, ShardWritePermit};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DataControlEnvelope, DataFrame, GetShardRequest, PutShardBegin, PutShardFinish, RequestHeader,
};
use meshspan_transport::{
    StreamKind, open_stream, receive_data_control, receive_data_frame, send_data_control,
    send_data_frame,
};

use crate::DataPlaneError;
use crate::capability::{encode_read_permit, encode_write_permit};
use crate::wire::{receipt, remote_rejection, require_durable, shard, wire_shard};

/// Writes one exact immutable shard and returns only a decoded durable provider receipt.
///
/// # Errors
///
/// Rejects local request contradictions, transport/wire failure, typed remote rejection and any
/// receipt that does not bind the exact operation, target, shard, length and digest.
pub async fn put_shard(
    connection: &quinn::Connection,
    header: RequestHeader,
    permit: ShardWritePermit,
    bytes: &BoundedBytes,
    limits: WireLimits,
) -> Result<ShardReceipt, DataPlaneError> {
    let maximum_bytes =
        usize::try_from(permit.maximum_bytes).map_err(|_| DataPlaneError::InvalidMessage)?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(DataPlaneError::InvalidMessage);
    }
    let digest: [u8; 32] = blake3::hash(bytes.as_slice()).into();
    let (mut send, mut receive) = open_stream(connection, StreamKind::Data).await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(Message::PutShardBegin(PutShardBegin {
                header: Some(header),
                target_id: permit.target_id.as_bytes().to_vec(),
                target_generation: permit.target_generation,
                shard: Some(wire_shard(permit.shard)),
                declared_length: bytes.len() as u64,
                declared_digest: digest.to_vec(),
                write_capability: encode_write_permit(permit),
            })),
        },
        limits,
    )
    .await?;
    let ready = receive_data_control(&mut receive, limits)
        .await?
        .into_inner();
    let Message::PutShardReady(ready) = ready.message.ok_or(DataPlaneError::InvalidMessage)? else {
        return Err(DataPlaneError::InvalidMessage);
    };
    if let Some(error) = ready.rejection.as_ref() {
        return Err(remote_rejection(error)?);
    }
    if ready.reservation.is_empty()
        || ready.maximum_frame_bytes == 0
        || ready.maximum_frame_bytes > limits.maximum_data_frame_bytes() as u64
    {
        return Err(DataPlaneError::InvalidMessage);
    }
    send_bytes(
        &mut send,
        bytes.as_slice(),
        ready.maximum_frame_bytes,
        limits,
    )
    .await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(Message::PutShardFinish(PutShardFinish {
                final_length: bytes.len() as u64,
                final_digest: digest.to_vec(),
            })),
        },
        limits,
    )
    .await?;
    send.finish()
        .map_err(meshspan_transport::TransportError::from)?;
    let result = receive_data_control(&mut receive, limits)
        .await?
        .into_inner();
    let Message::PutShardResult(result) = result.message.ok_or(DataPlaneError::InvalidMessage)?
    else {
        return Err(DataPlaneError::InvalidMessage);
    };
    require_durable(result.result.as_ref())?;
    let receipt = receipt(result.receipt.as_ref())?;
    if receipt.operation_id != permit.operation_id
        || receipt.target_id != permit.target_id
        || receipt.target_generation != permit.target_generation
        || receipt.shard != permit.shard
        || receipt.length != bytes.len() as u64
        || receipt.digest != digest
    {
        return Err(DataPlaneError::InvalidMessage);
    }
    Ok(receipt)
}

/// Reads and independently verifies one exact immutable shard from an authenticated peer.
///
/// # Errors
///
/// Rejects typed remote failure, identity/offset/length/digest mismatch and configured byte excess.
pub async fn get_shard(
    connection: &quinn::Connection,
    header: RequestHeader,
    permit: ShardReadPermit,
    maximum_shard_bytes: usize,
    limits: WireLimits,
) -> Result<BoundedBytes, DataPlaneError> {
    if maximum_shard_bytes == 0 {
        return Err(DataPlaneError::InvalidMessage);
    }
    let (mut send, mut receive) = open_stream(connection, StreamKind::Data).await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(Message::GetShardRequest(GetShardRequest {
                header: Some(header),
                target_id: permit.target_id.as_bytes().to_vec(),
                target_generation: permit.target_generation,
                shard: Some(wire_shard(permit.shard)),
                read_capability: encode_read_permit(permit),
            })),
        },
        limits,
    )
    .await?;
    send.finish()
        .map_err(meshspan_transport::TransportError::from)?;
    let header = receive_data_control(&mut receive, limits)
        .await?
        .into_inner();
    let Message::GetShardHeader(header) = header.message.ok_or(DataPlaneError::InvalidMessage)?
    else {
        return Err(DataPlaneError::InvalidMessage);
    };
    if let Some(error) = header.rejection.as_ref() {
        return Err(remote_rejection(error)?);
    }
    let returned_shard = shard(
        header
            .shard
            .as_ref()
            .ok_or(DataPlaneError::InvalidMessage)?,
    )?;
    let length = usize::try_from(header.length).map_err(|_| DataPlaneError::InvalidMessage)?;
    let digest: [u8; 32] = header
        .digest
        .as_slice()
        .try_into()
        .map_err(|_| DataPlaneError::InvalidMessage)?;
    if returned_shard != permit.shard
        || length == 0
        || length > maximum_shard_bytes
        || header.maximum_frame_bytes == 0
        || header.maximum_frame_bytes > limits.maximum_data_frame_bytes() as u64
    {
        return Err(DataPlaneError::InvalidMessage);
    }
    let bytes = receive_bytes(&mut receive, length, limits).await?;
    let result = receive_data_control(&mut receive, limits)
        .await?
        .into_inner();
    let Message::GetShardResult(result) = result.message.ok_or(DataPlaneError::InvalidMessage)?
    else {
        return Err(DataPlaneError::InvalidMessage);
    };
    require_durable(result.result.as_ref())?;
    if blake3::hash(&bytes).as_bytes() != &digest {
        return Err(DataPlaneError::InvalidMessage);
    }
    BoundedBytes::copy_from(&bytes, maximum_shard_bytes).map_err(|_| DataPlaneError::InvalidMessage)
}

async fn send_bytes(
    send: &mut quinn::SendStream,
    bytes: &[u8],
    negotiated_frame_bytes: u64,
    limits: WireLimits,
) -> Result<(), DataPlaneError> {
    let frame_bytes =
        usize::try_from(negotiated_frame_bytes).map_err(|_| DataPlaneError::InvalidMessage)?;
    for (index, chunk) in bytes.chunks(frame_bytes).enumerate() {
        let offset = index
            .checked_mul(frame_bytes)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(DataPlaneError::InvalidMessage)?;
        send_data_frame(
            send,
            &DataFrame {
                offset,
                bytes: chunk.to_vec(),
            },
            limits,
        )
        .await?;
    }
    Ok(())
}

async fn receive_bytes(
    receive: &mut quinn::RecvStream,
    length: usize,
    limits: WireLimits,
) -> Result<Vec<u8>, DataPlaneError> {
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let frame = receive_data_frame(receive, limits).await?.into_inner();
        if frame.offset != bytes.len() as u64 {
            return Err(DataPlaneError::InvalidMessage);
        }
        let new_length = bytes
            .len()
            .checked_add(frame.bytes.len())
            .ok_or(DataPlaneError::InvalidMessage)?;
        if new_length > length {
            return Err(DataPlaneError::InvalidMessage);
        }
        bytes.extend_from_slice(&frame.bytes);
    }
    Ok(bytes)
}
