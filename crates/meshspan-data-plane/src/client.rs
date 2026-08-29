// SPDX-License-Identifier: GPL-2.0-only

//! Client side of exact remote shard lifecycle streams.

use meshspan_contracts::{
    BoundedBytes, ReclamationReceipt, RemovalPermit, ShardReadPermit, ShardReceipt,
    ShardWritePermit, TombstoneReceipt, reclamation_receipt_digest, tombstone_receipt_digest,
};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DataControlEnvelope, DataFrame, DeleteShardRequest, GetShardRequest, PutShardBegin,
    PutShardFinish, ReclaimShardRequest, RequestHeader,
};
use meshspan_transport::{
    StreamKind, open_stream, receive_data_control, receive_data_frame, send_data_control,
    send_data_frame,
};

use crate::DataPlaneError;
use crate::capability::{encode_read_permit, encode_write_permit};
use crate::wire::{
    receipt, reclamation_receipt, remote_rejection, removal_permit_payload, request_context,
    request_context_without_revision, require_durable, shard, tombstone_receipt,
    tombstone_receipt_payload, wire_shard,
};

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

/// Makes one exact shard generation durably unreachable on an authenticated remote provider.
///
/// # Errors
///
/// Rejects contradictory local authority, transport/wire failure, typed remote rejection and any
/// receipt that does not bind the exact operation, target, shard and removal permit.
pub async fn tombstone_shard(
    connection: &quinn::Connection,
    header: RequestHeader,
    permit: RemovalPermit,
    limits: WireLimits,
) -> Result<TombstoneReceipt, DataPlaneError> {
    let context = request_context(&header, permit.catalogue_revision)?;
    if context.operation_id != permit.operation_id
        || header.mesh_id.as_slice() != permit.mesh_id.as_bytes()
        || context.deadline.get() <= 0
    {
        return Err(DataPlaneError::InvalidMessage);
    }
    let (mut send, mut receive) = open_stream(connection, StreamKind::Data).await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(Message::DeleteShardRequest(DeleteShardRequest {
                header: Some(header),
                target_id: permit.target_id.as_bytes().to_vec(),
                target_generation: permit.target_generation,
                shard: Some(wire_shard(permit.shard)),
                removal_permit: Some(removal_permit_payload(permit)),
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
    let Message::DeleteShardResult(result) =
        result.message.ok_or(DataPlaneError::InvalidMessage)?
    else {
        return Err(DataPlaneError::InvalidMessage);
    };
    require_durable(result.result.as_ref())?;
    let receipt = tombstone_receipt(result.receipt.as_ref())?;
    if receipt.operation_id != permit.operation_id
        || receipt.target_id != permit.target_id
        || receipt.target_generation != permit.target_generation
        || receipt.shard != permit.shard
        || receipt.permit_digest != permit.permit_digest
        || receipt.tombstone_digest != tombstone_receipt_digest(permit)
    {
        return Err(DataPlaneError::InvalidMessage);
    }
    Ok(receipt)
}

/// Physically unlinks one exact remotely tombstoned shard and returns durable accounting proof.
///
/// # Errors
///
/// Rejects contradictory local evidence, transport/wire failure, typed remote rejection and any
/// receipt that does not exactly contain and bind the supplied tombstone.
pub async fn reclaim_shard(
    connection: &quinn::Connection,
    header: RequestHeader,
    tombstone: TombstoneReceipt,
    limits: WireLimits,
) -> Result<ReclamationReceipt, DataPlaneError> {
    let context = request_context_without_revision(&header)?;
    if context.operation_id != tombstone.operation_id || context.deadline.get() <= 0 {
        return Err(DataPlaneError::InvalidMessage);
    }
    let (mut send, mut receive) = open_stream(connection, StreamKind::Data).await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(Message::ReclaimShardRequest(ReclaimShardRequest {
                header: Some(header),
                target_id: tombstone.target_id.as_bytes().to_vec(),
                target_generation: tombstone.target_generation,
                shard: Some(wire_shard(tombstone.shard)),
                tombstone_receipt: Some(tombstone_receipt_payload(tombstone)),
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
    let Message::ReclaimShardResult(result) =
        result.message.ok_or(DataPlaneError::InvalidMessage)?
    else {
        return Err(DataPlaneError::InvalidMessage);
    };
    require_durable(result.result.as_ref())?;
    let receipt = reclamation_receipt(result.receipt.as_ref())?;
    if receipt.tombstone != tombstone
        || receipt.reclamation_digest
            != reclamation_receipt_digest(
                tombstone,
                receipt.bytes_unlinked_at,
                receipt.reclaimed_bytes,
            )
    {
        return Err(DataPlaneError::InvalidMessage);
    }
    Ok(receipt)
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
