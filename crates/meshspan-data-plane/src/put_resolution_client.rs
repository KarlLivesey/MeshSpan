// SPDX-License-Identifier: GPL-2.0-only

//! Resolve a provider write without retransmitting bytes or changing its original admission.

use meshspan_contracts::{ContractVersion, ShardPutIdentity, ShardPutResolution, ShardWritePermit};
use meshspan_protocol::{
    WireLimits,
    v1::{
        DataControlEnvelope, RequestHeader, ResolveShardPutRequest, VersionedPayload,
        data_control_envelope::Message, resolve_shard_put_result::Outcome,
    },
};
use meshspan_transport::{StreamKind, open_stream, receive_data_control, send_data_control};

use crate::{
    DataPlaneError,
    capability::{decode_put_identity, encode_put_identity, encode_write_permit},
    wire::{receipt, remote_rejection, request_context},
};

/// Queries and independently verifies an exact original operation under fresh write authority.
/// Unknown/prepared outcomes never authorise another upload or destination selection.
/// # Errors
/// Rejects contradictory input, transport failure, stale authority and substituted results.
pub(crate) async fn resolve_shard_put(
    connection: &quinn::Connection,
    header: RequestHeader,
    original: ShardPutIdentity,
    authority: ShardWritePermit,
    limits: WireLimits,
) -> Result<ShardPutResolution, DataPlaneError> {
    let bytes = encode_put_identity(original);
    if original.context.contract_version != ContractVersion::V1_0
        || decode_put_identity(&bytes)? != original
        || request_context(&header, authority.authorization_revision)?.operation_id
            != original.context.operation_id
        || header.mesh_id.as_slice() != authority.mesh_id.as_bytes()
        || header.deadline_unix_micros > authority.expires_at.get()
    {
        return Err(DataPlaneError::InvalidMessage);
    }
    let (mut send, mut receive) = open_stream(connection, StreamKind::Data).await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(Message::ResolveShardPutRequest(ResolveShardPutRequest {
                header: Some(header),
                target_id: original.reservation.target_id.as_bytes().to_vec(),
                target_generation: original.reservation.target_generation,
                original: Some(VersionedPayload {
                    format_version: 1,
                    canonical_bytes: bytes,
                }),
                write_capability: encode_write_permit(authority),
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
    let Some(Message::ResolveShardPutResult(response)) = response.message else {
        return Err(DataPlaneError::InvalidMessage);
    };
    if response.original_request_digest.as_slice() != original.request_digest() {
        return Err(DataPlaneError::InvalidMessage);
    }
    match response.outcome.ok_or(DataPlaneError::InvalidMessage)? {
        Outcome::Unknown(true) => Ok(ShardPutResolution::Unknown),
        Outcome::Prepared(true) => Ok(ShardPutResolution::Prepared),
        Outcome::Unknown(false) | Outcome::Prepared(false) => Err(DataPlaneError::InvalidMessage),
        Outcome::Rejection(error) => Err(remote_rejection(&error)?),
        Outcome::Verified(value) => verified(original, &value),
    }
}

fn verified(
    original: ShardPutIdentity,
    value: &VersionedPayload,
) -> Result<ShardPutResolution, DataPlaneError> {
    let receipt = receipt(Some(value))?;
    if receipt.operation_id != original.context.operation_id
        || receipt.shard != original.shard
        || receipt.target_id != original.reservation.target_id
        || receipt.target_generation != original.reservation.target_generation
        || receipt.length != original.expected_length
        || receipt.digest != original.expected_digest
    {
        return Err(DataPlaneError::InvalidMessage);
    }
    Ok(ShardPutResolution::Verified(receipt))
}
