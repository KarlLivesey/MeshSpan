// SPDX-License-Identifier: GPL-2.0-only

//! Same-swarm authenticated resolution of an immutable original put admission.

use meshspan_contracts::{
    ContractError, ShardPutIdentity, ShardPutResolution, StorageProvider, verify_write_permit_mac,
};
use meshspan_domain::UnixMicros;
use meshspan_protocol::{
    WireLimits,
    v1::{
        DataControlEnvelope, ResolveShardPutRequest, ResolveShardPutResult,
        data_control_envelope::Message, resolve_shard_put_result::Outcome,
    },
};
use meshspan_transport::{AcceptedStream, send_data_control};

use super::RemoteShardService;
use crate::{
    DataPlaneError,
    capability::{decode_put_identity, decode_write_permit},
    wire::{receipt_payload, request_context, wire_error},
};

impl<Provider: StorageProvider> RemoteShardService<Provider> {
    pub(super) async fn serve_put_resolution(
        &mut self,
        stream: &mut AcceptedStream,
        limits: WireLimits,
        observed_at: UnixMicros,
        request: ResolveShardPutRequest,
    ) -> Result<(), DataPlaneError> {
        let payload = request
            .original
            .as_ref()
            .ok_or(DataPlaneError::InvalidMessage)?;
        if payload.format_version != 1 {
            return Err(DataPlaneError::InvalidMessage);
        }
        let original = decode_put_identity(&payload.canonical_bytes)?;
        let outcome = match self.resolve_authorised_put(&request, original, observed_at) {
            Ok(ShardPutResolution::Unknown) => Outcome::Unknown(true),
            Ok(ShardPutResolution::Prepared) => Outcome::Prepared(true),
            Ok(ShardPutResolution::Verified(receipt)) => {
                Outcome::Verified(receipt_payload(receipt))
            }
            Err(error) => Outcome::Rejection(wire_error(error)),
        };
        send_data_control(
            &mut stream.send,
            &DataControlEnvelope {
                message: Some(Message::ResolveShardPutResult(ResolveShardPutResult {
                    original_request_digest: original.request_digest().to_vec(),
                    outcome: Some(outcome),
                })),
            },
            limits,
        )
        .await?;
        stream
            .send
            .finish()
            .map_err(meshspan_transport::TransportError::from)?;
        Ok(())
    }

    fn resolve_authorised_put(
        &mut self,
        request: &ResolveShardPutRequest,
        original: ShardPutIdentity,
        now: UnixMicros,
    ) -> Result<ShardPutResolution, ContractError> {
        let authority = decode_write_permit(&request.write_capability)
            .map_err(|_| ContractError::Unauthorized)?;
        let header = request.header.as_ref().ok_or(ContractError::InvalidInput)?;
        let context = request_context(header, authority.authorization_revision)
            .map_err(|_| ContractError::InvalidInput)?;
        if !verify_write_permit_mac(&self.write_key, authority)
            || authority.mesh_id != self.mesh_id
            || header.mesh_id.as_slice() != self.mesh_id.as_bytes()
            || request.target_id.as_slice() != self.target_id.as_bytes()
            || request.target_generation != self.target_generation
            || authority.target_id != self.target_id
            || authority.target_generation != self.target_generation
            || original.reservation.target_id != self.target_id
            || original.reservation.target_generation != self.target_generation
            || context.operation_id != original.context.operation_id
            || authority.operation_id != original.context.operation_id
            || authority.shard != original.shard
            || authority.reservation_class != original.reservation.class
            || original.expected_length > authority.maximum_bytes
            || original.expected_length > self.maximum_shard_bytes as u64
            || context.deadline > authority.expires_at
            || context.deadline <= now
            || now.get() < 0
        {
            return Err(ContractError::Unauthorized);
        }
        self.provider.resolve_put(original, authority, now)
    }
}
