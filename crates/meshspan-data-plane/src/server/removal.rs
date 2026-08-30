// SPDX-License-Identifier: GPL-2.0-only

//! Exact remote tombstone and physical-reclamation server transitions.

use meshspan_contracts::{
    ContractError, ReclamationReceipt, RemovalPermit, StorageProvider, TombstoneReceipt,
};
use meshspan_domain::UnixMicros;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DataControlEnvelope, DeleteShardRequest, DeleteShardResult, ReclaimShardRequest,
    ReclaimShardResult,
};
use meshspan_transport::{AcceptedStream, send_data_control};

use super::RemoteShardService;
use crate::DataPlaneError;
use crate::wire::{
    durable_result, reclamation_receipt_payload, rejected_result, removal_permit, request_context,
    request_context_without_revision, shard, tombstone_receipt, tombstone_receipt_payload,
};

impl<Provider: StorageProvider> RemoteShardService<Provider> {
    pub(super) async fn serve_delete(
        &mut self,
        stream: &mut AcceptedStream,
        limits: WireLimits,
        observed_at: UnixMicros,
        request: DeleteShardRequest,
    ) -> Result<(), DataPlaneError> {
        let Ok(permit) = removal_permit(request.removal_permit.as_ref()) else {
            return reject_delete(stream, limits, ContractError::Unauthorized).await;
        };
        if let Err(error) = self.authorise_delete(&request, permit, observed_at) {
            return reject_delete(stream, limits, error).await;
        }
        let result = self.provider.tombstone(permit, observed_at);
        send_delete_result(stream, limits, result).await
    }

    pub(super) async fn serve_reclaim(
        &mut self,
        stream: &mut AcceptedStream,
        limits: WireLimits,
        observed_at: UnixMicros,
        request: ReclaimShardRequest,
    ) -> Result<(), DataPlaneError> {
        let Ok(receipt) = tombstone_receipt(request.tombstone_receipt.as_ref()) else {
            return reject_reclaim(stream, limits, ContractError::InvalidInput).await;
        };
        if let Err(error) = self.authorise_reclaim(&request, receipt, observed_at) {
            return reject_reclaim(stream, limits, error).await;
        }
        let result = self.provider.unlink_tombstoned(receipt, observed_at);
        send_reclaim_result(stream, limits, result).await
    }

    fn authorise_delete(
        &self,
        request: &DeleteShardRequest,
        permit: RemovalPermit,
        observed_at: UnixMicros,
    ) -> Result<(), ContractError> {
        let header = request.header.as_ref().ok_or(ContractError::InvalidInput)?;
        let context = request_context(header, permit.catalogue_revision)
            .map_err(|_| ContractError::InvalidInput)?;
        let requested_shard = request
            .shard
            .as_ref()
            .ok_or(ContractError::InvalidInput)
            .and_then(|value| shard(value).map_err(|_| ContractError::InvalidInput))?;
        let authorised = permit.operation_id == context.operation_id
            && permit.mesh_id == self.mesh_id
            && header.mesh_id.as_slice() == self.mesh_id.as_bytes()
            && permit.target_id == self.target_id
            && request.target_id.as_slice() == self.target_id.as_bytes()
            && permit.target_generation == self.target_generation
            && request.target_generation == self.target_generation
            && permit.shard == requested_shard
            && permit.expires_at > observed_at
            && context.deadline > observed_at;
        authorised.then_some(()).ok_or(ContractError::Unauthorized)
    }

    fn authorise_reclaim(
        &self,
        request: &ReclaimShardRequest,
        receipt: TombstoneReceipt,
        observed_at: UnixMicros,
    ) -> Result<(), ContractError> {
        let header = request.header.as_ref().ok_or(ContractError::InvalidInput)?;
        let context =
            request_context_without_revision(header).map_err(|_| ContractError::InvalidInput)?;
        let requested_shard = request
            .shard
            .as_ref()
            .ok_or(ContractError::InvalidInput)
            .and_then(|value| shard(value).map_err(|_| ContractError::InvalidInput))?;
        let authorised = receipt.operation_id == context.operation_id
            && header.mesh_id.as_slice() == self.mesh_id.as_bytes()
            && receipt.target_id == self.target_id
            && request.target_id.as_slice() == self.target_id.as_bytes()
            && receipt.target_generation == self.target_generation
            && request.target_generation == self.target_generation
            && receipt.shard == requested_shard
            && context.deadline > observed_at;
        authorised.then_some(()).ok_or(ContractError::Unauthorized)
    }
}

pub(super) async fn reject_delete(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    error: ContractError,
) -> Result<(), DataPlaneError> {
    send_delete_result(stream, limits, Err(error)).await
}

pub(super) async fn send_delete_result(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    result: Result<TombstoneReceipt, ContractError>,
) -> Result<(), DataPlaneError> {
    let (operation, receipt) = match result {
        Ok(receipt) => (durable_result(), Some(tombstone_receipt_payload(receipt))),
        Err(error) => (rejected_result(error), None),
    };
    send_result(
        stream,
        limits,
        Message::DeleteShardResult(DeleteShardResult {
            result: Some(operation),
            receipt,
        }),
    )
    .await
}

pub(super) async fn reject_reclaim(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    error: ContractError,
) -> Result<(), DataPlaneError> {
    send_reclaim_result(stream, limits, Err(error)).await
}

pub(super) async fn send_reclaim_result(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    result: Result<ReclamationReceipt, ContractError>,
) -> Result<(), DataPlaneError> {
    let (operation, receipt) = match result {
        Ok(receipt) => (durable_result(), Some(reclamation_receipt_payload(receipt))),
        Err(error) => (rejected_result(error), None),
    };
    send_result(
        stream,
        limits,
        Message::ReclaimShardResult(ReclaimShardResult {
            result: Some(operation),
            receipt,
        }),
    )
    .await
}

async fn send_result(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    message: Message,
) -> Result<(), DataPlaneError> {
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(message),
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
