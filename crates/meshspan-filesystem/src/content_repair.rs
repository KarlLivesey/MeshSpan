// SPDX-License-Identifier: GPL-2.0-only

//! Exact reconstruction and replacement of one erasure-coded shard.

use std::collections::BTreeSet;

use meshspan_contracts::{
    BoundedBytes, BoundedItems, CodingScheme, ContractError, ContractVersion, PutShardRequest,
    ReconstructionRequest, RequestContext, ReservationClass, ReserveStorageRequest,
    ShardReadPermit, ShardReceipt, StoragePermitMacKey, read_permit_mac,
};
use meshspan_domain::{MeshId, OperationId, Revision, TargetId, UnixMicros};

use crate::{CommittedProtectedStripe, ContentShardRouter};

/// Complete authority and destination for one physical shard repair attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardRepairRequest {
    /// Idempotent identity for the replacement provider mutation.
    pub replacement_operation_id: OperationId,
    /// Exact currently-authoritative location and immutable shard identity.
    pub source_receipt: ShardReceipt,
    /// Destination selected by the authoritative repair planner.
    pub replacement_target_id: TargetId,
    /// Exact destination incarnation fence.
    pub replacement_target_generation: u64,
    /// Authorization revision under which the repair was admitted.
    pub authorization_revision: Revision,
    /// Authoritative deadline shared by reads, reservation and write.
    pub deadline: UnixMicros,
    /// Quorum-derived current time for this attempt.
    pub observed_at: UnixMicros,
}

/// Target-neutral repair executor over replaceable routing and coding boundaries.
pub struct ProtectedShardRepairer<Router, Coding> {
    router: Router,
    coding: Coding,
    mesh_id: MeshId,
    read_permit_key: StoragePermitMacKey,
}

impl<Router, Coding> ProtectedShardRepairer<Router, Coding>
where
    Router: ContentShardRouter,
    Coding: CodingScheme,
{
    /// Binds physical repair to one mesh's exact-shard read authority.
    #[must_use]
    pub const fn new(
        router: Router,
        coding: Coding,
        mesh_id: MeshId,
        read_permit_key: StoragePermitMacKey,
    ) -> Self {
        Self {
            router,
            coding,
            mesh_id,
            read_permit_key,
        }
    }

    /// Reconstructs one missing/corrupt shard and durably writes its exact original bytes.
    ///
    /// No metadata location changes here. The caller must submit the returned provider receipt
    /// through the fenced authoritative repair transition before exposing the new route.
    ///
    /// # Errors
    ///
    /// Rejects malformed or conflicting stripe evidence, stale authority, insufficient verified
    /// slices, reconstruction mismatch, unavailable capacity and provider contract violations.
    pub fn repair(
        &mut self,
        request: ShardRepairRequest,
        stripe: &CommittedProtectedStripe,
    ) -> Result<ShardReceipt, ContractError> {
        let source_index = validate_request(request, stripe)?;
        let context = repair_context(request);
        let available = self.read_verified_slices(request, stripe)?;
        let encoded = reconstruct_and_encode(&self.coding, context, stripe, available)?;
        let replacement_bytes = encoded
            .as_slice()
            .get(source_index)
            .cloned()
            .ok_or(ContractError::InternalContract)?;
        verify_replacement_bytes(request.source_receipt, &replacement_bytes)?;
        let reservation = self.router.reserve(ReserveStorageRequest {
            context,
            target_id: request.replacement_target_id,
            target_generation: request.replacement_target_generation,
            class: ReservationClass::Repair,
            bytes: request.source_receipt.length,
            observed_at: request.observed_at,
        })?;
        let receipt = self.router.put_exact(
            PutShardRequest {
                context,
                reservation,
                shard: request.source_receipt.shard,
                expected_length: request.source_receipt.length,
                expected_digest: request.source_receipt.digest,
                bytes: replacement_bytes,
            },
            request.observed_at,
        )?;
        validate_replacement_receipt(request, receipt)?;
        Ok(receipt)
    }

    /// Returns the owned routed storage implementation after orderly worker shutdown.
    #[must_use]
    pub fn into_router(self) -> Router {
        self.router
    }

    fn read_verified_slices(
        &self,
        request: ShardRepairRequest,
        stripe: &CommittedProtectedStripe,
    ) -> Result<BoundedItems<Option<BoundedBytes>>, ContractError> {
        let total = usize::from(stripe.stripe.coding_layout().total_slices());
        let required = usize::from(stripe.stripe.coding_layout().data_slices());
        let mut available = vec![None; total];
        let mut valid = 0_usize;
        for receipt in stripe.receipts.as_slice() {
            if valid == required {
                break;
            }
            let index = usize::from(receipt.shard.shard_index);
            let context = read_context(request, *receipt)?;
            let mut permit = ShardReadPermit {
                operation_id: context.operation_id,
                mesh_id: self.mesh_id,
                target_id: receipt.target_id,
                target_generation: receipt.target_generation,
                shard: receipt.shard,
                authorization_revision: request.authorization_revision,
                expires_at: request.deadline,
                permit_digest: [0; 32],
            };
            permit.permit_digest = read_permit_mac(&self.read_permit_key, permit);
            match self.router.get_exact(context, permit, request.observed_at) {
                Ok(bytes) if receipt_matches_bytes(*receipt, &bytes) => {
                    available[index] = Some(bytes);
                    valid += 1;
                }
                Ok(_)
                | Err(
                    ContractError::Corrupt | ContractError::NotFound | ContractError::Unavailable,
                ) => {}
                Err(error) => return Err(error),
            }
        }
        if valid < required {
            return Err(ContractError::Unavailable);
        }
        BoundedItems::new(available, total).map_err(|_| ContractError::InternalContract)
    }
}

fn validate_request(
    request: ShardRepairRequest,
    stripe: &CommittedProtectedStripe,
) -> Result<usize, ContractError> {
    let source = request.source_receipt;
    let index = usize::from(source.shard.shard_index);
    let planned = stripe
        .stripe
        .shards()
        .get(index)
        .ok_or(ContractError::InvalidInput)?;
    if request.deadline <= request.observed_at
        || request.replacement_target_generation == 0
        || request.replacement_operation_id == source.operation_id
        || (request.replacement_target_id == source.target_id
            && request.replacement_target_generation == source.target_generation)
        || source.length == 0
        || source.digest == [0; 32]
        || source.shard.manifest_digest == [0; 32]
        || planned.shard_index != source.shard.shard_index
        || planned.shard_generation != source.shard.generation
        || planned.expected_length != source.length
        || planned.expected_digest != source.digest
        || stripe.stripe.chunk().chunk_index != source.shard.stripe_index
    {
        return Err(ContractError::InvalidInput);
    }
    validate_receipts(stripe, source.shard.manifest_digest)?;
    Ok(index)
}

fn validate_receipts(
    stripe: &CommittedProtectedStripe,
    manifest_digest: [u8; 32],
) -> Result<(), ContractError> {
    let total = usize::from(stripe.stripe.coding_layout().total_slices());
    let mut indices = BTreeSet::new();
    for receipt in stripe.receipts.as_slice() {
        let index = usize::from(receipt.shard.shard_index);
        let planned = stripe
            .stripe
            .shards()
            .get(index)
            .ok_or(ContractError::InvalidInput)?;
        if !indices.insert(index)
            || index >= total
            || receipt.shard.manifest_digest != manifest_digest
            || receipt.shard.stripe_index != stripe.stripe.chunk().chunk_index
            || receipt.shard.generation != planned.shard_generation
            || receipt.length != planned.expected_length
            || receipt.digest != planned.expected_digest
            || receipt.target_generation == 0
        {
            return Err(ContractError::InvalidInput);
        }
    }
    Ok(())
}

fn reconstruct_and_encode<Coding: CodingScheme>(
    coding: &Coding,
    context: RequestContext,
    stripe: &CommittedProtectedStripe,
    available: BoundedItems<Option<BoundedBytes>>,
) -> Result<BoundedItems<BoundedBytes>, ContractError> {
    let digests = stripe
        .stripe
        .shards()
        .iter()
        .map(|shard| shard.expected_digest)
        .collect::<Vec<_>>();
    let ciphertext = coding.reconstruct(&ReconstructionRequest {
        context,
        layout: stripe.stripe.coding_layout(),
        available_slices: available,
        slice_digests: BoundedItems::new(digests, stripe.stripe.shards().len())
            .map_err(|_| ContractError::InternalContract)?,
        logical_length: stripe.stripe.chunk().ciphertext_length,
        logical_digest: stripe.stripe.chunk().ciphertext_digest,
    })?;
    coding.encode(context, stripe.stripe.coding_layout(), &ciphertext)
}

const fn repair_context(request: ShardRepairRequest) -> RequestContext {
    RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: request.replacement_operation_id,
        deadline: request.deadline,
        expected_revision: Some(request.authorization_revision),
    }
}

fn read_context(
    request: ShardRepairRequest,
    receipt: ShardReceipt,
) -> Result<RequestContext, ContractError> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.content.repair-read.v1\0");
    digest.update(&request.replacement_operation_id.as_bytes());
    digest.update(&receipt.operation_id.as_bytes());
    digest.update(&receipt.shard.shard_index.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    let operation_id = OperationId::from_bytes(meshspan_domain::uuid_v8(bytes))
        .map_err(|_| ContractError::InternalContract)?;
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id,
        deadline: request.deadline,
        expected_revision: Some(request.authorization_revision),
    })
}

fn receipt_matches_bytes(receipt: ShardReceipt, bytes: &BoundedBytes) -> bool {
    u64::try_from(bytes.len()).ok() == Some(receipt.length)
        && blake3::hash(bytes.as_slice()).as_bytes() == &receipt.digest
}

fn verify_replacement_bytes(
    source: ShardReceipt,
    bytes: &BoundedBytes,
) -> Result<(), ContractError> {
    if receipt_matches_bytes(source, bytes) {
        Ok(())
    } else {
        Err(ContractError::Corrupt)
    }
}

fn validate_replacement_receipt(
    request: ShardRepairRequest,
    receipt: ShardReceipt,
) -> Result<(), ContractError> {
    if receipt.operation_id == request.replacement_operation_id
        && receipt.shard == request.source_receipt.shard
        && receipt.length == request.source_receipt.length
        && receipt.digest == request.source_receipt.digest
        && receipt.target_id == request.replacement_target_id
        && receipt.target_generation == request.replacement_target_generation
    {
        Ok(())
    } else {
        Err(ContractError::InternalContract)
    }
}
