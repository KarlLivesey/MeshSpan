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

mod recovery;
mod resume;
pub use recovery::restore_recovery_stripe;

/// Authority and deadline for checking an encrypted stripe without modifying storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StripeReadRequest {
    /// Identity for this check and its derived exact-shard reads.
    pub operation_id: OperationId,
    /// Current authority admitting the maintenance read.
    pub authorization_revision: Revision,
    /// Exclusive deadline for all provider reads.
    pub deadline: UnixMicros,
    /// Authority-agreed time at admission.
    pub observed_at: UnixMicros,
}

struct VerifiedSlices {
    bytes: BoundedItems<Option<BoundedBytes>>,
    receipts: BoundedItems<ShardReceipt>,
}

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
        let bytes = self.reconstruct_replacement(request, stripe)?;
        store_replacement(&mut self.router, request, bytes)
    }

    /// Proves current decodability using only the explicitly permitted targets.
    ///
    /// Reads and verifies enough distinct slices, reconstructs encrypted content and checks
    /// its recorded length/digest. Returns the exact contributing receipts, not ciphertext
    /// or a decryption key. No reservation, write, repair or metadata mutation occurs.
    /// The caller owns scope/target selection and must bind this observation to its admission
    /// barrier: success is neither a future availability lease nor proof of locality policy.
    ///
    /// # Errors
    /// Rejects malformed authority/layout/receipts, duplicate or excessive target selectors,
    /// insufficient surviving data, mismatched reconstructed content and provider failures.
    pub fn verify_read_availability(
        &self,
        request: StripeReadRequest,
        stripe: &CommittedProtectedStripe,
        permitted_targets: &[TargetId],
    ) -> Result<BoundedItems<ShardReceipt>, ContractError> {
        if request.deadline <= request.observed_at
            || request.observed_at.get() < 0
            || request.authorization_revision == Revision::ZERO
            || permitted_targets.len() > 24
        {
            return Err(ContractError::InvalidInput);
        }
        let targets: BTreeSet<_> = permitted_targets.iter().copied().collect();
        if targets.len() != permitted_targets.len() {
            return Err(ContractError::InvalidInput);
        }
        let manifest = stripe
            .receipts
            .as_slice()
            .first()
            .ok_or(ContractError::Unavailable)?
            .shard
            .manifest_digest;
        if manifest == [0; 32] {
            return Err(ContractError::InvalidInput);
        }
        validate_receipts(stripe, manifest)?;
        let available = self.read_verified_slices(request, stripe, &targets)?;
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: request.operation_id,
            expected_revision: Some(request.authorization_revision),
            deadline: request.deadline,
        };
        reconstruct_ciphertext(&self.coding, context, stripe, available.bytes)?;
        Ok(available.receipts)
    }

    /// Returns the owned routed storage implementation after orderly worker shutdown.
    #[must_use]
    pub fn into_router(self) -> Router {
        self.router
    }

    fn reconstruct_replacement(
        &self,
        request: ShardRepairRequest,
        stripe: &CommittedProtectedStripe,
    ) -> Result<BoundedBytes, ContractError> {
        let source_index = validate_request(request, stripe)?;
        let context = repair_context(request);
        let read = StripeReadRequest {
            operation_id: request.replacement_operation_id,
            authorization_revision: request.authorization_revision,
            deadline: request.deadline,
            observed_at: request.observed_at,
        };
        let targets = stripe
            .receipts
            .as_slice()
            .iter()
            .map(|receipt| receipt.target_id)
            .collect();
        let available = self.read_verified_slices(read, stripe, &targets)?;
        let ciphertext = reconstruct_ciphertext(&self.coding, context, stripe, available.bytes)?;
        let encoded = self
            .coding
            .encode(context, stripe.stripe.coding_layout(), &ciphertext)?;
        let replacement_bytes = encoded
            .as_slice()
            .get(source_index)
            .cloned()
            .ok_or(ContractError::InternalContract)?;
        Ok(replacement_bytes)
    }

    fn read_verified_slices(
        &self,
        request: StripeReadRequest,
        stripe: &CommittedProtectedStripe,
        targets: &BTreeSet<TargetId>,
    ) -> Result<VerifiedSlices, ContractError> {
        let total = usize::from(stripe.stripe.coding_layout().total_slices());
        let required = usize::from(stripe.stripe.coding_layout().data_slices());
        let mut available = vec![None; total];
        let mut receipts = Vec::with_capacity(required);
        for receipt in stripe.receipts.as_slice() {
            if receipts.len() == required {
                break;
            }
            if !targets.contains(&receipt.target_id) {
                continue;
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
                    receipts.push(*receipt);
                }
                Ok(_)
                | Err(
                    ContractError::Corrupt | ContractError::NotFound | ContractError::Unavailable,
                ) => {}
                Err(error) => return Err(error),
            }
        }
        if receipts.len() < required {
            return Err(ContractError::Unavailable);
        }
        Ok(VerifiedSlices {
            bytes: BoundedItems::new(available, total)
                .map_err(|_| ContractError::InternalContract)?,
            receipts: BoundedItems::new(receipts, required)
                .map_err(|_| ContractError::InternalContract)?,
        })
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

fn reconstruct_ciphertext<Coding: CodingScheme>(
    coding: &Coding,
    context: RequestContext,
    stripe: &CommittedProtectedStripe,
    available: BoundedItems<Option<BoundedBytes>>,
) -> Result<BoundedBytes, ContractError> {
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
    let chunk = stripe.stripe.chunk();
    if u64::try_from(ciphertext.len()).ok() != Some(chunk.ciphertext_length)
        || blake3::hash(ciphertext.as_slice()).as_bytes() != &chunk.ciphertext_digest
    {
        return Err(ContractError::Corrupt);
    }
    Ok(ciphertext)
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
    request: StripeReadRequest,
    receipt: ShardReceipt,
) -> Result<RequestContext, ContractError> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.content.repair-read.v1\0");
    digest.update(&request.operation_id.as_bytes());
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

/// Provider durability is shared by live repair and isolated offline restoration.
fn store_replacement(
    router: &mut impl ContentShardRouter,
    request: ShardRepairRequest,
    bytes: BoundedBytes,
) -> Result<ShardReceipt, ContractError> {
    verify_replacement_bytes(request.source_receipt, &bytes)?;
    let context = repair_context(request);
    let reservation = router.reserve(ReserveStorageRequest {
        context,
        target_id: request.replacement_target_id,
        target_generation: request.replacement_target_generation,
        class: ReservationClass::Repair,
        bytes: request.source_receipt.length,
        observed_at: request.observed_at,
    })?;
    let receipt = router.put_exact(
        PutShardRequest {
            context,
            reservation,
            shard: request.source_receipt.shard,
            expected_length: request.source_receipt.length,
            expected_digest: request.source_receipt.digest,
            bytes,
        },
        request.observed_at,
    )?;
    validate_replacement_receipt(request, receipt)?;
    Ok(receipt)
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
