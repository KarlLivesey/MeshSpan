// SPDX-License-Identifier: GPL-2.0-only

//! Offline ciphertext restoration through the normal provider durability boundary.

use std::collections::BTreeSet;

use meshspan_contracts::{BoundedItems, CodingScheme, ContractError, ShardReceipt};
use meshspan_domain::Revision;

use super::{ShardRepairRequest, repair_context, store_replacement, validate_request};
use crate::{CommittedProtectedStripe, ContentReadError, ContentShardRouter, RecoveryShardSource};

/// Reconstructs one archived stripe once and durably restores its selected original slices.
///
/// The recovery coordinator must independently authorise the archive, salvage source and
/// replacement targets using its offline root. This function is not a live endpoint and cannot
/// grant recovery authority. It needs no volume decryption key: ciphertext and every regenerated
/// slice must match the immutable archive evidence before the first provider write.
///
/// Success returns exact normal provider receipts, not an updated route or protection claim.
/// The caller retains them before any separately authorised catalogue/admission transition.
/// Failure may leave a prefix durably stored; replay the same operation IDs to recover their
/// existing receipts. No old target is changed or deleted. Memory is bounded by one stripe.
///
/// # Errors
/// Rejects inconsistent/duplicate requests before IO, insufficient intact source slices,
/// reconstructed-byte mismatch, provider capacity/IO failures and substituted receipts.
pub fn restore_recovery_stripe(
    requests: &[ShardRepairRequest],
    stripe: &CommittedProtectedStripe,
    coding: &impl CodingScheme,
    source: &mut impl RecoveryShardSource,
    destination: &mut impl ContentShardRouter,
) -> Result<BoundedItems<ShardReceipt>, ContractError> {
    let first = validate_requests(requests, stripe)?;
    let context = repair_context(first);
    let encrypted = crate::content_recovery::reconstruct_chunk(
        context,
        first.source_receipt.shard.manifest_digest,
        &stripe.stripe,
        coding,
        source,
    )
    .map_err(|error| map_source(&error))?;
    let regenerated = coding.encode(
        context,
        stripe.stripe.coding_layout(),
        &encrypted.ciphertext,
    )?;
    // Verify the whole selected set before IO, not only each slice immediately before its put.
    for request in requests {
        let bytes = regenerated
            .as_slice()
            .get(usize::from(request.source_receipt.shard.shard_index))
            .ok_or(ContractError::Corrupt)?;
        super::verify_replacement_bytes(request.source_receipt, bytes)?;
    }
    let mut receipts = Vec::with_capacity(requests.len());
    for request in requests {
        let bytes = regenerated
            .as_slice()
            .get(usize::from(request.source_receipt.shard.shard_index))
            .cloned()
            .ok_or(ContractError::Corrupt)?;
        receipts.push(store_replacement(destination, *request, bytes)?);
    }
    BoundedItems::new(receipts, 24).map_err(|_| ContractError::InternalContract)
}

fn validate_requests(
    requests: &[ShardRepairRequest],
    stripe: &CommittedProtectedStripe,
) -> Result<ShardRepairRequest, ContractError> {
    if requests.len() > 24 {
        return Err(ContractError::InvalidInput);
    }
    let first = requests
        .first()
        .copied()
        .ok_or(ContractError::InvalidInput)?;
    let mut shards = BTreeSet::new();
    let mut operations = BTreeSet::new();
    for request in requests {
        validate_request(*request, stripe)?;
        if request.authorization_revision == Revision::ZERO
            || request.observed_at.get() < 0
            || request.authorization_revision != first.authorization_revision
            || request.observed_at != first.observed_at
            || request.deadline != first.deadline
            || !stripe.receipts.as_slice().contains(&request.source_receipt)
            || !shards.insert(request.source_receipt.shard.shard_index)
            || !operations.insert(request.replacement_operation_id)
        {
            return Err(ContractError::InvalidInput);
        }
    }
    Ok(first)
}

fn map_source(error: &ContentReadError) -> ContractError {
    match error {
        ContentReadError::InvalidInput => ContractError::InvalidInput,
        ContentReadError::Conflict => ContractError::Conflict,
        ContentReadError::Corrupt => ContractError::Corrupt,
        ContentReadError::Unavailable | ContentReadError::Io(_) => ContractError::Unavailable,
    }
}
