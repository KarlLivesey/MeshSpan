// SPDX-License-Identifier: GPL-2.0-only

//! Bounded cleanup placement pages and their immutable sealing witness.

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{AppendVersionCleanupItems, SealVersionCleanupInventory, VersionCleanupItemPlacement};
use meshspan_contracts::{BoundedItems, ShardIdentity};
use meshspan_domain::{NodeId, OperationId, Revision, TargetId};

pub(super) fn encode_append(
    encoder: &mut Encoder,
    value: &AppendVersionCleanupItems,
) -> Result<(), MetadataCommandCodecError> {
    validate_page(
        value.start_index,
        value.expected_item_count,
        value.items.len(),
    )?;
    encoder.identifier(value.cleanup_operation_id.as_bytes())?;
    encoder.u64(value.cleanup_revision.get())?;
    encoder.u64(value.authorisation_revision.get())?;
    encoder.u64(value.expected_item_count)?;
    encoder.u64(value.start_index)?;
    encoder
        .u16(u16::try_from(value.items.len()).map_err(|_| MetadataCommandCodecError::Invalid)?)?;
    for item in value.items.as_slice() {
        encoder.identifier(item.removal_operation_id.as_bytes())?;
        encode_shard(encoder, item.shard)?;
        encoder.identifier(item.target_id.as_bytes())?;
        encoder.u64(item.target_generation)?;
        encoder.identifier(item.storage_node_id.as_bytes())?;
    }
    Ok(())
}

pub(super) fn decode_append(
    decoder: &mut Decoder<'_>,
) -> Result<AppendVersionCleanupItems, MetadataCommandCodecError> {
    let cleanup_operation_id = OperationId::from_bytes(decoder.identifier()?)?;
    let cleanup_revision = Revision::new(decoder.u64()?);
    let authorisation_revision = Revision::new(decoder.u64()?);
    let expected_item_count = decoder.u64()?;
    let start_index = decoder.u64()?;
    let count = usize::from(decoder.u16()?);
    // Reject the claimed count/range before reserving or reading placements.
    validate_page(start_index, expected_item_count, count)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(VersionCleanupItemPlacement {
            removal_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
            shard: decode_shard(decoder)?,
            target_id: TargetId::from_bytes(decoder.identifier()?)?,
            target_generation: decoder.u64()?,
            storage_node_id: NodeId::from_bytes(decoder.identifier()?)?,
        });
    }
    Ok(AppendVersionCleanupItems {
        cleanup_operation_id,
        cleanup_revision,
        authorisation_revision,
        expected_item_count,
        start_index,
        items: BoundedItems::new(items, crate::command::MAXIMUM_CLEANUP_APPEND_ITEMS)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
    })
}

fn validate_page(start: u64, expected: u64, count: usize) -> Result<(), MetadataCommandCodecError> {
    if count == 0
        || count > crate::command::MAXIMUM_CLEANUP_APPEND_ITEMS
        || start
            .checked_add(u64::try_from(count).map_err(|_| MetadataCommandCodecError::Invalid)?)
            .is_none_or(|end| end > expected)
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(())
}

pub(super) fn encode_seal(
    encoder: &mut Encoder,
    value: &SealVersionCleanupInventory,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.cleanup_operation_id.as_bytes())?;
    encoder.u64(value.cleanup_revision.get())?;
    encoder.u64(value.authorisation_revision.get())?;
    encoder.u64(value.expected_item_count)?;
    encoder.fixed(&value.inventory_digest)
}

pub(super) fn decode_seal(
    decoder: &mut Decoder<'_>,
) -> Result<SealVersionCleanupInventory, MetadataCommandCodecError> {
    Ok(SealVersionCleanupInventory {
        cleanup_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        cleanup_revision: Revision::new(decoder.u64()?),
        authorisation_revision: Revision::new(decoder.u64()?),
        expected_item_count: decoder.u64()?,
        inventory_digest: decoder.fixed()?,
    })
}

pub(super) fn encode_shard(
    encoder: &mut Encoder,
    shard: ShardIdentity,
) -> Result<(), MetadataCommandCodecError> {
    encoder.fixed(&shard.manifest_digest)?;
    encoder.u64(shard.stripe_index)?;
    encoder.u16(shard.shard_index)?;
    encoder.fixed(&shard.generation.to_be_bytes())
}

pub(super) fn decode_shard(
    decoder: &mut Decoder<'_>,
) -> Result<ShardIdentity, MetadataCommandCodecError> {
    Ok(ShardIdentity {
        manifest_digest: decoder.fixed()?,
        stripe_index: decoder.u64()?,
        shard_index: decoder.u16()?,
        generation: u32::from_be_bytes(decoder.fixed()?),
    })
}
