// SPDX-License-Identifier: GPL-2.0-only

//! Exact permit and provider receipt bytes carried in replicated cleanup transitions.

use super::{Decoder, Encoder, MetadataCommandCodecError, inventory};
use crate::{
    CompleteVersionCleanupItem, ConfirmVersionCleanupReclamation, IssueVersionCleanupPermit,
};
use meshspan_contracts::{ReclamationReceipt, RemovalPermit, TombstoneReceipt};
use meshspan_domain::{MeshId, NodeId, OperationId, Revision, TargetId, UnixMicros};

pub(super) fn encode_issue(
    encoder: &mut Encoder,
    value: &IssueVersionCleanupPermit,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.cleanup_operation_id.as_bytes())?;
    encoder.u64(value.inventory_sealed_revision.get())?;
    encoder.u64(value.item_index)?;
    encoder.u64(value.attempt_sequence)?;
    let permit = value.permit;
    encoder.identifier(permit.operation_id.as_bytes())?;
    encoder.identifier(permit.mesh_id.as_bytes())?;
    encoder.identifier(permit.target_id.as_bytes())?;
    inventory::encode_shard(encoder, permit.shard)?;
    encoder.u64(permit.target_generation)?;
    encoder.u64(permit.authority_epoch)?;
    encoder.u64(permit.catalogue_revision.get())?;
    encoder.i64(permit.expires_at.get())?;
    encoder.fixed(&permit.permit_digest)
}

pub(super) fn decode_issue(
    decoder: &mut Decoder<'_>,
) -> Result<IssueVersionCleanupPermit, MetadataCommandCodecError> {
    Ok(IssueVersionCleanupPermit {
        cleanup_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        inventory_sealed_revision: Revision::new(decoder.u64()?),
        item_index: decoder.u64()?,
        attempt_sequence: decoder.u64()?,
        permit: RemovalPermit {
            operation_id: OperationId::from_bytes(decoder.identifier()?)?,
            mesh_id: MeshId::from_bytes(decoder.identifier()?)?,
            target_id: TargetId::from_bytes(decoder.identifier()?)?,
            shard: inventory::decode_shard(decoder)?,
            target_generation: decoder.u64()?,
            authority_epoch: decoder.u64()?,
            catalogue_revision: Revision::new(decoder.u64()?),
            expires_at: UnixMicros::new(decoder.i64()?),
            permit_digest: decoder.fixed()?,
        },
    })
}

pub(super) fn encode_complete(
    encoder: &mut Encoder,
    value: &CompleteVersionCleanupItem,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.cleanup_operation_id.as_bytes())?;
    encoder.u64(value.inventory_sealed_revision.get())?;
    encoder.u64(value.item_index)?;
    encoder.u64(value.permit_attempt_sequence)?;
    encode_tombstone(encoder, value.receipt)?;
    encoder.identifier(value.reporter_node_id.as_bytes())?;
    encoder.u64(value.reporter_incarnation)
}

pub(super) fn decode_complete(
    decoder: &mut Decoder<'_>,
) -> Result<CompleteVersionCleanupItem, MetadataCommandCodecError> {
    Ok(CompleteVersionCleanupItem {
        cleanup_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        inventory_sealed_revision: Revision::new(decoder.u64()?),
        item_index: decoder.u64()?,
        permit_attempt_sequence: decoder.u64()?,
        receipt: decode_tombstone(decoder)?,
        reporter_node_id: NodeId::from_bytes(decoder.identifier()?)?,
        reporter_incarnation: decoder.u64()?,
    })
}

pub(super) fn encode_reclamation(
    encoder: &mut Encoder,
    value: &ConfirmVersionCleanupReclamation,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.cleanup_operation_id.as_bytes())?;
    encoder.u64(value.item_index)?;
    encode_tombstone(encoder, value.receipt.tombstone)?;
    encoder.i64(value.receipt.bytes_unlinked_at.get())?;
    encoder.u64(value.receipt.reclaimed_bytes)?;
    encoder.fixed(&value.receipt.reclamation_digest)?;
    encoder.identifier(value.reporter_node_id.as_bytes())?;
    encoder.u64(value.reporter_incarnation)
}

pub(super) fn decode_reclamation(
    decoder: &mut Decoder<'_>,
) -> Result<ConfirmVersionCleanupReclamation, MetadataCommandCodecError> {
    Ok(ConfirmVersionCleanupReclamation {
        cleanup_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        item_index: decoder.u64()?,
        receipt: ReclamationReceipt {
            tombstone: decode_tombstone(decoder)?,
            bytes_unlinked_at: UnixMicros::new(decoder.i64()?),
            reclaimed_bytes: decoder.u64()?,
            reclamation_digest: decoder.fixed()?,
        },
        reporter_node_id: NodeId::from_bytes(decoder.identifier()?)?,
        reporter_incarnation: decoder.u64()?,
    })
}

fn encode_tombstone(
    encoder: &mut Encoder,
    receipt: TombstoneReceipt,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(receipt.operation_id.as_bytes())?;
    inventory::encode_shard(encoder, receipt.shard)?;
    encoder.identifier(receipt.target_id.as_bytes())?;
    encoder.u64(receipt.target_generation)?;
    encoder.fixed(&receipt.permit_digest)?;
    encoder.fixed(&receipt.tombstone_digest)
}

fn decode_tombstone(
    decoder: &mut Decoder<'_>,
) -> Result<TombstoneReceipt, MetadataCommandCodecError> {
    Ok(TombstoneReceipt {
        operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        shard: inventory::decode_shard(decoder)?,
        target_id: TargetId::from_bytes(decoder.identifier()?)?,
        target_generation: decoder.u64()?,
        permit_digest: decoder.fixed()?,
        tombstone_digest: decoder.fixed()?,
    })
}
