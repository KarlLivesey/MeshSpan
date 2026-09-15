// SPDX-License-Identifier: GPL-2.0-only

//! Canonical repair selection, separately versioned from legacy effect commands.

use meshspan_contracts::{
    SHARD_PUT_INTENT_V1_BYTES, decode_shard_put_intent_v1, encode_shard_put_intent_v1,
};
use meshspan_domain::{AuditEventId, OperationId, PrincipalId, Revision, UnixMicros};

use super::{
    Decoder, Encoder, MetadataCommandCodecError, PLAN_SHARD_REPAIR, decode_claim_identity,
    decode_shard_receipt, encode_claim_identity, encode_shard_receipt,
};
use crate::{ClaimMaintenanceWork, CommandContext, PlanShardRepair};

pub(super) fn encode(
    encoder: &mut Encoder,
    value: &PlanShardRepair,
) -> Result<(), MetadataCommandCodecError> {
    value
        .intent
        .validate()
        .map_err(|_| MetadataCommandCodecError::Invalid)?;
    encoder.u16(PLAN_SHARD_REPAIR)?;
    let claim = value.claim;
    encode_claim_identity(
        encoder,
        claim.work_id,
        claim.claim_generation,
        claim.worker_node_id,
        claim.worker_incarnation,
        claim.fence,
    )?;
    encoder.i64(claim.lease_expires_at.get())?;
    encoder.u64(super::positive(value.source_layout_generation)?)?;
    encode_shard_receipt(encoder, value.source_receipt)?;
    encoder.fixed(&encode_shard_put_intent_v1(value.intent))?;
    encode_context(encoder, value.effect_context)?;
    encode_context(encoder, value.completion_context)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<PlanShardRepair, MetadataCommandCodecError> {
    let claim = decode_claim_identity(decoder)?;
    let claim = ClaimMaintenanceWork {
        work_id: claim.work_id,
        claim_generation: claim.claim_generation,
        worker_node_id: claim.worker_node_id,
        worker_incarnation: claim.worker_incarnation,
        fence: claim.fence,
        lease_expires_at: UnixMicros::new(decoder.i64()?),
    };
    let source_layout_generation = super::positive(decoder.u64()?)?;
    let source_receipt = decode_shard_receipt(decoder)?;
    let intent = decode_shard_put_intent_v1(&decoder.fixed::<SHARD_PUT_INTENT_V1_BYTES>()?)
        .map_err(|_| MetadataCommandCodecError::Invalid)?;
    Ok(PlanShardRepair {
        claim,
        source_layout_generation,
        source_receipt,
        intent,
        effect_context: decode_context(decoder)?,
        completion_context: decode_context(decoder)?,
    })
}

fn encode_context(
    encoder: &mut Encoder,
    context: CommandContext,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(context.operation_id.as_bytes())?;
    encoder.identifier(context.actor_principal_id.as_bytes())?;
    encoder.identifier(context.audit_event_id.as_bytes())?;
    encoder.i64(context.occurred_at.get())?;
    encoder.optional_u64(context.expected_revision.map(Revision::get))
}

fn decode_context(decoder: &mut Decoder<'_>) -> Result<CommandContext, MetadataCommandCodecError> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        actor_principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
        audit_event_id: AuditEventId::from_bytes(decoder.identifier()?)?,
        occurred_at: UnixMicros::new(decoder.i64()?),
        expected_revision: decoder.optional_u64()?.map(Revision::new),
    })
}
