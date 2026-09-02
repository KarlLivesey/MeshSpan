// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{ShardIdentity, ShardReceipt};
use meshspan_domain::{NodeId, OperationId, Revision, TargetId, UnixMicros, WorkId};
use meshspan_work::{MAXIMUM_WORK_SUBJECT_BYTES, WorkDemand, WorkSignals, WorkSubject};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    AttestStorageTargetDrain, BeginStorageTargetDrain, ClaimMaintenanceWork,
    CommitRebalanceScanPage, CommitScrubPass, CommitShardRepair, CommitTargetReconciliation,
    CompleteMaintenanceWork, MaintenanceWorkCompletion, QueueMaintenanceWork, RebalanceScanCursor,
    RenewMaintenanceWork,
};

pub(super) const QUEUE_MAINTENANCE_WORK: u16 = 36;
pub(super) const CLAIM_MAINTENANCE_WORK: u16 = 37;
pub(super) const RENEW_MAINTENANCE_WORK: u16 = 38;
pub(super) const COMPLETE_MAINTENANCE_WORK: u16 = 39;
pub(super) const COMMIT_SHARD_REPAIR: u16 = 40;
pub(super) const COMMIT_SCRUB_PASS: u16 = 41;
pub(super) const BEGIN_STORAGE_TARGET_DRAIN: u16 = 42;
pub(super) const ATTEST_STORAGE_TARGET_DRAIN: u16 = 43;
pub(super) const COMMIT_REBALANCE_SCAN_PAGE: u16 = 44;
pub(super) const COMMIT_TARGET_RECONCILIATION: u16 = 45;

pub(super) fn encode_command(
    encoder: &mut Encoder,
    command: &crate::AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        crate::AuthoritativeCommand::QueueMaintenanceWork(value) => {
            encode_queue(encoder, *value)?;
        }
        crate::AuthoritativeCommand::ClaimMaintenanceWork(value) => {
            encode_claim(encoder, *value)?;
        }
        crate::AuthoritativeCommand::RenewMaintenanceWork(value) => {
            encode_renew(encoder, *value)?;
        }
        crate::AuthoritativeCommand::CompleteMaintenanceWork(value) => {
            encode_complete(encoder, *value)?;
        }
        crate::AuthoritativeCommand::CommitShardRepair(value) => {
            encode_repair(encoder, value)?;
        }
        crate::AuthoritativeCommand::CommitScrubPass(value) => {
            encode_scrub(encoder, *value)?;
        }
        crate::AuthoritativeCommand::BeginStorageTargetDrain(value) => {
            encode_begin_target_drain(encoder, *value)?;
        }
        crate::AuthoritativeCommand::AttestStorageTargetDrain(value) => {
            encode_target_drain_attestation(encoder, *value)?;
        }
        crate::AuthoritativeCommand::CommitRebalanceScanPage(value) => {
            encode_rebalance_scan_page(encoder, *value)?;
        }
        crate::AuthoritativeCommand::CommitTargetReconciliation(value) => {
            encode_reconciliation(encoder, *value)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) const fn is_command_kind(kind: u16) -> bool {
    matches!(
        kind,
        QUEUE_MAINTENANCE_WORK
            | CLAIM_MAINTENANCE_WORK
            | RENEW_MAINTENANCE_WORK
            | COMPLETE_MAINTENANCE_WORK
            | COMMIT_SHARD_REPAIR
            | COMMIT_SCRUB_PASS
            | BEGIN_STORAGE_TARGET_DRAIN
            | ATTEST_STORAGE_TARGET_DRAIN
            | COMMIT_REBALANCE_SCAN_PAGE
            | COMMIT_TARGET_RECONCILIATION
    )
}

pub(super) fn decode_command(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<crate::AuthoritativeCommand, MetadataCommandCodecError> {
    match kind {
        QUEUE_MAINTENANCE_WORK => {
            decode_queue(decoder).map(crate::AuthoritativeCommand::QueueMaintenanceWork)
        }
        CLAIM_MAINTENANCE_WORK => {
            decode_claim(decoder).map(crate::AuthoritativeCommand::ClaimMaintenanceWork)
        }
        RENEW_MAINTENANCE_WORK => {
            decode_renew(decoder).map(crate::AuthoritativeCommand::RenewMaintenanceWork)
        }
        COMPLETE_MAINTENANCE_WORK => {
            decode_complete(decoder).map(crate::AuthoritativeCommand::CompleteMaintenanceWork)
        }
        COMMIT_SHARD_REPAIR => {
            decode_repair(decoder).map(crate::AuthoritativeCommand::CommitShardRepair)
        }
        COMMIT_SCRUB_PASS => {
            decode_scrub(decoder).map(crate::AuthoritativeCommand::CommitScrubPass)
        }
        BEGIN_STORAGE_TARGET_DRAIN => decode_begin_target_drain(decoder)
            .map(crate::AuthoritativeCommand::BeginStorageTargetDrain),
        ATTEST_STORAGE_TARGET_DRAIN => decode_target_drain_attestation(decoder)
            .map(crate::AuthoritativeCommand::AttestStorageTargetDrain),
        COMMIT_REBALANCE_SCAN_PAGE => decode_rebalance_scan_page(decoder)
            .map(crate::AuthoritativeCommand::CommitRebalanceScanPage),
        COMMIT_TARGET_RECONCILIATION => decode_reconciliation(decoder)
            .map(crate::AuthoritativeCommand::CommitTargetReconciliation),
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn encode_queue(
    encoder: &mut Encoder,
    value: QueueMaintenanceWork,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(QUEUE_MAINTENANCE_WORK)?;
    encode_queue_fields(encoder, value)
}

fn encode_queue_fields(
    encoder: &mut Encoder,
    value: QueueMaintenanceWork,
) -> Result<(), MetadataCommandCodecError> {
    let subject = value.subject.encode();
    if value.deduplication_key == [0; 32]
        || WorkSubject::decode(&subject).ok() != Some(value.subject)
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.identifier(value.work_id.as_bytes())?;
    encoder.fixed(&value.deduplication_key)?;
    encoder.bytes(&subject, MAXIMUM_WORK_SUBJECT_BYTES)?;
    encoder.bool(value.signals.data_unavailable)?;
    encoder.u16(value.signals.remaining_recovery_margin)?;
    encoder.u16(value.signals.protection_debt)?;
    encoder.u16(value.signals.locality_debt)?;
    encoder.u16(value.signals.instability)?;
    encoder.u16(value.signals.access_heat)?;
    encoder.i64(value.signals.created_at.get())?;
    encoder.optional_i64(value.signals.due_at.map(UnixMicros::get))?;
    encoder.u64(value.demand.in_flight_bytes)?;
    encoder.i64(value.next_attempt_at.get())
}

fn decode_queue(
    decoder: &mut Decoder<'_>,
) -> Result<QueueMaintenanceWork, MetadataCommandCodecError> {
    decode_queue_fields(decoder)
}

fn decode_queue_fields(
    decoder: &mut Decoder<'_>,
) -> Result<QueueMaintenanceWork, MetadataCommandCodecError> {
    let value = QueueMaintenanceWork {
        work_id: WorkId::from_bytes(decoder.identifier()?)?,
        deduplication_key: decoder.fixed()?,
        subject: WorkSubject::decode(&decoder.bytes(MAXIMUM_WORK_SUBJECT_BYTES)?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        signals: WorkSignals {
            data_unavailable: decoder.bool()?,
            remaining_recovery_margin: decoder.u16()?,
            protection_debt: decoder.u16()?,
            locality_debt: decoder.u16()?,
            instability: decoder.u16()?,
            access_heat: decoder.u16()?,
            created_at: UnixMicros::new(decoder.i64()?),
            due_at: decoder.optional_i64()?.map(UnixMicros::new),
        },
        demand: WorkDemand {
            in_flight_bytes: positive(decoder.u64()?)?,
        },
        next_attempt_at: UnixMicros::new(decoder.i64()?),
    };
    if value.deduplication_key == [0; 32] {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(value)
    }
}

fn encode_begin_target_drain(
    encoder: &mut Encoder,
    value: BeginStorageTargetDrain,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(BEGIN_STORAGE_TARGET_DRAIN)?;
    encode_queue_fields(encoder, value.work)?;
    encoder.bool(value.allow_temporary_degraded)?;
    encoder.bool(value.cleanup_requested)
}

fn decode_begin_target_drain(
    decoder: &mut Decoder<'_>,
) -> Result<BeginStorageTargetDrain, MetadataCommandCodecError> {
    Ok(BeginStorageTargetDrain {
        work: decode_queue_fields(decoder)?,
        allow_temporary_degraded: decoder.bool()?,
        cleanup_requested: decoder.bool()?,
    })
}

fn encode_target_drain_attestation(
    encoder: &mut Encoder,
    value: AttestStorageTargetDrain,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(ATTEST_STORAGE_TARGET_DRAIN)?;
    encode_claim_identity(
        encoder,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encoder.identifier(value.target_id.as_bytes())?;
    encoder.u64(positive(value.target_generation)?)?;
    encoder.u64(positive(value.observed_authority_revision.get())?)?;
    encoder.fixed(&nonzero_digest(value.empty_catalogue_digest)?)
}

fn decode_target_drain_attestation(
    decoder: &mut Decoder<'_>,
) -> Result<AttestStorageTargetDrain, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    Ok(AttestStorageTargetDrain {
        work_id: identity.work_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        target_id: TargetId::from_bytes(decoder.identifier()?)?,
        target_generation: positive(decoder.u64()?)?,
        observed_authority_revision: Revision::new(positive(decoder.u64()?)?),
        empty_catalogue_digest: nonzero_digest(decoder.fixed()?)?,
    })
}

fn encode_rebalance_scan_page(
    encoder: &mut Encoder,
    value: CommitRebalanceScanPage,
) -> Result<(), MetadataCommandCodecError> {
    validate_rebalance_scan_page(value)?;
    encoder.u16(COMMIT_REBALANCE_SCAN_PAGE)?;
    encode_claim_identity(
        encoder,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encoder.identifier(value.volume_id.as_bytes())?;
    encoder.u64(value.topology_revision.get())?;
    encode_rebalance_cursor(encoder, value.after)?;
    encode_rebalance_cursor(encoder, value.next)?;
    encoder.u16(value.scanned_stripes)?;
    encoder.u16(value.queued_repairs)?;
    encoder.optional_u64(value.superseded_by_revision.map(Revision::get))?;
    encoder.fixed(&value.page_digest)
}

fn decode_rebalance_scan_page(
    decoder: &mut Decoder<'_>,
) -> Result<CommitRebalanceScanPage, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    let value = CommitRebalanceScanPage {
        work_id: identity.work_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        volume_id: meshspan_domain::VolumeId::from_bytes(decoder.identifier()?)?,
        topology_revision: Revision::new(positive(decoder.u64()?)?),
        after: decode_rebalance_cursor(decoder)?,
        next: decode_rebalance_cursor(decoder)?,
        scanned_stripes: decoder.u16()?,
        queued_repairs: decoder.u16()?,
        superseded_by_revision: decoder.optional_u64()?.map(Revision::new),
        page_digest: decoder.fixed()?,
    };
    validate_rebalance_scan_page(value)?;
    Ok(value)
}

fn encode_rebalance_cursor(
    encoder: &mut Encoder,
    cursor: Option<RebalanceScanCursor>,
) -> Result<(), MetadataCommandCodecError> {
    encoder.bool(cursor.is_some())?;
    if let Some(cursor) = cursor {
        encoder.identifier(cursor.publication_operation_id.as_bytes())?;
        encoder.u64(cursor.stripe_index)?;
    }
    Ok(())
}

fn decode_rebalance_cursor(
    decoder: &mut Decoder<'_>,
) -> Result<Option<RebalanceScanCursor>, MetadataCommandCodecError> {
    if decoder.bool()? {
        Ok(Some(RebalanceScanCursor {
            publication_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
            stripe_index: decoder.u64()?,
        }))
    } else {
        Ok(None)
    }
}

fn validate_rebalance_scan_page(
    value: CommitRebalanceScanPage,
) -> Result<(), MetadataCommandCodecError> {
    if value.topology_revision == Revision::ZERO
        || value.page_digest == [0; 32]
        || value.queued_repairs > value.scanned_stripes
        || value.superseded_by_revision.is_some_and(|revision| {
            revision <= value.topology_revision
                || value.scanned_stripes != 0
                || value.queued_repairs != 0
                || value.next.is_some()
        })
        || value.next.is_some_and(|next| {
            value.scanned_stripes == 0 || value.after.is_some_and(|after| next <= after)
        })
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn encode_claim(
    encoder: &mut Encoder,
    value: ClaimMaintenanceWork,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(CLAIM_MAINTENANCE_WORK)?;
    encode_claim_identity(
        encoder,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encoder.i64(value.lease_expires_at.get())
}

fn decode_claim(
    decoder: &mut Decoder<'_>,
) -> Result<ClaimMaintenanceWork, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    Ok(ClaimMaintenanceWork {
        work_id: identity.work_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        lease_expires_at: UnixMicros::new(decoder.i64()?),
    })
}

fn encode_renew(
    encoder: &mut Encoder,
    value: RenewMaintenanceWork,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(RENEW_MAINTENANCE_WORK)?;
    encode_claim_identity(
        encoder,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encoder.i64(value.lease_expires_at.get())
}

fn decode_renew(
    decoder: &mut Decoder<'_>,
) -> Result<RenewMaintenanceWork, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    Ok(RenewMaintenanceWork {
        work_id: identity.work_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        lease_expires_at: UnixMicros::new(decoder.i64()?),
    })
}

fn encode_complete(
    encoder: &mut Encoder,
    value: CompleteMaintenanceWork,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(COMPLETE_MAINTENANCE_WORK)?;
    encode_claim_identity(
        encoder,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    match value.outcome {
        MaintenanceWorkCompletion::Succeeded {
            effect_operation_id,
            effect_revision,
            effect_result_digest,
        } => {
            encoder.u8(1)?;
            encoder.identifier(effect_operation_id.as_bytes())?;
            encoder.u64(effect_revision.get())?;
            encoder.fixed(&effect_result_digest)
        }
        MaintenanceWorkCompletion::Retry {
            failure_digest,
            retry_at,
        } => {
            encoder.u8(2)?;
            encoder.fixed(&failure_digest)?;
            encoder.i64(retry_at.get())
        }
        MaintenanceWorkCompletion::Continue {
            progress_digest,
            retry_at,
        } => {
            encoder.u8(3)?;
            encoder.fixed(&progress_digest)?;
            encoder.i64(retry_at.get())
        }
    }
}

fn decode_complete(
    decoder: &mut Decoder<'_>,
) -> Result<CompleteMaintenanceWork, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    let outcome = match decoder.u8()? {
        1 => MaintenanceWorkCompletion::Succeeded {
            effect_operation_id: meshspan_domain::OperationId::from_bytes(decoder.identifier()?)?,
            effect_revision: meshspan_domain::Revision::new(positive(decoder.u64()?)?),
            effect_result_digest: nonzero_digest(decoder.fixed()?)?,
        },
        2 => MaintenanceWorkCompletion::Retry {
            failure_digest: nonzero_digest(decoder.fixed()?)?,
            retry_at: UnixMicros::new(decoder.i64()?),
        },
        3 => MaintenanceWorkCompletion::Continue {
            progress_digest: nonzero_digest(decoder.fixed()?)?,
            retry_at: UnixMicros::new(decoder.i64()?),
        },
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    Ok(CompleteMaintenanceWork {
        work_id: identity.work_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        outcome,
    })
}

fn encode_repair(
    encoder: &mut Encoder,
    value: &CommitShardRepair,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(COMMIT_SHARD_REPAIR)?;
    encode_claim_identity(
        encoder,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encoder.identifier(value.volume_id.as_bytes())?;
    encoder.identifier(value.manifest_id.as_bytes())?;
    encoder.u64(positive(value.source_layout_generation)?)?;
    encode_shard_receipt(encoder, value.source_receipt)?;
    encode_shard_receipt(encoder, value.replacement_receipt)
}

fn decode_repair(
    decoder: &mut Decoder<'_>,
) -> Result<CommitShardRepair, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    Ok(CommitShardRepair {
        work_id: identity.work_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        volume_id: meshspan_domain::VolumeId::from_bytes(decoder.identifier()?)?,
        manifest_id: meshspan_domain::ContentManifestId::from_bytes(decoder.identifier()?)?,
        source_layout_generation: positive(decoder.u64()?)?,
        source_receipt: decode_shard_receipt(decoder)?,
        replacement_receipt: decode_shard_receipt(decoder)?,
    })
}

fn encode_scrub(
    encoder: &mut Encoder,
    value: CommitScrubPass,
) -> Result<(), MetadataCommandCodecError> {
    validate_scrub_summary(value)?;
    encoder.u16(COMMIT_SCRUB_PASS)?;
    encode_claim_identity(
        encoder,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encoder.identifier(value.target_id.as_bytes())?;
    encoder.u64(value.target_generation)?;
    encoder.u64(value.observation_count)?;
    encoder.u64(value.verified_bytes)?;
    encoder.u64(value.healthy_count)?;
    encoder.u64(value.missing_count)?;
    encoder.u64(value.corrupt_count)?;
    encoder.u64(value.unreadable_count)?;
    encoder.u64(value.unexpected_count)?;
    encoder.u64(value.deferred_count)?;
    encoder.fixed(&value.evidence_digest)
}

fn decode_scrub(decoder: &mut Decoder<'_>) -> Result<CommitScrubPass, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    let value = CommitScrubPass {
        work_id: identity.work_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        target_id: TargetId::from_bytes(decoder.identifier()?)?,
        target_generation: decoder.u64()?,
        observation_count: decoder.u64()?,
        verified_bytes: decoder.u64()?,
        healthy_count: decoder.u64()?,
        missing_count: decoder.u64()?,
        corrupt_count: decoder.u64()?,
        unreadable_count: decoder.u64()?,
        unexpected_count: decoder.u64()?,
        deferred_count: decoder.u64()?,
        evidence_digest: decoder.fixed()?,
    };
    validate_scrub_summary(value)?;
    Ok(value)
}

fn validate_scrub_summary(value: CommitScrubPass) -> Result<(), MetadataCommandCodecError> {
    validate_verification_summary(
        value.target_generation,
        value.observation_count,
        [
            value.healthy_count,
            value.missing_count,
            value.corrupt_count,
            value.unreadable_count,
            value.unexpected_count,
            value.deferred_count,
        ],
        value.evidence_digest,
    )
}

fn encode_reconciliation(
    encoder: &mut Encoder,
    value: CommitTargetReconciliation,
) -> Result<(), MetadataCommandCodecError> {
    validate_reconciliation_summary(value)?;
    encoder.u16(COMMIT_TARGET_RECONCILIATION)?;
    encode_claim_identity(
        encoder,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encoder.identifier(value.target_id.as_bytes())?;
    encoder.u64(value.target_generation)?;
    encoder.u64(value.observation_count)?;
    encoder.u64(value.verified_bytes)?;
    encoder.u64(value.healthy_count)?;
    encoder.u64(value.missing_count)?;
    encoder.u64(value.corrupt_count)?;
    encoder.u64(value.unreadable_count)?;
    encoder.u64(value.unexpected_count)?;
    encoder.u64(value.deferred_count)?;
    encoder.fixed(&value.evidence_digest)
}

fn decode_reconciliation(
    decoder: &mut Decoder<'_>,
) -> Result<CommitTargetReconciliation, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    let value = CommitTargetReconciliation {
        work_id: identity.work_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        target_id: TargetId::from_bytes(decoder.identifier()?)?,
        target_generation: decoder.u64()?,
        observation_count: decoder.u64()?,
        verified_bytes: decoder.u64()?,
        healthy_count: decoder.u64()?,
        missing_count: decoder.u64()?,
        corrupt_count: decoder.u64()?,
        unreadable_count: decoder.u64()?,
        unexpected_count: decoder.u64()?,
        deferred_count: decoder.u64()?,
        evidence_digest: decoder.fixed()?,
    };
    validate_reconciliation_summary(value)?;
    Ok(value)
}

fn validate_reconciliation_summary(
    value: CommitTargetReconciliation,
) -> Result<(), MetadataCommandCodecError> {
    validate_verification_summary(
        value.target_generation,
        value.observation_count,
        [
            value.healthy_count,
            value.missing_count,
            value.corrupt_count,
            value.unreadable_count,
            value.unexpected_count,
            value.deferred_count,
        ],
        value.evidence_digest,
    )
}

fn validate_verification_summary(
    target_generation: u64,
    observation_count: u64,
    outcome_counts: [u64; 6],
    evidence_digest: [u8; 32],
) -> Result<(), MetadataCommandCodecError> {
    let classified = outcome_counts.into_iter().try_fold(0_u64, u64::checked_add);
    if target_generation == 0 || evidence_digest == [0; 32] || classified != Some(observation_count)
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn encode_shard_receipt(
    encoder: &mut Encoder,
    receipt: ShardReceipt,
) -> Result<(), MetadataCommandCodecError> {
    if !valid_shard_receipt(receipt) {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.identifier(receipt.operation_id.as_bytes())?;
    encoder.fixed(&receipt.shard.manifest_digest)?;
    encoder.u64(receipt.shard.stripe_index)?;
    encoder.u16(receipt.shard.shard_index)?;
    encoder.u64(u64::from(receipt.shard.generation))?;
    encoder.u64(receipt.length)?;
    encoder.fixed(&receipt.digest)?;
    encoder.identifier(receipt.target_id.as_bytes())?;
    encoder.u64(receipt.target_generation)
}

fn decode_shard_receipt(
    decoder: &mut Decoder<'_>,
) -> Result<ShardReceipt, MetadataCommandCodecError> {
    let operation_id = OperationId::from_bytes(decoder.identifier()?)?;
    let manifest_digest = nonzero_digest(decoder.fixed()?)?;
    let stripe_index = decoder.u64()?;
    let shard_index = decoder.u16()?;
    let generation =
        u32::try_from(positive(decoder.u64()?)?).map_err(|_| MetadataCommandCodecError::Invalid)?;
    let receipt = ShardReceipt {
        operation_id,
        shard: ShardIdentity {
            manifest_digest,
            stripe_index,
            shard_index,
            generation,
        },
        length: positive(decoder.u64()?)?,
        digest: nonzero_digest(decoder.fixed()?)?,
        target_id: TargetId::from_bytes(decoder.identifier()?)?,
        target_generation: positive(decoder.u64()?)?,
    };
    if valid_shard_receipt(receipt) {
        Ok(receipt)
    } else {
        Err(MetadataCommandCodecError::Invalid)
    }
}

fn valid_shard_receipt(receipt: ShardReceipt) -> bool {
    receipt.shard.manifest_digest != [0; 32]
        && receipt.shard.generation > 0
        && receipt.length > 0
        && receipt.digest != [0; 32]
        && receipt.target_generation > 0
}

fn positive(value: u64) -> Result<u64, MetadataCommandCodecError> {
    if value == 0 {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(value)
    }
}

fn nonzero_digest(value: [u8; 32]) -> Result<[u8; 32], MetadataCommandCodecError> {
    if value == [0; 32] {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(value)
    }
}

fn encode_claim_identity(
    encoder: &mut Encoder,
    work_id: WorkId,
    claim_generation: u64,
    worker_node_id: NodeId,
    worker_incarnation: u64,
    fence: u64,
) -> Result<(), MetadataCommandCodecError> {
    if claim_generation == 0 || worker_incarnation == 0 || fence == 0 {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.identifier(work_id.as_bytes())?;
    encoder.u64(claim_generation)?;
    encoder.identifier(worker_node_id.as_bytes())?;
    encoder.u64(worker_incarnation)?;
    encoder.u64(fence)
}

fn decode_claim_identity(
    decoder: &mut Decoder<'_>,
) -> Result<ClaimIdentity, MetadataCommandCodecError> {
    let value = ClaimIdentity {
        work_id: WorkId::from_bytes(decoder.identifier()?)?,
        claim_generation: decoder.u64()?,
        worker_node_id: NodeId::from_bytes(decoder.identifier()?)?,
        worker_incarnation: decoder.u64()?,
        fence: decoder.u64()?,
    };
    if value.claim_generation == 0 || value.worker_incarnation == 0 || value.fence == 0 {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(value)
    }
}

struct ClaimIdentity {
    work_id: WorkId,
    claim_generation: u64,
    worker_node_id: NodeId,
    worker_incarnation: u64,
    fence: u64,
}
