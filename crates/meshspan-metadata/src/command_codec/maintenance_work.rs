// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{NodeId, UnixMicros, WorkId};
use meshspan_work::{MAXIMUM_WORK_SUBJECT_BYTES, WorkSignals, WorkSubject};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    ClaimMaintenanceWork, CompleteMaintenanceWork, MaintenanceWorkCompletion, QueueMaintenanceWork,
    RenewMaintenanceWork,
};

pub(super) const QUEUE_MAINTENANCE_WORK: u16 = 36;
pub(super) const CLAIM_MAINTENANCE_WORK: u16 = 37;
pub(super) const RENEW_MAINTENANCE_WORK: u16 = 38;
pub(super) const COMPLETE_MAINTENANCE_WORK: u16 = 39;

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
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn encode_queue(
    encoder: &mut Encoder,
    value: QueueMaintenanceWork,
) -> Result<(), MetadataCommandCodecError> {
    let subject = value.subject.encode();
    if value.deduplication_key == [0; 32]
        || WorkSubject::decode(&subject).ok() != Some(value.subject)
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.u16(QUEUE_MAINTENANCE_WORK)?;
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
    encoder.i64(value.next_attempt_at.get())
}

fn decode_queue(
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
        next_attempt_at: UnixMicros::new(decoder.i64()?),
    };
    if value.deduplication_key == [0; 32] {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(value)
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
