// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BackupDestinationId, BackupId, ComponentInstanceId, DurationMicros, MeshId, NodeId,
    PartitionId, Revision, TargetId, UnixMicros,
};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    BackupDestinationBinding, BackupFailureRelationship, ClaimMetadataBackupRun,
    CompleteMetadataBackupRun, ConfigureBackupDestination, ConfigureMetadataBackupSchedule,
    InitialBackupCopy, MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES, MetadataBackupRunClaim,
    MetadataBackupRunCompletion, QueueMetadataBackupRun, RecordBackupCopy, RecordMetadataBackup,
    RecordName, RenewMetadataBackupRun, VerifyBackupCopy,
};

// Kind 63 was the pre-alpha blind upsert. Never reinterpret its old bytes as CAS input.
pub(super) const CONFIGURE_BACKUP_DESTINATION: u16 = 72;
pub(super) const RECORD_METADATA_BACKUP: u16 = 64;
pub(super) const RECORD_BACKUP_COPY: u16 = 65;
pub(super) const VERIFY_BACKUP_COPY: u16 = 66;
pub(super) const CONFIGURE_METADATA_BACKUP_SCHEDULE: u16 = 67;
pub(super) const QUEUE_METADATA_BACKUP_RUN: u16 = 68;
pub(super) const CLAIM_METADATA_BACKUP_RUN: u16 = 69;
pub(super) const RENEW_METADATA_BACKUP_RUN: u16 = 70;
pub(super) const COMPLETE_METADATA_BACKUP_RUN: u16 = 71;
const MAXIMUM_NAME_BYTES: usize = 128;

pub(super) const fn is_command_kind(kind: u16) -> bool {
    matches!(
        kind,
        CONFIGURE_BACKUP_DESTINATION
            | RECORD_METADATA_BACKUP
            | RECORD_BACKUP_COPY
            | VERIFY_BACKUP_COPY
            | CONFIGURE_METADATA_BACKUP_SCHEDULE
            | QUEUE_METADATA_BACKUP_RUN
            | CLAIM_METADATA_BACKUP_RUN
            | RENEW_METADATA_BACKUP_RUN
            | COMPLETE_METADATA_BACKUP_RUN
    )
}

pub(super) fn encode_command(
    encoder: &mut Encoder,
    command: &crate::AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        crate::AuthoritativeCommand::ConfigureBackupDestination(value) => {
            encode_destination(encoder, value)?;
        }
        crate::AuthoritativeCommand::ConfigureMetadataBackupSchedule(value) => {
            encode_schedule(encoder, *value)?;
        }
        crate::AuthoritativeCommand::QueueMetadataBackupRun(value) => {
            encode_run(encoder, *value)?;
        }
        crate::AuthoritativeCommand::ClaimMetadataBackupRun(value) => {
            encode_claim_command(encoder, *value)?;
        }
        crate::AuthoritativeCommand::RenewMetadataBackupRun(value) => {
            encode_renew_command(encoder, *value)?;
        }
        crate::AuthoritativeCommand::CompleteMetadataBackupRun(value) => {
            encode_completion(encoder, *value)?;
        }
        crate::AuthoritativeCommand::RecordMetadataBackup(value) => {
            encode_backup(encoder, value)?;
        }
        crate::AuthoritativeCommand::RecordBackupCopy(value) => encode_copy(encoder, value)?,
        crate::AuthoritativeCommand::VerifyBackupCopy(value) => {
            encode_verification(encoder, *value)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decode_command(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<crate::AuthoritativeCommand, MetadataCommandCodecError> {
    match kind {
        CONFIGURE_BACKUP_DESTINATION => {
            decode_destination(decoder).map(crate::AuthoritativeCommand::ConfigureBackupDestination)
        }
        CONFIGURE_METADATA_BACKUP_SCHEDULE => decode_schedule(decoder)
            .map(crate::AuthoritativeCommand::ConfigureMetadataBackupSchedule),
        QUEUE_METADATA_BACKUP_RUN => {
            decode_run(decoder).map(crate::AuthoritativeCommand::QueueMetadataBackupRun)
        }
        CLAIM_METADATA_BACKUP_RUN => {
            decode_claim_command(decoder).map(crate::AuthoritativeCommand::ClaimMetadataBackupRun)
        }
        RENEW_METADATA_BACKUP_RUN => {
            decode_renew_command(decoder).map(crate::AuthoritativeCommand::RenewMetadataBackupRun)
        }
        COMPLETE_METADATA_BACKUP_RUN => {
            decode_completion(decoder).map(crate::AuthoritativeCommand::CompleteMetadataBackupRun)
        }
        RECORD_METADATA_BACKUP => {
            decode_backup(decoder).map(crate::AuthoritativeCommand::RecordMetadataBackup)
        }
        RECORD_BACKUP_COPY => {
            decode_copy(decoder).map(crate::AuthoritativeCommand::RecordBackupCopy)
        }
        VERIFY_BACKUP_COPY => {
            decode_verification(decoder).map(crate::AuthoritativeCommand::VerifyBackupCopy)
        }
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn encode_schedule(
    encoder: &mut Encoder,
    value: ConfigureMetadataBackupSchedule,
) -> Result<(), MetadataCommandCodecError> {
    validate_schedule(value)?;
    encoder.u16(CONFIGURE_METADATA_BACKUP_SCHEDULE)?;
    encoder.identifier(value.partition_id.as_bytes())?;
    encoder.u64(value.expected_schedule_sequence)?;
    encoder.u64(value.interval.get())?;
    encoder.u16(value.retained_generations)?;
    encoder.u8(value.minimum_verified_copies)?;
    encoder.u8(value.minimum_independent_copies)?;
    encoder.bool(value.enabled)?;
    encoder.i64(value.next_due_at.get())
}

fn decode_schedule(
    decoder: &mut Decoder<'_>,
) -> Result<ConfigureMetadataBackupSchedule, MetadataCommandCodecError> {
    let value = ConfigureMetadataBackupSchedule {
        partition_id: PartitionId::from_bytes(decoder.identifier()?)?,
        expected_schedule_sequence: decoder.u64()?,
        interval: DurationMicros::new(decoder.u64()?),
        retained_generations: decoder.u16()?,
        minimum_verified_copies: decoder.u8()?,
        minimum_independent_copies: decoder.u8()?,
        enabled: decoder.bool()?,
        next_due_at: UnixMicros::new(decoder.i64()?),
    };
    validate_schedule(value)?;
    Ok(value)
}

fn encode_run(
    encoder: &mut Encoder,
    value: QueueMetadataBackupRun,
) -> Result<(), MetadataCommandCodecError> {
    validate_run(value)?;
    encoder.u16(QUEUE_METADATA_BACKUP_RUN)?;
    encoder.identifier(value.backup_id.as_bytes())?;
    encoder.identifier(value.partition_id.as_bytes())?;
    encoder.u64(value.expected_schedule_sequence)?;
    encoder.i64(value.scheduled_for.get())
}

fn decode_run(
    decoder: &mut Decoder<'_>,
) -> Result<QueueMetadataBackupRun, MetadataCommandCodecError> {
    let value = QueueMetadataBackupRun {
        backup_id: BackupId::from_bytes(decoder.identifier()?)?,
        partition_id: PartitionId::from_bytes(decoder.identifier()?)?,
        expected_schedule_sequence: decoder.u64()?,
        scheduled_for: UnixMicros::new(decoder.i64()?),
    };
    validate_run(value)?;
    Ok(value)
}

fn encode_claim_command(
    encoder: &mut Encoder,
    value: ClaimMetadataBackupRun,
) -> Result<(), MetadataCommandCodecError> {
    validate_claim(value.claim)?;
    encoder.u16(CLAIM_METADATA_BACKUP_RUN)?;
    encoder.identifier(value.backup_id.as_bytes())?;
    encode_claim(encoder, value.claim)?;
    encoder.i64(value.lease_expires_at.get())
}

fn decode_claim_command(
    decoder: &mut Decoder<'_>,
) -> Result<ClaimMetadataBackupRun, MetadataCommandCodecError> {
    let value = ClaimMetadataBackupRun {
        backup_id: BackupId::from_bytes(decoder.identifier()?)?,
        claim: decode_claim(decoder)?,
        lease_expires_at: UnixMicros::new(decoder.i64()?),
    };
    validate_claim(value.claim)?;
    Ok(value)
}

fn encode_renew_command(
    encoder: &mut Encoder,
    value: RenewMetadataBackupRun,
) -> Result<(), MetadataCommandCodecError> {
    validate_claim(value.claim)?;
    encoder.u16(RENEW_METADATA_BACKUP_RUN)?;
    encoder.identifier(value.backup_id.as_bytes())?;
    encode_claim(encoder, value.claim)?;
    encoder.i64(value.lease_expires_at.get())
}

fn decode_renew_command(
    decoder: &mut Decoder<'_>,
) -> Result<RenewMetadataBackupRun, MetadataCommandCodecError> {
    let value = RenewMetadataBackupRun {
        backup_id: BackupId::from_bytes(decoder.identifier()?)?,
        claim: decode_claim(decoder)?,
        lease_expires_at: UnixMicros::new(decoder.i64()?),
    };
    validate_claim(value.claim)?;
    Ok(value)
}

fn encode_completion(
    encoder: &mut Encoder,
    value: CompleteMetadataBackupRun,
) -> Result<(), MetadataCommandCodecError> {
    validate_completion(value.outcome)?;
    encoder.u16(COMPLETE_METADATA_BACKUP_RUN)?;
    encoder.identifier(value.backup_id.as_bytes())?;
    match value.outcome {
        MetadataBackupRunCompletion::Protected { result_digest } => {
            encoder.u8(1)?;
            encoder.fixed(&result_digest)
        }
        MetadataBackupRunCompletion::Incomplete { result_digest } => {
            encoder.u8(2)?;
            encoder.fixed(&result_digest)
        }
    }
}

fn decode_completion(
    decoder: &mut Decoder<'_>,
) -> Result<CompleteMetadataBackupRun, MetadataCommandCodecError> {
    let backup_id = BackupId::from_bytes(decoder.identifier()?)?;
    let outcome = match decoder.u8()? {
        1 => MetadataBackupRunCompletion::Protected {
            result_digest: decoder.fixed()?,
        },
        2 => MetadataBackupRunCompletion::Incomplete {
            result_digest: decoder.fixed()?,
        },
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    validate_completion(outcome)?;
    Ok(CompleteMetadataBackupRun { backup_id, outcome })
}

fn encode_claim(
    encoder: &mut Encoder,
    value: MetadataBackupRunClaim,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u64(value.claim_generation)?;
    encoder.identifier(value.worker_node_id.as_bytes())?;
    encoder.u64(value.worker_incarnation)?;
    encoder.u64(value.fence)
}

fn decode_claim(
    decoder: &mut Decoder<'_>,
) -> Result<MetadataBackupRunClaim, MetadataCommandCodecError> {
    Ok(MetadataBackupRunClaim {
        claim_generation: decoder.u64()?,
        worker_node_id: NodeId::from_bytes(decoder.identifier()?)?,
        worker_incarnation: decoder.u64()?,
        fence: decoder.u64()?,
    })
}

fn encode_destination(
    encoder: &mut Encoder,
    value: &ConfigureBackupDestination,
) -> Result<(), MetadataCommandCodecError> {
    validate_generation(value.binding.provider_generation())?;
    encoder.u16(CONFIGURE_BACKUP_DESTINATION)?;
    encoder.identifier(value.destination_id.as_bytes())?;
    encoder.u64(value.expected_destination_revision.get())?;
    encoder.text(value.name.display(), MAXIMUM_NAME_BYTES)?;
    match value.binding {
        BackupDestinationBinding::RegisteredTarget {
            target_id,
            target_generation,
        } => {
            encoder.u8(1)?;
            encoder.identifier(target_id.as_bytes())?;
            encoder.u64(target_generation)?;
        }
        BackupDestinationBinding::FederatedMesh {
            remote_mesh_id,
            provider_generation,
        } => {
            encoder.u8(2)?;
            encoder.identifier(remote_mesh_id.as_bytes())?;
            encoder.u64(provider_generation)?;
        }
        BackupDestinationBinding::ComponentProvider {
            instance_id,
            provider_generation,
        } => {
            encoder.u8(3)?;
            encoder.identifier(instance_id.as_bytes())?;
            encoder.u64(provider_generation)?;
        }
    }
    encoder.u8(failure_relationship_code(value.failure_relationship))?;
    encoder.fixed(&value.failure_evidence_digest)?;
    encoder.bool(value.enabled)
}

fn decode_destination(
    decoder: &mut Decoder<'_>,
) -> Result<ConfigureBackupDestination, MetadataCommandCodecError> {
    let destination_id = BackupDestinationId::from_bytes(decoder.identifier()?)?;
    let expected_destination_revision = Revision::new(decoder.u64()?);
    let name = RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)?;
    let binding = match decoder.u8()? {
        1 => BackupDestinationBinding::RegisteredTarget {
            target_id: TargetId::from_bytes(decoder.identifier()?)?,
            target_generation: decoder.u64()?,
        },
        2 => BackupDestinationBinding::FederatedMesh {
            remote_mesh_id: MeshId::from_bytes(decoder.identifier()?)?,
            provider_generation: decoder.u64()?,
        },
        3 => BackupDestinationBinding::ComponentProvider {
            instance_id: ComponentInstanceId::from_bytes(decoder.identifier()?)?,
            provider_generation: decoder.u64()?,
        },
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    validate_generation(binding.provider_generation())?;
    Ok(ConfigureBackupDestination {
        destination_id,
        expected_destination_revision,
        name,
        binding,
        failure_relationship: decode_failure_relationship(decoder.u8()?)?,
        failure_evidence_digest: decoder.fixed()?,
        enabled: decoder.bool()?,
    })
}

fn encode_backup(
    encoder: &mut Encoder,
    value: &RecordMetadataBackup,
) -> Result<(), MetadataCommandCodecError> {
    validate_backup(value)?;
    encoder.u16(RECORD_METADATA_BACKUP)?;
    encoder.identifier(value.backup_id.as_bytes())?;
    encoder.identifier(value.partition_id.as_bytes())?;
    encoder.identifier(value.mesh_id.as_bytes())?;
    encoder.u64(value.last_log_index)?;
    encoder.u64(value.last_log_term)?;
    encoder.u64(value.state_revision.get())?;
    encoder.u64(u64::from(value.schema_version))?;
    encoder.u64(value.source_byte_length)?;
    encoder.fixed(&value.source_digest)?;
    encoder.fixed(&value.manifest_digest)?;
    encoder.u64(value.encrypted_byte_length)?;
    encoder.fixed(&value.encrypted_digest)?;
    encode_claim(encoder, value.claim)?;
    encode_initial_copy(encoder, &value.initial_copy)
}

fn decode_backup(
    decoder: &mut Decoder<'_>,
) -> Result<RecordMetadataBackup, MetadataCommandCodecError> {
    let value = RecordMetadataBackup {
        backup_id: BackupId::from_bytes(decoder.identifier()?)?,
        partition_id: PartitionId::from_bytes(decoder.identifier()?)?,
        mesh_id: MeshId::from_bytes(decoder.identifier()?)?,
        last_log_index: decoder.u64()?,
        last_log_term: decoder.u64()?,
        state_revision: Revision::new(decoder.u64()?),
        schema_version: u32::try_from(decoder.u64()?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        source_byte_length: decoder.u64()?,
        source_digest: decoder.fixed()?,
        manifest_digest: decoder.fixed()?,
        encrypted_byte_length: decoder.u64()?,
        encrypted_digest: decoder.fixed()?,
        claim: decode_claim(decoder)?,
        initial_copy: decode_initial_copy(decoder)?,
    };
    validate_backup(&value)?;
    Ok(value)
}

fn encode_initial_copy(
    encoder: &mut Encoder,
    value: &InitialBackupCopy,
) -> Result<(), MetadataCommandCodecError> {
    validate_initial_copy(value)?;
    encoder.identifier(value.destination_id.as_bytes())?;
    encoder.u64(value.provider_generation)?;
    encoder.text(
        &value.object_reference,
        MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES,
    )?;
    encoder.u64(value.byte_length)?;
    encoder.fixed(&value.copy_digest)
}

fn decode_initial_copy(
    decoder: &mut Decoder<'_>,
) -> Result<InitialBackupCopy, MetadataCommandCodecError> {
    let value = InitialBackupCopy {
        destination_id: BackupDestinationId::from_bytes(decoder.identifier()?)?,
        provider_generation: decoder.u64()?,
        object_reference: decoder.text(MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES)?,
        byte_length: decoder.u64()?,
        copy_digest: decoder.fixed()?,
    };
    validate_initial_copy(&value)?;
    Ok(value)
}

fn encode_copy(
    encoder: &mut Encoder,
    value: &RecordBackupCopy,
) -> Result<(), MetadataCommandCodecError> {
    validate_copy(value)?;
    encoder.u16(RECORD_BACKUP_COPY)?;
    encoder.identifier(value.backup_id.as_bytes())?;
    encoder.identifier(value.destination_id.as_bytes())?;
    encoder.u64(value.provider_generation)?;
    encoder.text(
        &value.object_reference,
        MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES,
    )?;
    encoder.u64(value.byte_length)?;
    encoder.fixed(&value.copy_digest)
}

fn decode_copy(decoder: &mut Decoder<'_>) -> Result<RecordBackupCopy, MetadataCommandCodecError> {
    let value = RecordBackupCopy {
        backup_id: BackupId::from_bytes(decoder.identifier()?)?,
        destination_id: BackupDestinationId::from_bytes(decoder.identifier()?)?,
        provider_generation: decoder.u64()?,
        object_reference: decoder.text(MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES)?,
        byte_length: decoder.u64()?,
        copy_digest: decoder.fixed()?,
    };
    validate_copy(&value)?;
    Ok(value)
}

fn encode_verification(
    encoder: &mut Encoder,
    value: VerifyBackupCopy,
) -> Result<(), MetadataCommandCodecError> {
    validate_generation(value.provider_generation)?;
    encoder.u16(VERIFY_BACKUP_COPY)?;
    encoder.identifier(value.backup_id.as_bytes())?;
    encoder.identifier(value.destination_id.as_bytes())?;
    encoder.u64(value.provider_generation)?;
    encoder.fixed(&value.copy_digest)
}

fn decode_verification(
    decoder: &mut Decoder<'_>,
) -> Result<VerifyBackupCopy, MetadataCommandCodecError> {
    let value = VerifyBackupCopy {
        backup_id: BackupId::from_bytes(decoder.identifier()?)?,
        destination_id: BackupDestinationId::from_bytes(decoder.identifier()?)?,
        provider_generation: decoder.u64()?,
        copy_digest: decoder.fixed()?,
    };
    validate_generation(value.provider_generation)?;
    Ok(value)
}

const fn failure_relationship_code(value: BackupFailureRelationship) -> u8 {
    match value {
        BackupFailureRelationship::Unknown => 1,
        BackupFailureRelationship::Overlapping => 2,
        BackupFailureRelationship::Independent => 3,
    }
}

fn decode_failure_relationship(
    value: u8,
) -> Result<BackupFailureRelationship, MetadataCommandCodecError> {
    match value {
        1 => Ok(BackupFailureRelationship::Unknown),
        2 => Ok(BackupFailureRelationship::Overlapping),
        3 => Ok(BackupFailureRelationship::Independent),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}

fn validate_backup(value: &RecordMetadataBackup) -> Result<(), MetadataCommandCodecError> {
    if value.last_log_index == 0
        || value.last_log_term == 0
        || value.state_revision.get() == 0
        || value.schema_version == 0
        || value.source_byte_length == 0
        || value.encrypted_byte_length == 0
        || validate_claim(value.claim).is_err()
        || value.initial_copy.byte_length != value.encrypted_byte_length
        || value.initial_copy.copy_digest != value.encrypted_digest
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_claim(value: MetadataBackupRunClaim) -> Result<(), MetadataCommandCodecError> {
    if value.claim_generation == 0 || value.worker_incarnation == 0 || value.fence == 0 {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_completion(
    value: MetadataBackupRunCompletion,
) -> Result<(), MetadataCommandCodecError> {
    let result_digest = match value {
        MetadataBackupRunCompletion::Protected { result_digest }
        | MetadataBackupRunCompletion::Incomplete { result_digest } => result_digest,
    };
    if result_digest == [0; 32] {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_initial_copy(value: &InitialBackupCopy) -> Result<(), MetadataCommandCodecError> {
    validate_generation(value.provider_generation)?;
    if value.byte_length == 0
        || value.object_reference.is_empty()
        || value.object_reference.len() > MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES
        || value.object_reference.chars().any(char::is_control)
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_copy(value: &RecordBackupCopy) -> Result<(), MetadataCommandCodecError> {
    validate_generation(value.provider_generation)?;
    if value.byte_length == 0
        || value.object_reference.is_empty()
        || value.object_reference.len() > MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES
        || value.object_reference.chars().any(char::is_control)
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_generation(value: u64) -> Result<(), MetadataCommandCodecError> {
    if value == 0 {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_schedule(
    value: ConfigureMetadataBackupSchedule,
) -> Result<(), MetadataCommandCodecError> {
    if value.interval.get() == 0
        || value.retained_generations == 0
        || value.minimum_verified_copies == 0
        || value.minimum_independent_copies > value.minimum_verified_copies
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_run(value: QueueMetadataBackupRun) -> Result<(), MetadataCommandCodecError> {
    if value.expected_schedule_sequence == 0 {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}
