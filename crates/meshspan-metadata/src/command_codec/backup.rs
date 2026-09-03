// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BackupDestinationId, BackupId, ComponentInstanceId, MeshId, PartitionId, Revision, TargetId,
};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    BackupDestinationBinding, BackupFailureRelationship, ConfigureBackupDestination,
    MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES, RecordBackupCopy, RecordMetadataBackup, RecordName,
    VerifyBackupCopy,
};

pub(super) const CONFIGURE_BACKUP_DESTINATION: u16 = 63;
pub(super) const RECORD_METADATA_BACKUP: u16 = 64;
pub(super) const RECORD_BACKUP_COPY: u16 = 65;
pub(super) const VERIFY_BACKUP_COPY: u16 = 66;
const MAXIMUM_NAME_BYTES: usize = 128;

pub(super) const fn is_command_kind(kind: u16) -> bool {
    matches!(
        kind,
        CONFIGURE_BACKUP_DESTINATION
            | RECORD_METADATA_BACKUP
            | RECORD_BACKUP_COPY
            | VERIFY_BACKUP_COPY
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
        crate::AuthoritativeCommand::RecordMetadataBackup(value) => {
            encode_backup(encoder, *value)?;
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

fn encode_destination(
    encoder: &mut Encoder,
    value: &ConfigureBackupDestination,
) -> Result<(), MetadataCommandCodecError> {
    validate_generation(value.binding.provider_generation())?;
    encoder.u16(CONFIGURE_BACKUP_DESTINATION)?;
    encoder.identifier(value.destination_id.as_bytes())?;
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
        name,
        binding,
        failure_relationship: decode_failure_relationship(decoder.u8()?)?,
        failure_evidence_digest: decoder.fixed()?,
        enabled: decoder.bool()?,
    })
}

fn encode_backup(
    encoder: &mut Encoder,
    value: RecordMetadataBackup,
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
    encoder.fixed(&value.encrypted_digest)
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
    };
    validate_backup(value)?;
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

fn validate_backup(value: RecordMetadataBackup) -> Result<(), MetadataCommandCodecError> {
    if value.last_log_index == 0
        || value.last_log_term == 0
        || value.state_revision.get() == 0
        || value.schema_version == 0
        || value.source_byte_length == 0
        || value.encrypted_byte_length == 0
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
