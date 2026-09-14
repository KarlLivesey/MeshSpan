// SPDX-License-Identifier: GPL-2.0-only

//! Bounded retirement witnesses and exact provider-reclamation receipts.

use meshspan_contracts::{
    BackupDeleteReceipt, BackupObjectIdentity, BackupObjectReceipt, BackupObjectReference,
};
use meshspan_domain::{BackupDestinationId, BackupId, OperationId, Revision};

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{
    AuthoritativeCommand, RecordBackupReclamation, RetireAbandonedBackupCopy, RetireMetadataBackup,
};

const RETIRE_BACKUP: u16 = 73;
const RECORD_RECLAMATION: u16 = 74;
const RETIRE_ABANDONED_COPY: u16 = 124;

#[cfg(test)]
#[path = "backup_retention_tests.rs"]
mod tests;

pub(super) fn is_command_kind(kind: u16) -> bool {
    matches!(
        kind,
        RETIRE_BACKUP | RECORD_RECLAMATION | RETIRE_ABANDONED_COPY
    )
}

pub(super) fn encode_command(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::RetireAbandonedBackupCopy(value) => {
            validate_abandoned(value)?;
            encoder.u16(RETIRE_ABANDONED_COPY)?;
            encoder.u64(value.expected_run_revision.get())?;
            let receipt = &value.receipt;
            encoder.identifier(receipt.operation_id.as_bytes())?;
            encoder.identifier(receipt.object.backup_id.as_bytes())?;
            encoder.identifier(receipt.object.destination_id.as_bytes())?;
            encoder.u64(receipt.object.provider_generation)?;
            encoder.u64(receipt.object.byte_length)?;
            encoder.fixed(&receipt.object.digest)?;
            encoder.text(
                receipt.object_reference.as_str(),
                crate::MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES,
            )?;
        }
        AuthoritativeCommand::RetireMetadataBackup(value) => {
            validate_retirement(value)?;
            encoder.u16(RETIRE_BACKUP)?;
            encoder.identifier(value.backup_id.as_bytes())?;
            encoder.u64(value.expected_backup_revision.get())?;
            encoder.u64(value.expected_schedule_sequence)?;
            encoder.u16(
                u16::try_from(value.retained_backups.len())
                    .map_err(|_| MetadataCommandCodecError::Invalid)?,
            )?;
            for backup_id in &value.retained_backups {
                encoder.identifier(backup_id.as_bytes())?;
            }
        }
        AuthoritativeCommand::RecordBackupReclamation(value) => {
            let receipt = value.receipt;
            validate_receipt(receipt)?;
            encoder.u16(RECORD_RECLAMATION)?;
            encoder.identifier(receipt.operation_id.as_bytes())?;
            encoder.identifier(receipt.object.backup_id.as_bytes())?;
            encoder.identifier(receipt.object.destination_id.as_bytes())?;
            encoder.u64(receipt.object.provider_generation)?;
            encoder.u64(receipt.object.byte_length)?;
            encoder.fixed(&receipt.object.digest)?;
            encoder.u64(receipt.retirement_revision.get())?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decode_command(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    match kind {
        RETIRE_ABANDONED_COPY => {
            let value = RetireAbandonedBackupCopy {
                expected_run_revision: Revision::new(decoder.u64()?),
                receipt: BackupObjectReceipt {
                    operation_id: OperationId::from_bytes(decoder.identifier()?)?,
                    object: BackupObjectIdentity {
                        backup_id: BackupId::from_bytes(decoder.identifier()?)?,
                        destination_id: BackupDestinationId::from_bytes(decoder.identifier()?)?,
                        provider_generation: decoder.u64()?,
                        byte_length: decoder.u64()?,
                        digest: decoder.fixed()?,
                    },
                    object_reference: BackupObjectReference::new(
                        decoder.text(crate::MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES)?,
                    )
                    .map_err(|_| MetadataCommandCodecError::Invalid)?,
                },
            };
            validate_abandoned(&value)?;
            Ok(AuthoritativeCommand::RetireAbandonedBackupCopy(value))
        }
        RETIRE_BACKUP => {
            let backup_id = BackupId::from_bytes(decoder.identifier()?)?;
            let expected_backup_revision = Revision::new(decoder.u64()?);
            let expected_schedule_sequence = decoder.u64()?;
            let count = usize::from(decoder.u16()?);
            if count == 0 || count > crate::MAXIMUM_BACKUP_RETENTION_WITNESSES {
                return Err(MetadataCommandCodecError::Invalid);
            }
            let mut retained_backups = Vec::with_capacity(count);
            for _ in 0..count {
                retained_backups.push(BackupId::from_bytes(decoder.identifier()?)?);
            }
            let value = RetireMetadataBackup {
                backup_id,
                expected_backup_revision,
                expected_schedule_sequence,
                retained_backups,
            };
            validate_retirement(&value)?;
            Ok(AuthoritativeCommand::RetireMetadataBackup(value))
        }
        RECORD_RECLAMATION => {
            let receipt = BackupDeleteReceipt {
                operation_id: OperationId::from_bytes(decoder.identifier()?)?,
                object: BackupObjectIdentity {
                    backup_id: BackupId::from_bytes(decoder.identifier()?)?,
                    destination_id: BackupDestinationId::from_bytes(decoder.identifier()?)?,
                    provider_generation: decoder.u64()?,
                    byte_length: decoder.u64()?,
                    digest: decoder.fixed()?,
                },
                retirement_revision: Revision::new(decoder.u64()?),
            };
            validate_receipt(receipt)?;
            Ok(AuthoritativeCommand::RecordBackupReclamation(
                RecordBackupReclamation { receipt },
            ))
        }
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn validate_retirement(value: &RetireMetadataBackup) -> Result<(), MetadataCommandCodecError> {
    if value.expected_backup_revision.get() == 0
        || value.expected_schedule_sequence == 0
        || value.retained_backups.is_empty()
        || value.retained_backups.len() > crate::MAXIMUM_BACKUP_RETENTION_WITNESSES
        || !value
            .retained_backups
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || value.retained_backups.contains(&value.backup_id)
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(())
}

fn validate_receipt(receipt: BackupDeleteReceipt) -> Result<(), MetadataCommandCodecError> {
    if receipt.object.provider_generation == 0
        || receipt.object.byte_length == 0
        || receipt.retirement_revision.get() == 0
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(())
}

fn validate_abandoned(value: &RetireAbandonedBackupCopy) -> Result<(), MetadataCommandCodecError> {
    if value.expected_run_revision.get() == 0
        || value.receipt.object.provider_generation == 0
        || value.receipt.object.byte_length == 0
        || value.receipt.object.digest == [0; 32]
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}
