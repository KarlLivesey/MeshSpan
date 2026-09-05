// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn backup_retirement_and_reclamation_roundtrip_and_reject_truncation()
-> Result<(), Box<dyn std::error::Error>> {
    let commands = [
        AuthoritativeCommand::RetireMetadataBackup(retirement()?),
        AuthoritativeCommand::RecordBackupReclamation(RecordBackupReclamation {
            receipt: BackupDeleteReceipt {
                operation_id: OperationId::from_bytes([5; 16])?,
                object: BackupObjectIdentity {
                    backup_id: BackupId::from_bytes([1; 16])?,
                    destination_id: BackupDestinationId::from_bytes([6; 16])?,
                    provider_generation: 1,
                    byte_length: 100,
                    digest: [7; 32],
                },
                retirement_revision: Revision::new(8),
            },
        }),
    ];
    for command in commands {
        let mut encoder = Encoder::new(4096);
        assert!(encode_command(&mut encoder, &command)?);
        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes);
        let kind = decoder.u16()?;
        assert_eq!(decode_command(kind, &mut decoder)?, command);
        decoder.finish()?;
        for length in 2..bytes.len() {
            let mut decoder = Decoder::new(&bytes[..length]);
            let kind = decoder.u16()?;
            assert!(decode_command(kind, &mut decoder).is_err());
        }
    }
    Ok(())
}

#[test]
fn retirement_witnesses_are_bounded_unique_sorted_and_exclude_victim()
-> Result<(), Box<dyn std::error::Error>> {
    let original = retirement()?;
    for witnesses in [
        vec![],
        vec![original.backup_id],
        vec![original.retained_backups[0]; 2],
        original.retained_backups.iter().rev().copied().collect(),
        vec![original.retained_backups[0]; crate::MAXIMUM_BACKUP_RETENTION_WITNESSES + 1],
    ] {
        let value = RetireMetadataBackup {
            retained_backups: witnesses,
            ..original.clone()
        };
        assert_eq!(
            validate_retirement(&value),
            Err(MetadataCommandCodecError::Invalid)
        );
    }
    // Reject the claimed allocation before attempting to consume any witness identities.
    let mut encoder = Encoder::new(128);
    encoder.identifier(original.backup_id.as_bytes())?;
    encoder.u64(1)?;
    encoder.u64(1)?;
    encoder.u16(1025)?;
    let bytes = encoder.finish();
    assert_eq!(
        decode_command(RETIRE_BACKUP, &mut Decoder::new(&bytes)),
        Err(MetadataCommandCodecError::Invalid)
    );
    Ok(())
}

fn retirement() -> Result<RetireMetadataBackup, meshspan_domain::IdentifierError> {
    Ok(RetireMetadataBackup {
        backup_id: BackupId::from_bytes([1; 16])?,
        expected_backup_revision: Revision::new(1),
        expected_schedule_sequence: 1,
        retained_backups: vec![
            BackupId::from_bytes([2; 16])?,
            BackupId::from_bytes([3; 16])?,
        ],
    })
}
