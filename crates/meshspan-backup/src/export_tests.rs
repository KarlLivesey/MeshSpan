// SPDX-License-Identifier: GPL-2.0-only

use crate::VerifiedBackupExport;
use meshspan_contracts::{
    BackupObjectIdentity, BackupObjectReference, BackupReadReceipt, BackupReadRequest,
    ContractVersion, RequestContext,
};
use meshspan_domain::{BackupDestinationId, BackupId, OperationId, Revision, UnixMicros};
use sha2::{Digest, Sha256};
use std::io::Write;

fn request(bytes: &[u8]) -> Result<BackupReadRequest, Box<dyn std::error::Error>> {
    Ok(BackupReadRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([1; 16])?,
            deadline: UnixMicros::new(100),
            expected_revision: Some(Revision::new(1)),
        },
        object: BackupObjectIdentity {
            backup_id: BackupId::from_bytes([2; 16])?,
            destination_id: BackupDestinationId::from_bytes([3; 16])?,
            provider_generation: 1,
            byte_length: u64::try_from(bytes.len())?,
            digest: Sha256::digest(bytes).into(),
        },
        object_reference: BackupObjectReference::new("opaque-copy".to_owned())?,
    })
}

fn receipt(request: &BackupReadRequest) -> BackupReadReceipt {
    BackupReadReceipt {
        operation_id: request.context.operation_id,
        byte_length: request.object.byte_length,
        digest: request.object.digest,
    }
}

#[test]
fn verified_export_preserves_bytes_across_frame_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    for size in [1, 65_535, 65_536, 65_537, 200_000] {
        let bytes = vec![42; size];
        let request = request(&bytes)?;
        let mut writer = VerifiedBackupExport::new(Vec::new(), &request, UnixMicros::new(1))?;
        for chunk in bytes.chunks(17_000) {
            writer.write_all(chunk)?;
            writer.flush()?;
        }
        assert_eq!(writer.finish(receipt(&request))?, bytes);
    }
    Ok(())
}

#[test]
fn failed_export_never_releases_a_complete_object_even_when_receipt_lies()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = vec![42; 200_000];
    let request = request(&bytes)?;
    for (source, received) in [
        (&bytes[..bytes.len() - 1], receipt(&request)),
        (&vec![43; bytes.len()][..], receipt(&request)),
        (
            &bytes[..],
            BackupReadReceipt {
                digest: [0; 32],
                ..receipt(&request)
            },
        ),
        (
            &bytes[..],
            BackupReadReceipt {
                byte_length: 1,
                ..receipt(&request)
            },
        ),
        (
            &bytes[..],
            BackupReadReceipt {
                operation_id: OperationId::from_bytes([4; 16])?,
                ..receipt(&request)
            },
        ),
    ] {
        let mut emitted = Vec::new();
        let mut writer = VerifiedBackupExport::new(&mut emitted, &request, UnixMicros::new(1))?;
        writer.write_all(source)?;
        writer.flush()?;
        assert!(writer.finish(received).is_err());
        assert!(emitted.len() < bytes.len());
    }
    Ok(())
}

#[test]
fn excessive_provider_bytes_poison_export_even_if_provider_ignores_error()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = vec![42; 65_537];
    let request = request(&bytes)?;
    let mut emitted = Vec::new();
    let mut writer = VerifiedBackupExport::new(&mut emitted, &request, UnixMicros::new(1))?;
    writer.write_all(&bytes)?;
    assert!(writer.write_all(&[1]).is_err());
    assert!(writer.finish(receipt(&request)).is_err());
    assert_eq!(emitted, bytes[..65_536]);
    Ok(())
}

#[test]
fn retry_discards_only_an_unpublished_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = vec![42; 65_537];
    let request = request(&bytes)?;
    let mut writer = VerifiedBackupExport::new(Vec::new(), &request, UnixMicros::new(1))?;
    writer.write_all(&[99; 1024])?;
    assert!(writer.can_restart());
    writer.restart()?;
    writer.write_all(&bytes)?;
    assert!(!writer.can_restart());
    assert!(writer.restart().is_err());
    assert_eq!(writer.finish(receipt(&request))?, bytes);

    let mut writer = VerifiedBackupExport::new(Vec::new(), &request, UnixMicros::new(1))?;
    assert!(writer.write_all(&vec![0; 65_538]).is_err());
    assert!(!writer.can_restart());
    assert!(writer.restart().is_err());
    Ok(())
}
