// SPDX-License-Identifier: GPL-2.0-only

use meshspan_backup::BackupSourceManifest;
use meshspan_contracts::{
    BackupDeleteReceipt, BackupDeleteRequest, BackupObjectReceipt, BackupProvider,
    BackupReadReceipt, BackupReadRequest, BackupStoreRequest, BackupVerifyRequest, ContractError,
    ContractKind, ContractLimits, ContractVersion, ImplementationDescriptor,
};
use meshspan_domain::{
    BackupDestinationId, BackupId, MeshId, OperationId, PartitionId, Revision, UnixMicros,
};
use meshspan_metadata::{
    BackupCopyRecord, BackupCopyState, MetadataBackupRecord, MetadataBackupState,
};
use meshspan_secret_envelope::WrappingPrivateKey;
use tempfile::tempdir;

use crate::backup_restore_readiness::validate_catalogue;
use crate::{
    BackupRestoreReadinessAuthority, BackupRestoreReadinessPaths, BackupRestoreReadinessRequest,
    MetadataBackupRestoreReadiness,
};

#[test]
fn exact_verified_catalogue_reconstructs_authenticated_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let (backup, copy, destination_id) = records()?;
    let manifest = validate_catalogue(backup, &copy, destination_id)?;
    assert_eq!(manifest.partition.backup_id, backup.backup_id);
    assert_eq!(manifest.partition.applied_position.index, 12);
    assert_eq!(manifest.partition.applied_position.term, 3);
    assert_eq!(manifest.encrypted.digest, backup.encrypted_digest);
    Ok(())
}

#[test]
fn changed_manifest_or_unverified_copy_is_never_restore_ready()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut backup, mut copy, destination_id) = records()?;
    backup.manifest_digest[0] ^= 1;
    assert!(validate_catalogue(backup, &copy, destination_id).is_err());
    let (backup, _, _) = records()?;
    copy.state = BackupCopyState::Stored;
    assert!(validate_catalogue(backup, &copy, destination_id).is_err());
    Ok(())
}

#[test]
fn failed_recovery_removes_every_staging_file() -> Result<(), Box<dyn std::error::Error>> {
    let (backup, copy, destination_id) = records()?;
    let authority = MemoryAuthority { backup, copy };
    let provider =
        InvalidContainerProvider(vec![8; usize::try_from(backup.encrypted_byte_length)?]);
    let directory = tempdir()?;
    let encrypted_staging = directory.path().join("encrypted.staging");
    let plaintext_staging = directory.path().join("plaintext.staging");
    let restored_database = directory.path().join("restored.sqlite3");
    let paths = BackupRestoreReadinessPaths {
        encrypted_staging: &encrypted_staging,
        plaintext_staging: &plaintext_staging,
        restored_database: &restored_database,
    };
    let result = MetadataBackupRestoreReadiness::new(&authority).check(
        &provider,
        &BackupRestoreReadinessRequest {
            backup_id: backup.backup_id,
            destination_id,
            operation_id: OperationId::from_bytes([9; 16])?,
            deadline: UnixMicros::new(100),
            checked_at: UnixMicros::new(20),
            recovery_key: &WrappingPrivateKey::from_bytes([10; 32])?,
            paths,
        },
    );
    assert!(result.is_err());
    assert!(!paths.encrypted_staging.exists());
    assert!(!paths.plaintext_staging.exists());
    assert!(!paths.restored_database.exists());
    Ok(())
}

struct MemoryAuthority {
    backup: MetadataBackupRecord,
    copy: BackupCopyRecord,
}

impl BackupRestoreReadinessAuthority for MemoryAuthority {
    fn metadata_backup(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRecord>, meshspan_metadata::RepositoryError> {
        Ok((backup_id == self.backup.backup_id).then_some(self.backup))
    }

    fn backup_copy(
        &self,
        backup_id: BackupId,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupCopyRecord>, meshspan_metadata::RepositoryError> {
        Ok(
            (backup_id == self.copy.backup_id && destination_id == self.copy.destination_id)
                .then(|| self.copy.clone()),
        )
    }
}

struct InvalidContainerProvider(Vec<u8>);

impl BackupProvider for InvalidContainerProvider {
    fn describe(&self) -> ImplementationDescriptor {
        ImplementationDescriptor {
            implementation_id: "invalid-container-test",
            contract: ContractKind::BackupProvider,
            versions: &[ContractVersion::V1_0],
            limits: ContractLimits {
                maximum_control_bytes: 1_024,
                maximum_items: 1,
                maximum_concurrency: 1,
            },
        }
    }

    fn store_exact(
        &mut self,
        _request: BackupStoreRequest,
        _source: &mut dyn std::io::Read,
        _observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        Err(ContractError::InternalContract)
    }

    fn read_exact(
        &self,
        request: &BackupReadRequest,
        destination: &mut dyn std::io::Write,
        _observed_at: UnixMicros,
    ) -> Result<BackupReadReceipt, ContractError> {
        destination
            .write_all(&self.0)
            .map_err(|_| ContractError::Unavailable)?;
        Ok(BackupReadReceipt {
            operation_id: request.context.operation_id,
            byte_length: self.0.len() as u64,
            digest: request.object.digest,
        })
    }

    fn verify_exact(
        &self,
        _request: &BackupVerifyRequest,
        _observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        Err(ContractError::InternalContract)
    }

    fn delete_exact(
        &mut self,
        _request: &BackupDeleteRequest,
        _observed_at: UnixMicros,
    ) -> Result<BackupDeleteReceipt, ContractError> {
        Err(ContractError::InternalContract)
    }
}

fn records()
-> Result<(MetadataBackupRecord, BackupCopyRecord, BackupDestinationId), Box<dyn std::error::Error>>
{
    let backup_id = BackupId::from_bytes([1; 16])?;
    let destination_id = BackupDestinationId::from_bytes([2; 16])?;
    let source = BackupSourceManifest {
        backup_id,
        partition_id: PartitionId::from_bytes([3; 16])?,
        mesh_id: MeshId::from_bytes([4; 16])?,
        last_log_index: 12,
        last_log_term: 3,
        state_revision: 9,
        schema_version: 81,
        byte_length: 4_096,
        digest: [5; 32],
        created_at: UnixMicros::new(10),
    };
    let backup = MetadataBackupRecord {
        backup_id,
        partition_id: source.partition_id,
        mesh_id: source.mesh_id,
        last_log_index: source.last_log_index,
        last_log_term: source.last_log_term,
        state_revision: Revision::new(source.state_revision),
        schema_version: source.schema_version,
        source_byte_length: source.byte_length,
        source_digest: source.digest,
        manifest_digest: source.catalogue_digest(),
        encrypted_byte_length: 4_500,
        encrypted_digest: [6; 32],
        state: MetadataBackupState::Verified,
        created_at: source.created_at,
        verified_at: Some(UnixMicros::new(11)),
        revision: Revision::new(7),
    };
    let copy = BackupCopyRecord {
        backup_id,
        destination_id,
        provider_generation: 1,
        object_reference: "backup-object".to_owned(),
        byte_length: backup.encrypted_byte_length,
        copy_digest: backup.encrypted_digest,
        state: BackupCopyState::Verified,
        stored_at: UnixMicros::new(11),
        verified_at: Some(UnixMicros::new(12)),
        revision: Revision::new(8),
    };
    Ok((backup, copy, destination_id))
}
