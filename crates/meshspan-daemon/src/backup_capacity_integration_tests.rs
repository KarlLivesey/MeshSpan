// SPDX-License-Identifier: GPL-2.0-only

//! Real directory backups and shard reservations consuming one folder allowance.

use std::io::Cursor;
use std::path::Path;

use meshspan_backup::DirectoryBackupProvider;
use meshspan_contracts::{
    BackupCapacityBudget, BackupDeleteRequest, BackupObjectIdentity, BackupProvider,
    BackupStoreRequest, ContractError, ContractVersion, RequestContext, ReservationClass,
    ReserveStorageRequest, StoragePermitMacKey, StorageProvider,
};
use meshspan_domain::{
    BackupDestinationId, BackupId, EntropyError, MeshId, OperationId, RandomSource, Revision,
    TargetId, UnixMicros,
};
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, SharedStorageProvider,
    StoragePermitVerifier, UsageLimit,
};
use sha2::{Digest, Sha256};

type Target = SharedStorageProvider<FolderShardStore>;
const PAYLOAD: &[u8] = b"six hundred is not needed: exact bytes suffice";

#[test]
fn deletion_retry_recovers_capacity_release_interrupted_after_provider_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut target = target(directory.path(), PAYLOAD.len() as u64)?;
    let mut provider =
        backup(directory.path(), 3)?.with_capacity_budget(Box::new(FailRelease(target.clone())))?;
    let store = request(3, 5)?;
    let stored = provider.store_exact(store, &mut Cursor::new(PAYLOAD), UnixMicros::new(2))?;
    let mut deletion = BackupDeleteRequest {
        context: context(9)?,
        object: store.object,
        object_reference: stored.object_reference,
        retirement_revision: Revision::new(1),
    };
    assert!(
        provider
            .delete_exact(&deletion, UnixMicros::new(4))
            .is_err()
    );
    assert_eq!(
        StorageProvider::reserve(&mut target, shard_request(7, 1)?),
        Err(ContractError::ResourceExhausted)
    );
    drop(provider);
    let mut reopened =
        backup(directory.path(), 3)?.with_capacity_budget(Box::new(target.clone()))?;
    deletion.context.deadline = UnixMicros::new(200);
    reopened.delete_exact(&deletion, UnixMicros::new(101))?;
    reopened.delete_exact(&deletion, UnixMicros::new(102))?;
    StorageProvider::reserve(&mut target, shard_request(10, PAYLOAD.len() as u64)?)?;
    assert_eq!(
        StorageProvider::reserve(&mut target, shard_request(11, 1)?),
        Err(ContractError::ResourceExhausted)
    );
    Ok(())
}

/// Inject exactly the boundary after provider deletion, before durable target accounting.
struct FailRelease(Target);

impl BackupCapacityBudget for FailRelease {
    fn reserve(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        BackupCapacityBudget::reserve(&mut self.0, object)
    }
    fn commit(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        BackupCapacityBudget::commit(&mut self.0, object)
    }
    fn reconcile_existing(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        BackupCapacityBudget::reconcile_existing(&mut self.0, object)
    }
    fn release(&mut self, _object: BackupObjectIdentity) -> Result<(), ContractError> {
        Err(ContractError::Unavailable)
    }
}

#[test]
fn backup_destinations_and_shard_writes_cannot_each_spend_the_folder_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let limit = PAYLOAD.len() as u64 * 2;
    let mut target = target(directory.path(), limit)?;
    let mut first = backup(directory.path(), 3)?.with_capacity_budget(Box::new(target.clone()))?;
    let mut second = backup(directory.path(), 4)?.with_capacity_budget(Box::new(target.clone()))?;
    let first_request = request(3, 5)?;
    let first_receipt =
        first.store_exact(first_request, &mut Cursor::new(PAYLOAD), UnixMicros::new(2))?;
    let second_request = request(4, 6)?;
    second.store_exact(
        second_request,
        &mut Cursor::new(PAYLOAD),
        UnixMicros::new(2),
    )?;
    assert_eq!(
        StorageProvider::reserve(&mut target, shard_request(7, 1)?),
        Err(ContractError::ResourceExhausted)
    );
    let mut untouched = Cursor::new(PAYLOAD);
    assert_eq!(
        second.store_exact(request(4, 8)?, &mut untouched, UnixMicros::new(3)),
        Err(ContractError::ResourceExhausted)
    );
    assert_eq!(untouched.position(), 0);
    let deletion = BackupDeleteRequest {
        context: context(9)?,
        object: first_request.object,
        object_reference: first_receipt.object_reference,
        retirement_revision: Revision::new(1),
    };
    first.delete_exact(&deletion, UnixMicros::new(4))?;
    first.delete_exact(&deletion, UnixMicros::new(5))?;
    StorageProvider::reserve(&mut target, shard_request(10, PAYLOAD.len() as u64)?)?;
    assert_eq!(
        StorageProvider::reserve(&mut target, shard_request(11, 1)?),
        Err(ContractError::ResourceExhausted)
    );
    Ok(())
}

#[test]
fn failed_backup_keeps_its_hold_and_exact_retry_after_provider_restart_uses_it()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut target = target(directory.path(), PAYLOAD.len() as u64)?;
    let store = request(3, 12)?;
    let mut provider =
        backup(directory.path(), 3)?.with_capacity_budget(Box::new(target.clone()))?;
    assert_eq!(
        provider.store_exact(store, &mut Cursor::new(b"short"), UnixMicros::new(2)),
        Err(ContractError::Corrupt)
    );
    drop(provider);
    assert_eq!(
        StorageProvider::reserve(&mut target, shard_request(13, 1)?),
        Err(ContractError::ResourceExhausted)
    );
    let mut provider =
        backup(directory.path(), 3)?.with_capacity_budget(Box::new(target.clone()))?;
    let receipt = provider.store_exact(store, &mut Cursor::new(PAYLOAD), UnixMicros::new(3))?;
    assert_eq!(receipt.object, store.object);
    assert_eq!(
        provider.store_exact(store, &mut Cursor::new(PAYLOAD), UnixMicros::new(4))?,
        receipt
    );
    let deletion = BackupDeleteRequest {
        context: context(14)?,
        object: store.object,
        object_reference: receipt.object_reference,
        retirement_revision: Revision::new(1),
    };
    provider.delete_exact(&deletion, UnixMicros::new(5))?;
    StorageProvider::reserve(&mut target, shard_request(15, PAYLOAD.len() as u64)?)?;
    Ok(())
}

#[test]
fn existing_backup_is_charged_on_attach_even_when_larger_than_current_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut target = target(directory.path(), 1)?;
    let mut provider = backup(directory.path(), 3)?;
    provider.store_exact(
        request(3, 16)?,
        &mut Cursor::new(PAYLOAD),
        UnixMicros::new(2),
    )?;
    drop(provider);
    let _provider = backup(directory.path(), 3)?.with_capacity_budget(Box::new(target.clone()))?;
    assert_eq!(
        StorageProvider::reserve(&mut target, shard_request(17, 1)?),
        Err(ContractError::ResourceExhausted)
    );
    Ok(())
}

fn target(root: &Path, limit: u64) -> Result<Target, Box<dyn std::error::Error>> {
    let folder_path = root.join("storage");
    std::fs::create_dir(&folder_path)?;
    let mesh_id = MeshId::from_bytes([1; 16])?;
    let folder = RegisteredFolder::register_new(
        &folder_path,
        FolderRegistration {
            mesh_id,
            target_id: TargetId::from_bytes([2; 16])?,
            generation: 1,
            usage_limit: UsageLimit::Bytes(limit),
        },
        &mut Random,
    )?;
    Ok(SharedStorageProvider::new(FolderShardStore::open(
        folder,
        &root.join("state"),
        CapacityPolicy {
            usage_limit: UsageLimit::Bytes(limit),
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            mesh_id,
            1,
            Revision::new(1),
            StoragePermitMacKey::from_bytes([42; 32])?,
        )?,
        UnixMicros::new(1),
        &mut Random,
    )?))
}

fn backup(
    root: &Path,
    destination: u8,
) -> Result<DirectoryBackupProvider, Box<dyn std::error::Error>> {
    Ok(DirectoryBackupProvider::open(
        &root.join("storage"),
        BackupDestinationId::from_bytes([destination; 16])?,
        1,
        1_000_000,
        UnixMicros::new(1),
    )?)
}

fn request(destination: u8, id: u8) -> Result<BackupStoreRequest, Box<dyn std::error::Error>> {
    Ok(BackupStoreRequest {
        context: context(id)?,
        object: BackupObjectIdentity {
            backup_id: BackupId::from_bytes([id; 16])?,
            destination_id: BackupDestinationId::from_bytes([destination; 16])?,
            provider_generation: 1,
            byte_length: PAYLOAD.len() as u64,
            digest: Sha256::digest(PAYLOAD).into(),
        },
    })
}

fn context(id: u8) -> Result<RequestContext, Box<dyn std::error::Error>> {
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([id; 16])?,
        deadline: UnixMicros::new(100),
        expected_revision: Some(Revision::new(1)),
    })
}

fn shard_request(id: u8, bytes: u64) -> Result<ReserveStorageRequest, Box<dyn std::error::Error>> {
    Ok(ReserveStorageRequest {
        context: context(id)?,
        target_id: TargetId::from_bytes([2; 16])?,
        target_generation: 1,
        class: ReservationClass::ForegroundWrite,
        bytes,
        observed_at: UnixMicros::new(2),
    })
}

struct Random;
impl RandomSource for Random {
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), EntropyError> {
        bytes.fill(42);
        Ok(())
    }
}
