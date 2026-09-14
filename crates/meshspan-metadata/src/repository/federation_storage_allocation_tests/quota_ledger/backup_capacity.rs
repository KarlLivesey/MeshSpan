// SPDX-License-Identifier: GPL-2.0-only

use super::{QuotaFixture, assert_usage, request, shard};
use crate::{
    FederatedBackupCapacityState, FederationStorageQuotaDisposition, FederationStorageQuotaError,
    LocalDatabase,
};
use meshspan_contracts::BackupObjectIdentity;
use meshspan_domain::{BackupDestinationId, BackupId, UnixMicros};

#[test]
fn backups_and_shards_share_one_budget_across_retries_and_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = QuotaFixture::open()?;
    let object = object(101, 30)?;
    let allocation = fixture.allocation.allocation_id();
    let authority = fixture.authority(30)?;
    assert_eq!(
        fixture
            .local
            .reserve_federated_backup_capacity(authority, object)?,
        FederationStorageQuotaDisposition::Applied
    );
    assert_eq!(
        fixture
            .local
            .reserve_federated_backup_capacity(authority, object)?,
        FederationStorageQuotaDisposition::Replayed
    );
    assert_usage(&fixture, 50, 0, 30)?;
    let excessive = request(102, 103, fixture.authority(21)?, shard(104))?;
    assert!(matches!(
        fixture
            .local
            .reserve_federated_storage_write(fixture.authority(21)?, excessive),
        Err(FederationStorageQuotaError::CapacityExceeded)
    ));
    let fitting = request(105, 106, fixture.authority(20)?, shard(107))?;
    fixture
        .local
        .reserve_federated_storage_write(fixture.authority(20)?, fitting)?;
    assert_usage(&fixture, 50, 0, 50)?;
    fixture
        .local
        .commit_federated_backup_capacity(allocation, object, UnixMicros::new(16))?;
    assert_usage(&fixture, 50, 30, 20)?;
    assert_eq!(
        fixture
            .local
            .commit_federated_backup_capacity(allocation, object, UnixMicros::new(17))?,
        FederationStorageQuotaDisposition::Replayed
    );
    assert!(matches!(
        fixture
            .local
            .cancel_federated_backup_capacity(allocation, object, UnixMicros::new(17)),
        Err(FederationStorageQuotaError::Conflict)
    ));
    let file_path = fixture.local_path.clone();
    let node = fixture.repository_ids.provider_node;
    drop(fixture.local);
    fixture.local = LocalDatabase::open(&file_path, node, UnixMicros::new(18))?;
    assert_eq!(
        fixture
            .local
            .federated_backup_capacity_state(allocation, object)?,
        Some(FederatedBackupCapacityState::Stored)
    );
    assert_usage(&fixture, 50, 30, 20)?;
    fixture
        .local
        .release_federated_backup_capacity(allocation, object, UnixMicros::new(19))?;
    assert_eq!(
        fixture
            .local
            .release_federated_backup_capacity(allocation, object, UnixMicros::new(20))?,
        FederationStorageQuotaDisposition::Replayed
    );
    assert_usage(&fixture, 50, 0, 20)?;
    assert!(matches!(
        fixture
            .local
            .reserve_federated_backup_capacity(authority, object),
        Err(FederationStorageQuotaError::Conflict)
    ));
    Ok(())
}

#[test]
fn held_objects_require_exact_recovery_and_changed_identity_never_releases_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = QuotaFixture::open()?;
    let first = object(101, 20)?;
    let second = object(102, 20)?;
    let allocation = fixture.allocation.allocation_id();
    fixture
        .local
        .reserve_federated_backup_capacity(fixture.authority(20)?, first)?;
    fixture
        .local
        .reserve_federated_backup_capacity(fixture.authority(20)?, second)?;
    assert_eq!(
        fixture.local.pending_federated_backup_capacity(
            allocation,
            first.destination_id,
            1,
            None
        )?,
        vec![first, second]
    );
    assert_eq!(
        fixture.local.pending_federated_backup_capacity(
            allocation,
            first.destination_id,
            1,
            Some(first.backup_id)
        )?,
        vec![second]
    );
    assert!(
        fixture
            .local
            .pending_federated_backup_capacity(allocation, first.destination_id, 2, None)?
            .is_empty()
    );
    for altered in [
        BackupObjectIdentity {
            byte_length: 19,
            ..first
        },
        BackupObjectIdentity {
            digest: [111; 32],
            ..first
        },
    ] {
        assert!(matches!(
            fixture.local.reserve_federated_backup_capacity(
                fixture.authority(altered.byte_length)?,
                altered
            ),
            Err(FederationStorageQuotaError::Conflict)
        ));
        assert!(matches!(
            fixture.local.cancel_federated_backup_capacity(
                allocation,
                altered,
                UnixMicros::new(20)
            ),
            Err(FederationStorageQuotaError::Conflict)
        ));
    }
    // Passage of time alone makes no accounting transition; a held object still consumes space.
    assert_eq!(
        fixture
            .local
            .federated_backup_capacity_state(allocation, first)?,
        Some(FederatedBackupCapacityState::Held)
    );
    assert!(matches!(
        fixture
            .local
            .release_federated_backup_capacity(allocation, first, UnixMicros::new(999)),
        Err(FederationStorageQuotaError::Conflict)
    ));
    assert_usage(&fixture, 50, 0, 40)?;
    fixture
        .local
        .cancel_federated_backup_capacity(allocation, first, UnixMicros::new(20))?;
    assert_eq!(
        fixture
            .local
            .cancel_federated_backup_capacity(allocation, first, UnixMicros::new(21))?,
        FederationStorageQuotaDisposition::Replayed
    );
    assert_usage(&fixture, 50, 0, 20)?;
    fixture
        .local
        .reserve_federated_backup_capacity(fixture.authority(20)?, first)?;
    assert_usage(&fixture, 50, 0, 40)
}

#[test]
fn shard_holds_fence_backups_and_failed_reservations_leave_no_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = QuotaFixture::open()?;
    let shard_request = request(105, 106, fixture.authority(40)?, shard(107))?;
    fixture
        .local
        .reserve_federated_storage_write(fixture.authority(40)?, shard_request)?;
    let object = object(101, 11)?;
    let allocation = fixture.allocation.allocation_id();
    assert!(matches!(
        fixture
            .local
            .reserve_federated_backup_capacity(fixture.authority(11)?, object),
        Err(FederationStorageQuotaError::CapacityExceeded)
    ));
    assert_eq!(
        fixture
            .local
            .federated_backup_capacity_state(allocation, object)?,
        None
    );
    assert_usage(&fixture, 50, 0, 40)?;
    assert!(matches!(
        fixture
            .local
            .reserve_federated_backup_capacity(fixture.authority(10)?, object),
        Err(FederationStorageQuotaError::Invalid)
    ));
    assert_eq!(
        fixture
            .local
            .federated_backup_capacity_state(allocation, object)?,
        None
    );
    Ok(())
}

fn object(marker: u8, length: u64) -> Result<BackupObjectIdentity, Box<dyn std::error::Error>> {
    Ok(BackupObjectIdentity {
        backup_id: BackupId::from_bytes([marker; 16])?,
        destination_id: BackupDestinationId::from_bytes([100; 16])?,
        provider_generation: 1,
        byte_length: length,
        digest: [marker; 32],
    })
}
