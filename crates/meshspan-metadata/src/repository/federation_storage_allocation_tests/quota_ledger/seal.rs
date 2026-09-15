// SPDX-License-Identifier: GPL-2.0-only

use super::{QuotaFixture, assert_usage, completion, request, shard};
use crate::{
    FederationStorageQuotaDisposition as Disposition, FederationStorageQuotaError as Error,
    LocalDatabase,
};
use meshspan_contracts::BackupObjectIdentity;
use meshspan_domain::{BackupDestinationId, BackupId, UnixMicros};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn capacity_seal_retains_inflight_charges_and_blocks_new_shards_and_backups() -> TestResult {
    let mut fixture = QuotaFixture::open()?;
    let authority = fixture.authority(20)?;
    let object = object(100, 20)?;
    let write = request(101, 102, authority, shard(103))?;
    fixture
        .local
        .reserve_federated_backup_capacity(authority, object)?;
    fixture
        .local
        .reserve_federated_storage_write(authority, write)?;
    let first = fixture.local.seal_federated_storage_capacity(authority)?;
    assert_eq!((first.ceiling_bytes, first.sequence), (40, 1));
    assert_eq!(first.provider_node_id, fixture.repository_ids.provider_node);
    assert_eq!(first.target_id, fixture.allocation.target_id());
    assert_eq!(
        first.target_generation,
        fixture.allocation.target_generation()
    );
    assert_eq!(
        fixture.local.seal_federated_storage_capacity(authority)?,
        first
    );

    let smaller = fixture.authority(1)?;
    assert!(matches!(
        fixture
            .local
            .reserve_federated_backup_capacity(smaller, self::object(104, 1)?),
        Err(Error::CapacityExceeded)
    ));
    assert!(matches!(
        fixture
            .local
            .reserve_federated_storage_write(smaller, request(105, 106, smaller, shard(107))?),
        Err(Error::CapacityExceeded)
    ));
    assert_usage(&fixture, 50, 0, 40)?;
    assert_eq!(
        fixture
            .local
            .reserve_federated_backup_capacity(authority, object)?,
        Disposition::Replayed
    );
    assert_eq!(
        fixture
            .local
            .reserve_federated_storage_write(authority, write)?
            .0,
        Disposition::Replayed
    );
    fixture
        .local
        .commit_federated_storage_write(completion(write, 15, 108, 109, 18))?;
    fixture.local.commit_federated_backup_capacity(
        first.allocation_id,
        object,
        UnixMicros::new(18),
    )?;
    assert_usage(&fixture, 50, 35, 0)?;
    let reduced = fixture.local.seal_federated_storage_capacity(authority)?;
    assert_eq!((reduced.ceiling_bytes, reduced.sequence), (35, 2));

    let file_path = fixture.local_path.clone();
    drop(fixture.local);
    fixture.local = LocalDatabase::open_existing(&file_path, UnixMicros::new(19))?;
    assert_eq!(
        fixture.local.seal_federated_storage_capacity(authority)?,
        reduced
    );
    assert!(matches!(
        fixture
            .local
            .reserve_federated_backup_capacity(smaller, self::object(110, 1)?),
        Err(Error::CapacityExceeded)
    ));
    fixture.local.release_federated_backup_capacity(
        first.allocation_id,
        object,
        UnixMicros::new(19),
    )?;
    let final_seal = fixture.local.seal_federated_storage_capacity(authority)?;
    assert_eq!((final_seal.ceiling_bytes, final_seal.sequence), (15, 3));
    assert_usage(&fixture, 50, 15, 0)
}

#[test]
fn empty_capacity_seal_is_durable_and_cannot_be_raised_or_removed() -> TestResult {
    let mut fixture = QuotaFixture::open()?;
    let authority = fixture.authority(1)?;
    let sealed = fixture.local.seal_federated_storage_capacity(authority)?;
    assert_eq!((sealed.ceiling_bytes, sealed.sequence), (0, 1));
    let allocation = sealed.allocation_id.as_bytes();
    for sql in [
        "DELETE FROM local_federation_storage_seals WHERE allocation_id=?1",
        "UPDATE local_federation_storage_seals SET ceiling_bytes=1,sequence=2 WHERE allocation_id=?1",
        "UPDATE local_federation_storage_usage SET reserved_bytes=1 WHERE allocation_id=?1",
    ] {
        assert!(
            fixture
                .local
                .connection()
                .execute(sql, [allocation.as_slice()])
                .is_err()
        );
    }
    assert!(matches!(
        fixture
            .local
            .reserve_federated_backup_capacity(authority, object(111, 1)?),
        Err(Error::CapacityExceeded)
    ));
    assert_eq!(
        fixture.local.seal_federated_storage_capacity(authority)?,
        sealed
    );
    assert_usage(&fixture, 50, 0, 0)
}

#[test]
fn capacity_seal_and_admission_race_has_one_durable_accounting_order() -> TestResult {
    let fixture = QuotaFixture::open()?;
    let authority = fixture.authority(20)?;
    let mut writer = LocalDatabase::open_existing(&fixture.local_path, UnixMicros::new(15))?;
    let mut sealer = LocalDatabase::open_existing(&fixture.local_path, UnixMicros::new(15))?;
    let object = object(112, 20)?;
    let barrier = std::sync::Barrier::new(2);
    let (seal, admitted) = std::thread::scope(|scope| {
        let sealing = scope.spawn(|| {
            barrier.wait();
            sealer.seal_federated_storage_capacity(authority)
        });
        barrier.wait();
        let admitted = writer.reserve_federated_backup_capacity(authority, object);
        (sealing.join(), admitted)
    });
    let seal = seal.map_err(|_| "sealing worker panicked")??;
    match admitted {
        Ok(Disposition::Applied) => {
            assert_eq!(seal.ceiling_bytes, 20);
            assert_usage(&fixture, 50, 0, 20)?;
        }
        Err(Error::CapacityExceeded) => {
            assert_eq!(seal.ceiling_bytes, 0);
            assert_usage(&fixture, 50, 0, 0)?;
        }
        other => return Err(format!("unexpected admission outcome: {other:?}").into()),
    }
    assert!(matches!(
        writer.reserve_federated_backup_capacity(authority, self::object(113, 20)?),
        Err(Error::CapacityExceeded)
    ));
    Ok(())
}

#[test]
fn capacity_seal_failure_rolls_back_identity_and_rejects_wrong_node() -> TestResult {
    let mut fixture = QuotaFixture::open()?;
    let authority = fixture.authority(1)?;
    fixture.local.connection().execute_batch(
        "CREATE TRIGGER inject_seal_failure BEFORE INSERT ON local_federation_storage_seals
         BEGIN SELECT RAISE(ABORT, 'injected seal failure'); END;",
    )?;
    assert!(matches!(
        fixture.local.seal_federated_storage_capacity(authority),
        Err(Error::Database(_))
    ));
    assert!(
        fixture
            .local
            .federated_storage_usage(fixture.allocation.allocation_id())?
            .is_none()
    );
    fixture
        .local
        .connection()
        .execute_batch("DROP TRIGGER inject_seal_failure")?;
    let wrong_node = meshspan_domain::NodeId::from_bytes([114; 16])?;
    let mut wrong = LocalDatabase::open(
        &fixture.directory.path().join("wrong-sealer.sqlite3"),
        wrong_node,
        UnixMicros::new(15),
    )?;
    assert!(matches!(
        wrong.seal_federated_storage_capacity(authority),
        Err(Error::Invalid)
    ));
    assert!(
        wrong
            .federated_storage_usage(fixture.allocation.allocation_id())?
            .is_none()
    );
    assert_eq!(
        fixture
            .local
            .seal_federated_storage_capacity(authority)?
            .ceiling_bytes,
        0
    );
    Ok(())
}

#[test]
fn capacity_seal_migrates_v14_without_discarding_pending_backup_charges() -> TestResult {
    let fixture = QuotaFixture::open()?;
    let authority = fixture.authority(20)?;
    let object = object(115, 20)?;
    let legacy_path = fixture.directory.path().join("v14.sqlite3");
    let mut connection = rusqlite::Connection::open(&legacy_path)?;
    crate::migration::migrate_local_through(&mut connection, 14, 15)?;
    let tx = connection.transaction()?;
    tx.execute(
        "INSERT INTO local_identity(singleton,node_id,schema_version) VALUES(1,?1,14)",
        [fixture.repository_ids.provider_node.as_bytes().as_slice()],
    )?;
    crate::federation_storage_quota::install_or_validate_usage(
        &tx,
        authority,
        UnixMicros::new(15),
    )?;
    tx.execute(
        "UPDATE local_federation_storage_usage SET reserved_bytes=20 WHERE allocation_id=?1",
        [fixture.allocation.allocation_id().as_bytes().as_slice()],
    )?;
    tx.execute("INSERT INTO local_federation_backup_capacity
        (allocation_id,destination_id,provider_generation,backup_id,byte_length,digest,state,updated_at)
        VALUES(?1,?2,1,?3,20,?4,1,15)", rusqlite::params![
        fixture.allocation.allocation_id().as_bytes().as_slice(), object.destination_id.as_bytes().as_slice(),
        object.backup_id.as_bytes().as_slice(), object.digest.as_slice()])?;
    tx.commit()?;
    drop(connection);

    let mut migrated = LocalDatabase::open_existing(&legacy_path, UnixMicros::new(16))?;
    // Opening v14 also applies v16 recovered-target and v17 capability-cache metadata;
    // the v15 capacity seal must preserve the reservation through all later migrations.
    assert_eq!(migrated.check_integrity()?.schema_version, 17);
    let sealed = migrated.seal_federated_storage_capacity(authority)?;
    assert_eq!((sealed.ceiling_bytes, sealed.sequence), (20, 1));
    assert_eq!(
        migrated.reserve_federated_backup_capacity(authority, object)?,
        Disposition::Replayed
    );
    migrated.commit_federated_backup_capacity(sealed.allocation_id, object, UnixMicros::new(17))?;
    let usage = migrated
        .federated_storage_usage(sealed.allocation_id)?
        .ok_or("migrated usage")?;
    assert_eq!((usage.committed_bytes, usage.reserved_bytes), (20, 0));
    assert_eq!(migrated.seal_federated_storage_capacity(authority)?, sealed);
    Ok(())
}

fn object(
    seed: u8,
    byte_length: u64,
) -> Result<BackupObjectIdentity, meshspan_domain::IdentifierError> {
    Ok(BackupObjectIdentity {
        destination_id: BackupDestinationId::from_bytes([99; 16])?,
        backup_id: BackupId::from_bytes([seed; 16])?,
        provider_generation: 1,
        byte_length,
        digest: [seed; 32],
    })
}
