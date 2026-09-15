// SPDX-License-Identifier: GPL-2.0-only

use super::*;

const SCOPE: [u8; 32] = [39; 32];

#[test]
fn manifest_binds_copied_bytes_not_paths_or_disposable_shared_memory() -> TestResult {
    let fixture = fixture(true)?;
    let source = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let work = fixture.directory.path().join("manifest-inventory");
    let mut inventory = RecoveryInventory::create(&work, SCOPE, 1024 * 1024)?;
    inventory.capture_pack(&source, 1)?;
    let mut manifest = Vec::new();
    inventory.write_manifest(&mut manifest)?;
    assert!(manifest.starts_with(b"MSRECOVERYPACKS\x01"));
    assert_eq!(&manifest[16..24], &1_u64.to_be_bytes());
    let second = fixture.directory.path().join("different-path");
    let mut other = RecoveryInventory::create(&second, SCOPE, 1024 * 1024)?;
    other.capture_pack(&source, 1)?;
    let mut equivalent = Vec::new();
    other.write_manifest(&mut equivalent)?;
    assert_eq!(manifest, equivalent);
    drop(inventory);
    fs::remove_file(work.join("pack-0000000000000001/pack.sqlite3-shm"))?;
    let inventory = RecoveryInventory::open(&work, SCOPE)?;
    assert!(
        inventory
            .read_exact(
                fixture.shard,
                PAYLOAD.len() as u64,
                blake3::hash(PAYLOAD).into()
            )?
            .is_some()
    );
    let mut reopened = Vec::new();
    inventory.write_manifest(&mut reopened)?;
    assert_eq!(manifest, reopened);
    let wal = work.join("pack-0000000000000001/pack.sqlite3-wal");
    let mut changed = fs::read(&wal)?;
    *changed.last_mut().ok_or("WAL empty")? ^= 1;
    fs::write(&wal, changed)?;
    let mut altered = Vec::new();
    inventory.write_manifest(&mut altered)?;
    assert_ne!(manifest, altered);
    fs::rename(&wal, work.join("unavailable-wal"))?;
    assert!(inventory.write_manifest(&mut Vec::new()).is_err());
    Ok(())
}

#[test]
fn manifest_order_does_not_depend_on_pack_discovery_or_local_ids() -> TestResult {
    let fixture = fixture(false)?;
    copy_second_pack(&fixture)?;
    let source = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let mut first =
        RecoveryInventory::create(&fixture.directory.path().join("first"), SCOPE, 1024 * 1024)?;
    first.capture_pack(&source, 1)?;
    first.capture_pack(&source, 2)?;
    let mut second =
        RecoveryInventory::create(&fixture.directory.path().join("second"), SCOPE, 1024 * 1024)?;
    second.capture_pack(&source, 2)?;
    second.capture_pack(&source, 1)?;
    let mut first_manifest = Vec::new();
    let mut second_manifest = Vec::new();
    first.write_manifest(&mut first_manifest)?;
    second.write_manifest(&mut second_manifest)?;
    assert_eq!(first_manifest, second_manifest);
    Ok(())
}

fn copy_second_pack(fixture: &Fixture) -> TestResult {
    let directory = fixture.storage.join(".meshspan/packs");
    let second = directory.join("0000000000000002.sqlite3");
    fs::copy(directory.join("0000000000000001.sqlite3"), &second)?;
    let connection = rusqlite::Connection::open(&second)?;
    connection.execute("UPDATE pack_state SET pack_sequence = 2", [])?;
    Ok(())
}

#[test]
fn durable_inventory_reads_after_original_media_disappears_and_rejects_scope_change() -> TestResult
{
    let fixture = fixture(true)?;
    let original = source_files(&fixture.storage)?;
    let source = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let work = fixture.directory.path().join("inventory");
    let mut inventory = RecoveryInventory::create(&work, SCOPE, 1024 * 1024)?;
    assert!(matches!(
        RecoveryInventory::open(&work, SCOPE),
        Err(RecoveryStorageError::AlreadyOwned)
    ));
    inventory.capture_pack(&source, 1)?;
    let summary = inventory.summary()?;
    assert_eq!(summary.packs, 1);
    assert_eq!(summary.retained_shards, 1);
    assert!(summary.copied_bytes > PAYLOAD.len() as u64);
    inventory.capture_pack(&source, 1)?;
    assert_eq!(inventory.summary()?, summary);
    assert_eq!(source_files(&fixture.storage)?, original);
    drop(source);
    drop(inventory);
    fs::rename(
        &fixture.storage,
        fixture.directory.path().join("unavailable-original"),
    )?;
    assert!(matches!(
        RecoveryInventory::open(&work, [40; 32]),
        Err(RecoveryStorageError::IdentityMismatch)
    ));
    let inventory = RecoveryInventory::open(&work, SCOPE)?;
    assert_eq!(inventory.summary()?, summary);
    assert_eq!(
        inventory
            .read_exact(
                fixture.shard,
                PAYLOAD.len() as u64,
                blake3::hash(PAYLOAD).into()
            )?
            .ok_or("recovered bytes absent")?
            .as_slice(),
        PAYLOAD
    );
    assert!(
        inventory
            .read_exact(fixture.shard, PAYLOAD.len() as u64, [0; 32])?
            .is_none()
    );
    assert!(!fixture.storage.exists());
    Ok(())
}

#[test]
fn failed_copy_is_not_readable_and_rebuilds_after_restart() -> TestResult {
    let fixture = fixture(false)?;
    let file = fixture
        .storage
        .join(".meshspan/packs/0000000000000001.sqlite3");
    let original = fs::read(&file)?;
    fs::write(&file, b"interrupted pack")?;
    let source = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let work = fixture.directory.path().join("inventory");
    let mut inventory = RecoveryInventory::create(&work, SCOPE, 1024 * 1024)?;
    assert!(inventory.capture_pack(&source, 1).is_err());
    assert!(matches!(
        inventory.summary(),
        Err(RecoveryStorageError::Incomplete)
    ));
    assert!(
        inventory
            .read_exact(
                fixture.shard,
                PAYLOAD.len() as u64,
                blake3::hash(PAYLOAD).into()
            )?
            .is_none()
    );
    drop(inventory);
    fs::write(&file, &original)?;
    let mut inventory = RecoveryInventory::open(&work, SCOPE)?;
    inventory.capture_pack(&source, 1)?;
    assert_eq!(inventory.summary()?.packs, 1);
    assert_eq!(inventory.summary()?.retained_shards, 1);
    assert_eq!(
        inventory
            .read_exact(
                fixture.shard,
                PAYLOAD.len() as u64,
                blake3::hash(PAYLOAD).into()
            )?
            .ok_or("recovered bytes absent")?
            .as_slice(),
        PAYLOAD
    );
    assert_eq!(fs::read(&file)?, original);
    Ok(())
}

#[test]
fn copy_budget_and_unrecognised_pending_files_cannot_be_bypassed() -> TestResult {
    let fixture = fixture(false)?;
    let source = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let work = fixture.directory.path().join("inventory");
    let mut inventory = RecoveryInventory::create(&work, SCOPE, 1)?;
    assert!(inventory.capture_pack(&source, 1).is_err());
    let scratch = work.join("pack-0000000000000001");
    assert_eq!(fs::read_dir(&scratch)?.count(), 0);
    fs::write(scratch.join("unrelated"), b"keep me")?;
    drop(inventory);
    let mut inventory = RecoveryInventory::open(&work, SCOPE)?;
    assert!(matches!(
        inventory.capture_pack(&source, 1),
        Err(RecoveryStorageError::InvalidInput)
    ));
    assert_eq!(fs::read(scratch.join("unrelated"))?, b"keep me");
    assert!(matches!(
        inventory.summary(),
        Err(RecoveryStorageError::Incomplete)
    ));
    Ok(())
}

#[test]
fn index_tries_another_copy_after_ciphertext_damage() -> TestResult {
    let fixture = fixture(false)?;
    copy_second_pack(&fixture)?;
    let source = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let work = fixture.directory.path().join("inventory");
    let mut inventory = RecoveryInventory::create(&work, SCOPE, 1024 * 1024)?;
    inventory.capture_pack(&source, 1)?;
    inventory.capture_pack(&source, 2)?;
    assert_eq!(inventory.summary()?.packs, 2);
    assert_eq!(inventory.summary()?.retained_shards, 2);
    let connection = rusqlite::Connection::open(work.join("pack-0000000000000001/pack.sqlite3"))?;
    connection.execute(
        "UPDATE shards SET stored_bytes = zeroblob(stored_length)",
        [],
    )?;
    drop(connection);
    assert_eq!(
        inventory
            .read_exact(
                fixture.shard,
                PAYLOAD.len() as u64,
                blake3::hash(PAYLOAD).into()
            )?
            .ok_or("surviving duplicate absent")?
            .as_slice(),
        PAYLOAD
    );
    fs::rename(
        work.join("pack-0000000000000001"),
        work.join("missing-copy"),
    )?;
    assert_eq!(
        inventory
            .read_exact(
                fixture.shard,
                PAYLOAD.len() as u64,
                blake3::hash(PAYLOAD).into()
            )?
            .ok_or("duplicate after missing copy absent")?
            .as_slice(),
        PAYLOAD
    );
    let plan = rusqlite::Connection::open(work.join("inventory.sqlite3"))?;
    let details: String = plan.query_row("EXPLAIN QUERY PLAN SELECT packs.id, packs.sequence, CASE WHEN length(packs.marker) = 116 THEN packs.marker END FROM shards INDEXED BY shards_exact JOIN packs ON packs.id = shards.pack_id WHERE shard_identity = ?1 AND stored_length = ?2 AND digest = ?3 AND pack_id > 0 AND complete = 1 ORDER BY pack_id LIMIT 1",
        rusqlite::params![crate::shard::encode_shard(fixture.shard).as_slice(), i64::try_from(PAYLOAD.len())?, blake3::hash(PAYLOAD).as_bytes().as_slice()], |row| row.get(3))?;
    assert!(
        details.contains("SEARCH shards USING COVERING INDEX shards_exact"),
        "{details}"
    );
    Ok(())
}

#[test]
fn archived_content_recovers_from_newer_physical_generation() -> TestResult {
    let fixture = fixture(false)?;
    let source = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let mut inventory = RecoveryInventory::create(
        &fixture.directory.path().join("newer-copy"),
        SCOPE,
        1024 * 1024,
    )?;
    inventory.capture_pack(&source, 1)?;
    let archived = meshspan_contracts::ShardIdentity {
        generation: fixture.shard.generation - 1,
        ..fixture.shard
    };
    let recovered = inventory.read_content_shard(
        archived,
        PAYLOAD.len() as u64,
        blake3::hash(PAYLOAD).into(),
    )?;
    assert_eq!(
        recovered.as_ref().map(BoundedBytes::as_slice),
        Some(PAYLOAD)
    );
    assert!(
        inventory
            .read_exact(archived, PAYLOAD.len() as u64, blake3::hash(PAYLOAD).into())?
            .is_none()
    );
    for wrong in [
        ShardIdentity {
            manifest_digest: [44; 32],
            ..archived
        },
        ShardIdentity {
            stripe_index: 9,
            ..archived
        },
        ShardIdentity {
            shard_index: 9,
            ..archived
        },
    ] {
        assert!(
            inventory
                .read_content_shard(wrong, PAYLOAD.len() as u64, blake3::hash(PAYLOAD).into())?
                .is_none()
        );
    }
    assert!(
        inventory
            .read_content_shard(
                archived,
                PAYLOAD.len() as u64 + 1,
                blake3::hash(PAYLOAD).into()
            )?
            .is_none()
    );
    assert!(
        inventory
            .read_content_shard(archived, PAYLOAD.len() as u64, [44; 32])?
            .is_none()
    );
    Ok(())
}

#[test]
fn content_lookup_tries_another_generation_in_the_same_pack() -> TestResult {
    let fixture = fixture(false)?;
    let folder = RegisteredFolder::reopen(
        &fixture.storage,
        FolderRegistration {
            mesh_id: MeshId::from_bytes([1; 16])?,
            target_id: TargetId::from_bytes([2; 16])?,
            generation: 3,
            usage_limit: UsageLimit::DEFAULT,
        },
        fixture.fingerprint,
    )?;
    let mut pack = PackStore::open(&folder, 1, UnixMicros::new(3))?;
    let bytes = BoundedBytes::copy_from(PAYLOAD, 1024)?;
    pack.put_exact(PackPutRequest {
        operation_id: OperationId::from_bytes([18; 16])?,
        request_digest: [19; 32],
        shard: ShardIdentity {
            generation: 8,
            ..fixture.shard
        },
        expected_digest: blake3::hash(PAYLOAD).into(),
        bytes: &bytes,
        now: UnixMicros::new(4),
    })?;
    drop(pack);
    drop(folder);
    let source = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let work = fixture.directory.path().join("same-pack-generations");
    let mut inventory = RecoveryInventory::create(&work, SCOPE, 1024 * 1024)?;
    inventory.capture_pack(&source, 1)?;
    let connection = rusqlite::Connection::open(work.join("pack-0000000000000001/pack.sqlite3"))?;
    connection.execute(
        "UPDATE shards SET stored_bytes = zeroblob(stored_length) WHERE shard_generation = 7",
        [],
    )?;
    let archived = ShardIdentity {
        generation: 6,
        ..fixture.shard
    };
    let recovered = inventory.read_content_shard(
        archived,
        PAYLOAD.len() as u64,
        blake3::hash(PAYLOAD).into(),
    )?;
    assert_eq!(
        recovered.as_ref().map(BoundedBytes::as_slice),
        Some(PAYLOAD)
    );
    assert!(
        inventory
            .read_exact(
                fixture.shard,
                PAYLOAD.len() as u64,
                blake3::hash(PAYLOAD).into()
            )?
            .is_none()
    );
    connection.execute(
        "UPDATE shards SET stored_bytes = zeroblob(stored_length) WHERE shard_generation = 8",
        [],
    )?;
    assert!(
        inventory
            .read_content_shard(archived, PAYLOAD.len() as u64, blake3::hash(PAYLOAD).into())?
            .is_none()
    );
    Ok(())
}
