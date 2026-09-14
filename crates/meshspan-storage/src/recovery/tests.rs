// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{
    FolderRegistration, RegisteredFolder, UsageLimit,
    pack::{PackPutRequest, PackStore},
};
use meshspan_domain::{EntropyError, MeshId, OperationId, RandomSource, TargetId, UnixMicros};
use tempfile::{TempDir, tempdir};

#[path = "tests/inventory.rs"]
mod inventory;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PAYLOAD: &[u8] = b"encrypted recovery bytes must survive without the node journal";

struct FixedRandom;
impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), EntropyError> {
        bytes.fill(19);
        Ok(())
    }
}

struct Fixture {
    directory: TempDir,
    storage: PathBuf,
    fingerprint: MarkerFingerprint,
    shard: ShardIdentity,
}

fn fixture(crash_wal: bool) -> TestResult<Fixture> {
    let directory = tempdir()?;
    let storage = directory.path().join("target ? # %");
    fs::create_dir(&storage)?;
    let folder = RegisteredFolder::register_new(
        &storage,
        FolderRegistration {
            mesh_id: MeshId::from_bytes([1; 16])?,
            target_id: TargetId::from_bytes([2; 16])?,
            generation: 3,
            usage_limit: UsageLimit::DEFAULT,
        },
        &mut FixedRandom,
    )?;
    let shard = ShardIdentity {
        manifest_digest: [4; 32],
        stripe_index: 5,
        shard_index: 6,
        generation: 7,
    };
    let bytes = BoundedBytes::copy_from(PAYLOAD, 1024)?;
    let mut pack = PackStore::open(&folder, 1, UnixMicros::new(1))?;
    pack.put_exact(PackPutRequest {
        operation_id: OperationId::from_bytes([8; 16])?,
        request_digest: [9; 32],
        shard,
        expected_digest: blake3::hash(PAYLOAD).into(),
        bytes: &bytes,
        now: UnixMicros::new(2),
    })?;
    let fingerprint = folder.marker().fingerprint();
    assert!(matches!(
        RecoveryFolder::open(&storage, fingerprint),
        Err(RecoveryStorageError::AlreadyOwned)
    ));
    let recovery_storage = if crash_wal {
        // A point-in-time crash image of this idle, single-writer fixture, before close/checkpoint.
        // No production code copies live SQLite files.
        let target = directory.path().join("crash image ? # %");
        fs::create_dir_all(target.join(".meshspan/packs"))?;
        for name in [
            "target.marker",
            "target.lock",
            "packs/0000000000000001.sqlite3",
            "packs/0000000000000001.sqlite3-wal",
        ] {
            fs::copy(
                storage.join(".meshspan").join(name),
                target.join(".meshspan").join(name),
            )?;
        }
        assert!(
            fs::metadata(target.join(".meshspan/packs/0000000000000001.sqlite3-wal"))?.len() > 0
        );
        target
    } else {
        storage
    };
    drop(pack);
    drop(folder);
    Ok(Fixture {
        directory,
        storage: recovery_storage,
        fingerprint,
        shard,
    })
}

#[test]
fn recovery_reads_crash_left_wal_without_creating_sidecars_or_node_journal() -> TestResult {
    let fixture = fixture(true)?;
    let before = source_files(&fixture.storage)?;
    let reader = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    assert_eq!(reader.marker().generation(), 3);
    assert_eq!(
        reader.pack_sequences()?.collect::<Result<Vec<_>, _>>()?,
        [1]
    );
    let workspace = fixture.directory.path().join("recovery-pack");
    let pack = reader.open_pack(1, &workspace, 1024 * 1024)?;
    assert_eq!(
        pack.read_exact(
            fixture.shard,
            PAYLOAD.len() as u64,
            blake3::hash(PAYLOAD).into()
        )?
        .as_slice(),
        PAYLOAD
    );
    pack.finish()?;
    assert!(!workspace.exists());
    drop(reader);
    assert_eq!(source_files(&fixture.storage)?, before);
    assert!(!fixture.directory.path().join("storage-targets").exists());
    Ok(())
}

#[test]
fn recovery_rejects_substitution_missing_data_and_excessive_lengths() -> TestResult {
    let fixture = fixture(false)?;
    assert!(matches!(
        RecoveryFolder::open(&fixture.storage, MarkerFingerprint::from_bytes([0; 32])),
        Err(RecoveryStorageError::IdentityMismatch)
    ));
    let reader = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let pack = reader.open_pack(
        1,
        &fixture.directory.path().join("recovery-pack"),
        1024 * 1024,
    )?;
    assert!(matches!(
        pack.read_exact(fixture.shard, PAYLOAD.len() as u64, [0; 32]),
        Err(RecoveryStorageError::Corrupt)
    ));
    assert!(matches!(
        pack.read_exact(fixture.shard, 1, blake3::hash(PAYLOAD).into()),
        Err(RecoveryStorageError::Corrupt)
    ));
    assert!(matches!(
        pack.read_exact(fixture.shard, u64::MAX, [0; 32]),
        Err(RecoveryStorageError::InvalidInput)
    ));
    let missing = ShardIdentity {
        stripe_index: 99,
        ..fixture.shard
    };
    assert!(matches!(
        pack.read_exact(missing, PAYLOAD.len() as u64, blake3::hash(PAYLOAD).into()),
        Err(RecoveryStorageError::NotFound)
    ));
    let missing_work = fixture.directory.path().join("missing-pack");
    assert!(reader.open_pack(2, &missing_work, 1024 * 1024).is_err());
    assert!(reader.open_pack(0, &missing_work, 1024 * 1024).is_err());
    pack.finish()?;
    Ok(())
}

#[test]
fn recovery_salvages_retained_tombstones_but_rejects_corrupted_ciphertext() -> TestResult {
    let fixture = fixture(false)?;
    let pack_path = fixture
        .storage
        .join(".meshspan/packs/0000000000000001.sqlite3");
    let connection = rusqlite::Connection::open(&pack_path)?;
    connection.execute("UPDATE shards SET state = 2, tombstoned_at = 3", [])?;
    drop(connection);
    let reader = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let workspace = fixture.directory.path().join("recovery-pack");
    let pack = reader.open_pack(1, &workspace, 1024 * 1024)?;
    assert_eq!(
        pack.read_exact(
            fixture.shard,
            PAYLOAD.len() as u64,
            blake3::hash(PAYLOAD).into()
        )?
        .as_slice(),
        PAYLOAD
    );
    pack.finish()?;
    drop(reader);
    let connection = rusqlite::Connection::open(&pack_path)?;
    connection.execute(
        "UPDATE shards SET stored_bytes = zeroblob(stored_length)",
        [],
    )?;
    drop(connection);
    let reader = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    assert!(matches!(
        reader.open_pack(1, &workspace, 1024 * 1024)?.read_exact(
            fixture.shard,
            PAYLOAD.len() as u64,
            blake3::hash(PAYLOAD).into()
        ),
        Err(RecoveryStorageError::Corrupt)
    ));
    Ok(())
}

fn source_files(storage: &Path) -> TestResult<Vec<(PathBuf, Vec<u8>)>> {
    let mut files = Vec::new();
    for subdirectory in [".meshspan", ".meshspan/packs"] {
        for entry in fs::read_dir(storage.join(subdirectory))? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                files.push((entry.path(), fs::read(entry.path())?));
            }
        }
    }
    files.sort();
    Ok(files)
}

#[test]
fn recovery_workspace_is_bounded_exclusive_and_outside_source() -> TestResult {
    let fixture = fixture(true)?;
    let before = source_files(&fixture.storage)?;
    let reader = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let nested = fixture.storage.join("scratch");
    assert!(matches!(
        reader.open_pack(1, &nested, 1024 * 1024),
        Err(RecoveryStorageError::InvalidInput)
    ));
    assert!(!nested.exists());
    let limited = fixture.directory.path().join("limited");
    assert!(matches!(
        reader.open_pack(1, &limited, 1),
        Err(RecoveryStorageError::InvalidInput)
    ));
    assert_eq!(fs::read_dir(&limited)?.count(), 0);
    let workspace = fixture.directory.path().join("recovery-pack");
    let pack = reader.open_pack(1, &workspace, 1024 * 1024)?;
    assert!(reader.open_pack(1, &workspace, 1024 * 1024).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&workspace)?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(workspace.join("pack.sqlite3"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    fs::write(workspace.join("unrelated.txt"), b"preserve this")?;
    assert!(matches!(
        pack.finish(),
        Err(RecoveryStorageError::InvalidInput)
    ));
    assert_eq!(fs::read(workspace.join("unrelated.txt"))?, b"preserve this");
    assert_eq!(source_files(&fixture.storage)?, before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn recovery_rejects_source_symlinks_without_touching_their_destination() -> TestResult {
    use std::os::unix::fs::symlink;
    let fixture = fixture(false)?;
    let reader = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let pack = fixture
        .storage
        .join(".meshspan/packs/0000000000000001.sqlite3");
    let outside = fixture.directory.path().join("outside.sqlite3");
    fs::rename(&pack, &outside)?;
    let before = fs::read(&outside)?;
    symlink(&outside, &pack)?;
    let workspace = fixture.directory.path().join("rejected");
    assert!(matches!(
        reader.open_pack(1, &workspace, 1024 * 1024),
        Err(RecoveryStorageError::InvalidInput)
    ));
    assert!(!workspace.exists());
    assert_eq!(fs::read(&outside)?, before);
    Ok(())
}

#[test]
fn recovery_inventory_pages_retained_and_unlinked_records_without_claiming_integrity() -> TestResult
{
    let fixture = fixture(false)?;
    let connection = rusqlite::Connection::open(
        fixture
            .storage
            .join(".meshspan/packs/0000000000000001.sqlite3"),
    )?;
    for state in [2_u16, 3] {
        let shard = ShardIdentity {
            shard_index: state,
            ..fixture.shard
        };
        connection.execute(
            "INSERT INTO shards (
                record_number, shard_identity, manifest_digest, stripe_index, shard_index,
                shard_generation, stored_length, stored_digest, stored_bytes, state,
                put_operation_id, created_at, tombstoned_at, unlinked_at
             ) SELECT ?1, ?2, manifest_digest, stripe_index, ?1, shard_generation,
                stored_length, stored_digest, CASE WHEN ?1 = 3 THEN NULL ELSE stored_bytes END,
                ?1, put_operation_id, created_at, 4, CASE WHEN ?1 = 3 THEN 5 ELSE NULL END
             FROM shards WHERE record_number = 1",
            rusqlite::params![state, crate::shard::encode_shard(shard).as_slice()],
        )?;
    }
    // Inventory remains locators only even when the bytes no longer match them.
    connection.execute(
        "UPDATE shards SET stored_bytes = zeroblob(stored_length) WHERE state = 1",
        [],
    )?;
    drop(connection);
    let reader = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
    let pack = reader.open_pack(1, &fixture.directory.path().join("inventory"), 1024 * 1024)?;
    let first = pack.inventory_page(0, 2)?;
    assert_eq!(first.next_after_record, Some(2));
    assert_eq!(first.records.len(), 2);
    assert_eq!(
        first.records[0],
        RecoveryShardRecord {
            record_number: 1,
            shard: fixture.shard,
            length: PAYLOAD.len() as u64,
            digest: blake3::hash(PAYLOAD).into(),
            retention: RecoveryShardRetention::Active,
        }
    );
    assert_eq!(
        first.records[1].retention,
        RecoveryShardRetention::Tombstoned
    );
    assert!(matches!(
        pack.read_exact(
            fixture.shard,
            PAYLOAD.len() as u64,
            blake3::hash(PAYLOAD).into()
        ),
        Err(RecoveryStorageError::Corrupt)
    ));
    let last = pack.inventory_page(2, 2)?;
    assert_eq!(last.next_after_record, None);
    assert_eq!(last.records.len(), 1);
    assert_eq!(last.records[0].record_number, 3);
    assert_eq!(last.records[0].retention, RecoveryShardRetention::Unlinked);
    assert!(pack.inventory_page(3, 2)?.records.is_empty());
    for (after, limit) in [(0, 0), (0, 1001), (u64::MAX, 1)] {
        assert!(matches!(
            pack.inventory_page(after, limit),
            Err(RecoveryStorageError::InvalidInput)
        ));
    }
    pack.finish()?;
    Ok(())
}

#[test]
fn recovery_inventory_rejects_malformed_persisted_claims() -> TestResult {
    let fixture = fixture(false)?;
    let file_path = fixture
        .storage
        .join(".meshspan/packs/0000000000000001.sqlite3");
    for (index, mutation) in [
        "UPDATE shards SET stored_digest = zeroblob(33)",
        "UPDATE shards SET shard_identity = zeroblob(47)",
        "UPDATE shards SET stored_length = 67108865",
        "UPDATE shards SET state = 4",
    ]
    .into_iter()
    .enumerate()
    {
        let connection = rusqlite::Connection::open(&file_path)?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
        connection.execute("UPDATE shards SET stored_digest = ?1, shard_identity = ?2, stored_length = ?3, state = 1", rusqlite::params![blake3::hash(PAYLOAD).as_bytes().as_slice(), crate::shard::encode_shard(fixture.shard).as_slice(), i64::try_from(PAYLOAD.len())?])?;
        connection.execute(mutation, [])?;
        drop(connection);
        let reader = RecoveryFolder::open(&fixture.storage, fixture.fingerprint)?;
        let pack = reader.open_pack(
            1,
            &fixture.directory.path().join(format!("invalid-{index}")),
            1024 * 1024,
        )?;
        assert!(matches!(
            pack.inventory_page(0, 1),
            Err(RecoveryStorageError::Corrupt)
        ));
        pack.finish()?;
    }
    Ok(())
}
