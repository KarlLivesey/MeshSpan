// SPDX-License-Identifier: GPL-2.0-only

//! Real older-schema databases, not current databases with a decremented version label.

use std::{fs, path::Path};

use meshspan_domain::{BackupId, MeshId, PartitionId, Revision, UnixMicros};
use rusqlite::{Connection, params};
use sha2::{Digest as _, Sha256};

use super::{
    EncryptedPartitionBackupManifest, EncryptedRestorePaths, LogPosition, PartitionBackupManifest,
    RepositoryError, restore_encrypted_partition_backup, restore_partition_backup,
};
use crate::PartitionDatabase;

#[test]
fn older_backup_restores_through_supported_migrations_without_changing_committed_position()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("schema-92.sqlite3");
    let destination = directory.path().join("recovered.sqlite3");
    let manifest = legacy_backup(&source)?;
    let original = fs::read(&source)?;
    let restored = restore_partition_backup(&source, &destination, manifest, UnixMicros::new(20))?;
    assert_eq!(
        restored.schema_version(),
        PartitionDatabase::supported_schema_version()
    );
    let state: (i64, i64, i64) = restored.connection().query_row(
        "SELECT last_log_index, last_log_term, state_revision FROM applied_state WHERE singleton = 1",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(state, (7, 2, 5));
    let name: String =
        restored
            .connection()
            .query_row("SELECT display_name FROM meshes", [], |row| row.get(0))?;
    assert_eq!(name, "Recover this mesh");
    // The migration really ran; the source genuinely has no such column.
    restored
        .connection()
        .prepare("SELECT preparation_log_index FROM update_rollout_nodes")?;
    assert_eq!(fs::read(&source)?, original);
    drop(restored);
    PartitionDatabase::open_existing(&destination, UnixMicros::new(21))?.check_integrity()?;
    Ok(())
}

#[test]
fn encrypted_older_backup_authenticates_original_bytes_then_migrates_the_new_copy()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("old.sqlite3");
    let encrypted = directory.path().join("backup.msbackup");
    let staging = directory.path().join("plaintext.sqlite3");
    let destination = directory.path().join("recovered.sqlite3");
    let manifest = legacy_backup(&source)?;
    let key = meshspan_secret_envelope::WrappingPrivateKey::from_bytes([7; 32])?;
    let evidence = meshspan_backup::encrypt_backup(
        &source,
        &encrypted,
        meshspan_backup::BackupSourceManifest {
            backup_id: manifest.backup_id,
            mesh_id: manifest.mesh_id,
            partition_id: manifest.partition_id,
            last_log_index: 7,
            last_log_term: 2,
            state_revision: 5,
            schema_version: 92,
            byte_length: manifest.byte_length,
            digest: manifest.digest,
            created_at: manifest.created_at,
        },
        &[key.public_key()],
        &mut crate::test_support::SequentialRandom(17),
    )?;
    let before = fs::read(&encrypted)?;
    let restored = restore_encrypted_partition_backup(
        EncryptedRestorePaths {
            encrypted_source: &encrypted,
            plaintext_staging: &staging,
            restored_destination: &destination,
        },
        EncryptedPartitionBackupManifest {
            partition: manifest,
            encrypted: evidence,
        },
        &key,
        UnixMicros::new(30),
    )?;
    assert_eq!(
        restored.schema_version(),
        PartitionDatabase::supported_schema_version()
    );
    assert_eq!(
        super::AuthoritativeRepository::new(restored).current_revision()?,
        Revision::new(5)
    );
    assert!(!staging.exists());
    assert_eq!(fs::read(&encrypted)?, before);
    Ok(())
}

#[test]
fn backup_restore_still_rejects_changed_migration_history() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("changed-history.sqlite3");
    let mut manifest = legacy_backup(&source)?;
    let database = Connection::open(&source)?;
    database.execute(
        "UPDATE schema_migrations SET migration_digest = zeroblob(32) WHERE version = 92",
        [],
    )?;
    database.close().map_err(|(_, error)| error)?;
    let bytes = fs::read(&source)?;
    manifest.byte_length = u64::try_from(bytes.len())?;
    manifest.digest = Sha256::digest(&bytes).into();
    let result = restore_partition_backup(
        &source,
        &directory.path().join("refused.sqlite3"),
        manifest,
        UnixMicros::new(20),
    );
    assert!(matches!(
        result,
        Err(RepositoryError::Store(
            crate::MetadataStoreError::MigrationDigestMismatch { version: 92 }
        ))
    ));
    assert_eq!(fs::read(&source)?, bytes);
    Ok(())
}

fn legacy_backup(source: &Path) -> Result<PartitionBackupManifest, Box<dyn std::error::Error>> {
    let partition = PartitionId::from_bytes([1; 16])?;
    let mesh = MeshId::from_bytes([2; 16])?;
    let mut database = Connection::open(source)?;
    database.pragma_update(None, "foreign_keys", true)?;
    crate::migration::migrate_partition_through(&mut database, 92, 10)?;
    database.execute(
        "INSERT INTO applied_state VALUES (1, ?1, 7, 2, 5, 92)",
        [partition.as_bytes().as_slice()],
    )?;
    database.execute(
        "INSERT INTO meshes VALUES (?1, 'Recover this mesh', 'recover this mesh', 10, 1, 1, 1, 5)",
        [mesh.as_bytes().as_slice()],
    )?;
    database.execute(
        "INSERT INTO hosts VALUES (?1, 'Host', 'host', 1, 10, NULL, 1)",
        [[3_u8; 16].as_slice()],
    )?;
    database.execute("INSERT INTO nodes(node_id, host_id, display_name, canonical_name, state, current_incarnation,
        admitted_at, activated_at, revision) VALUES (?1, ?2, 'Node', 'node', 2, 1, 10, 10, 1)",
        params![[4_u8; 16].as_slice(), [3_u8; 16].as_slice()])?;
    database.execute(
        "INSERT INTO metadata_partitions VALUES (?1, 1, 'Root', 1, 1, 1, 10, NULL, 1)",
        [partition.as_bytes().as_slice()],
    )?;
    database.execute(
        "INSERT INTO partition_voters VALUES (?1, ?2, 1, 1, 1, 1)",
        params![partition.as_bytes().as_slice(), [4_u8; 16].as_slice()],
    )?;
    let administrator = meshspan_domain::PrincipalId::from_bytes([6; 16])?;
    database.execute(
        "INSERT INTO principals VALUES (?1, 1, 'Administrator', 'administrator', 1, 10, NULL, 1)",
        [administrator.as_bytes().as_slice()],
    )?;
    database.execute(
        "INSERT INTO users VALUES (?1, NULL)",
        [administrator.as_bytes().as_slice()],
    )?;
    let transaction = database.transaction()?;
    super::authentication_policy::bootstrap_defaults(
        &transaction,
        administrator,
        UnixMicros::new(10),
        Revision::new(1),
    )?;
    transaction.commit()?;
    assert!(
        database
            .prepare("SELECT preparation_log_index FROM update_rollout_nodes")
            .is_err()
    );
    database.close().map_err(|(_, error)| error)?;
    let bytes = fs::read(source)?;
    Ok(PartitionBackupManifest {
        backup_id: BackupId::from_bytes([5; 16])?,
        partition_id: partition,
        mesh_id: mesh,
        applied_position: LogPosition { index: 7, term: 2 },
        state_revision: Revision::new(5),
        schema_version: 92,
        byte_length: u64::try_from(bytes.len())?,
        digest: Sha256::digest(&bytes).into(),
        created_at: UnixMicros::new(11),
    })
}
