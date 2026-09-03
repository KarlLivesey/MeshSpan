// SPDX-License-Identifier: GPL-2.0-only

//! Exact-state online backup creation and fail-closed staged restoration.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use meshspan_backup::{BackupFileEvidence, BackupSourceManifest, encrypt_backup, restore_backup};
use meshspan_domain::{BackupId, MeshId, PartitionId, RandomSource, Revision, UnixMicros};
use meshspan_secret_envelope::{WrappingPrivateKey, WrappingPublicKey};
use rusqlite::{Connection, MAIN_DB, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};

use super::{LogPosition, RepositoryError};
use crate::PartitionDatabase;

const HASH_BUFFER_BYTES: usize = 64 * 1_024;

/// Exact identity and committed state represented by one SQLite backup file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartitionBackupManifest {
    /// Caller-allocated backup identity.
    pub backup_id: BackupId,
    /// Partition whose complete state was copied.
    pub partition_id: PartitionId,
    /// Mesh whose recovery authority owns the partition.
    pub mesh_id: MeshId,
    /// Last applied committed log position in the copy.
    pub applied_position: LogPosition,
    /// Exact authoritative state revision in the copy.
    pub state_revision: Revision,
    /// Compiled schema version represented by the copy.
    pub schema_version: u32,
    /// Exact file length covered by `digest`.
    pub byte_length: u64,
    /// SHA-256 of the complete closed backup file.
    pub digest: [u8; 32],
    /// Authoritative instant at which backup creation was requested.
    pub created_at: UnixMicros,
}

/// Exact database state and encrypted-container evidence for one recoverable backup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptedPartitionBackupManifest {
    /// Verified SQLite backup state contained in the encrypted bytes.
    pub partition: PartitionBackupManifest,
    /// Exact authenticated encrypted-container length and digest.
    pub encrypted: BackupFileEvidence,
}

pub(super) fn create_partition_backup(
    database: &PartitionDatabase,
    backup_id: BackupId,
    destination: &Path,
    created_at: UnixMicros,
) -> Result<PartitionBackupManifest, RepositoryError> {
    require_absent(destination)?;
    let state = read_state(database.connection())?;
    let mesh_id = read_mesh_id(database.connection())?;
    database.connection().backup(MAIN_DB, destination, None)?;
    let (byte_length, digest) = hash_file(destination)?;
    let manifest = PartitionBackupManifest {
        backup_id,
        partition_id: database.partition_id(),
        mesh_id,
        applied_position: state.0,
        state_revision: state.1,
        schema_version: database.schema_version(),
        byte_length,
        digest,
        created_at,
    };
    verify_source(destination, manifest)?;
    Ok(manifest)
}

/// Creates a consistent SQLite backup, encrypts it for exact recovery recipients and removes the
/// temporary plaintext copy before returning.
///
/// # Errors
///
/// Refuses overlapping or existing paths and fails closed for snapshot, encryption or cleanup
/// errors. A failed encrypted destination remains staged and must never be published.
pub fn create_encrypted_partition_backup(
    database: &PartitionDatabase,
    paths: EncryptedBackupPaths<'_>,
    backup_id: BackupId,
    created_at: UnixMicros,
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<EncryptedPartitionBackupManifest, RepositoryError> {
    validate_create_paths(paths)?;
    let partition =
        create_partition_backup(database, backup_id, paths.plaintext_staging, created_at)?;
    let encrypted = encrypt_backup(
        paths.plaintext_staging,
        paths.encrypted_destination,
        source_manifest(partition),
        recipients,
        random,
    );
    remove_plaintext_staging(paths.plaintext_staging)?;
    Ok(EncryptedPartitionBackupManifest {
        partition,
        encrypted: encrypted?,
    })
}

/// Decrypts an exact backup into a temporary plaintext file, applies the existing SQLite restore
/// verification and removes the plaintext staging copy before returning.
///
/// # Errors
///
/// Refuses overlapping or existing paths and rejects changed evidence, wrong recipients, invalid
/// SQLite state, unavailable membership or cleanup failures.
pub fn restore_encrypted_partition_backup(
    paths: EncryptedRestorePaths<'_>,
    manifest: EncryptedPartitionBackupManifest,
    recipient: &WrappingPrivateKey,
    migration_time: UnixMicros,
) -> Result<PartitionDatabase, RepositoryError> {
    validate_restore_paths(paths)?;
    if manifest.encrypted.source != source_manifest(manifest.partition) {
        return Err(RepositoryError::BackupMismatch);
    }
    let decrypted = restore_backup(
        paths.encrypted_source,
        paths.plaintext_staging,
        manifest.encrypted,
        recipient,
    );
    if let Err(error) = decrypted {
        remove_staging_if_present(paths.plaintext_staging)?;
        return Err(error.into());
    }
    let restored = restore_partition_backup(
        paths.plaintext_staging,
        paths.restored_destination,
        manifest.partition,
        migration_time,
    );
    remove_plaintext_staging(paths.plaintext_staging)?;
    restored
}

/// Non-overlapping paths used while creating one encrypted backup.
#[derive(Clone, Copy, Debug)]
pub struct EncryptedBackupPaths<'a> {
    /// New temporary path for the consistent plaintext SQLite copy.
    pub plaintext_staging: &'a Path,
    /// New durable path for the authenticated encrypted container.
    pub encrypted_destination: &'a Path,
}

/// Non-overlapping paths used while restoring one encrypted backup.
#[derive(Clone, Copy, Debug)]
pub struct EncryptedRestorePaths<'a> {
    /// Existing authenticated encrypted container.
    pub encrypted_source: &'a Path,
    /// New temporary path for decrypted SQLite bytes.
    pub plaintext_staging: &'a Path,
    /// New path which becomes eligible for admission only after SQLite verification.
    pub restored_destination: &'a Path,
}

/// Verifies a closed backup and restores it into a new, never-overwritten database path.
///
/// # Errors
///
/// Refuses an existing destination and fails for digest, length, identity, schema, integrity or
/// exact committed-state mismatch. A failed destination remains staged and is never activated.
pub fn restore_partition_backup(
    source: &Path,
    destination: &Path,
    manifest: PartitionBackupManifest,
    migration_time: UnixMicros,
) -> Result<PartitionDatabase, RepositoryError> {
    require_absent(destination)?;
    let source_connection = verify_source(source, manifest)?;
    source_connection.backup(MAIN_DB, destination, None)?;
    drop(source_connection);
    let restored = PartitionDatabase::open(destination, manifest.partition_id, migration_time)?;
    let state = read_state(restored.connection())?;
    if state != (manifest.applied_position, manifest.state_revision)
        || restored.schema_version() != manifest.schema_version
    {
        return Err(RepositoryError::BackupMismatch);
    }
    restored.check_integrity()?;
    Ok(restored)
}

fn verify_source(
    source: &Path,
    manifest: PartitionBackupManifest,
) -> Result<Connection, RepositoryError> {
    let (byte_length, digest) = hash_file(source)?;
    if byte_length != manifest.byte_length || digest != manifest.digest {
        return Err(RepositoryError::BackupMismatch);
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(source, flags)?;
    let state = read_state(&connection)?;
    let stored_partition: Vec<u8> = connection.query_row(
        "SELECT partition_id FROM applied_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let stored_mesh_id = read_mesh_id(&connection)?;
    let schema_version: u32 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let quick_check: String =
        connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    let foreign_key_violation = connection
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()?;
    let partition = manifest.partition_id.as_bytes();
    let admitted: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM metadata_partitions mp
            JOIN partition_voters pv ON pv.partition_id = mp.partition_id
            WHERE mp.partition_id = ?1 AND mp.state = 1 AND pv.state = 1
         )",
        [partition.as_slice()],
        |row| row.get(0),
    )?;
    if stored_partition.as_slice() != manifest.partition_id.as_bytes()
        || stored_mesh_id != manifest.mesh_id
        || schema_version != manifest.schema_version
        || state != (manifest.applied_position, manifest.state_revision)
        || quick_check != "ok"
        || foreign_key_violation.is_some()
        || admitted != 1
    {
        return Err(RepositoryError::BackupMismatch);
    }
    Ok(connection)
}

fn read_state(connection: &Connection) -> Result<(LogPosition, Revision), RepositoryError> {
    let (index, term, revision) = connection.query_row(
        "SELECT last_log_index, last_log_term, state_revision
         FROM applied_state WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    Ok((
        LogPosition {
            index: parse_u64(index)?,
            term: parse_u64(term)?,
        },
        Revision::new(parse_u64(revision)?),
    ))
}

fn read_mesh_id(connection: &Connection) -> Result<MeshId, RepositoryError> {
    let mut statement =
        connection.prepare("SELECT mesh_id FROM meshes ORDER BY mesh_id LIMIT 2")?;
    let rows = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let [mesh_id] = rows.as_slice() else {
        return Err(RepositoryError::BackupMismatch);
    };
    MeshId::from_bytes(
        mesh_id
            .as_slice()
            .try_into()
            .map_err(|_| RepositoryError::BackupMismatch)?,
    )
    .map_err(|_| RepositoryError::BackupMismatch)
}

fn require_absent(file_path: &Path) -> Result<(), RepositoryError> {
    match file_path.try_exists() {
        Ok(false) => Ok(()),
        Ok(true) => Err(RepositoryError::BackupDestinationExists),
        Err(error) => Err(RepositoryError::Io(error)),
    }
}

fn hash_file(file_path: &Path) -> Result<(u64, [u8; 32]), RepositoryError> {
    let mut file = File::open(file_path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut length = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(read).map_err(|_| RepositoryError::BackupMismatch)?)
            .ok_or(RepositoryError::BackupMismatch)?;
        digest.update(&buffer[..read]);
    }
    Ok((length, digest.finalize().into()))
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::BackupMismatch)
}

fn source_manifest(manifest: PartitionBackupManifest) -> BackupSourceManifest {
    BackupSourceManifest {
        backup_id: manifest.backup_id,
        partition_id: manifest.partition_id,
        mesh_id: manifest.mesh_id,
        last_log_index: manifest.applied_position.index,
        last_log_term: manifest.applied_position.term,
        state_revision: manifest.state_revision.get(),
        schema_version: manifest.schema_version,
        byte_length: manifest.byte_length,
        digest: manifest.digest,
        created_at: manifest.created_at,
    }
}

fn validate_create_paths(paths: EncryptedBackupPaths<'_>) -> Result<(), RepositoryError> {
    if paths.plaintext_staging == paths.encrypted_destination {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_restore_paths(paths: EncryptedRestorePaths<'_>) -> Result<(), RepositoryError> {
    if paths.encrypted_source == paths.plaintext_staging
        || paths.encrypted_source == paths.restored_destination
        || paths.plaintext_staging == paths.restored_destination
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn remove_plaintext_staging(staging: &Path) -> Result<(), RepositoryError> {
    std::fs::remove_file(staging).map_err(RepositoryError::Io)
}

fn remove_staging_if_present(staging: &Path) -> Result<(), RepositoryError> {
    match staging.try_exists() {
        Ok(true) => remove_plaintext_staging(staging),
        Ok(false) => Ok(()),
        Err(error) => Err(RepositoryError::Io(error)),
    }
}
