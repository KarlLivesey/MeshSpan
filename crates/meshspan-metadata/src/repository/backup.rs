// SPDX-License-Identifier: GPL-2.0-only

//! Exact-state online backup creation and fail-closed staged restoration.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use meshspan_domain::{BackupId, PartitionId, Revision, UnixMicros};
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

pub(super) fn create_partition_backup(
    database: &PartitionDatabase,
    backup_id: BackupId,
    destination: &Path,
    created_at: UnixMicros,
) -> Result<PartitionBackupManifest, RepositoryError> {
    require_absent(destination)?;
    let state = read_state(database.connection())?;
    database.connection().backup(MAIN_DB, destination, None)?;
    let (byte_length, digest) = hash_file(destination)?;
    let manifest = PartitionBackupManifest {
        backup_id,
        partition_id: database.partition_id(),
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
