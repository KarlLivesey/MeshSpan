// SPDX-License-Identifier: GPL-2.0-only

//! SQLite opening, migration, identity binding and startup integrity checks.

use std::path::Path;
use std::time::Duration;

use meshspan_domain::{BackupDestinationId, UnixMicros};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::{to_i64, to_u64};
use crate::directory_provider::DirectoryBackupProviderError;

const SCHEMA: &str = include_str!("../../../schema/directory_provider/001_initial.sql");
const SCHEMA_VERSION: u32 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn open(
    file_path: &Path,
    destination_id: BackupDestinationId,
    provider_generation: u64,
    maximum_bytes: u64,
    opened_at: UnixMicros,
) -> Result<Connection, DirectoryBackupProviderError> {
    let mut connection = open_connection(file_path)?;
    migrate(&mut connection, opened_at)?;
    bind_identity(
        &mut connection,
        destination_id,
        provider_generation,
        maximum_bytes,
        opened_at,
    )?;
    check_integrity(&connection)?;
    Ok(connection)
}

fn open_connection(file_path: &Path) -> Result<Connection, DirectoryBackupProviderError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(file_path, flags)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(connection)
}

fn migrate(
    connection: &mut Connection,
    applied_at: UnixMicros,
) -> Result<(), DirectoryBackupProviderError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, migration_digest, applied_at)
             VALUES (1, ?1, ?2)",
            params![
                Sha256::digest(SCHEMA.as_bytes()).as_slice(),
                applied_at.get()
            ],
        )?;
        transaction.commit()?;
    } else if version != SCHEMA_VERSION {
        return Err(DirectoryBackupProviderError::SchemaMismatch);
    }
    let stored: Vec<u8> = connection.query_row(
        "SELECT migration_digest FROM schema_migrations WHERE version = 1",
        [],
        |row| row.get(0),
    )?;
    if stored.as_slice() != Sha256::digest(SCHEMA.as_bytes()).as_slice() {
        return Err(DirectoryBackupProviderError::SchemaMismatch);
    }
    Ok(())
}

fn bind_identity(
    connection: &mut Connection,
    destination_id: BackupDestinationId,
    provider_generation: u64,
    maximum_bytes: u64,
    opened_at: UnixMicros,
) -> Result<(), DirectoryBackupProviderError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT OR IGNORE INTO provider_state(
            singleton, destination_id, provider_generation, maximum_bytes, created_at
         ) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            destination_id.as_bytes().as_slice(),
            to_i64(provider_generation)?,
            to_i64(maximum_bytes)?,
            opened_at.get(),
        ],
    )?;
    let stored = transaction.query_row(
        "SELECT destination_id, provider_generation, maximum_bytes
         FROM provider_state WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    if stored.0.as_slice() != destination_id.as_bytes()
        || to_u64(stored.1)? != provider_generation
        || to_u64(stored.2)? != maximum_bytes
    {
        return Err(DirectoryBackupProviderError::IdentityMismatch);
    }
    transaction.commit()?;
    Ok(())
}

fn check_integrity(connection: &Connection) -> Result<(), DirectoryBackupProviderError> {
    let result: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    let foreign_key_violation = connection
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()?;
    if result == "ok" && foreign_key_violation.is_none() {
        Ok(())
    } else {
        Err(DirectoryBackupProviderError::Corrupt)
    }
}
