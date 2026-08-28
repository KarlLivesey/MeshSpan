// SPDX-License-Identifier: GPL-2.0-only

//! Database ownership, hardening, identity binding and integrity checks.

use std::path::Path;
use std::time::Duration;

use meshspan_domain::{NodeId, PartitionId, UnixMicros};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::migration::{
    LOCAL_SCHEMA_VERSION, MetadataStoreError, PARTITION_SCHEMA_VERSION, migrate_local,
    migrate_partition,
};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Successful bounded SQLite and relational integrity result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityReport {
    /// Schema version checked by the operation.
    pub schema_version: u32,
    /// Whether SQLite's structural integrity result was exactly `ok`.
    pub sqlite_ok: bool,
    /// Whether no foreign-key violation row exists.
    pub foreign_keys_ok: bool,
}

/// One authoritative partition database with identity fixed at open.
pub struct PartitionDatabase {
    connection: Connection,
    partition_id: PartitionId,
}

impl PartitionDatabase {
    /// Opens, hardens, migrates and identity-binds one partition database.
    ///
    /// # Errors
    ///
    /// Rejects SQLite failure, migration drift/newer schema or a different stored partition ID.
    pub fn open(
        file_path: &Path,
        partition_id: PartitionId,
        migration_time: UnixMicros,
    ) -> Result<Self, MetadataStoreError> {
        let mut connection = open_connection(file_path)?;
        migrate_partition(&mut connection, migration_time.get())?;
        bind_partition_identity(&mut connection, partition_id)?;
        let database = Self {
            connection,
            partition_id,
        };
        database.check_integrity()?;
        Ok(database)
    }

    /// Returns the immutable partition identity verified at open.
    #[must_use]
    pub const fn partition_id(&self) -> PartitionId {
        self.partition_id
    }

    /// Returns the current compiled partition schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        PARTITION_SCHEMA_VERSION
    }

    /// Runs bounded structural and foreign-key verification.
    ///
    /// # Errors
    ///
    /// Fails closed for any non-`ok` integrity value or first foreign-key violation.
    pub fn check_integrity(&self) -> Result<IntegrityReport, MetadataStoreError> {
        check_integrity(&self.connection, PARTITION_SCHEMA_VERSION)
    }

    pub(crate) const fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub(crate) const fn connection(&self) -> &Connection {
        &self.connection
    }
}

/// One daemon-local database with identity fixed at open.
pub struct LocalDatabase {
    connection: Connection,
    node_id: NodeId,
}

impl LocalDatabase {
    /// Opens, hardens, migrates and identity-binds one daemon-local database.
    ///
    /// # Errors
    ///
    /// Rejects SQLite failure, migration drift/newer schema or a different stored node ID.
    pub fn open(
        file_path: &Path,
        node_id: NodeId,
        migration_time: UnixMicros,
    ) -> Result<Self, MetadataStoreError> {
        let mut connection = open_connection(file_path)?;
        migrate_local(&mut connection, migration_time.get())?;
        bind_local_identity(&mut connection, node_id)?;
        let database = Self {
            connection,
            node_id,
        };
        database.check_integrity()?;
        Ok(database)
    }

    /// Returns the immutable node identity verified at open.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the current compiled local schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        LOCAL_SCHEMA_VERSION
    }

    /// Runs bounded structural and foreign-key verification.
    ///
    /// # Errors
    ///
    /// Fails closed for any non-`ok` integrity value or first foreign-key violation.
    pub fn check_integrity(&self) -> Result<IntegrityReport, MetadataStoreError> {
        check_integrity(&self.connection, LOCAL_SCHEMA_VERSION)
    }
}

fn open_connection(file_path: &Path) -> Result<Connection, MetadataStoreError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(file_path, flags)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA recursive_triggers = OFF;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA temp_store = MEMORY;",
    )?;
    Ok(connection)
}

fn bind_partition_identity(
    connection: &mut Connection,
    partition_id: PartitionId,
) -> Result<(), MetadataStoreError> {
    let partition_bytes = partition_id.as_bytes();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT OR IGNORE INTO applied_state(
            singleton, partition_id, last_log_index, last_log_term, state_revision, schema_version
         ) VALUES (1, ?1, 0, 0, 0, ?2)",
        params![partition_bytes.as_slice(), PARTITION_SCHEMA_VERSION],
    )?;
    let stored: Vec<u8> = transaction.query_row(
        "SELECT partition_id FROM applied_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if stored.as_slice() != partition_bytes {
        return Err(MetadataStoreError::IdentityMismatch);
    }
    transaction.execute(
        "UPDATE applied_state SET schema_version = ?1 WHERE singleton = 1",
        [PARTITION_SCHEMA_VERSION],
    )?;
    transaction.commit()?;
    Ok(())
}

fn bind_local_identity(
    connection: &mut Connection,
    node_id: NodeId,
) -> Result<(), MetadataStoreError> {
    let node_bytes = node_id.as_bytes();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT OR IGNORE INTO local_identity(singleton, node_id, schema_version)
         VALUES (1, ?1, ?2)",
        params![node_bytes.as_slice(), LOCAL_SCHEMA_VERSION],
    )?;
    let stored: Vec<u8> = transaction.query_row(
        "SELECT node_id FROM local_identity WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if stored.as_slice() != node_bytes {
        return Err(MetadataStoreError::IdentityMismatch);
    }
    transaction.commit()?;
    Ok(())
}

fn check_integrity(
    connection: &Connection,
    schema_version: u32,
) -> Result<IntegrityReport, MetadataStoreError> {
    let quick_check: String =
        connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    let foreign_key_violation = connection
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()?;
    let user_version: u32 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if quick_check != "ok" || foreign_key_violation.is_some() || user_version != schema_version {
        return Err(MetadataStoreError::IntegrityFailed);
    }
    Ok(IntegrityReport {
        schema_version,
        sqlite_ok: true,
        foreign_keys_ok: true,
    })
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{NodeId, PartitionId, UnixMicros};
    use rusqlite::params;
    use tempfile::tempdir;

    use super::{LocalDatabase, MetadataStoreError, PartitionDatabase};
    use crate::migration::{
        local_migration_digest, partition_migration_digest, partition_roles_migration_digest,
    };

    #[test]
    fn partition_database_migrates_reopens_and_rejects_another_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("partition.sqlite3");
        let first = PartitionId::from_bytes([1; 16])?;
        let second = PartitionId::from_bytes([2; 16])?;
        let database = PartitionDatabase::open(&file_path, first, UnixMicros::new(10))?;
        assert_eq!(database.partition_id(), first);
        assert_eq!(database.check_integrity()?.schema_version, 2);
        drop(database);
        assert!(PartitionDatabase::open(&file_path, first, UnixMicros::new(11)).is_ok());
        assert!(matches!(
            PartitionDatabase::open(&file_path, second, UnixMicros::new(11)),
            Err(MetadataStoreError::IdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn local_database_migrates_reopens_and_rejects_another_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("local.sqlite3");
        let first = NodeId::from_bytes([3; 16])?;
        let second = NodeId::from_bytes([4; 16])?;
        let database = LocalDatabase::open(&file_path, first, UnixMicros::new(10))?;
        assert_eq!(database.node_id(), first);
        drop(database);
        assert!(LocalDatabase::open(&file_path, first, UnixMicros::new(11)).is_ok());
        assert!(matches!(
            LocalDatabase::open(&file_path, second, UnixMicros::new(11)),
            Err(MetadataStoreError::IdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn migration_digest_drift_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("partition.sqlite3");
        let partition_id = PartitionId::from_bytes([5; 16])?;
        let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(10))?;
        database.connection().execute(
            "UPDATE schema_migrations SET migration_digest = ?1 WHERE version = 1",
            params![vec![9_u8; 32]],
        )?;
        drop(database);
        assert!(matches!(
            PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(11)),
            Err(MetadataStoreError::MigrationDigestMismatch { version: 1 })
        ));
        Ok(())
    }

    #[test]
    fn initial_migration_digest_is_a_committed_compatibility_value() {
        assert_eq!(
            partition_migration_digest(),
            [
                0x08, 0x57, 0xd9, 0x70, 0x44, 0xdc, 0x98, 0x19, 0x3e, 0x28, 0xb7, 0x0a, 0x2b, 0xcf,
                0xa0, 0x4c, 0x29, 0xa6, 0xcc, 0x76, 0xc7, 0x67, 0x73, 0x0d, 0xa6, 0x5a, 0xa4, 0xcd,
                0x39, 0x8d, 0x27, 0x31,
            ]
        );
        assert_eq!(
            local_migration_digest(),
            [
                0x6d, 0x94, 0xdb, 0x99, 0x71, 0xa3, 0xc3, 0x74, 0x3f, 0xce, 0xf1, 0x6b, 0x7c, 0xb3,
                0x30, 0xdf, 0xd0, 0x7d, 0x63, 0xf7, 0x69, 0xf7, 0xdb, 0xe3, 0x9f, 0x72, 0x9d, 0x2d,
                0xbb, 0x53, 0xa5, 0x10,
            ]
        );
        assert_eq!(
            partition_roles_migration_digest(),
            [
                0x64, 0x03, 0x34, 0x75, 0x75, 0x48, 0x36, 0x42, 0x6b, 0x9c, 0x8e, 0x1d, 0xca, 0xad,
                0xbb, 0x85, 0x6b, 0x00, 0xc1, 0x3a, 0x36, 0xa3, 0xe5, 0xc7, 0xef, 0xfe, 0x2d, 0x51,
                0x84, 0xf8, 0x75, 0xd1,
            ]
        );
    }

    #[test]
    fn strict_relational_constraints_reject_malformed_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("partition.sqlite3");
        let partition_id = PartitionId::from_bytes([6; 16])?;
        let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(10))?;
        let rejected = database.connection().execute(
            "INSERT INTO principals(
                principal_id, principal_kind, display_name, canonical_name,
                state, created_at, revision
             ) VALUES (?1, 1, 'user', 'user', 1, 10, 1)",
            params![vec![1_u8; 15]],
        );
        assert!(rejected.is_err());
        assert!(database.check_integrity()?.foreign_keys_ok);
        Ok(())
    }
}
