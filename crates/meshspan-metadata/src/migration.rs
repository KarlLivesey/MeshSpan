// SPDX-License-Identifier: GPL-2.0-only

//! Numbered transactional migration runner with immutable digest verification.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAXIMUM_MIGRATIONS: usize = 256;

pub(crate) const PARTITION_SCHEMA_VERSION: u32 = 14;
pub(crate) const LOCAL_SCHEMA_VERSION: u32 = 1;

const PARTITION_MIGRATIONS: [Migration; 14] = [
    Migration {
        version: 1,
        sql: include_str!("../schema/partition/001_initial.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../schema/partition/002_roles.sql"),
    },
    Migration {
        version: 3,
        sql: include_str!("../schema/partition/003_component_rollout.sql"),
    },
    Migration {
        version: 4,
        sql: include_str!("../schema/partition/004_cluster_enrollment.sql"),
    },
    Migration {
        version: 5,
        sql: include_str!("../schema/partition/005_partition_routing.sql"),
    },
    Migration {
        version: 6,
        sql: include_str!("../schema/partition/006_active_quorum_plan.sql"),
    },
    Migration {
        version: 7,
        sql: include_str!("../schema/partition/007_converged_volume_heads.sql"),
    },
    Migration {
        version: 8,
        sql: include_str!("../schema/partition/008_volume_snapshots.sql"),
    },
    Migration {
        version: 9,
        sql: include_str!("../schema/partition/009_version_retention.sql"),
    },
    Migration {
        version: 10,
        sql: include_str!("../schema/partition/010_snapshot_expiry_requests.sql"),
    },
    Migration {
        version: 11,
        sql: include_str!("../schema/partition/011_snapshot_schedules.sql"),
    },
    Migration {
        version: 12,
        sql: include_str!("../schema/partition/012_snapshot_retention_selection.sql"),
    },
    Migration {
        version: 13,
        sql: include_str!("../schema/partition/013_snapshot_restores.sql"),
    },
    Migration {
        version: PARTITION_SCHEMA_VERSION,
        sql: include_str!("../schema/partition/014_snapshot_root_removals.sql"),
    },
];

const LOCAL_MIGRATIONS: [Migration; 1] = [Migration {
    version: LOCAL_SCHEMA_VERSION,
    sql: include_str!("../schema/local/001_initial.sql"),
}];

#[derive(Clone, Copy)]
struct Migration {
    version: u32,
    sql: &'static str,
}

/// Stable persistence and migration failure categories.
#[derive(Debug, Error)]
pub enum MetadataStoreError {
    /// SQLite rejected an operation or reported an IO/database failure.
    #[error("metadata database operation failed")]
    Sqlite(#[from] rusqlite::Error),
    /// An applied migration has different bytes from this build.
    #[error("applied migration {version} has a different digest")]
    MigrationDigestMismatch {
        /// Version whose immutable migration bytes changed.
        version: u32,
    },
    /// The database contains a schema version newer than this build.
    #[error("database schema version {found} is newer than this build")]
    UnsupportedSchema {
        /// Newer version found in the database.
        found: u32,
    },
    /// Applied migration versions are not a contiguous prefix.
    #[error("database migration history is incomplete or out of order")]
    InvalidMigrationHistory,
    /// The database belongs to another partition or node.
    #[error("database identity does not match the requested identity")]
    IdentityMismatch,
    /// SQLite or relational invariants reported corruption.
    #[error("database integrity verification failed")]
    IntegrityFailed,
}

pub(crate) fn migrate_partition(
    connection: &mut Connection,
    applied_at: i64,
) -> Result<(), MetadataStoreError> {
    apply_migrations(connection, &PARTITION_MIGRATIONS, applied_at)
}

pub(crate) fn migrate_local(
    connection: &mut Connection,
    applied_at: i64,
) -> Result<(), MetadataStoreError> {
    apply_migrations(connection, &LOCAL_MIGRATIONS, applied_at)
}

fn apply_migrations(
    connection: &mut Connection,
    migrations: &[Migration],
    applied_at: i64,
) -> Result<(), MetadataStoreError> {
    validate_migration_catalogue(migrations)?;
    let applied = read_applied_migrations(connection)?;
    validate_applied_history(&applied, migrations)?;

    for migration in migrations {
        if let Some(digest) = applied.get(&migration.version) {
            if digest.as_slice() != migration_digest(migration.sql) {
                return Err(MetadataStoreError::MigrationDigestMismatch {
                    version: migration.version,
                });
            }
            continue;
        }
        apply_one(connection, *migration, applied_at)?;
    }
    Ok(())
}

fn apply_one(
    connection: &mut Connection,
    migration: Migration,
    applied_at: i64,
) -> Result<(), MetadataStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(migration.sql)?;
    transaction.execute(
        "INSERT INTO schema_migrations(version, migration_digest, applied_at) VALUES (?1, ?2, ?3)",
        params![
            migration.version,
            migration_digest(migration.sql),
            applied_at
        ],
    )?;
    transaction.pragma_update(None, "user_version", migration.version)?;
    transaction.commit()?;
    Ok(())
}

fn read_applied_migrations(
    connection: &Connection,
) -> Result<BTreeMap<u32, Vec<u8>>, MetadataStoreError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_migrations' LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        return Ok(BTreeMap::new());
    }

    let mut statement = connection.prepare(
        "SELECT version, migration_digest FROM schema_migrations ORDER BY version LIMIT ?1",
    )?;
    let maximum_rows = i64::try_from(MAXIMUM_MIGRATIONS + 1)
        .map_err(|_| MetadataStoreError::InvalidMigrationHistory)?;
    let rows = statement.query_map([maximum_rows], |row| {
        Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut applied = BTreeMap::new();
    for row in rows {
        let (version, digest) = row?;
        if applied.insert(version, digest).is_some() || applied.len() > MAXIMUM_MIGRATIONS {
            return Err(MetadataStoreError::InvalidMigrationHistory);
        }
    }
    Ok(applied)
}

fn validate_applied_history(
    applied: &BTreeMap<u32, Vec<u8>>,
    migrations: &[Migration],
) -> Result<(), MetadataStoreError> {
    let latest = migrations.last().map_or(0, |migration| migration.version);
    if let Some(found) = applied
        .keys()
        .next_back()
        .copied()
        .filter(|value| *value > latest)
    {
        return Err(MetadataStoreError::UnsupportedSchema { found });
    }
    for (index, version) in applied.keys().enumerate() {
        let expected =
            u32::try_from(index + 1).map_err(|_| MetadataStoreError::InvalidMigrationHistory)?;
        if *version != expected {
            return Err(MetadataStoreError::InvalidMigrationHistory);
        }
    }
    Ok(())
}

fn validate_migration_catalogue(migrations: &[Migration]) -> Result<(), MetadataStoreError> {
    if migrations.is_empty() || migrations.len() > MAXIMUM_MIGRATIONS {
        return Err(MetadataStoreError::InvalidMigrationHistory);
    }
    for (index, migration) in migrations.iter().enumerate() {
        let expected =
            u32::try_from(index + 1).map_err(|_| MetadataStoreError::InvalidMigrationHistory)?;
        if migration.version != expected || migration.sql.trim().is_empty() {
            return Err(MetadataStoreError::InvalidMigrationHistory);
        }
    }
    Ok(())
}

fn migration_digest(sql: &str) -> [u8; 32] {
    Sha256::digest(sql.as_bytes()).into()
}

#[cfg(test)]
pub(crate) fn partition_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[0].sql)
}

#[cfg(test)]
pub(crate) fn partition_roles_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[1].sql)
}

#[cfg(test)]
pub(crate) fn partition_component_rollout_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[2].sql)
}

#[cfg(test)]
pub(crate) fn partition_cluster_enrollment_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[3].sql)
}

#[cfg(test)]
pub(crate) fn partition_routing_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[4].sql)
}

#[cfg(test)]
pub(crate) fn partition_active_quorum_plan_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[5].sql)
}

#[cfg(test)]
pub(crate) fn partition_volume_heads_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[6].sql)
}

#[cfg(test)]
pub(crate) fn partition_volume_snapshots_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[7].sql)
}

#[cfg(test)]
pub(crate) fn partition_version_retention_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[8].sql)
}

#[cfg(test)]
pub(crate) fn partition_snapshot_expiry_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[9].sql)
}

#[cfg(test)]
pub(crate) fn partition_snapshot_schedules_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[10].sql)
}

#[cfg(test)]
pub(crate) fn partition_snapshot_retention_selection_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[11].sql)
}

#[cfg(test)]
pub(crate) fn partition_snapshot_restores_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[12].sql)
}

#[cfg(test)]
pub(crate) fn partition_snapshot_root_removals_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[13].sql)
}

#[cfg(test)]
pub(crate) fn local_migration_digest() -> [u8; 32] {
    migration_digest(LOCAL_MIGRATIONS[0].sql)
}
