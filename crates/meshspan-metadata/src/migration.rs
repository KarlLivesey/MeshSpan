// SPDX-License-Identifier: GPL-2.0-only

//! Numbered transactional migration runner with immutable digest verification.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAXIMUM_MIGRATIONS: usize = 256;

pub(crate) const PARTITION_SCHEMA_VERSION: u32 = 46;
pub(crate) const LOCAL_SCHEMA_VERSION: u32 = 7;

const PARTITION_MIGRATIONS: [Migration; 46] = [
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
        version: 14,
        sql: include_str!("../schema/partition/014_snapshot_root_removals.sql"),
    },
    Migration {
        version: 15,
        sql: include_str!("../schema/partition/015_version_cleanup_intents.sql"),
    },
    Migration {
        version: 16,
        sql: include_str!("../schema/partition/016_version_cleanup_attestations.sql"),
    },
    Migration {
        version: 17,
        sql: include_str!("../schema/partition/017_version_cleanup_manifest_root.sql"),
    },
    Migration {
        version: 18,
        sql: include_str!("../schema/partition/018_version_cleanup_root_set_digest.sql"),
    },
    Migration {
        version: 19,
        sql: include_str!("../schema/partition/019_version_cleanup_finalisation.sql"),
    },
    Migration {
        version: 20,
        sql: include_str!("../schema/partition/020_version_cleanup_inventory.sql"),
    },
    Migration {
        version: 21,
        sql: include_str!("../schema/partition/021_version_cleanup_permits.sql"),
    },
    Migration {
        version: 22,
        sql: include_str!("../schema/partition/022_version_cleanup_completions.sql"),
    },
    Migration {
        version: 23,
        sql: include_str!("../schema/partition/023_version_cleanup_reclamations.sql"),
    },
    Migration {
        version: 24,
        sql: include_str!("../schema/partition/024_cleanup_target_ownership.sql"),
    },
    Migration {
        version: 25,
        sql: include_str!("../schema/partition/025_namespace_inheritance_boundaries.sql"),
    },
    Migration {
        version: 26,
        sql: include_str!("../schema/partition/026_access_revocation_evidence.sql"),
    },
    Migration {
        version: 27,
        sql: include_str!("../schema/partition/027_principal_lifecycle.sql"),
    },
    Migration {
        version: 28,
        sql: include_str!("../schema/partition/028_access_administration_queries.sql"),
    },
    Migration {
        version: 29,
        sql: include_str!("../schema/partition/029_federation_authority.sql"),
    },
    Migration {
        version: 30,
        sql: include_str!("../schema/partition/030_federation_relationship_history.sql"),
    },
    Migration {
        version: 31,
        sql: include_str!("../schema/partition/031_federation_grant_history.sql"),
    },
    Migration {
        version: 32,
        sql: include_str!("../schema/partition/032_federation_governance_proofs.sql"),
    },
    Migration {
        version: 33,
        sql: include_str!("../schema/partition/033_federation_actor_attestation_history.sql"),
    },
    Migration {
        version: 34,
        sql: include_str!("../schema/partition/034_federation_ownership_succession.sql"),
    },
    Migration {
        version: 35,
        sql: include_str!("../schema/partition/035_federation_quarantine_proofs.sql"),
    },
    Migration {
        version: 36,
        sql: include_str!("../schema/partition/036_root_delegation_directory.sql"),
    },
    Migration {
        version: 37,
        sql: include_str!("../schema/partition/037_federation_relationship_evidence_guards.sql"),
    },
    Migration {
        version: 38,
        sql: include_str!("../schema/partition/038_federation_grant_evidence.sql"),
    },
    Migration {
        version: 39,
        sql: include_str!("../schema/partition/039_federation_grant_paging.sql"),
    },
    Migration {
        version: 40,
        sql: include_str!("../schema/partition/040_federation_storage_allocations.sql"),
    },
    Migration {
        version: 41,
        sql: include_str!("../schema/partition/041_principal_inactive_quarantine.sql"),
    },
    Migration {
        version: 42,
        sql: include_str!("../schema/partition/042_typed_authentication_methods.sql"),
    },
    Migration {
        version: 43,
        sql: include_str!("../schema/partition/043_authentication_method_events.sql"),
    },
    Migration {
        version: 44,
        sql: include_str!("../schema/partition/044_authentication_credential_constraints.sql"),
    },
    Migration {
        version: 45,
        sql: include_str!("../schema/partition/045_authentication_session_factors.sql"),
    },
    Migration {
        version: PARTITION_SCHEMA_VERSION,
        sql: include_str!("../schema/partition/046_authentication_policies.sql"),
    },
];

const LOCAL_MIGRATIONS: [Migration; 7] = [
    Migration {
        version: 1,
        sql: include_str!("../schema/local/001_initial.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../schema/local/002_federation_authority_cache.sql"),
    },
    Migration {
        version: 3,
        sql: include_str!("../schema/local/003_federation_storage_quota.sql"),
    },
    Migration {
        version: 4,
        sql: include_str!("../schema/local/004_federation_storage_capabilities.sql"),
    },
    Migration {
        version: 5,
        sql: include_str!("../schema/local/005_federation_storage_lifecycle.sql"),
    },
    Migration {
        version: 6,
        sql: include_str!("../schema/local/006_federation_storage_scrubs.sql"),
    },
    Migration {
        version: LOCAL_SCHEMA_VERSION,
        sql: include_str!("../schema/local/007_local_claim_bundles.sql"),
    },
];

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

#[cfg(test)]
pub(crate) fn migrate_partition_through(
    connection: &mut Connection,
    version: usize,
    applied_at: i64,
) -> Result<(), MetadataStoreError> {
    let migrations = PARTITION_MIGRATIONS
        .get(..version)
        .ok_or(MetadataStoreError::InvalidMigrationHistory)?;
    apply_migrations(connection, migrations, applied_at)
}

#[cfg(test)]
pub(crate) fn migrate_local_through(
    connection: &mut Connection,
    version: usize,
    applied_at: i64,
) -> Result<(), MetadataStoreError> {
    let migrations = LOCAL_MIGRATIONS
        .get(..version)
        .ok_or(MetadataStoreError::InvalidMigrationHistory)?;
    apply_migrations(connection, migrations, applied_at)
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
pub(crate) fn partition_version_cleanup_intents_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[14].sql)
}

#[cfg(test)]
pub(crate) fn partition_version_cleanup_attestations_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[15].sql)
}

#[cfg(test)]
pub(crate) fn partition_version_cleanup_manifest_root_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[16].sql)
}

#[cfg(test)]
pub(crate) fn partition_version_cleanup_root_set_digest_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[17].sql)
}

#[cfg(test)]
pub(crate) fn partition_version_cleanup_finalisation_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[18].sql)
}

#[cfg(test)]
pub(crate) fn partition_version_cleanup_inventory_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[19].sql)
}

#[cfg(test)]
pub(crate) fn partition_version_cleanup_permits_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[20].sql)
}

#[cfg(test)]
pub(crate) fn partition_version_cleanup_completions_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[21].sql)
}

#[cfg(test)]
pub(crate) fn partition_version_cleanup_reclamations_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[22].sql)
}

#[cfg(test)]
pub(crate) fn partition_cleanup_target_ownership_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[23].sql)
}

#[cfg(test)]
pub(crate) fn partition_namespace_inheritance_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[24].sql)
}

#[cfg(test)]
pub(crate) fn partition_access_revocation_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[25].sql)
}

#[cfg(test)]
pub(crate) fn partition_principal_lifecycle_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[26].sql)
}

#[cfg(test)]
pub(crate) fn partition_access_administration_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[27].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_authority_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[28].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_relationship_history_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[29].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_grant_history_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[30].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_governance_proof_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[31].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_actor_attestation_history_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[32].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_ownership_succession_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[33].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_quarantine_proof_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[34].sql)
}

#[cfg(test)]
pub(crate) fn partition_root_delegation_directory_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[35].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_relationship_evidence_guard_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[36].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_grant_evidence_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[37].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_grant_paging_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[38].sql)
}

#[cfg(test)]
pub(crate) fn partition_federation_storage_allocation_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[39].sql)
}

#[cfg(test)]
pub(crate) fn partition_principal_inactive_quarantine_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[40].sql)
}

#[cfg(test)]
pub(crate) fn partition_typed_authentication_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[41].sql)
}

#[cfg(test)]
pub(crate) fn partition_authentication_method_events_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[42].sql)
}

#[cfg(test)]
pub(crate) fn partition_authentication_credential_constraints_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[43].sql)
}

#[cfg(test)]
pub(crate) fn partition_authentication_session_factors_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[44].sql)
}

#[cfg(test)]
pub(crate) fn partition_authentication_policy_migration_digest() -> [u8; 32] {
    migration_digest(PARTITION_MIGRATIONS[45].sql)
}

#[cfg(test)]
pub(crate) fn local_migration_digest() -> [u8; 32] {
    migration_digest(LOCAL_MIGRATIONS[0].sql)
}

#[cfg(test)]
pub(crate) fn local_federation_authority_cache_migration_digest() -> [u8; 32] {
    migration_digest(LOCAL_MIGRATIONS[1].sql)
}

#[cfg(test)]
pub(crate) fn local_federation_storage_quota_migration_digest() -> [u8; 32] {
    migration_digest(LOCAL_MIGRATIONS[2].sql)
}

#[cfg(test)]
pub(crate) fn local_federation_storage_capability_migration_digest() -> [u8; 32] {
    migration_digest(LOCAL_MIGRATIONS[3].sql)
}

#[cfg(test)]
pub(crate) fn local_federation_storage_lifecycle_migration_digest() -> [u8; 32] {
    migration_digest(LOCAL_MIGRATIONS[4].sql)
}

#[cfg(test)]
pub(crate) fn local_federation_storage_scrub_migration_digest() -> [u8; 32] {
    migration_digest(LOCAL_MIGRATIONS[5].sql)
}

#[cfg(test)]
pub(crate) fn local_claim_bundle_migration_digest() -> [u8; 32] {
    migration_digest(LOCAL_MIGRATIONS[6].sql)
}
