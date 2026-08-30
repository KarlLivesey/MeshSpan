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

    pub(crate) const fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) const fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
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

    use super::{LocalDatabase, MetadataStoreError, PartitionDatabase, open_connection};
    use crate::migration::{
        local_federation_authority_cache_migration_digest,
        local_federation_storage_capability_migration_digest,
        local_federation_storage_lifecycle_migration_digest,
        local_federation_storage_quota_migration_digest,
        local_federation_storage_scrub_migration_digest, local_migration_digest, migrate_local,
        migrate_local_through, migrate_partition, migrate_partition_through,
        partition_access_administration_migration_digest,
        partition_access_revocation_migration_digest,
        partition_active_quorum_plan_migration_digest,
        partition_cleanup_target_ownership_migration_digest,
        partition_cluster_enrollment_migration_digest,
        partition_component_rollout_migration_digest,
        partition_federation_authority_migration_digest,
        partition_federation_governance_proof_migration_digest,
        partition_federation_grant_evidence_migration_digest,
        partition_federation_grant_history_migration_digest,
        partition_federation_grant_paging_migration_digest,
        partition_federation_ownership_succession_migration_digest,
        partition_federation_principal_history_migration_digest,
        partition_federation_quarantine_proof_migration_digest,
        partition_federation_relationship_evidence_guard_migration_digest,
        partition_federation_relationship_history_migration_digest,
        partition_federation_storage_allocation_migration_digest, partition_migration_digest,
        partition_namespace_inheritance_migration_digest,
        partition_principal_lifecycle_migration_digest, partition_roles_migration_digest,
        partition_root_delegation_directory_migration_digest, partition_routing_migration_digest,
        partition_snapshot_expiry_migration_digest, partition_snapshot_restores_migration_digest,
        partition_snapshot_retention_selection_migration_digest,
        partition_snapshot_root_removals_migration_digest,
        partition_snapshot_schedules_migration_digest,
        partition_version_cleanup_attestations_migration_digest,
        partition_version_cleanup_completions_migration_digest,
        partition_version_cleanup_finalisation_migration_digest,
        partition_version_cleanup_intents_migration_digest,
        partition_version_cleanup_inventory_migration_digest,
        partition_version_cleanup_manifest_root_migration_digest,
        partition_version_cleanup_permits_migration_digest,
        partition_version_cleanup_reclamations_migration_digest,
        partition_version_cleanup_root_set_digest_migration_digest,
        partition_version_retention_migration_digest, partition_volume_heads_migration_digest,
        partition_volume_snapshots_migration_digest,
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
        assert_eq!(database.check_integrity()?.schema_version, 40);
        drop(database);
        assert!(PartitionDatabase::open(&file_path, first, UnixMicros::new(11)).is_ok());
        assert!(matches!(
            PartitionDatabase::open(&file_path, second, UnixMicros::new(11)),
            Err(MetadataStoreError::IdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn principal_lifecycle_migration_backfills_existing_principals()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory
            .path()
            .join("principal-lifecycle-migration.sqlite3");
        let mut connection = open_connection(&file_path)?;
        migrate_partition_through(&mut connection, 26, 10)?;
        let principal = [44_u8; 16];
        connection.execute(
            "INSERT INTO principals(
                principal_id, principal_kind, display_name, canonical_name, state,
                created_at, retired_at, revision
             ) VALUES (?1, 1, 'Existing user', 'existing user', 1, 20, NULL, 7)",
            [principal.as_slice()],
        )?;

        migrate_partition(&mut connection, 30)?;
        let event: (i64, Option<i64>, i64, Option<String>, Vec<u8>, i64, i64) = connection
            .query_row(
                "SELECT event_kind, prior_state, resulting_state, reason,
                        changed_by, changed_at, revision
                 FROM principal_lifecycle_events WHERE principal_id = ?1",
                [principal.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )?;
        assert_eq!(event, (1, None, 1, None, principal.to_vec(), 20, 7));
        assert_eq!(
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
            40
        );
        Ok(())
    }

    #[test]
    fn grant_evidence_migration_marks_discarded_legacy_reason_as_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("grant-evidence-migration.sqlite3");
        let mut connection = open_connection(&file_path)?;
        migrate_partition_through(&mut connection, 37, 10)?;
        let local_mesh = [50_u8; 16];
        let remote_mesh = [51_u8; 16];
        let relationship = [52_u8; 16];
        let grant = [53_u8; 16];
        connection.execute(
            "INSERT INTO meshes(
                mesh_id, display_name, canonical_name, created_at,
                configuration_revision, identity_revision, namespace_revision, revision
             ) VALUES (?1, 'Local', 'local', 1, 1, 1, 1, 1)",
            [local_mesh.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO federation_relationships(
                relationship_id, local_mesh_id, remote_mesh_id, relationship_kind,
                governance_direction, state, authority_epoch, remote_display_name,
                proposed_at, approved_at, restricted_at, revoked_at, retired_at, revision
             ) VALUES (?1, ?2, ?3, 1, 0, 2, 1, 'Remote', 1, 2, NULL, NULL, NULL, 2)",
            params![
                relationship.as_slice(),
                local_mesh.as_slice(),
                remote_mesh.as_slice(),
            ],
        )?;
        connection.execute(
            "INSERT INTO federation_grants(
                grant_id, relationship_id, subject_home_mesh_id, subject_principal_id,
                resource_kind, authority_mesh_id, volume_id, object_id, authority_epoch,
                valid_from, valid_until, state, effective_policy_digest, issued_at,
                revoked_at, revision
             ) VALUES (?1, ?2, ?3, ?4, 4, ?5, NULL, NULL, 1, 1, NULL, 3, ?6, 3, 7, 7)",
            params![
                grant.as_slice(),
                relationship.as_slice(),
                local_mesh.as_slice(),
                [54_u8; 16].as_slice(),
                remote_mesh.as_slice(),
                [55_u8; 32].as_slice(),
            ],
        )?;

        migrate_partition(&mut connection, 20)?;
        let termination: (i64, Option<String>, i64, i64) = connection.query_row(
            "SELECT termination_kind, reason, terminated_at, revision
             FROM federation_grant_terminations WHERE grant_id = ?1",
            [grant.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(termination, (4, None, 7, 7));
        let Err(rejected) = connection.execute(
            "INSERT INTO federation_grant_terminations(
                grant_id, termination_kind, reason, terminated_at, revision
             ) VALUES (?1, 4, NULL, 8, 8)",
            [[56_u8; 16].as_slice()],
        ) else {
            return Err("post-migration legacy evidence was accepted".into());
        };
        assert!(rejected.to_string().contains("migration-only"));
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
        assert_eq!(database.schema_version(), 6);
        drop(database);
        assert!(LocalDatabase::open(&file_path, first, UnixMicros::new(11)).is_ok());
        assert!(matches!(
            LocalDatabase::open(&file_path, second, UnixMicros::new(11)),
            Err(MetadataStoreError::IdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn lifecycle_migration_preserves_exact_federated_scope_and_tenant()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("local-v4.sqlite3");
        let mut connection = open_connection(&file_path)?;
        migrate_local_through(&mut connection, 4, 10)?;
        insert_v4_usage(&connection)?;
        insert_v4_reservation(&connection)?;
        insert_v4_capability(&connection)?;
        insert_v4_shard(&connection)?;

        migrate_local(&mut connection, 20)?;
        let reservation: (Vec<u8>, Vec<u8>) = connection.query_row(
            "SELECT remote_mesh_id, scope_digest FROM local_federation_storage_reservations
             WHERE operation_id = ?1",
            [[12_u8; 16].as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(reservation, (vec![2; 16], vec![13; 32]));
        let shard: (Vec<u8>, Vec<u8>) = connection.query_row(
            "SELECT remote_mesh_id, scope_digest FROM local_federation_storage_shards
             WHERE committed_operation_id = ?1",
            [[12_u8; 16].as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(shard, reservation);
        let foreign_key_failures: i64 =
            connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })?;
        assert_eq!(foreign_key_failures, 0);
        Ok(())
    }

    #[test]
    fn lifecycle_migration_rejects_unscoped_legacy_reservation_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("local-v4-unscoped.sqlite3");
        let mut connection = open_connection(&file_path)?;
        migrate_local_through(&mut connection, 4, 10)?;
        insert_v4_usage(&connection)?;
        insert_v4_reservation(&connection)?;

        assert!(matches!(
            migrate_local(&mut connection, 20),
            Err(MetadataStoreError::Sqlite(_))
        ));
        assert_eq!(
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
            4
        );
        let reservation_count: i64 = connection.query_row(
            "SELECT count(*) FROM local_federation_storage_reservations",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(reservation_count, 1);
        Ok(())
    }

    fn insert_v4_usage(connection: &rusqlite::Connection) -> rusqlite::Result<()> {
        connection.execute(
            "INSERT INTO local_federation_storage_usage(
                allocation_id, relationship_id, remote_mesh_id, grant_id, provider_node_id,
                target_id, target_generation, maximum_bytes, committed_bytes, reserved_bytes,
                valid_from, valid_until, relationship_authority_epoch, grant_revision,
                allocation_revision, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 100, 10, 0, 10, 100, 1, 4, 5, 20)",
            params![
                [1_u8; 16].as_slice(),
                [3_u8; 16].as_slice(),
                [2_u8; 16].as_slice(),
                [4_u8; 16].as_slice(),
                [5_u8; 16].as_slice(),
                [6_u8; 16].as_slice(),
            ],
        )?;
        Ok(())
    }

    fn insert_v4_reservation(connection: &rusqlite::Connection) -> rusqlite::Result<()> {
        connection.execute(
            "INSERT INTO local_federation_storage_reservations(
                operation_id, allocation_id, request_digest, capability_nonce, manifest_digest,
                stripe_index, shard_index, shard_generation, action, maximum_bytes,
                permit_digest, expires_at, state, affected_bytes, charged_bytes, content_digest,
                result_digest, absence_evidence_digest, issued_at, completed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 2, 1, 1, 10, ?6, 30, 2, 10, 10, ?7, ?8,
                       NULL, 20, 21)",
            params![
                [12_u8; 16].as_slice(),
                [1_u8; 16].as_slice(),
                [14_u8; 32].as_slice(),
                [15_u8; 32].as_slice(),
                [16_u8; 32].as_slice(),
                [17_u8; 32].as_slice(),
                [18_u8; 32].as_slice(),
                [19_u8; 32].as_slice(),
            ],
        )?;
        Ok(())
    }

    fn insert_v4_capability(connection: &rusqlite::Connection) -> rusqlite::Result<()> {
        connection.execute(
            "INSERT INTO local_federation_storage_capabilities(
                capability_digest, operation_id, permit_digest, relationship_id, remote_mesh_id,
                provider_mesh_id, allocation_id, grant_id, provider_node_id, target_id,
                target_generation, manifest_digest, stripe_index, shard_index, shard_generation,
                action, maximum_bytes, relationship_authority_epoch, grant_revision,
                allocation_revision, capability_nonce, scope_digest, request_digest, issued_at,
                expires_at, protocol_major, protocol_minor, request_id, trace_id,
                request_deadline, response_replay_nonce, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11, 1, 2, 1, 1, 10,
                       1, 4, 5, ?12, ?13, ?14, 20, 30, 1, 0, ?15, ?16, 30, ?17, 20)",
            params![
                [20_u8; 32].as_slice(),
                [12_u8; 16].as_slice(),
                [17_u8; 32].as_slice(),
                [3_u8; 16].as_slice(),
                [2_u8; 16].as_slice(),
                [21_u8; 16].as_slice(),
                [1_u8; 16].as_slice(),
                [4_u8; 16].as_slice(),
                [5_u8; 16].as_slice(),
                [6_u8; 16].as_slice(),
                [16_u8; 32].as_slice(),
                [15_u8; 32].as_slice(),
                [13_u8; 32].as_slice(),
                [14_u8; 32].as_slice(),
                [22_u8; 16].as_slice(),
                [23_u8; 16].as_slice(),
                [24_u8; 32].as_slice(),
            ],
        )?;
        Ok(())
    }

    fn insert_v4_shard(connection: &rusqlite::Connection) -> rusqlite::Result<()> {
        connection.execute(
            "INSERT INTO local_federation_storage_shards(
                grant_id, target_id, target_generation, manifest_digest, stripe_index,
                shard_index, shard_generation, allocation_id, length, content_digest,
                committed_operation_id, committed_at
             ) VALUES (?1, ?2, 1, ?3, 1, 2, 1, ?4, 10, ?5, ?6, 21)",
            params![
                [4_u8; 16].as_slice(),
                [6_u8; 16].as_slice(),
                [16_u8; 32].as_slice(),
                [1_u8; 16].as_slice(),
                [18_u8; 32].as_slice(),
                [12_u8; 16].as_slice(),
            ],
        )?;
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
    fn foundational_migration_digests_are_committed_compatibility_values() {
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
            local_federation_authority_cache_migration_digest(),
            [
                0x14, 0xb5, 0x12, 0x46, 0x24, 0xbb, 0x2b, 0xf7, 0x14, 0x29, 0x26, 0x35, 0xab, 0x2e,
                0x15, 0x65, 0xdb, 0x12, 0x7b, 0x72, 0x7a, 0xde, 0xee, 0x88, 0x0a, 0xe7, 0x56, 0x86,
                0x90, 0x1d, 0x81, 0xd3,
            ]
        );
        assert_eq!(
            local_federation_storage_quota_migration_digest(),
            [
                0x29, 0x74, 0xc7, 0x78, 0x54, 0x40, 0x0a, 0x17, 0xbd, 0x5b, 0xb4, 0x60, 0xd1, 0x33,
                0x8b, 0xcf, 0x46, 0x48, 0xf8, 0xf9, 0xb7, 0xdd, 0x95, 0x8d, 0xf9, 0xe9, 0x0c, 0xde,
                0xfe, 0x5c, 0xc8, 0x9a,
            ]
        );
        assert_eq!(
            local_federation_storage_capability_migration_digest(),
            [
                0x9c, 0xbc, 0x20, 0xdb, 0x9a, 0x24, 0xde, 0x48, 0x11, 0xec, 0x5f, 0x6e, 0xa1, 0x11,
                0x35, 0x74, 0x82, 0x14, 0xd5, 0xb2, 0x72, 0x87, 0x0b, 0xe8, 0xf4, 0x13, 0x7f, 0xb1,
                0xfa, 0x21, 0x0b, 0x0e,
            ]
        );
        assert_eq!(
            local_federation_storage_lifecycle_migration_digest(),
            [
                0xcc, 0x9f, 0x12, 0x3b, 0x42, 0x63, 0x9f, 0x56, 0xe8, 0xc8, 0x4c, 0x06, 0x8e, 0x81,
                0x5d, 0xdf, 0xca, 0xfa, 0xa2, 0xc5, 0xa9, 0xfc, 0x8a, 0xc5, 0x50, 0x92, 0x38, 0x4f,
                0xc7, 0x3a, 0x3f, 0x50,
            ]
        );
        assert_eq!(
            local_federation_storage_scrub_migration_digest(),
            [
                0x74, 0x0e, 0xb7, 0x1a, 0x04, 0x71, 0x7c, 0x9f, 0x5b, 0x94, 0xbc, 0x6d, 0x63, 0xcd,
                0xd7, 0xb3, 0x61, 0x84, 0x3e, 0x9f, 0x46, 0x69, 0x89, 0x1a, 0x90, 0x98, 0xb6, 0xfc,
                0x59, 0xb3, 0xb5, 0x8e,
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
        assert_eq!(
            partition_component_rollout_migration_digest(),
            [
                0xa4, 0xd1, 0x40, 0x9a, 0xd9, 0xf8, 0x37, 0x7e, 0x59, 0x71, 0x43, 0xb4, 0xf0, 0x16,
                0xcc, 0xf0, 0xcd, 0x11, 0xac, 0x48, 0xe0, 0x0b, 0x03, 0xd1, 0xb4, 0x99, 0x8b, 0x69,
                0x14, 0x7e, 0xa8, 0xf1,
            ]
        );
        assert_eq!(
            partition_cluster_enrollment_migration_digest(),
            [
                0x9d, 0x45, 0xe9, 0x30, 0x1e, 0xae, 0x55, 0x03, 0xed, 0x0d, 0xaf, 0xd7, 0x9e, 0x9d,
                0x6b, 0xf1, 0x31, 0x64, 0xb4, 0x09, 0x93, 0x43, 0x99, 0xd0, 0xc5, 0x51, 0xe3, 0x43,
                0x3e, 0x55, 0x25, 0x2e,
            ]
        );
        assert_eq!(
            partition_routing_migration_digest(),
            [
                0xf7, 0x9d, 0xbb, 0x32, 0xca, 0x8e, 0xba, 0x5b, 0xaf, 0xb2, 0xb4, 0x91, 0x28, 0xe2,
                0x0b, 0xb1, 0x94, 0x4d, 0x99, 0x04, 0x07, 0x74, 0x80, 0x92, 0xc1, 0x59, 0x65, 0x2f,
                0xc5, 0x92, 0xc6, 0x65,
            ]
        );
        assert_eq!(
            partition_active_quorum_plan_migration_digest(),
            [
                0xd2, 0x59, 0x59, 0x77, 0x59, 0xf3, 0x4d, 0x9b, 0x13, 0xc5, 0x70, 0x6e, 0x01, 0x78,
                0xae, 0xbf, 0xd7, 0x86, 0x01, 0x85, 0xad, 0x37, 0x81, 0x53, 0x9d, 0x86, 0x05, 0x5c,
                0x09, 0x0f, 0x15, 0xcc,
            ]
        );
    }

    #[test]
    fn filesystem_migration_digests_are_committed_compatibility_values() {
        assert_eq!(
            partition_volume_heads_migration_digest(),
            [
                0x30, 0xb9, 0xa0, 0xc5, 0x66, 0x90, 0x98, 0x00, 0xdc, 0xa9, 0x6e, 0x43, 0xff, 0xa9,
                0x3b, 0x0f, 0x65, 0x79, 0xe3, 0x66, 0x4f, 0xde, 0xd1, 0xc5, 0x12, 0x64, 0x67, 0xe7,
                0xa1, 0xb6, 0x00, 0x73,
            ]
        );
        assert_eq!(
            partition_volume_snapshots_migration_digest(),
            [
                0xf1, 0x91, 0x31, 0x2a, 0x94, 0x28, 0xd8, 0xb8, 0x3a, 0xdd, 0xa3, 0xf0, 0xb7, 0xc8,
                0xc5, 0x3e, 0x1d, 0x16, 0x61, 0xbf, 0xaa, 0x2d, 0x16, 0xb9, 0xfd, 0x49, 0x0e, 0x0d,
                0xa4, 0x61, 0xda, 0xe1,
            ]
        );
        assert_eq!(
            partition_version_retention_migration_digest(),
            [
                0xa2, 0x60, 0xd4, 0xee, 0x00, 0xa5, 0x64, 0x05, 0xf9, 0x96, 0x26, 0x47, 0xc1, 0x11,
                0x39, 0x72, 0xe6, 0xb8, 0xcb, 0x39, 0xd8, 0x12, 0xfb, 0xac, 0x4c, 0xfc, 0xec, 0x71,
                0x87, 0x87, 0x33, 0x76,
            ]
        );
        assert_eq!(
            partition_snapshot_expiry_migration_digest(),
            [
                0x69, 0xeb, 0x29, 0xc3, 0x42, 0xd9, 0x79, 0x08, 0xf0, 0x31, 0x57, 0xcf, 0x05, 0xe5,
                0x36, 0x8c, 0xee, 0x0f, 0x6a, 0xe7, 0x67, 0x6d, 0x38, 0x88, 0xfa, 0x11, 0xc8, 0x06,
                0x99, 0x9b, 0x0f, 0x8e,
            ]
        );
        assert_eq!(
            partition_snapshot_schedules_migration_digest(),
            [
                0x8d, 0xee, 0xb6, 0xce, 0xda, 0x2f, 0x17, 0xa6, 0x74, 0x82, 0x7a, 0x3f, 0x09, 0xd0,
                0xb8, 0xf0, 0xe0, 0xcf, 0xec, 0x8a, 0xc6, 0x4a, 0x80, 0x51, 0x16, 0x94, 0x6a, 0xcb,
                0xec, 0x26, 0xe2, 0xff,
            ]
        );
        assert_eq!(
            partition_snapshot_retention_selection_migration_digest(),
            [
                0x25, 0xb5, 0x2c, 0xb6, 0xb3, 0xfd, 0x98, 0x43, 0x01, 0x27, 0x3e, 0xd3, 0x99, 0xf7,
                0xa6, 0x62, 0xc8, 0x52, 0x2c, 0x0c, 0x52, 0x2a, 0x82, 0x76, 0x61, 0x4b, 0x53, 0x39,
                0x02, 0x46, 0xac, 0x3b,
            ]
        );
        assert_eq!(
            partition_snapshot_restores_migration_digest(),
            [
                0xeb, 0xd6, 0x79, 0x94, 0x8d, 0xb3, 0x21, 0xac, 0x99, 0x9b, 0x5a, 0x99, 0x8f, 0x6b,
                0xa7, 0xd2, 0x35, 0xe8, 0x0f, 0x14, 0x82, 0x7e, 0xc2, 0xcd, 0x73, 0xcd, 0xb9, 0x9d,
                0x81, 0x16, 0x86, 0xfe,
            ]
        );
        assert_eq!(
            partition_snapshot_root_removals_migration_digest(),
            [
                0x15, 0xb9, 0xb4, 0x96, 0x72, 0xa2, 0x8c, 0x2b, 0xec, 0x1e, 0xdb, 0xaa, 0xcd, 0xcf,
                0x49, 0xb0, 0x0f, 0xdd, 0x88, 0x59, 0x9c, 0x7a, 0x19, 0xa0, 0xa6, 0x95, 0x99, 0x38,
                0xdd, 0xca, 0xef, 0x6e,
            ]
        );
    }

    #[test]
    fn cleanup_migration_digests_are_committed_compatibility_values() {
        assert_eq!(
            partition_version_cleanup_intents_migration_digest(),
            [
                0xec, 0xde, 0xad, 0xa0, 0x79, 0x56, 0xd3, 0x06, 0xf5, 0x0b, 0x10, 0x80, 0x9f, 0x4e,
                0x07, 0x37, 0x7d, 0xcd, 0x69, 0x11, 0x4a, 0xab, 0x2a, 0x1d, 0xbc, 0x54, 0xbd, 0x95,
                0xe3, 0x93, 0xed, 0xb5,
            ]
        );
        assert_eq!(
            partition_version_cleanup_attestations_migration_digest(),
            [
                0xc5, 0x89, 0xdf, 0xc9, 0x7b, 0xdc, 0x23, 0xda, 0x8f, 0x8d, 0xfa, 0x50, 0x4b, 0x5a,
                0x4e, 0x10, 0x09, 0x37, 0xbb, 0xab, 0xe2, 0xb7, 0xfa, 0x7b, 0x7d, 0x35, 0xbe, 0xe9,
                0xe4, 0x85, 0x37, 0x1f,
            ]
        );
        assert_eq!(
            partition_version_cleanup_manifest_root_migration_digest(),
            [
                0x53, 0x58, 0xfb, 0xbf, 0x3e, 0xe5, 0x9a, 0x8a, 0xc4, 0x59, 0x0f, 0x80, 0x7e, 0x4d,
                0x1f, 0xa7, 0xf1, 0x25, 0x3f, 0xd5, 0xd6, 0x75, 0x31, 0xd2, 0x9c, 0x7f, 0x2f, 0x84,
                0xcb, 0xcd, 0xd2, 0x6c,
            ]
        );
        assert_eq!(
            partition_version_cleanup_root_set_digest_migration_digest(),
            [
                0xb0, 0xf7, 0x2b, 0x54, 0xa2, 0x93, 0xbc, 0xfc, 0x05, 0x59, 0xf5, 0x2a, 0x35, 0x15,
                0xe6, 0x4b, 0x18, 0xb5, 0xb2, 0x06, 0x4c, 0xd7, 0xec, 0xa4, 0xd7, 0x85, 0x7f, 0xef,
                0x58, 0xc2, 0x24, 0x42,
            ]
        );
        assert_eq!(
            partition_version_cleanup_finalisation_migration_digest(),
            [
                0x8b, 0xe5, 0x4b, 0x06, 0x2d, 0x07, 0xfd, 0x47, 0xae, 0x7d, 0x16, 0xdc, 0xcd, 0xe1,
                0xb3, 0xae, 0x37, 0x04, 0xd4, 0x36, 0xbf, 0xc9, 0x90, 0x78, 0xe4, 0xa1, 0xc4, 0x2e,
                0x3e, 0x0a, 0x7c, 0x90,
            ]
        );
        assert_eq!(
            partition_version_cleanup_inventory_migration_digest(),
            [
                0x01, 0x29, 0x92, 0xc3, 0x44, 0xa6, 0xc5, 0x95, 0x95, 0xc7, 0x46, 0x83, 0x43, 0x32,
                0x0b, 0xc8, 0x9a, 0x31, 0xbf, 0xa4, 0x94, 0xdf, 0x35, 0xdd, 0xb7, 0x5e, 0xa1, 0x99,
                0xe5, 0x13, 0xd1, 0xfb,
            ]
        );
        assert_eq!(
            partition_version_cleanup_permits_migration_digest(),
            [
                0xaf, 0x4f, 0x98, 0xd8, 0x16, 0xde, 0x61, 0x0d, 0x4c, 0xe1, 0x88, 0xaa, 0x81, 0x82,
                0x8b, 0xa5, 0xab, 0xf2, 0x5e, 0x17, 0x19, 0x7f, 0x8c, 0x40, 0xd6, 0xdc, 0x56, 0xcf,
                0x97, 0x46, 0x06, 0x25,
            ]
        );
        assert_eq!(
            partition_version_cleanup_completions_migration_digest(),
            [
                0xa8, 0xfe, 0x5c, 0xfc, 0xb9, 0x5a, 0x32, 0x0b, 0x6c, 0xe5, 0x04, 0xaa, 0xf4, 0x62,
                0xe1, 0x2d, 0x7b, 0xb2, 0x0b, 0x8d, 0x51, 0xd4, 0xe1, 0xc9, 0x34, 0xea, 0x34, 0x6d,
                0x73, 0x74, 0xaa, 0xd4,
            ]
        );
        assert_eq!(
            partition_version_cleanup_reclamations_migration_digest(),
            [
                0xaa, 0x4e, 0x37, 0xb4, 0x28, 0xe0, 0x25, 0xed, 0xb8, 0x57, 0x37, 0x36, 0x7e, 0x94,
                0x6e, 0x5d, 0xdf, 0x5d, 0x88, 0x2b, 0x79, 0xd1, 0x1d, 0x27, 0x39, 0x78, 0xb5, 0x89,
                0x9a, 0x89, 0xd8, 0x3b,
            ]
        );
        assert_eq!(
            partition_cleanup_target_ownership_migration_digest(),
            [
                0x55, 0x71, 0xe7, 0x55, 0x85, 0x43, 0x70, 0x97, 0xb0, 0xe8, 0x43, 0x89, 0x7b, 0x30,
                0x62, 0x59, 0x7d, 0x3f, 0x11, 0x5e, 0x38, 0x3c, 0x49, 0x15, 0x5d, 0xec, 0x00, 0xb6,
                0x7d, 0x31, 0x3f, 0x3f,
            ]
        );
    }

    #[test]
    fn access_migration_digests_are_committed_compatibility_values() {
        assert_eq!(
            partition_namespace_inheritance_migration_digest(),
            [
                0x63, 0xbb, 0x62, 0x4f, 0x9d, 0x55, 0xb9, 0x9f, 0x69, 0xbe, 0x4b, 0x09, 0x29, 0x1e,
                0x52, 0x02, 0x0d, 0x11, 0x4e, 0x13, 0xb3, 0x02, 0xcd, 0x9d, 0x55, 0x02, 0x56, 0xa6,
                0x46, 0xdb, 0x73, 0x64,
            ]
        );
        assert_eq!(
            partition_access_revocation_migration_digest(),
            [
                0x09, 0x3f, 0xe5, 0xa1, 0x24, 0xb8, 0xdc, 0x67, 0xe4, 0xe4, 0x1d, 0xb6, 0x94, 0x6f,
                0x70, 0xc5, 0xbe, 0xc3, 0xca, 0xc3, 0x33, 0x8d, 0x41, 0x4c, 0xc3, 0xe2, 0x4d, 0x79,
                0x40, 0x32, 0x6f, 0x87,
            ]
        );
        assert_eq!(
            partition_principal_lifecycle_migration_digest(),
            [
                0x38, 0x5a, 0x07, 0x96, 0xd7, 0xf3, 0x06, 0xe6, 0x15, 0x30, 0x32, 0xe6, 0x56, 0x49,
                0xca, 0x04, 0xc1, 0x9b, 0xdb, 0xaa, 0x08, 0x98, 0x8c, 0x0d, 0xfd, 0xb7, 0x4d, 0x2f,
                0x97, 0x17, 0x1b, 0x8f,
            ]
        );
        assert_eq!(
            partition_access_administration_migration_digest(),
            [
                0xdc, 0x97, 0x88, 0xee, 0xe7, 0xb0, 0xe2, 0x46, 0x4e, 0x2c, 0xae, 0xac, 0x10, 0x72,
                0x06, 0xb4, 0xa6, 0xf3, 0xc9, 0xe7, 0x23, 0xde, 0x94, 0xf5, 0x6f, 0x6b, 0xdd, 0x7f,
                0xf2, 0x74, 0x34, 0x5a,
            ]
        );
    }

    #[test]
    fn federation_migration_digests_are_committed_compatibility_values() {
        assert_eq!(
            partition_federation_authority_migration_digest(),
            [
                0xfb, 0x27, 0xb3, 0xc5, 0x3b, 0xb8, 0x7d, 0x53, 0x5f, 0x07, 0x95, 0x4d, 0xfa, 0xc2,
                0x34, 0x14, 0x72, 0x5c, 0xa5, 0x94, 0xe9, 0xf7, 0x55, 0x52, 0x3e, 0x41, 0x92, 0xc2,
                0x61, 0x20, 0x57, 0xb1,
            ]
        );
        assert_eq!(
            partition_federation_relationship_history_migration_digest(),
            [
                0x72, 0x22, 0xb7, 0x98, 0x76, 0x1b, 0x71, 0x8b, 0xb5, 0x9f, 0x86, 0x7f, 0x2e, 0x9b,
                0x2d, 0xcf, 0x6e, 0x9d, 0x4d, 0xd4, 0xab, 0x55, 0x14, 0xeb, 0xa8, 0xe6, 0x95, 0x9d,
                0xc4, 0x13, 0xd7, 0x5e,
            ]
        );
        assert_eq!(
            partition_federation_grant_history_migration_digest(),
            [
                0x2f, 0x42, 0x05, 0x02, 0xfb, 0x52, 0x66, 0xd6, 0xc6, 0x8d, 0x49, 0x42, 0xb2, 0x0f,
                0x04, 0xf7, 0xe6, 0x80, 0x30, 0xad, 0x1f, 0x26, 0x8f, 0xfc, 0x17, 0x3c, 0x15, 0x7a,
                0xfb, 0xc6, 0xc6, 0x31,
            ]
        );
        assert_eq!(
            partition_federation_governance_proof_migration_digest(),
            [
                0x31, 0x0f, 0x6e, 0xe6, 0x41, 0x63, 0x43, 0xf5, 0x9d, 0xef, 0x00, 0x05, 0x6c, 0x12,
                0xaa, 0xf1, 0x12, 0x0d, 0x10, 0xbd, 0xc5, 0x30, 0xb9, 0x86, 0x17, 0xbf, 0xc3, 0xe0,
                0x47, 0x99, 0xe5, 0x98,
            ]
        );
        assert_eq!(
            partition_federation_principal_history_migration_digest(),
            [
                0xd6, 0xcf, 0xc2, 0x4f, 0x6d, 0xb1, 0x7f, 0xf1, 0x25, 0xd2, 0x2d, 0xc6, 0xaf, 0x27,
                0xf6, 0x69, 0xa7, 0x6f, 0xbe, 0x8b, 0xa5, 0x7a, 0x42, 0x58, 0xad, 0x34, 0xd0, 0x4c,
                0x22, 0x6c, 0x27, 0x3f,
            ]
        );
        assert_eq!(
            partition_federation_ownership_succession_migration_digest(),
            [
                0x47, 0x17, 0x9a, 0xd6, 0x2d, 0xf2, 0xc7, 0x52, 0x13, 0x9e, 0x69, 0x4e, 0xb6, 0x20,
                0x72, 0x57, 0x88, 0xea, 0xd4, 0xd0, 0x53, 0xf6, 0x45, 0xed, 0x4c, 0xf0, 0x56, 0x0a,
                0x85, 0x3f, 0x16, 0xe1,
            ]
        );
        assert_eq!(
            partition_federation_quarantine_proof_migration_digest(),
            [
                0x15, 0xe6, 0xd6, 0x0c, 0x27, 0xe7, 0x28, 0xb2, 0x2b, 0x28, 0x77, 0x41, 0x6e, 0x39,
                0xeb, 0x59, 0x5a, 0x7b, 0x95, 0x88, 0xa5, 0x16, 0xc2, 0xee, 0xce, 0x8c, 0x76, 0x3c,
                0x50, 0xd1, 0xc7, 0x9b,
            ]
        );
        assert_eq!(
            partition_root_delegation_directory_migration_digest(),
            [
                0x07, 0x63, 0xbe, 0xe3, 0x61, 0xfa, 0xfe, 0x32, 0xd6, 0xfd, 0x89, 0xb3, 0x14, 0x16,
                0x14, 0xb0, 0xdd, 0x51, 0x42, 0x12, 0x49, 0x73, 0x40, 0x70, 0x72, 0x32, 0xcc, 0x63,
                0x62, 0x38, 0xa4, 0xd1,
            ]
        );
        assert_eq!(
            partition_federation_relationship_evidence_guard_migration_digest(),
            [
                0x5b, 0x47, 0x8b, 0xf9, 0x48, 0x78, 0xcf, 0x50, 0x3a, 0x3d, 0x88, 0x65, 0x20, 0x5c,
                0xde, 0xd2, 0xe7, 0x6b, 0x0a, 0xe8, 0x49, 0x83, 0x60, 0xb2, 0x60, 0xbc, 0xdf, 0x8e,
                0x0b, 0xc3, 0x69, 0x9d,
            ]
        );
        assert_eq!(
            partition_federation_grant_evidence_migration_digest(),
            [
                0xd5, 0xdb, 0xdd, 0x4a, 0x61, 0x06, 0x6f, 0xca, 0x2a, 0x43, 0xa7, 0x05, 0xfc, 0x60,
                0x83, 0xf0, 0xdb, 0x78, 0x3e, 0x7a, 0xb0, 0x1d, 0x5b, 0xd1, 0x91, 0xf9, 0xe0, 0x7d,
                0x9f, 0x24, 0xad, 0x21,
            ]
        );
        assert_eq!(
            partition_federation_grant_paging_migration_digest(),
            [
                0x2b, 0x33, 0xa8, 0x58, 0x5b, 0x02, 0x7a, 0xe9, 0xa3, 0x2c, 0x07, 0x72, 0x5f, 0xa5,
                0x76, 0x81, 0xe9, 0xb8, 0xec, 0xd1, 0xf9, 0x0d, 0x81, 0xef, 0x06, 0xec, 0x61, 0xf1,
                0x3b, 0xd4, 0xe0, 0xc6,
            ]
        );
        assert_eq!(
            partition_federation_storage_allocation_migration_digest(),
            [
                0xc5, 0x12, 0xc6, 0x6d, 0x16, 0x7f, 0xbe, 0xff, 0xd9, 0x42, 0xad, 0xcd, 0xaf, 0x76,
                0x90, 0x64, 0xeb, 0x16, 0xd8, 0x6f, 0x2c, 0x80, 0x0e, 0x66, 0x34, 0x8e, 0x63, 0x6c,
                0x32, 0x80, 0x27, 0xa5,
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
