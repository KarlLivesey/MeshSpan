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

    /// Opens an existing partition database using its durably bound partition identity.
    ///
    /// # Errors
    ///
    /// Rejects a missing database, SQLite failure, migration drift/newer schema, malformed or
    /// absent stored identity and failed integrity checks.
    pub fn open_existing(
        file_path: &Path,
        migration_time: UnixMicros,
    ) -> Result<Self, MetadataStoreError> {
        let mut connection = open_existing_connection(file_path)?;
        migrate_partition(&mut connection, migration_time.get())?;
        let stored: Vec<u8> = connection.query_row(
            "SELECT partition_id FROM applied_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let partition_bytes: [u8; 16] = stored
            .try_into()
            .map_err(|_| MetadataStoreError::IntegrityFailed)?;
        let partition_id = PartitionId::from_bytes(partition_bytes)
            .map_err(|_| MetadataStoreError::IntegrityFailed)?;
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
        let report = check_integrity(&self.connection, PARTITION_SCHEMA_VERSION)?;
        crate::authentication_integrity::check_method_shapes(&self.connection)?;
        Ok(report)
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

    /// Opens an existing daemon-local database using its durably bound node identity.
    ///
    /// # Errors
    ///
    /// Rejects a missing database, SQLite failure, migration drift/newer schema, malformed or
    /// absent stored identity and failed integrity checks.
    pub fn open_existing(
        file_path: &Path,
        migration_time: UnixMicros,
    ) -> Result<Self, MetadataStoreError> {
        let mut connection = open_existing_connection(file_path)?;
        migrate_local(&mut connection, migration_time.get())?;
        let stored: Vec<u8> = connection.query_row(
            "SELECT node_id FROM local_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let node_bytes: [u8; 16] = stored
            .try_into()
            .map_err(|_| MetadataStoreError::IntegrityFailed)?;
        let node_id =
            NodeId::from_bytes(node_bytes).map_err(|_| MetadataStoreError::IntegrityFailed)?;
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
    open_connection_with_flags(file_path, flags)
}

fn open_existing_connection(file_path: &Path) -> Result<Connection, MetadataStoreError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    open_connection_with_flags(file_path, flags)
}

fn open_connection_with_flags(
    file_path: &Path,
    flags: OpenFlags,
) -> Result<Connection, MetadataStoreError> {
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
    transaction.execute(
        "UPDATE local_identity SET schema_version = ?1 WHERE singleton = 1",
        [LOCAL_SCHEMA_VERSION],
    )?;
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
        LOCAL_SCHEMA_VERSION, PARTITION_SCHEMA_VERSION,
        local_authentication_ceremony_migration_digest, local_claim_bundle_migration_digest,
        local_federation_authority_cache_migration_digest,
        local_federation_storage_capability_migration_digest,
        local_federation_storage_lifecycle_migration_digest,
        local_federation_storage_quota_migration_digest,
        local_federation_storage_scrub_migration_digest,
        local_maintenance_scrub_progress_migration_digest,
        local_metadata_backup_staging_migration_digest, local_migration_digest,
        local_setup_operation_migration_digest, local_storage_target_registration_migration_digest,
        local_totp_registration_ceremony_migration_digest, migrate_local, migrate_local_through,
        migrate_partition, migrate_partition_through,
        partition_access_administration_migration_digest,
        partition_access_revocation_migration_digest,
        partition_active_quorum_plan_migration_digest,
        partition_authentication_credential_constraints_migration_digest,
        partition_authentication_method_events_migration_digest,
        partition_authentication_policy_migration_digest,
        partition_authentication_session_delivery_migration_digest,
        partition_authentication_session_factors_migration_digest,
        partition_authentication_session_rotation_migration_digest,
        partition_backup_reclamation_migration_digest,
        partition_builtin_fault_classes_migration_digest,
        partition_cleanup_target_ownership_migration_digest,
        partition_cluster_enrollment_migration_digest,
        partition_component_rollout_migration_digest,
        partition_federation_actor_attestation_history_migration_digest,
        partition_federation_authority_migration_digest,
        partition_federation_governance_proof_migration_digest,
        partition_federation_grant_evidence_migration_digest,
        partition_federation_grant_history_migration_digest,
        partition_federation_grant_paging_migration_digest,
        partition_federation_ownership_succession_migration_digest,
        partition_federation_quarantine_proof_migration_digest,
        partition_federation_relationship_evidence_guard_migration_digest,
        partition_federation_relationship_history_migration_digest,
        partition_federation_storage_allocation_migration_digest,
        partition_metadata_backup_catalogue_migration_digest,
        partition_metadata_backup_claim_migration_digest,
        partition_metadata_backup_schedule_migration_digest, partition_migration_digest,
        partition_namespace_inheritance_migration_digest,
        partition_node_activations_migration_digest, partition_node_wrapping_keys_migration_digest,
        partition_online_certificate_authority_migration_digest,
        partition_pending_node_activations_migration_digest,
        partition_principal_inactive_quarantine_migration_digest,
        partition_principal_lifecycle_migration_digest,
        partition_recovery_authority_migration_digest, partition_roles_migration_digest,
        partition_root_delegation_directory_migration_digest, partition_routing_migration_digest,
        partition_secret_generations_migration_digest, partition_smb_exports_migration_digest,
        partition_snapshot_expiry_migration_digest, partition_snapshot_restores_migration_digest,
        partition_snapshot_retention_selection_migration_digest,
        partition_snapshot_root_removals_migration_digest,
        partition_snapshot_schedules_migration_digest, partition_storage_policies_migration_digest,
        partition_storage_targets_migration_digest,
        partition_totp_session_replay_steps_migration_digest,
        partition_typed_authentication_migration_digest,
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
        assert_eq!(
            database.check_integrity()?.schema_version,
            PARTITION_SCHEMA_VERSION
        );
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
            PARTITION_SCHEMA_VERSION
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
                grant_id, relationship_id, issuer_mesh_id, recipient_mesh_id,
                upstream_grant_id, route_depth,
                resource_kind, authority_mesh_id, volume_id, object_id, authority_epoch,
                valid_from, valid_until, state, effective_policy_digest, issued_at,
                revoked_at, revision
             ) VALUES (?1, ?2, ?3, ?4, NULL, 0, 4, ?3, NULL, NULL, 1,
                       1, NULL, 3, ?5, 3, 7, 7)",
            params![
                grant.as_slice(),
                relationship.as_slice(),
                remote_mesh.as_slice(),
                local_mesh.as_slice(),
                [55_u8; 32].as_slice(),
            ],
        )?;
        seed_grant_route(&connection, grant, remote_mesh, local_mesh, 7)?;

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
    fn inactive_principal_quarantine_migration_preserves_evidence_and_accepts_reason_six()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory
            .path()
            .join("principal-inactive-quarantine.sqlite3");
        let mut connection = open_connection(&file_path)?;
        migrate_partition_through(&mut connection, 40, 10)?;
        seed_legacy_federation_quarantine(&connection)?;

        migrate_partition(&mut connection, 20)?;
        assert_eq!(
            connection.query_row(
                "SELECT reason_kind FROM federation_quarantine WHERE quarantine_id = ?1",
                [[8_u8; 16].as_slice()],
                |row| row.get::<_, i64>(0),
            )?,
            5
        );
        for table in [
            "federation_quarantine_acknowledgements",
            "federation_quarantine_events",
        ] {
            let count: i64 =
                connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            assert_eq!(count, 1);
        }
        connection.execute(
            "INSERT INTO federation_quarantine(
                quarantine_id, relationship_id, operation_id, grant_id,
                subject_home_mesh_id, subject_principal_id, accepted_at, reason_kind,
                payload_digest, acknowledgement_digest, state, surfaced_at, resolved_at,
                resolution_kind, resolution_operation_id, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 30, 6, ?7, ?8, 1,
                       NULL, NULL, NULL, NULL, 2)",
            params![
                [13_u8; 16].as_slice(),
                [3_u8; 16].as_slice(),
                [14_u8; 16].as_slice(),
                [4_u8; 16].as_slice(),
                [2_u8; 16].as_slice(),
                [5_u8; 16].as_slice(),
                [15_u8; 32].as_slice(),
                [16_u8; 32].as_slice(),
            ],
        )?;
        let foreign_key_failures: i64 =
            connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })?;
        assert_eq!(foreign_key_failures, 0);
        Ok(())
    }

    fn seed_legacy_federation_quarantine(
        connection: &rusqlite::Connection,
    ) -> rusqlite::Result<()> {
        connection.execute(
            "INSERT INTO meshes(
                mesh_id, display_name, canonical_name, created_at,
                configuration_revision, identity_revision, namespace_revision, revision
             ) VALUES (?1, 'Local', 'local', 1, 1, 1, 1, 1)",
            [[1_u8; 16].as_slice()],
        )?;
        connection.execute(
            "INSERT INTO federation_relationships(
                relationship_id, local_mesh_id, remote_mesh_id, relationship_kind,
                governance_direction, state, authority_epoch, remote_display_name,
                proposed_at, approved_at, restricted_at, revoked_at, retired_at, revision
             ) VALUES (?1, ?2, ?3, 1, 0, 2, 1, 'Remote', 1, 2, NULL, NULL, NULL, 2)",
            params![
                [3_u8; 16].as_slice(),
                [1_u8; 16].as_slice(),
                [2_u8; 16].as_slice(),
            ],
        )?;
        connection.execute(
            "INSERT INTO federation_grants(
                grant_id, relationship_id, issuer_mesh_id, recipient_mesh_id,
                upstream_grant_id, route_depth,
                resource_kind, authority_mesh_id, volume_id, object_id, authority_epoch,
                valid_from, valid_until, state, effective_policy_digest, issued_at,
                revoked_at, revision
             ) VALUES (?1, ?2, ?3, ?4, NULL, 0, 1, ?3, ?5, NULL, 1,
                       1, NULL, 1, ?6, 2, NULL, 1)",
            params![
                [4_u8; 16].as_slice(),
                [3_u8; 16].as_slice(),
                [2_u8; 16].as_slice(),
                [1_u8; 16].as_slice(),
                [6_u8; 16].as_slice(),
                [7_u8; 32].as_slice(),
            ],
        )?;
        seed_grant_route(connection, [4; 16], [2; 16], [1; 16], 1)?;
        connection.execute(
            "INSERT INTO federation_quarantine(
                quarantine_id, relationship_id, operation_id, grant_id,
                subject_home_mesh_id, subject_principal_id, accepted_at, reason_kind,
                payload_digest, acknowledgement_digest, state, surfaced_at, resolved_at,
                resolution_kind, resolution_operation_id, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 12, 5, ?7, ?8, 1,
                       NULL, NULL, NULL, NULL, 1)",
            params![
                [8_u8; 16].as_slice(),
                [3_u8; 16].as_slice(),
                [9_u8; 16].as_slice(),
                [4_u8; 16].as_slice(),
                [2_u8; 16].as_slice(),
                [5_u8; 16].as_slice(),
                [10_u8; 32].as_slice(),
                [11_u8; 32].as_slice(),
            ],
        )?;
        connection.execute(
            "INSERT INTO federation_quarantine_acknowledgements(
                quarantine_id, signer_mesh_id, signer_generation, signature, authority_epoch,
                required_rights, storage_bytes, resource_kind, authority_mesh_id,
                volume_id, object_id, revision
             ) VALUES (?1, ?2, 1, ?3, 1, 2, 0, 1, ?4, ?5, NULL, 1)",
            params![
                [8_u8; 16].as_slice(),
                [2_u8; 16].as_slice(),
                [12_u8; 64].as_slice(),
                [1_u8; 16].as_slice(),
                [6_u8; 16].as_slice(),
            ],
        )?;
        connection.execute(
            "INSERT INTO federation_quarantine_events(
                quarantine_id, event_sequence, event_kind, prior_state, resulting_state,
                reason, changed_by, changed_at, revision
             ) VALUES (?1, 1, 1, NULL, 1, NULL, ?2, 12, 1)",
            params![[8_u8; 16].as_slice(), [1_u8; 16].as_slice()],
        )?;
        Ok(())
    }

    fn seed_grant_route(
        connection: &rusqlite::Connection,
        grant_id: [u8; 16],
        issuer_mesh_id: [u8; 16],
        recipient_mesh_id: [u8; 16],
        revision: i64,
    ) -> rusqlite::Result<()> {
        for (hop_index, mesh_id) in [(0_i64, issuer_mesh_id), (1_i64, recipient_mesh_id)] {
            connection.execute(
                "INSERT INTO federation_grant_route_hops(
                    grant_id, hop_index, mesh_id, revision
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![grant_id.as_slice(), hop_index, mesh_id.as_slice(), revision],
            )?;
        }
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
        assert_eq!(database.schema_version(), LOCAL_SCHEMA_VERSION);
        drop(database);
        assert!(LocalDatabase::open(&file_path, first, UnixMicros::new(11)).is_ok());
        let existing = LocalDatabase::open_existing(&file_path, UnixMicros::new(12))?;
        assert_eq!(existing.node_id(), first);
        assert!(matches!(
            LocalDatabase::open_existing(
                &directory.path().join("missing.sqlite3"),
                UnixMicros::new(13)
            ),
            Err(MetadataStoreError::Sqlite(_))
        ));
        assert!(matches!(
            LocalDatabase::open(&file_path, second, UnixMicros::new(11)),
            Err(MetadataStoreError::IdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn local_claim_schema_retains_only_one_active_digest_bound_to_a_node_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("local-claim.sqlite3");
        let node = NodeId::from_bytes([5; 16])?;
        let database = LocalDatabase::open(&file_path, node, UnixMicros::new(10))?;

        let plaintext_columns: i64 = database.connection().query_row(
            "SELECT count(*) FROM pragma_table_info('local_claim_bundles')
             WHERE name IN ('secret', 'claim_secret', 'bundle')",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(plaintext_columns, 0);

        database.connection().execute(
            "INSERT INTO local_claim_bundles(
                claim_id, node_public_key_fingerprint, secret_digest, state,
                created_at, consumed_at, rotated_at, revision
             ) VALUES (?1, ?2, ?3, 1, 20, NULL, NULL, 1)",
            params![
                [1_u8; 16].as_slice(),
                [2_u8; 32].as_slice(),
                [3_u8; 32].as_slice(),
            ],
        )?;
        assert!(
            database
                .connection()
                .execute(
                    "INSERT INTO local_claim_bundles(
                        claim_id, node_public_key_fingerprint, secret_digest, state,
                        created_at, consumed_at, rotated_at, revision
                     ) VALUES (?1, ?2, ?3, 1, 21, NULL, NULL, 2)",
                    params![
                        [4_u8; 16].as_slice(),
                        [5_u8; 32].as_slice(),
                        [6_u8; 32].as_slice(),
                    ],
                )
                .is_err()
        );
        database.connection().execute(
            "UPDATE local_claim_bundles
             SET state = 3, rotated_at = 21, revision = 2
             WHERE claim_id = ?1",
            [[1_u8; 16].as_slice()],
        )?;
        database.connection().execute(
            "INSERT INTO local_claim_bundles(
                claim_id, node_public_key_fingerprint, secret_digest, state,
                created_at, consumed_at, rotated_at, revision
             ) VALUES (?1, ?2, ?3, 1, 21, NULL, NULL, 2)",
            params![
                [4_u8; 16].as_slice(),
                [5_u8; 32].as_slice(),
                [6_u8; 32].as_slice(),
            ],
        )?;
        assert!(
            database
                .connection()
                .execute(
                    "UPDATE local_claim_bundles
                     SET state = 2, consumed_at = NULL, revision = 3
                     WHERE claim_id = ?1",
                    [[4_u8; 16].as_slice()],
                )
                .is_err()
        );
        assert_eq!(
            database.check_integrity()?.schema_version,
            LOCAL_SCHEMA_VERSION
        );
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
    fn local_claim_migration_digest_is_a_committed_compatibility_value() {
        assert_eq!(
            local_claim_bundle_migration_digest(),
            [
                0x7c, 0xd7, 0x7b, 0x8e, 0x91, 0x06, 0xc7, 0x88, 0x36, 0xa8, 0xec, 0x0d, 0xc3, 0xad,
                0xe2, 0x65, 0xc8, 0xab, 0x35, 0x69, 0x5f, 0x45, 0x9a, 0x6a, 0xed, 0x9f, 0xef, 0x1e,
                0x06, 0x01, 0x10, 0x90,
            ]
        );
        assert_eq!(
            local_setup_operation_migration_digest(),
            [
                0xeb, 0xb2, 0xed, 0x6b, 0x07, 0x6e, 0xd1, 0xa5, 0xb5, 0xf2, 0xd0, 0x9d, 0xb1, 0x14,
                0xd2, 0x19, 0x89, 0xe6, 0x78, 0x84, 0x62, 0x80, 0xf9, 0xbd, 0x3f, 0x28, 0xa4, 0xcb,
                0xf4, 0xd4, 0xfe, 0x87,
            ]
        );
        assert_eq!(
            local_authentication_ceremony_migration_digest(),
            [
                0x18, 0x3e, 0x9a, 0x32, 0x42, 0xd5, 0xd1, 0xef, 0xe4, 0xe1, 0x37, 0x4f, 0xa5, 0xef,
                0x1f, 0x67, 0x0e, 0x01, 0xca, 0x80, 0xd7, 0x69, 0x9e, 0x8b, 0xb7, 0x8e, 0xb5, 0xfd,
                0x42, 0x64, 0xf2, 0xf9,
            ]
        );
        assert_eq!(
            local_totp_registration_ceremony_migration_digest(),
            [
                0x58, 0xf9, 0xa8, 0x28, 0x1a, 0xd5, 0xeb, 0x99, 0x47, 0x1a, 0x7f, 0xad, 0x97, 0x57,
                0x44, 0x7e, 0x1f, 0x08, 0x8b, 0xc8, 0x66, 0x8d, 0x4a, 0xdd, 0xd8, 0x63, 0xd2, 0x3a,
                0xf4, 0x2d, 0x46, 0xa4,
            ]
        );
        assert_eq!(
            local_storage_target_registration_migration_digest(),
            [
                0x67, 0x26, 0x17, 0xa3, 0xa0, 0xe8, 0xa5, 0xad, 0xd8, 0x52, 0x58, 0xff, 0xb6, 0x11,
                0x6f, 0xc9, 0x8f, 0xcb, 0x48, 0x34, 0x41, 0x61, 0x1c, 0x4f, 0x29, 0x7e, 0x5f, 0xeb,
                0xd0, 0xcf, 0x11, 0xdb,
            ]
        );
        assert_eq!(
            local_maintenance_scrub_progress_migration_digest(),
            [
                0x1d, 0x11, 0xf2, 0x39, 0x9c, 0x46, 0x7b, 0x5b, 0x95, 0xf6, 0xca, 0x7a, 0xd2, 0x95,
                0x51, 0xad, 0xbb, 0xad, 0x20, 0x02, 0xef, 0x26, 0x97, 0xe5, 0x0a, 0x69, 0x80, 0x45,
                0x34, 0xe4, 0x53, 0x2b,
            ]
        );
        assert_eq!(
            local_metadata_backup_staging_migration_digest(),
            [
                0xf9, 0xc1, 0xa5, 0xa5, 0xfe, 0x72, 0xad, 0xc6, 0x36, 0xde, 0x59, 0xb1, 0xaa, 0x06,
                0x39, 0x7b, 0x67, 0xbd, 0x11, 0xfa, 0x33, 0x7f, 0x2f, 0x8b, 0x69, 0x90, 0x81, 0xc6,
                0x30, 0x69, 0x26, 0x54,
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
                0x65, 0xa5, 0xa9, 0xb3, 0xe6, 0xa0, 0x6e, 0x7f, 0xd1, 0xc6, 0x5b, 0xbf, 0x84, 0xbd,
                0x2e, 0xc4, 0xd9, 0x25, 0x5f, 0x5e, 0x08, 0x61, 0xfd, 0xae, 0xc2, 0x83, 0x95, 0xb8,
                0xad, 0x9b, 0x3e, 0x0e,
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
                0x3c, 0xf5, 0xb4, 0x14, 0x3d, 0xc3, 0xb5, 0xc0, 0x66, 0xcc, 0xb9, 0xb4, 0xd0, 0x91,
                0x54, 0x39, 0x69, 0xdd, 0x9b, 0x6e, 0x2c, 0xe8, 0xf7, 0x42, 0x8f, 0xd3, 0x9e, 0x62,
                0xec, 0xca, 0x1f, 0xf6,
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
            partition_federation_actor_attestation_history_migration_digest(),
            [
                0x03, 0xfb, 0x42, 0x12, 0x0a, 0x25, 0x8e, 0x5b, 0x3b, 0xd1, 0xd3, 0xdf, 0x89, 0xff,
                0x5f, 0x81, 0x97, 0x10, 0xdc, 0x66, 0x37, 0x4e, 0x83, 0xe9, 0x85, 0x5d, 0xdb, 0xe2,
                0x72, 0x85, 0x63, 0xeb,
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
    fn principal_inactive_quarantine_migration_digest_is_committed_compatibility_value() {
        assert_eq!(
            partition_principal_inactive_quarantine_migration_digest(),
            [
                0xeb, 0x96, 0xd6, 0x5b, 0x41, 0x2a, 0xfc, 0xea, 0x7f, 0x77, 0xd1, 0xb7, 0x07, 0xd4,
                0x91, 0x1b, 0x13, 0x63, 0x74, 0xf8, 0x95, 0x5e, 0xe1, 0x58, 0xe8, 0x2f, 0x70, 0xbf,
                0xc7, 0x90, 0x4d, 0x5e,
            ]
        );
    }

    #[test]
    fn typed_authentication_migration_digest_is_a_committed_compatibility_value() {
        assert_eq!(
            partition_typed_authentication_migration_digest(),
            [
                0xa7, 0x02, 0x30, 0x33, 0x3f, 0x8a, 0xb3, 0x24, 0xa2, 0x7e, 0x92, 0xb4, 0xb8, 0x61,
                0xa0, 0x33, 0x28, 0x3b, 0x73, 0xc0, 0x74, 0x43, 0x8f, 0x14, 0x87, 0x2c, 0x3f, 0xd3,
                0x60, 0x73, 0xc9, 0x1c,
            ]
        );
    }

    #[test]
    fn authentication_method_events_migration_digest_is_a_committed_compatibility_value() {
        assert_eq!(
            partition_authentication_method_events_migration_digest(),
            [
                0xc9, 0x7a, 0x73, 0x66, 0x3a, 0x1d, 0xb7, 0x1a, 0x37, 0xd5, 0x76, 0xce, 0x35, 0x68,
                0x07, 0x01, 0x8c, 0x95, 0x4b, 0x66, 0xb0, 0x78, 0x24, 0x73, 0x71, 0x9e, 0xf0, 0xe1,
                0x4f, 0x51, 0x44, 0xc6,
            ]
        );
    }

    #[test]
    fn authentication_credential_constraints_migration_digest_is_committed() {
        assert_eq!(
            partition_authentication_credential_constraints_migration_digest(),
            [
                0xe8, 0xf8, 0x06, 0x50, 0x0b, 0x39, 0x16, 0xf0, 0x6b, 0x49, 0x73, 0xcb, 0xa2, 0x62,
                0x73, 0x34, 0xc7, 0x06, 0x1f, 0x8a, 0xea, 0xed, 0xb0, 0xd5, 0xca, 0x73, 0xff, 0x80,
                0xea, 0x3a, 0x45, 0x47,
            ]
        );
    }

    #[test]
    fn authentication_session_factors_migration_digest_is_committed() {
        assert_eq!(
            partition_authentication_session_factors_migration_digest(),
            [
                0xe4, 0x69, 0x83, 0xf1, 0xb0, 0x9c, 0x32, 0xb7, 0x83, 0x0e, 0x50, 0x3a, 0x4e, 0x00,
                0x27, 0x7d, 0xa4, 0x57, 0xd8, 0x7a, 0xf8, 0xda, 0x41, 0xec, 0x14, 0x01, 0xb0, 0x57,
                0x30, 0xb0, 0x9c, 0x4d,
            ]
        );
    }

    #[test]
    fn authentication_policy_migration_digest_is_committed() {
        assert_eq!(
            partition_authentication_policy_migration_digest(),
            [
                0x96, 0xd6, 0x98, 0x96, 0xc1, 0xc2, 0x65, 0x70, 0x53, 0xb0, 0x9f, 0x19, 0xa8, 0x42,
                0x8b, 0xda, 0x05, 0x4c, 0xff, 0xb7, 0xff, 0xae, 0x3a, 0x2e, 0xb5, 0xbf, 0x38, 0xe5,
                0x38, 0x2e, 0x33, 0xac,
            ]
        );
    }

    #[test]
    fn authentication_session_delivery_migration_digest_is_committed() {
        assert_eq!(
            partition_authentication_session_delivery_migration_digest(),
            [
                0xbd, 0x92, 0x6f, 0xe0, 0x97, 0xde, 0x7f, 0xd8, 0x1c, 0x15, 0xdf, 0xee, 0x8f, 0xe6,
                0x90, 0x7c, 0x96, 0x07, 0xe3, 0x6d, 0x6e, 0xd1, 0x7d, 0xff, 0x57, 0x52, 0x2f, 0xbd,
                0xe2, 0x16, 0x4c, 0xd9,
            ]
        );
    }

    #[test]
    fn totp_session_replay_steps_migration_digest_is_committed() {
        assert_eq!(
            partition_totp_session_replay_steps_migration_digest(),
            [
                0xa8, 0xcc, 0xd5, 0x16, 0xa9, 0xa1, 0xd6, 0x9b, 0x77, 0xc1, 0x9e, 0x0e, 0xbd, 0xf0,
                0xe6, 0x6a, 0x62, 0x22, 0x65, 0x28, 0xaf, 0x2f, 0x78, 0x6a, 0xce, 0xfb, 0x81, 0x90,
                0xec, 0x80, 0x2e, 0xd5,
            ]
        );
    }

    #[test]
    fn authentication_session_rotation_migration_digest_is_committed() {
        assert_eq!(
            partition_authentication_session_rotation_migration_digest(),
            [
                0x2a, 0x62, 0xce, 0xf0, 0x3a, 0xfb, 0x3f, 0xfc, 0x4f, 0x92, 0xd4, 0x26, 0x60, 0xc2,
                0x33, 0x34, 0x78, 0xfc, 0x9d, 0x4b, 0x4d, 0xe8, 0xfc, 0x91, 0xcd, 0x55, 0xd0, 0x3a,
                0x53, 0x2b, 0xf6, 0xde,
            ]
        );
    }

    #[test]
    fn storage_targets_migration_digest_is_committed() {
        assert_eq!(
            partition_storage_targets_migration_digest(),
            [
                0x8d, 0x8c, 0x56, 0xd5, 0x91, 0xbc, 0x17, 0x85, 0x01, 0x64, 0xfd, 0x0d, 0x73, 0xcc,
                0xba, 0x63, 0xb0, 0xa6, 0x63, 0xc4, 0x4a, 0x31, 0x34, 0x58, 0xc6, 0x6e, 0x72, 0xf2,
                0x12, 0x61, 0xd4, 0x70,
            ]
        );
    }

    #[test]
    fn metadata_backup_catalogue_migration_digest_is_committed() {
        assert_eq!(
            partition_metadata_backup_catalogue_migration_digest(),
            [
                0xc2, 0xfe, 0x4d, 0xcb, 0x91, 0x60, 0xc4, 0x15, 0x19, 0x82, 0xa1, 0x09, 0x3b, 0x38,
                0xf2, 0x77, 0x0d, 0xda, 0x08, 0x5b, 0x87, 0x1b, 0x03, 0x80, 0xdb, 0xbb, 0x2f, 0xbd,
                0x11, 0xda, 0x77, 0xc5,
            ]
        );
    }

    #[test]
    fn metadata_backup_schedule_migration_digest_is_committed() {
        assert_eq!(
            partition_metadata_backup_schedule_migration_digest(),
            [
                0x56, 0x79, 0x03, 0x45, 0xf7, 0x0f, 0x58, 0xd6, 0x44, 0x90, 0x0e, 0xf4, 0x25, 0xab,
                0x63, 0xbf, 0xd2, 0x81, 0x9c, 0xd3, 0x59, 0x99, 0x16, 0x0a, 0xcf, 0x75, 0x2a, 0xbf,
                0x01, 0x91, 0xaf, 0x7b,
            ]
        );
    }

    #[test]
    fn metadata_backup_claim_migration_digest_is_committed() {
        assert_eq!(
            partition_metadata_backup_claim_migration_digest(),
            [
                0x5b, 0x3e, 0xbf, 0x52, 0x99, 0xb8, 0x57, 0xf8, 0xc1, 0x61, 0xe9, 0xf6, 0x0c, 0x03,
                0x56, 0x1d, 0x14, 0x4f, 0x69, 0x37, 0x7b, 0x83, 0x8c, 0x58, 0xa2, 0x90, 0x8a, 0x9d,
                0xfc, 0x47, 0xed, 0xc1,
            ]
        );
    }

    #[test]
    fn backup_defaults_migration_is_fingerprinted_and_upgrades_schema_84()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            crate::migration::partition_backup_defaults_migration_digest(),
            [
                0xe9, 0x14, 0xd7, 0xb1, 0x75, 0xff, 0x6a, 0xa8, 0xe2, 0x15, 0x6f, 0x76, 0xe3, 0xe0,
                0xa1, 0xe7, 0xbb, 0xc1, 0x97, 0xd3, 0x09, 0x98, 0x4f, 0xc7, 0x69, 0x34, 0x83, 0x6d,
                0x5d, 0x2f, 0x37, 0x82,
            ]
        );
        let directory = tempdir()?;
        let mut connection = open_connection(&directory.path().join("upgrade.sqlite3"))?;
        migrate_partition_through(&mut connection, 84, 10)?;
        connection.execute("INSERT INTO backup_destinations(destination_id, display_name, canonical_name,
            destination_kind, remote_mesh_id, provider_generation, failure_relationship,
            failure_evidence_digest, state, created_at, revision)
            VALUES (?1, 'Existing paused destination', 'existing paused destination', 2, ?2, 1, 3, ?3, 2, 10, 1)",
            rusqlite::params![[1_u8; 16].as_slice(), [2_u8; 16].as_slice(), [3_u8; 32].as_slice()])?;
        migrate_partition(&mut connection, 20)?;
        assert_eq!(
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
            PARTITION_SCHEMA_VERSION
        );
        let preserved = connection.query_row(
            "SELECT configuration_origin, state, revision FROM backup_destinations",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        assert_eq!(preserved, (2, 2, 1));
        let integrity: String =
            connection.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
        assert_eq!(integrity, "ok");
        assert!(!connection.prepare("PRAGMA foreign_key_check")?.exists([])?);
        Ok(())
    }

    #[test]
    fn backup_reclamation_migration_is_fingerprinted_and_upgrades_schema_83()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            partition_backup_reclamation_migration_digest(),
            [
                0x75, 0xe1, 0x5e, 0x52, 0xe9, 0xe2, 0x78, 0xf3, 0x7f, 0xd1, 0xbc, 0x77, 0x58, 0xb9,
                0x5c, 0x18, 0x1e, 0x7d, 0x3d, 0x67, 0x01, 0xd2, 0x6d, 0xb5, 0x84, 0xf0, 0x4c, 0xce,
                0x64, 0xd0, 0xc4, 0x1c,
            ]
        );
        let directory = tempdir()?;
        let mut connection = open_connection(&directory.path().join("upgrade.sqlite3"))?;
        migrate_partition_through(&mut connection, 83, 10)?;
        migrate_partition(&mut connection, 20)?;
        assert_eq!(
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
            PARTITION_SCHEMA_VERSION
        );
        let integrity: String =
            connection.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
        assert_eq!(integrity, "ok");
        let tables: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'backup_copy_reclamations'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(tables, 1);
        Ok(())
    }

    #[test]
    fn metadata_backup_catalogue_refuses_legacy_rows_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("legacy-backup-catalogue.sqlite3");
        let mut connection = open_connection(&file_path)?;
        migrate_partition_through(&mut connection, 80, 10)?;
        connection.execute(
            "INSERT INTO metadata_backups(
                backup_id, partition_id, last_log_index, last_log_term, state_revision,
                schema_version, byte_length, digest, state, created_at
             ) VALUES (?1, ?2, 1, 1, 1, 80, 32, ?3, 1, 10)",
            params![
                [70_u8; 16].as_slice(),
                [71_u8; 16].as_slice(),
                [72_u8; 32].as_slice(),
            ],
        )?;

        assert!(migrate_partition(&mut connection, 20).is_err());
        assert_eq!(
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
            80
        );
        let retained: i64 = connection.query_row(
            "SELECT count(*) FROM metadata_backups WHERE backup_id = ?1",
            [[70_u8; 16].as_slice()],
            |row| row.get(0),
        )?;
        assert_eq!(retained, 1);
        let new_table: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'backup_copies'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(new_table, 0);
        Ok(())
    }

    #[test]
    fn node_wrapping_keys_migration_digest_is_committed() {
        assert_eq!(
            partition_node_wrapping_keys_migration_digest(),
            [
                0xba, 0x18, 0xb4, 0x1a, 0x73, 0x58, 0x0d, 0x92, 0xd6, 0xf2, 0x80, 0x70, 0x79, 0x42,
                0xd9, 0x22, 0x03, 0x70, 0x00, 0x50, 0xd1, 0xe4, 0x00, 0xe5, 0x83, 0xd8, 0xde, 0x68,
                0xfd, 0x74, 0x6f, 0xb1,
            ]
        );
    }

    #[test]
    fn secret_generations_migration_digest_is_committed() {
        assert_eq!(
            partition_secret_generations_migration_digest(),
            [
                0xad, 0xe1, 0x28, 0xdc, 0x29, 0xa3, 0x3b, 0xe1, 0x6d, 0x63, 0x0a, 0x4a, 0xdd, 0xca,
                0xff, 0x96, 0x71, 0xc3, 0x86, 0x66, 0x34, 0xe0, 0x55, 0x50, 0x6c, 0x2b, 0x82, 0x04,
                0xbb, 0xf9, 0x65, 0x96,
            ]
        );
    }

    #[test]
    fn recovery_authority_migration_digest_is_committed() {
        assert_eq!(
            partition_recovery_authority_migration_digest(),
            [
                0x67, 0x6a, 0x50, 0xd6, 0x39, 0xcc, 0x2d, 0x25, 0x45, 0x46, 0x87, 0x78, 0xb7, 0x3b,
                0x6a, 0x6f, 0x1d, 0xac, 0xe3, 0xf7, 0x3a, 0x70, 0xb3, 0x9d, 0xee, 0x76, 0x66, 0x7d,
                0x61, 0xcf, 0xed, 0xc6,
            ]
        );
    }

    #[test]
    fn online_certificate_authority_migration_digest_is_committed() {
        assert_eq!(
            partition_online_certificate_authority_migration_digest(),
            [
                0xf6, 0x6e, 0x98, 0xc4, 0xc2, 0x18, 0xac, 0xc2, 0xd7, 0x8e, 0xc6, 0xe5, 0x27, 0x22,
                0x1d, 0x7f, 0x08, 0x05, 0x9e, 0xf5, 0x06, 0xbc, 0xcd, 0x11, 0x51, 0xcb, 0xdf, 0xad,
                0x9d, 0x53, 0x84, 0xfa,
            ]
        );
    }

    #[test]
    fn pending_node_activations_migration_digest_is_committed() {
        assert_eq!(
            partition_pending_node_activations_migration_digest(),
            [
                0x02, 0x7a, 0x6b, 0xbf, 0x07, 0xb2, 0x43, 0x9a, 0xa3, 0x91, 0x0d, 0x60, 0x06, 0x92,
                0xb2, 0x6c, 0x63, 0x7d, 0xc7, 0x7c, 0xdf, 0x95, 0x13, 0xb5, 0xc4, 0x77, 0x84, 0x01,
                0x33, 0xf2, 0x0a, 0x52,
            ]
        );
    }

    #[test]
    fn node_activations_migration_digest_is_committed() {
        assert_eq!(
            partition_node_activations_migration_digest(),
            [
                0xff, 0x45, 0x62, 0x90, 0xb5, 0xf6, 0x67, 0xdb, 0xc4, 0x73, 0x62, 0x0e, 0xc9, 0x1d,
                0xc8, 0x63, 0x6c, 0x5a, 0x66, 0x21, 0x16, 0x8f, 0x5e, 0x13, 0x5d, 0x87, 0xb5, 0xa6,
                0x45, 0x01, 0xcc, 0x00,
            ]
        );
    }

    #[test]
    fn smb_exports_migration_digest_is_committed() {
        assert_eq!(
            partition_smb_exports_migration_digest(),
            [
                0xe2, 0xcb, 0x55, 0x39, 0xaf, 0x4a, 0x6a, 0x28, 0x62, 0x9b, 0xad, 0x19, 0x8c, 0x14,
                0x44, 0xd7, 0xa1, 0x64, 0xdd, 0x3f, 0xe8, 0xd9, 0x75, 0x87, 0xc0, 0x20, 0x3b, 0xe5,
                0x8d, 0x60, 0x53, 0x47,
            ]
        );
    }

    #[test]
    fn storage_policies_migration_digest_is_committed() {
        assert_eq!(
            partition_storage_policies_migration_digest(),
            [
                0x48, 0xde, 0x3f, 0x2d, 0x81, 0x1c, 0x6b, 0xa3, 0x13, 0xc3, 0xb7, 0xb8, 0x57, 0xae,
                0xb2, 0x6b, 0x1f, 0x67, 0x3b, 0x39, 0xb2, 0x40, 0x97, 0x25, 0x3e, 0x34, 0x94, 0xc3,
                0x7b, 0x53, 0x06, 0x71,
            ]
        );
    }

    #[test]
    fn builtin_fault_classes_migration_digest_is_committed() {
        assert_eq!(
            partition_builtin_fault_classes_migration_digest(),
            [
                0x02, 0x52, 0x94, 0x2c, 0xdc, 0x91, 0x1c, 0xf2, 0xa4, 0xaa, 0x82, 0xf6, 0x86, 0x4b,
                0x8c, 0xb0, 0x77, 0x24, 0xfe, 0x55, 0xc1, 0xf2, 0x57, 0xf3, 0xee, 0xe8, 0x63, 0x05,
                0x4a, 0xdb, 0xc0, 0x40,
            ]
        );
    }

    #[test]
    fn storage_policy_schema_separates_survival_locality_and_acknowledgement()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let database = PartitionDatabase::open(
            &directory.path().join("storage-policies.sqlite3"),
            PartitionId::from_bytes([61; 16])?,
            UnixMicros::new(10),
        )?;
        let connection = database.connection();
        for table in [
            "availability_cells",
            "host_cell_memberships",
            "target_cell_memberships",
            "protection_policies",
            "protection_scenarios",
            "protection_scenario_terms",
            "locality_policies",
            "locality_requirements",
            "object_locality_bindings",
            "acknowledgement_policies",
            "acknowledgement_policy_scenarios",
            "acknowledgement_zone_requirements",
            "object_acknowledgement_bindings",
        ] {
            assert_eq!(
                connection.query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get::<_, u8>(0),
                )?,
                1,
                "missing storage-policy relation {table}",
            );
        }

        let columns = connection
            .prepare("SELECT name FROM pragma_table_info('volumes') ORDER BY cid")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for expected in [
            "protection_policy_id",
            "default_locality_policy_id",
            "default_acknowledgement_policy_id",
        ] {
            assert!(columns.iter().any(|column| column == expected));
        }

        connection.execute(
            "INSERT INTO principals(
                principal_id, principal_kind, display_name, canonical_name,
                state, created_at, revision
             ) VALUES (?1, 1, 'Policy administrator', 'policy administrator', 1, 10, 1)",
            [[1_u8; 16].as_slice()],
        )?;
        connection.execute(
            "INSERT INTO acknowledgement_policies(
                acknowledgement_policy_id, display_name, canonical_name, consistency_class,
                minimum_durable_targets, minimum_distinct_nodes, strong_wait_micros,
                fallback_mode, state, created_by, created_at, revision
             ) VALUES (?1, 'Availability first', 'availability first', 1, 1, 1, NULL,
                1, 1, ?2, 10, 1)",
            params![[2_u8; 16].as_slice(), [1_u8; 16].as_slice()],
        )?;
        assert!(
            connection
                .execute(
                    "INSERT INTO acknowledgement_policies(
                        acknowledgement_policy_id, display_name, canonical_name,
                        consistency_class, minimum_durable_targets, minimum_distinct_nodes,
                        strong_wait_micros, fallback_mode, state, created_by, created_at, revision
                     ) VALUES (?1, 'Impossible counts', 'impossible counts', 1, 1, 2, NULL,
                        1, 1, ?2, 10, 1)",
                    params![[3_u8; 16].as_slice(), [1_u8; 16].as_slice()],
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn authentication_policy_migration_seeds_complete_existing_mesh_defaults()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory
            .path()
            .join("legacy-authentication-policy.sqlite3");
        let mut connection = open_connection(&file_path)?;
        migrate_partition_through(&mut connection, 45, 10)?;
        let principal = [90_u8; 16];
        let mesh = [91_u8; 16];
        let role = [92_u8; 16];
        connection.execute(
            "INSERT INTO principals(
                principal_id, principal_kind, display_name, canonical_name,
                state, created_at, revision
             ) VALUES (?1, 1, 'Administrator', 'administrator', 1, 10, 1)",
            [principal.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO users(principal_id, primary_email) VALUES (?1, NULL)",
            [principal.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO meshes(
                mesh_id, display_name, canonical_name, created_at,
                configuration_revision, identity_revision, namespace_revision, revision
             ) VALUES (?1, 'Existing mesh', 'existing mesh', 10, 1, 1, 1, 1)",
            [mesh.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO roles(
                role_id, display_name, canonical_name, system_rights, created_at, revision
             ) VALUES (?1, 'System administrators', 'system administrators', 255, 10, 1)",
            [role.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO role_grants(
                role_id, principal_id, valid_from, valid_until, activation_policy_id,
                created_by, created_at, revision
             ) VALUES (?1, ?2, NULL, NULL, NULL, ?2, 10, 1)",
            params![role.as_slice(), principal.as_slice()],
        )?;

        migrate_partition(&mut connection, 20)?;
        let count: i64 = connection.query_row(
            "SELECT count(*) FROM authentication_policy_revisions",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 12);
        let policy_id: Vec<u8> = connection.query_row(
            "SELECT policy_id FROM authentication_policy_revisions
             WHERE service = 1 AND operation_class = 1",
            [],
            |row| row.get(0),
        )?;
        let mut expected = [0_u8; 16];
        expected[0] = 0xa6;
        expected[14] = 1;
        expected[15] = 1;
        assert_eq!(policy_id, expected);
        assert_eq!(
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
            PARTITION_SCHEMA_VERSION
        );
        Ok(())
    }

    #[test]
    fn authentication_session_migration_revokes_unbound_legacy_sessions_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("legacy-sessions.sqlite3");
        let mut connection = open_connection(&file_path)?;
        migrate_partition_through(&mut connection, 44, 10)?;
        let principal = [80_u8; 16];
        connection.execute(
            "INSERT INTO principals(
                principal_id, principal_kind, display_name, canonical_name,
                state, created_at, revision
             ) VALUES (?1, 1, 'Legacy user', 'legacy user', 1, 10, 1)",
            [principal.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO users(principal_id, primary_email) VALUES (?1, NULL)",
            [principal.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO authentication_sessions(
                session_id, token_digest, user_principal_id, assurance,
                identity_revision, issued_at, expires_at, revoked_at, revision
             ) VALUES (?1, ?2, ?3, 3, 1, 10, 100, NULL, 1)",
            params![
                [81_u8; 16].as_slice(),
                [82_u8; 32].as_slice(),
                principal.as_slice(),
            ],
        )?;

        migrate_partition(&mut connection, 20)?;
        let sessions: i64 =
            connection.query_row("SELECT count(*) FROM authentication_sessions", [], |row| {
                row.get(0)
            })?;
        assert_eq!(sessions, 0);
        assert_eq!(
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
            PARTITION_SCHEMA_VERSION
        );
        Ok(())
    }

    #[test]
    fn totp_replay_step_migration_invalidates_ambiguous_sessions_and_preserves_others()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("totp-replay-step-migration.sqlite3");
        let mut connection = open_connection(&file_path)?;
        migrate_partition_through(&mut connection, 47, 10)?;

        let principal = [100_u8; 16];
        let totp_method = [101_u8; 16];
        let api_key_method = [102_u8; 16];
        let api_key = [103_u8; 16];
        connection.execute(
            "INSERT INTO principals(
                principal_id, principal_kind, display_name, canonical_name,
                state, created_at, retired_at, revision
             ) VALUES (?1, 1, 'Test user', 'test user', 1, 1, NULL, 1)",
            [principal.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO users(principal_id, primary_email) VALUES (?1, NULL)",
            [principal.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO authentication_methods(
                method_id, user_principal_id, method_kind, label, service_scope,
                state, created_at, last_used_at, expires_at, credential_generation, revision
             ) VALUES (?1, ?2, 2, 'TOTP', 1, 1, 1, NULL, NULL, 1, 1)",
            params![totp_method.as_slice(), principal.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO authentication_methods(
                method_id, user_principal_id, method_kind, label, service_scope,
                state, created_at, last_used_at, expires_at, credential_generation, revision
             ) VALUES (?1, ?2, 4, 'API key', 1, 1, 1, NULL, NULL, 1, 1)",
            params![api_key_method.as_slice(), principal.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO totp_credentials(
                method_id, secret_ciphertext, algorithm, digits, period_seconds,
                accepted_step_window, revision, last_accepted_step
             ) VALUES (?1, ?2, 1, 6, 30, 1, 1, NULL)",
            params![totp_method.as_slice(), [1_u8; 32].as_slice()],
        )?;
        connection.execute(
            "INSERT INTO api_keys(
                method_id, key_id, key_digest, scopes, valid_from,
                valid_until, last_used_at, revision
             ) VALUES (?1, ?2, ?3, 1, 1, NULL, NULL, 1)",
            params![
                api_key_method.as_slice(),
                api_key.as_slice(),
                [2_u8; 32].as_slice()
            ],
        )?;

        insert_legacy_session(&connection, [104; 16], [105; 32], [106; 32], principal, 2)?;
        insert_legacy_factor(&connection, [104; 16], 1, api_key_method, 4, api_key)?;
        insert_legacy_factor(&connection, [104; 16], 2, totp_method, 2, totp_method)?;
        insert_legacy_session(&connection, [107; 16], [108; 32], [109; 32], principal, 1)?;
        insert_legacy_factor(&connection, [107; 16], 1, api_key_method, 4, api_key)?;

        migrate_partition(&mut connection, 20)?;
        assert_eq!(session_exists(&connection, [104; 16])?, 0);
        assert_eq!(session_exists(&connection, [107; 16])?, 1);

        insert_legacy_session(&connection, [110; 16], [111; 32], [112; 32], principal, 2)?;
        connection.execute(
            "INSERT INTO authentication_session_factors(
                session_id, factor_sequence, method_id, method_kind, credential_reference,
                credential_generation, method_revision, authenticated_at, revision
             ) VALUES (?1, 1, ?2, 2, ?3, 1, 1, 5, 1)",
            params![
                [110_u8; 16].as_slice(),
                totp_method.as_slice(),
                0_u64.to_be_bytes().as_slice()
            ],
        )?;
        insert_legacy_factor(&connection, [110; 16], 2, api_key_method, 4, api_key)?;
        insert_legacy_session(&connection, [113; 16], [114; 32], [115; 32], principal, 2)?;
        assert!(
            connection
                .execute(
                    "INSERT INTO authentication_session_factors(
                        session_id, factor_sequence, method_id, method_kind,
                        credential_reference, credential_generation, method_revision,
                        authenticated_at, revision
                     ) VALUES (?1, 1, ?2, 2, ?3, 1, 1, 5, 1)",
                    params![
                        [113_u8; 16].as_slice(),
                        totp_method.as_slice(),
                        totp_method.as_slice()
                    ],
                )
                .is_err()
        );
        Ok(())
    }

    fn insert_legacy_session(
        connection: &rusqlite::Connection,
        session_id: [u8; 16],
        token_digest: [u8; 32],
        csrf_digest: [u8; 32],
        principal_id: [u8; 16],
        assurance: u8,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO authentication_sessions(
                session_id, token_digest, user_principal_id, service, assurance,
                identity_revision, issued_at, expires_at, revoked_at, revision,
                csrf_digest, client_label_state, client_label, persistent_cookie
             ) VALUES (?1, ?2, ?3, 1, ?4, 1, 5, 10, NULL, 1, ?5, 1, NULL, 0)",
            params![
                session_id.as_slice(),
                token_digest.as_slice(),
                principal_id.as_slice(),
                assurance,
                csrf_digest.as_slice()
            ],
        )?;
        Ok(())
    }

    fn insert_legacy_factor(
        connection: &rusqlite::Connection,
        session_id: [u8; 16],
        sequence: u8,
        method_id: [u8; 16],
        method_kind: u8,
        credential_reference: [u8; 16],
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO authentication_session_factors(
                session_id, factor_sequence, method_id, method_kind, credential_reference,
                credential_generation, method_revision, authenticated_at, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 1, 5, 1)",
            params![
                session_id.as_slice(),
                sequence,
                method_id.as_slice(),
                method_kind,
                credential_reference.as_slice()
            ],
        )?;
        Ok(())
    }

    fn session_exists(
        connection: &rusqlite::Connection,
        session_id: [u8; 16],
    ) -> Result<i64, rusqlite::Error> {
        connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM authentication_sessions WHERE session_id = ?1)",
            [session_id.as_slice()],
            |row| row.get(0),
        )
    }

    #[test]
    fn typed_authentication_schema_has_only_bound_credential_subtypes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("typed-authentication.sqlite3");
        let partition_id = PartitionId::from_bytes([7; 16])?;
        let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(10))?;
        let principal = [20_u8; 16];
        let method = [21_u8; 16];
        database.connection().execute(
            "INSERT INTO principals(
                principal_id, principal_kind, display_name, canonical_name,
                state, created_at, revision
             ) VALUES (?1, 1, 'User', 'user', 1, 10, 1)",
            [principal.as_slice()],
        )?;
        database.connection().execute(
            "INSERT INTO users(principal_id, primary_email) VALUES (?1, NULL)",
            [principal.as_slice()],
        )?;

        let generic_secret_columns: i64 = database.connection().query_row(
            "SELECT count(*) FROM pragma_table_info('authentication_methods')
             WHERE name IN ('protected_material', 'secret', 'password', 'certificate')",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(generic_secret_columns, 0);
        assert!(
            database
                .connection()
                .execute(
                    "INSERT INTO authentication_methods(
                        method_id, user_principal_id, method_kind, label, service_scope,
                        state, created_at, last_used_at, expires_at,
                        credential_generation, revision
                     ) VALUES (?1, ?2, 5, 'obsolete', 1, 1, 10, NULL, NULL, 1, 1)",
                    params![method.as_slice(), principal.as_slice()],
                )
                .is_err()
        );
        database.connection().execute(
            "INSERT INTO authentication_methods(
                method_id, user_principal_id, method_kind, label, service_scope,
                state, created_at, last_used_at, expires_at,
                credential_generation, revision
             ) VALUES (?1, ?2, 1, 'passkey', 1, 1, 10, NULL, NULL, 1, 1)",
            params![method.as_slice(), principal.as_slice()],
        )?;
        database.connection().execute(
            "INSERT INTO webauthn_credentials(
                method_id, credential_id, public_key_algorithm, public_key,
                signature_counter, authenticator_guid, transports,
                backup_eligible, backup_state, revision
             ) VALUES (?1, ?2, 1, ?3, 0, NULL, 1, 1, 0, 1)",
            params![
                method.as_slice(),
                [22_u8; 32].as_slice(),
                [23_u8; 32].as_slice(),
            ],
        )?;
        database.connection().execute(
            "INSERT INTO authentication_method_events(
                method_id, event_sequence, event_kind, prior_state, resulting_state,
                reason, changed_by, changed_at, revision
             ) VALUES (?1, 1, 1, NULL, 1, NULL, ?2, 10, 1)",
            params![method.as_slice(), principal.as_slice()],
        )?;
        assert!(
            database
                .connection()
                .execute(
                    "INSERT INTO api_keys(
                        method_id, key_id, key_digest, scopes,
                        valid_from, valid_until, last_used_at, revision
                     ) VALUES (?1, ?2, ?3, 1, 10, NULL, NULL, 1)",
                    params![
                        method.as_slice(),
                        [24_u8; 16].as_slice(),
                        [25_u8; 32].as_slice(),
                    ],
                )
                .is_err()
        );
        assert!(database.check_integrity()?.foreign_keys_ok);
        let incomplete_method = [26_u8; 16];
        database.connection().execute(
            "INSERT INTO authentication_methods(
                method_id, user_principal_id, method_kind, label, service_scope,
                state, created_at, last_used_at, expires_at,
                credential_generation, revision
             ) VALUES (?1, ?2, 2, 'incomplete TOTP', 1, 1, 10, NULL, NULL, 1, 1)",
            params![incomplete_method.as_slice(), principal.as_slice()],
        )?;
        assert!(matches!(
            database.check_integrity(),
            Err(MetadataStoreError::IntegrityFailed)
        ));
        Ok(())
    }

    #[test]
    fn typed_authentication_migration_rejects_ambiguous_legacy_material_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("legacy-authentication.sqlite3");
        let mut connection = open_connection(&file_path)?;
        migrate_partition_through(&mut connection, 41, 10)?;
        let principal = [30_u8; 16];
        connection.execute(
            "INSERT INTO principals(
                principal_id, principal_kind, display_name, canonical_name,
                state, created_at, revision
             ) VALUES (?1, 1, 'Legacy user', 'legacy user', 1, 10, 1)",
            [principal.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO users(principal_id, primary_email) VALUES (?1, NULL)",
            [principal.as_slice()],
        )?;
        connection.execute(
            "INSERT INTO authentication_methods(
                method_id, user_principal_id, method_kind, label, service_scope,
                state, protected_material, created_at, valid_until, revision
             ) VALUES (?1, ?2, 1, 'ambiguous', 1, 1, ?3, 10, NULL, 1)",
            params![
                [31_u8; 16].as_slice(),
                principal.as_slice(),
                [32_u8; 32].as_slice(),
            ],
        )?;

        assert!(migrate_partition(&mut connection, 20).is_err());
        assert_eq!(
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
            41
        );
        let legacy_column: i64 = connection.query_row(
            "SELECT count(*) FROM pragma_table_info('authentication_methods')
             WHERE name = 'protected_material'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(legacy_column, 1);
        Ok(())
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
