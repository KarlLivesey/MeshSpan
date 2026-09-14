// SPDX-License-Identifier: GPL-2.0-only

//! Real pre-115 component/reference fixtures; not a supported downgrade path.

use super::{MetadataStoreError, migrate_partition_through};
use rusqlite::{Connection, OptionalExtension as _, types::Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TABLES: [&str; 7] = [
    "component_instances",
    "component_configurations",
    "component_assignments",
    "component_observations",
    "storage_targets",
    "target_generations",
    "backup_destinations",
];

#[test]
fn recovery_component_migration_preserves_principals_configurations_and_child_references()
-> TestResult {
    let mut connection = fixture()?;
    let original = TABLES
        .iter()
        .map(|table| rows(&connection, table))
        .collect::<TestResult<Vec<_>>>()?;
    migrate_partition_through(&mut connection, 115, 2)?;
    for (index, table) in TABLES.iter().enumerate() {
        let mut expected = original.get(index).ok_or("missing table")?.clone();
        if index < 2 {
            for row in &mut expected {
                row.push(Value::Null);
            }
        }
        assert_eq!(rows(&connection, table)?, expected, "{table}");
    }
    assert!(
        connection
            .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
            .optional()?
            .is_none()
    );
    assert!(connection.pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?);
    assert!(
        connection
            .execute("UPDATE component_instances SET created_by = NULL", [])
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE component_configurations SET recovery_preparation = 1",
                []
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn recovery_component_migration_failure_restores_schema_and_foreign_key_enforcement() -> TestResult
{
    let mut connection = fixture()?;
    connection.pragma_update(None, "foreign_keys", false)?;
    connection.execute(
        "UPDATE component_instances SET created_by = x'02020202020202020202020202020202'",
        [],
    )?;
    connection.pragma_update(None, "foreign_keys", true)?;
    let original = rows(&connection, "component_instances")?;
    assert!(matches!(
        migrate_partition_through(&mut connection, 115, 2),
        Err(MetadataStoreError::IntegrityFailed)
    ));
    assert_eq!(rows(&connection, "component_instances")?, original);
    assert_eq!(
        connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
        114
    );
    assert!(connection.pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?);
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'saved_component_%'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 115",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

fn rows(connection: &Connection, table: &str) -> TestResult<Vec<Vec<Value>>> {
    let mut statement = connection.prepare(&format!("SELECT * FROM {table}"))?;
    let columns = statement.column_count();
    Ok(statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<Result<Vec<Value>, _>>()
        })?
        .collect::<Result<Vec<_>, _>>()?)
}

fn fixture() -> TestResult<Connection> {
    let mut connection = Connection::open_in_memory()?;
    connection.pragma_update(None, "foreign_keys", true)?;
    migrate_partition_through(&mut connection, 114, 1)?;
    connection.execute_batch("INSERT INTO principals VALUES (zeroblob(16), 1, 'Owner', 'owner', 1, 1, NULL, 1);
        INSERT INTO hosts VALUES (zeroblob(16), 'Host', 'host', 1, 1, NULL, 1);
        INSERT INTO nodes(node_id, host_id, display_name, canonical_name, state, current_incarnation, admitted_at, activated_at, retired_at, revision)
            VALUES (zeroblob(16), zeroblob(16), 'Node', 'node', 2, 1, 1, 1, NULL, 1);
        INSERT INTO component_instances VALUES (zeroblob(16), 1, 'Provider', 'provider', 'meshspan-folder', 1, 0, 1, NULL, 1, 1, zeroblob(16), 1, NULL, 1);
        INSERT INTO component_configurations VALUES (zeroblob(16), 1, 1, x'7b7d', zeroblob(32), NULL, zeroblob(16), 1, 2);
        INSERT INTO component_assignments VALUES (zeroblob(16), 1, zeroblob(16), 1, 1);
        INSERT INTO component_observations VALUES (zeroblob(16), zeroblob(16), 1, 1, 1, NULL, 1, 1);
        INSERT INTO storage_targets VALUES (zeroblob(16), zeroblob(16), zeroblob(16), zeroblob(16), 'Target', 'target', 1, 1, 1, 95, 1, NULL, NULL, 1);
        INSERT INTO target_generations VALUES (zeroblob(16), 1, zeroblob(32), NULL, NULL, 1, NULL, 1, 1);
        INSERT INTO backup_destinations(destination_id, display_name, canonical_name, destination_kind,
            target_id, remote_mesh_id, provider_instance_id, provider_generation, failure_relationship,
            failure_evidence_digest, state, created_at, revision)
            VALUES (zeroblob(16), 'Backup', 'backup', 3, NULL, NULL, zeroblob(16), 1, 1, zeroblob(32), 1, 1, 1);")?;
    Ok(connection)
}

/// Removes post-114 component columns/guards in a legacy-history test fixture only.
/// No source recovery-origin records may be present; the old NOT NULL constraints enforce it.
pub(crate) fn restore_legacy_schema(connection: &Connection) -> TestResult {
    let enabled: bool = connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    connection.pragma_update(None, "foreign_keys", false)?;
    let result = legacy_transaction(connection);
    connection.pragma_update(None, "foreign_keys", enabled)?;
    result
}

fn legacy_transaction(connection: &Connection) -> TestResult {
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch("DROP TRIGGER component_recovery_origin_requires_projection;
        DROP TRIGGER component_configuration_recovery_origin_requires_projection;
        DROP TRIGGER component_origin_immutable; DROP TRIGGER component_configuration_origin_immutable;
        CREATE TABLE saved_component_instances AS SELECT instance_id, component_kind, display_name, canonical_name,
            implementation_id, contract_major, contract_minor, scope_kind, scope_id, desired_state, active_config_revision,
            created_by, created_at, retired_at, revision FROM component_instances;
        CREATE TABLE saved_component_configurations AS SELECT instance_id, config_revision, schema_version,
            canonical_config, config_digest, secret_generation_id, created_by, created_at, state FROM component_configurations;
        DROP TABLE component_configurations; DROP TABLE component_instances;")?;
    let schema = include_str!("../../schema/partition/001_initial.sql");
    let start = schema
        .find("CREATE TABLE component_instances (")
        .ok_or("missing old instances")?;
    let end = schema
        .find("CREATE TABLE component_assignments (")
        .ok_or("missing old assignments")?;
    transaction.execute_batch(schema.get(start..end).ok_or("invalid old schema range")?)?;
    transaction.execute_batch(
        "INSERT INTO component_instances SELECT * FROM saved_component_instances;
        INSERT INTO component_configurations SELECT * FROM saved_component_configurations;
        DROP TABLE saved_component_configurations; DROP TABLE saved_component_instances;",
    )?;
    transaction.commit()?;
    Ok(())
}
