// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_domain::UnixMicros;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn recovered_mount_reopens_exactly_without_a_synthetic_user_command() -> TestResult {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("local.sqlite3");
    let record = fixture()?;
    let mut database = LocalDatabase::open(&file, record.node_id, UnixMicros::new(1))?;
    assert_eq!(
        database.install_local_recovered_target(&record)?,
        LocalTargetDisposition::Applied
    );
    drop(database);
    let mut database = LocalDatabase::open_existing(&file, UnixMicros::new(2))?;
    assert_eq!(
        database.install_local_recovered_target(&record)?,
        LocalTargetDisposition::Replayed
    );
    assert_eq!(
        database.local_recovered_target_by_path(&record.canonical_path)?,
        Some(record.clone())
    );
    assert_eq!(database.local_recovered_targets()?, vec![record.clone()]);
    assert!(database.local_targets()?.is_empty());
    for changed in [
        LocalRecoveredTarget {
            state_digest: [9; 32],
            ..record.clone()
        },
        LocalRecoveredTarget {
            journal_directory: b"/changed-state".to_vec(),
            ..record.clone()
        },
        LocalRecoveredTarget {
            target_id: TargetId::from_bytes([8; 16])?,
            ..record.clone()
        },
    ] {
        assert_eq!(
            database.install_local_recovered_target(&changed),
            Err(LocalTargetError::Conflict)
        );
    }
    assert_eq!(database.local_recovered_targets()?, vec![record]);
    database.check_integrity()?;
    Ok(())
}

#[test]
fn recovered_and_user_registrations_cannot_claim_the_same_folder() -> TestResult {
    let directory = tempfile::tempdir()?;
    let record = fixture()?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        record.node_id,
        UnixMicros::new(1),
    )?;
    let mut ordinary = crate::local_target_tests::target_intent(record.node_id)?;
    database.prepare_local_target(&ordinary)?;
    let collision = LocalRecoveredTarget {
        canonical_path: ordinary.canonical_path.clone(),
        ..record.clone()
    };
    assert!(database.install_local_recovered_target(&collision).is_err());
    assert!(database.local_recovered_targets()?.is_empty());
    database.install_local_recovered_target(&record)?;
    ordinary.canonical_path = record.canonical_path;
    assert!(database.prepare_local_target(&ordinary).is_err());
    let mut foreign = fixture()?;
    foreign.node_id = NodeId::from_bytes([99; 16])?;
    assert_eq!(
        database.install_local_recovered_target(&foreign),
        Err(LocalTargetError::Invalid)
    );
    assert!(
        database
            .connection()
            .execute("UPDATE local_recovered_targets SET generation = 2", [])
            .is_err()
    );
    assert!(
        database
            .connection()
            .execute("DELETE FROM local_recovered_targets", [])
            .is_err()
    );
    database.check_integrity()?;
    Ok(())
}

#[test]
fn local_schema_fifteen_upgrade_preserves_existing_registration() -> TestResult {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("local.sqlite3");
    let record = fixture()?;
    let mut database = LocalDatabase::open(&file, record.node_id, UnixMicros::new(1))?;
    let ordinary = crate::local_target_tests::target_intent(record.node_id)?;
    database.prepare_local_target(&ordinary)?;
    database.connection().execute_batch(
        "DROP TRIGGER local_targets_recovery_conflict;
        DROP TABLE local_recovered_targets;
        DELETE FROM schema_migrations WHERE version = 16;
        PRAGMA user_version = 15; UPDATE local_identity SET schema_version = 15;",
    )?;
    drop(database);
    let database = LocalDatabase::open_existing(&file, UnixMicros::new(2))?;
    assert_eq!(database.schema_version(), 16);
    assert_eq!(
        database
            .local_target(ordinary.target_id)?
            .ok_or("lost original")?
            .intent,
        ordinary
    );
    assert!(database.local_recovered_targets()?.is_empty());
    database.check_integrity()?;
    Ok(())
}

fn fixture() -> Result<LocalRecoveredTarget, Box<dyn std::error::Error>> {
    Ok(LocalRecoveredTarget {
        target_id: TargetId::from_bytes([71; 16])?,
        node_id: NodeId::from_bytes([72; 16])?,
        mesh_id: MeshId::from_bytes([73; 16])?,
        recovery_id: OperationId::from_bytes([74; 16])?,
        state_digest: [75; 32],
        generation: 1,
        marker_fingerprint: [76; 32],
        canonical_path: b"/restored-folder".to_vec(),
        journal_directory: b"/original-journal-root".to_vec(),
        policy_revision: Revision::new(5),
        usage_limit: StorageUsageLimit::Percent(95),
    })
}
