// SPDX-License-Identifier: GPL-2.0-only

//! Upload intent is durable identity, never completion or removal authority.

use super::*;
use crate::BindBackupPublicationIntent;

#[test]
fn upload_intent_migration_does_not_infer_past_uploads() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut connection =
        rusqlite::Connection::open(directory.path().join("intent-migration.sqlite3"))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    crate::migration::migrate_partition_through(&mut connection, 102, 10)?;
    let before: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name = 'backup_publication_intents'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(before, 0);
    crate::migration::migrate_partition(&mut connection, 20)?;
    crate::migration::migrate_partition(&mut connection, 30)?;
    assert_eq!(
        connection.query_row(
            "SELECT count(*) FROM backup_publication_intents",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, i64>(0)
        })?,
        0
    );
    assert_eq!(
        connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
        crate::migration::PARTITION_SCHEMA_VERSION
    );
    Ok(())
}

#[test]
fn upload_intent_survives_reopen_and_abandonment_without_admitting_a_copy() -> TestResult {
    let (mut fixture, value, claim) = prepared()?;
    let binding = BindBackupPublicationIntent {
        object: value.receipt.object,
        store_operation_id: value.receipt.operation_id,
        claim,
        expected_destination_revision: Revision::new(3),
    };
    let command = AuthoritativeCommand::BindBackupPublicationIntent(binding);
    commit(&mut fixture, &command, 60)?;
    let retained = fixture
        .repository
        .backup_publication_intent(binding.object.backup_id, binding.object.destination_id)?
        .ok_or("intent")?;
    assert_eq!(retained.binding, binding);
    assert_eq!(retained.revision, Revision::new(7));
    assert!(
        fixture
            .repository
            .abandoned_backup_publications(None, PageLimit::new(1)?)?
            .items
            .is_empty()
    );
    commit(&mut fixture, &command, 70)?;
    abandon(&mut fixture, binding.object.backup_id, claim)?;
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("backup-catalogue.sqlite3"),
        UnixMicros::new(101),
    )?);
    assert_eq!(
        fixture
            .repository
            .backup_publication_intent(binding.object.backup_id, binding.object.destination_id)?,
        Some(retained)
    );
    assert!(
        fixture
            .repository
            .metadata_backup(binding.object.backup_id)?
            .is_none()
    );
    assert!(
        fixture
            .repository
            .backup_copy(binding.object.backup_id, binding.object.destination_id)?
            .is_none()
    );
    assert!(
        fixture
            .repository
            .pending_backup_reclamations(None, PageLimit::new(1)?)?
            .items
            .is_empty()
    );
    let discovered = fixture
        .repository
        .abandoned_backup_publications(None, PageLimit::new(1)?)?;
    assert_eq!(
        discovered.items,
        vec![crate::AbandonedBackupPublication {
            intent: retained,
            run_revision: Revision::new(9),
        }]
    );
    assert_eq!(discovered.next, None);
    // Merely discovering an intent never completes it, even across independent read views.
    assert_eq!(
        fixture
            .repository
            .abandoned_backup_publications(None, PageLimit::new(1)?)?
            .items,
        discovered.items
    );
    assert!(matches!(
        commit(&mut fixture, &command, 101),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

#[test]
fn upload_intent_rejects_changed_identity_and_stale_authority() -> TestResult {
    let (mut fixture, value, claim) = prepared()?;
    let binding = BindBackupPublicationIntent {
        object: value.receipt.object,
        store_operation_id: value.receipt.operation_id,
        claim,
        expected_destination_revision: Revision::new(3),
    };
    let stale = BindBackupPublicationIntent {
        expected_destination_revision: Revision::new(2),
        ..binding
    };
    assert!(matches!(
        commit(
            &mut fixture,
            &AuthoritativeCommand::BindBackupPublicationIntent(stale),
            60
        ),
        Err(RepositoryError::StaleRevision)
    ));
    commit(
        &mut fixture,
        &AuthoritativeCommand::BindBackupPublicationIntent(binding),
        60,
    )?;
    for changed in [
        BindBackupPublicationIntent {
            object: BackupObjectIdentity {
                digest: [90; 32],
                ..binding.object
            },
            ..binding
        },
        BindBackupPublicationIntent {
            store_operation_id: OperationId::from_bytes([191; 16])?,
            ..binding
        },
    ] {
        assert!(matches!(
            commit(
                &mut fixture,
                &AuthoritativeCommand::BindBackupPublicationIntent(changed),
                70
            ),
            Err(RepositoryError::InvalidCommand)
        ));
        assert_eq!(fixture.repository.current_revision()?, Revision::new(7));
    }
    let bytes = crate::encode_authoritative_command(
        context(170, fixture.administrator, 171, 60, 6)?,
        &AuthoritativeCommand::BindBackupPublicationIntent(binding),
    )?;
    assert_eq!(
        crate::decode_authoritative_command(&bytes)?.command,
        AuthoritativeCommand::BindBackupPublicationIntent(binding)
    );
    for length in 0..bytes.len() {
        assert!(crate::decode_authoritative_command(&bytes[..length]).is_err());
    }
    Ok(())
}

#[test]
fn abandoned_upload_discovery_seeks_and_hands_off_only_after_retirement() -> TestResult {
    let (mut fixture, mut retirement, claim) = prepared()?;
    let object = retirement.receipt.object;
    commit(
        &mut fixture,
        &AuthoritativeCommand::BindBackupPublicationIntent(BindBackupPublicationIntent {
            object,
            store_operation_id: retirement.receipt.operation_id,
            claim,
            expected_destination_revision: Revision::new(3),
        }),
        60,
    )?;
    abandon(&mut fixture, object.backup_id, claim)?;
    let cursor = crate::BackupReclamationCursor {
        backup_id: object.backup_id,
        destination_id: object.destination_id,
    };
    let page = fixture
        .repository
        .abandoned_backup_publications(None, PageLimit::new(1)?)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].intent.binding.object, object);
    assert_eq!(page.items[0].run_revision, Revision::new(8));
    assert_eq!(page.next, None);
    assert!(
        fixture
            .repository
            .abandoned_backup_publications(Some(cursor), PageLimit::new(1)?)?
            .items
            .is_empty()
    );
    retirement.expected_run_revision = Revision::new(8);
    commit(
        &mut fixture,
        &AuthoritativeCommand::RetireAbandonedBackupCopy(retirement),
        101,
    )?;
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("backup-catalogue.sqlite3"),
        UnixMicros::new(102),
    )?);
    assert!(
        fixture
            .repository
            .abandoned_backup_publications(None, PageLimit::new(1)?)?
            .items
            .is_empty()
    );
    let pending = fixture
        .repository
        .pending_backup_reclamations(None, PageLimit::new(1)?)?;
    assert_eq!(pending.items.len(), 1);
    assert_eq!(pending.items[0].object, object);
    assert_eq!(pending.items[0].retirement_revision, Revision::new(9));
    Ok(())
}
