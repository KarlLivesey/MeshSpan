// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn backup_copy_inventory_uses_bounded_indexed_pages_and_strict_records()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let first_id = BackupDestinationId::from_bytes([30; 16])?;
    let second_id = BackupDestinationId::from_bytes([40; 16])?;
    let backup = BackupId::from_bytes([31; 16])?;
    configure_destination(&mut fixture, first_id)?;
    let claim = queue_and_claim(&mut fixture, backup)?;
    record_and_verify_backup(&mut fixture, first_id, backup, [35; 32], claim)?;
    let first_copy = fixture
        .repository
        .backup_copy(backup, first_id)?
        .ok_or("copy missing")?;
    let target = fixture.target;
    commit(
        &mut fixture,
        90,
        &AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
            destination_id: second_id,
            expected_destination_revision: Revision::ZERO,
            name: RecordName::new("Second destination")?,
            binding: BackupDestinationBinding::RegisteredTarget {
                target_id: target,
                target_generation: 1,
            },
            failure_relationship: BackupFailureRelationship::Unknown,
            failure_evidence_digest: [41; 32],
            enabled: true,
        }),
    )?;
    commit(
        &mut fixture,
        92,
        &AuthoritativeCommand::RecordBackupCopy(crate::RecordBackupCopy {
            backup_id: backup,
            destination_id: second_id,
            provider_generation: 1,
            object_reference: "second-copy".to_owned(),
            byte_length: first_copy.byte_length,
            copy_digest: first_copy.copy_digest,
        }),
    )?;
    let first = fixture
        .repository
        .backup_copies(backup, None, PageLimit::new(1)?)?;
    assert_eq!(first.items, vec![first_copy]);
    let next = first.next.ok_or("continuation missing")?;
    assert_eq!(next.destination_id, first_id);
    let second = fixture
        .repository
        .backup_copies(backup, Some(next), PageLimit::new(1)?)?;
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].destination_id, second_id);
    assert_eq!(second.items[0].state, BackupCopyState::Stored);
    assert_eq!(second.next, None);
    assert!(
        fixture
            .repository
            .backup_copies(BackupId::from_bytes([99; 16])?, None, PageLimit::new(1)?)?
            .items
            .is_empty()
    );
    let connection = fixture.repository.database.connection();
    let details = connection.prepare("EXPLAIN QUERY PLAN SELECT backup_id, destination_id FROM backup_copies WHERE backup_id = ?1 AND destination_id > ?2 ORDER BY destination_id LIMIT ?3")?
        .query_map(rusqlite::params![backup.as_bytes().as_slice(), first_id.as_bytes().as_slice(), 2], |row| row.get::<_, String>(3))?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        details
            .iter()
            .any(|detail| detail.contains("SEARCH backup_copies")
                && detail.contains("backup_id=? AND destination_id>?")),
        "{details:?}"
    );
    assert!(
        !details
            .iter()
            .any(|detail| detail.contains("TEMP B-TREE") || detail.contains("SCAN backup_copies")),
        "{details:?}"
    );
    connection.execute("PRAGMA ignore_check_constraints = ON", [])?;
    connection.execute(
        "UPDATE backup_copies SET state = 99 WHERE destination_id = ?1",
        [second_id.as_bytes().as_slice()],
    )?;
    assert!(
        fixture
            .repository
            .backup_copies(backup, Some(next), PageLimit::new(1)?)
            .is_err()
    );
    Ok(())
}

fn commit(
    fixture: &mut Fixture,
    seed: u8,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let revision = fixture.repository.current_revision()?.get();
    fixture.repository.apply_committed(
        LogPosition {
            index: revision + 1,
            term: 1,
        },
        context(
            seed,
            fixture.administrator,
            seed + 1,
            i64::from(seed),
            revision,
        )?,
        command,
    )?;
    Ok(())
}
