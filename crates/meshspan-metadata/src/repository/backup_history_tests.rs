// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::PageLimit;

#[test]
fn backup_history_pages_newest_first_without_repeating_new_runs()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    assert!(
        fixture
            .repository
            .metadata_backup_runs(None, PageLimit::new(2)?)?
            .items
            .is_empty()
    );
    let first = BackupId::from_bytes([70; 16])?;
    queue_run(&mut fixture, first)?;
    finish_and_queue(&mut fixture, 80)?;
    finish_and_queue(&mut fixture, 90)?;
    let page = fixture
        .repository
        .metadata_backup_runs(None, PageLimit::new(2)?)?;
    assert_eq!(
        page.items
            .iter()
            .map(|run| run.run_sequence)
            .collect::<Vec<_>>(),
        vec![3, 2]
    );
    assert_eq!(page.next, Some(2));
    assert_eq!(page.items[0].state, MetadataBackupRunState::Queued);
    assert_eq!(page.items[1].state, MetadataBackupRunState::Incomplete);
    finish_and_queue(&mut fixture, 100)?;
    let next = fixture
        .repository
        .metadata_backup_runs(page.next, PageLimit::new(2)?)?;
    assert_eq!(
        next.items
            .iter()
            .map(|run| run.backup_id)
            .collect::<Vec<_>>(),
        vec![first]
    );
    assert_eq!(next.next, None);
    assert!(
        fixture
            .repository
            .metadata_backup_runs(Some(1), PageLimit::new(2)?)?
            .items
            .is_empty()
    );
    assert_eq!(
        fixture
            .repository
            .metadata_backup_runs(None, PageLimit::new(1)?)?
            .items[0]
            .run_sequence,
        4
    );
    for before in [0, u64::MAX] {
        assert!(matches!(
            fixture
                .repository
                .metadata_backup_runs(Some(before), PageLimit::new(1)?),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    Ok(())
}

#[test]
fn backup_history_uses_sequence_index_and_rejects_corrupt_records()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let backup = BackupId::from_bytes([70; 16])?;
    queue_run(&mut fixture, backup)?;
    let connection = fixture.repository.database.connection();
    let mut statement = connection.prepare("EXPLAIN QUERY PLAN SELECT backup_id FROM metadata_backup_runs WHERE partition_id = ?1 AND run_sequence <= ?2 ORDER BY run_sequence DESC LIMIT ?3")?;
    let details = statement
        .query_map(
            rusqlite::params![fixture.partition.as_bytes().as_slice(), i64::MAX, 3],
            |row| row.get::<_, String>(3),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        details.iter().any(
            |detail| detail.contains("SEARCH metadata_backup_runs USING INDEX")
                && detail.contains("partition_id=? AND run_sequence<?")
        ),
        "{details:?}"
    );
    assert!(
        !details
            .iter()
            .any(|detail| detail.contains("TEMP B-TREE")
                || detail.contains("SCAN metadata_backup_runs")),
        "{details:?}"
    );
    connection.execute("PRAGMA ignore_check_constraints = ON", [])?;
    connection.execute("UPDATE metadata_backup_runs SET state = 99", [])?;
    assert!(matches!(
        fixture
            .repository
            .metadata_backup_runs(None, PageLimit::new(1)?),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

fn finish_and_queue(fixture: &mut Fixture, seed: u8) -> Result<(), Box<dyn std::error::Error>> {
    let current = fixture
        .repository
        .unfinished_metadata_backup_run()?
        .ok_or("run missing")?;
    let evidence = fixture
        .repository
        .metadata_backup_protection_evidence(current.backup_id)?;
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
            current.scheduled_for.get() + 1,
            revision,
        )?,
        &AuthoritativeCommand::CompleteMetadataBackupRun(CompleteMetadataBackupRun {
            backup_id: current.backup_id,
            outcome: MetadataBackupRunCompletion::Incomplete {
                result_digest: evidence.digest,
            },
        }),
    )?;
    let due = fixture
        .repository
        .metadata_backup_schedule()?
        .ok_or("schedule missing")?;
    fixture.repository.apply_committed(
        LogPosition {
            index: revision + 2,
            term: 1,
        },
        context(
            seed + 2,
            fixture.administrator,
            seed + 3,
            due.next_due_at.get(),
            revision + 1,
        )?,
        &AuthoritativeCommand::QueueMetadataBackupRun(QueueMetadataBackupRun {
            backup_id: BackupId::from_bytes([seed + 4; 16])?,
            partition_id: fixture.partition,
            expected_schedule_sequence: due.sequence,
            scheduled_for: due.next_due_at,
        }),
    )?;
    Ok(())
}
