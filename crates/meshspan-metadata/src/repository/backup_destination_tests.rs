// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::RepositoryError;

#[test]
fn destination_edits_compare_their_own_revision_and_preserve_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let destination = BackupDestinationId::from_bytes([30; 16])?;
    configure_destination(&mut fixture, destination)?;
    let original = fixture
        .repository
        .backup_destination(destination)?
        .ok_or("missing")?;
    let other = command(&fixture, 31, 0, true)?;
    apply(&mut fixture, 4, 60, &other)?;
    let pause = command(&fixture, 30, original.revision.get(), false)?;
    let receipt = apply(&mut fixture, 5, 61, &pause)?;
    assert_eq!(receipt.committed_revision, Revision::new(5));
    let paused = fixture
        .repository
        .backup_destination(destination)?
        .ok_or("missing")?;
    assert_eq!(paused.state, BackupDestinationState::Paused);
    assert_eq!(paused.binding, original.binding);
    assert_eq!(paused.created_at, original.created_at);

    assert!(matches!(
        apply(&mut fixture, 6, 62, &pause),
        Err(RepositoryError::StaleRevision)
    ));
    let mut rebound = command(&fixture, 30, 5, true)?;
    rebound.binding = BackupDestinationBinding::RegisteredTarget {
        target_id: fixture.target,
        target_generation: 2,
    };
    assert!(matches!(
        apply(&mut fixture, 6, 63, &rebound),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(
        fixture.repository.backup_destination(destination)?,
        Some(paused)
    );
    let replay = apply(&mut fixture, 6, 61, &pause)?;
    assert_eq!(replay.disposition, crate::ApplyDisposition::Replayed);
    assert_eq!(replay.request_digest, receipt.request_digest);
    assert_eq!(replay.result_digest, receipt.result_digest);
    assert_eq!(replay.committed_revision, receipt.committed_revision);
    assert_eq!(replay.committed_position, receipt.committed_position);
    assert_eq!(replay.applied_position, LogPosition { index: 6, term: 1 });
    let resume = command(&fixture, 30, 5, true)?;
    assert_eq!(
        apply(&mut fixture, 7, 64, &resume)?.committed_revision,
        Revision::new(6)
    );
    assert_eq!(
        fixture
            .repository
            .backup_destination(destination)?
            .ok_or("missing")?
            .state,
        BackupDestinationState::Active
    );
    Ok(())
}

#[test]
fn administration_pages_include_paused_destinations_and_seek_without_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    for (id, enabled, index) in [(30, true, 3), (31, false, 4), (32, true, 5)] {
        let command = command(&fixture, id, 0, enabled)?;
        apply(&mut fixture, index, id + 40, &command)?;
    }
    let first = fixture
        .repository
        .backup_destinations(None, PageLimit::new(2)?)?;
    assert_eq!(first.items.len(), 2);
    assert_eq!(first.items[1].state, BackupDestinationState::Paused);
    let second = fixture
        .repository
        .backup_destinations(first.next, PageLimit::new(2)?)?;
    assert_eq!(second.items.len(), 1);
    assert_eq!(
        second.items[0].destination_id,
        BackupDestinationId::from_bytes([32; 16])?
    );
    assert_eq!(second.next, None);
    assert_eq!(
        fixture
            .repository
            .active_backup_destinations(None, PageLimit::new(10)?)?
            .items
            .len(),
        2
    );
    Ok(())
}

fn command(
    fixture: &Fixture,
    identity: u8,
    expected: u64,
    enabled: bool,
) -> Result<ConfigureBackupDestination, Box<dyn std::error::Error>> {
    Ok(ConfigureBackupDestination {
        destination_id: BackupDestinationId::from_bytes([identity; 16])?,
        expected_destination_revision: Revision::new(expected),
        name: RecordName::new(&format!("Backup {identity}"))?,
        binding: BackupDestinationBinding::RegisteredTarget {
            target_id: fixture.target,
            target_generation: 1,
        },
        failure_relationship: BackupFailureRelationship::Unknown,
        failure_evidence_digest: [identity; 32],
        enabled,
    })
}

fn apply(
    fixture: &mut Fixture,
    index: u64,
    operation: u8,
    command: &ConfigureBackupDestination,
) -> Result<crate::CommandReceipt, RepositoryError> {
    let mut context = context(operation, fixture.administrator, operation + 1, 100, 0)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    context.expected_revision = None;
    fixture.repository.apply_committed(
        LogPosition { index, term: 1 },
        context,
        &AuthoritativeCommand::ConfigureBackupDestination(command.clone()),
    )
}
