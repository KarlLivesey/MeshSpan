// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{SnapshotId, UnixMicros};
use tempfile::tempdir;

use super::volume_head_tests::{commit, context, fixture, open_and_prepare, publication_command};
use super::{ApplyDisposition, LogPosition, PageLimit, RepositoryError};
use crate::{AuthoritativeCommand, CreateVolumeSnapshot, RecordName};

#[test]
fn snapshots_pin_exact_heads_page_stably_and_replay_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("snapshots.sqlite3");
    let fixture = fixture()?;
    let mut repository = open_and_prepare(&file_path, &fixture)?;
    let head = publication_command(&fixture, None, 30, 31, 32, 33, 34)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(35, fixture.administrator, 36, 102, Some(2))?,
        &head,
    )?;
    for (index, identity, name) in [
        (4_u64, 40_u8, "Zulu"),
        (5_u64, 41_u8, "Alpha"),
        (6_u64, 42_u8, "Middle"),
    ] {
        repository.apply_committed(
            LogPosition { index, term: 1 },
            context(
                identity.saturating_add(10),
                fixture.administrator,
                identity.saturating_add(20),
                100 + i64::try_from(index)?,
                Some(index - 1),
            )?,
            &snapshot_command(identity, fixture.volume, name, 30)?,
        )?;
    }
    let first = repository.volume_snapshots(fixture.volume, None, PageLimit::new(2)?)?;
    assert_eq!(
        first
            .items
            .iter()
            .map(|snapshot| snapshot.display_name.as_str())
            .collect::<Vec<_>>(),
        ["Alpha", "Middle"]
    );
    let second =
        repository.volume_snapshots(fixture.volume, first.next.as_ref(), PageLimit::new(2)?)?;
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].display_name, "Zulu");
    assert!(second.next.is_none());

    let replay_context = context(50, fixture.administrator, 60, 104, Some(3))?;
    let replay = repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        replay_context,
        &snapshot_command(40, fixture.volume, "Zulu", 30)?,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    drop(repository);

    let database =
        crate::PartitionDatabase::open(&file_path, fixture.partition, UnixMicros::new(500))?;
    let reopened = super::AuthoritativeRepository::new(database);
    assert_eq!(
        reopened
            .volume_snapshots(fixture.volume, None, PageLimit::new(10)?)?
            .items
            .len(),
        3
    );
    Ok(())
}

#[test]
fn snapshot_rejects_stale_head_and_elapsed_expiry_without_state_change()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository = open_and_prepare(&directory.path().join("reject.sqlite3"), &fixture)?;
    let first = publication_command(&fixture, None, 70, 71, 72, 73, 74)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(75, fixture.administrator, 76, 102, Some(2))?,
        &first,
    )?;
    for command in [
        snapshot_command(77, fixture.volume, "Stale", 78)?,
        AuthoritativeCommand::CreateVolumeSnapshot(CreateVolumeSnapshot {
            snapshot_id: SnapshotId::from_bytes([79; 16])?,
            volume_id: fixture.volume,
            namespace_commit_id: commit(70)?,
            name: RecordName::new("Elapsed")?,
            expires_at: Some(UnixMicros::new(100)),
            protected_from_expiry: false,
        }),
    ] {
        assert!(matches!(
            repository.apply_committed(
                LogPosition { index: 4, term: 1 },
                context(80, fixture.administrator, 81, 102, Some(3))?,
                &command,
            ),
            Err(RepositoryError::StaleVolumeHead | RepositoryError::InvalidCommand)
        ));
    }
    assert!(
        repository
            .volume_snapshots(fixture.volume, None, PageLimit::new(10)?)?
            .items
            .is_empty()
    );
    Ok(())
}

fn snapshot_command(
    identity: u8,
    volume_id: meshspan_domain::VolumeId,
    name: &str,
    commit_byte: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::CreateVolumeSnapshot(
        CreateVolumeSnapshot {
            snapshot_id: SnapshotId::from_bytes([identity; 16])?,
            volume_id,
            namespace_commit_id: commit(commit_byte)?,
            name: RecordName::new(name)?,
            expires_at: Some(UnixMicros::new(10_000)),
            protected_from_expiry: false,
        },
    ))
}
