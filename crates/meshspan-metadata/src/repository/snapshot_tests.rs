// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{Revision, SnapshotId, UnixMicros};
use rusqlite::params;
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::volume_head_tests::{commit, context, fixture, open_and_prepare, publication_command};
use super::{ApplyDisposition, AuthoritativeRepository, LogPosition, PageLimit, RepositoryError};
use crate::{AuthoritativeCommand, CreateVolumeSnapshot, RecordName, RequestVolumeSnapshotExpiry};

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

#[test]
fn expiry_request_preserves_the_root_and_replays_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("expiry.sqlite3");
    let fixture = fixture()?;
    let mut repository = prepared_snapshot(&file_path, &fixture, 90, false, 10_000)?;
    let command = expiry_command(90, 4, false, 7)?;
    let expiry_context = context(91, fixture.administrator, 92, 200, Some(4))?;
    let receipt =
        repository.apply_committed(LogPosition { index: 5, term: 1 }, expiry_context, &command)?;

    let snapshot = only_snapshot(&repository, fixture.volume)?;
    assert_eq!(snapshot.state, 2);
    assert_eq!(snapshot.revision, Revision::new(5));
    assert_eq!(snapshot.namespace_commit_id, commit(30)?);
    assert_eq!(snapshot.root_object_revision_id.as_bytes(), [31; 16]);
    let request: (i64, i64, i64, i64) = repository.database.connection().query_row(
        "SELECT automatic, reason_code, requested_at, revision
         FROM snapshot_expiry_requests WHERE snapshot_id = ?1",
        [SnapshotId::from_bytes([90; 16])?.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(request, (0, 7, 200, 5));
    drop(repository);

    let database =
        crate::PartitionDatabase::open(&file_path, fixture.partition, UnixMicros::new(20_000))?;
    let mut reopened = AuthoritativeRepository::new(database);
    let replay =
        reopened.apply_committed(LogPosition { index: 6, term: 1 }, expiry_context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    assert_eq!(only_snapshot(&reopened, fixture.volume)?.state, 2);
    Ok(())
}

#[test]
fn expiry_request_rejects_stale_protected_and_early_automatic_requests()
-> Result<(), Box<dyn std::error::Error>> {
    for (identity, protected, occurred_at, expected_revision, expected_error) in [
        (100, false, 10_000, 3, RepositoryError::StaleSnapshot),
        (101, true, 10_000, 4, RepositoryError::InvalidCommand),
        (102, false, 9_999, 4, RepositoryError::InvalidCommand),
    ] {
        let directory = tempdir()?;
        let fixture = fixture()?;
        let mut repository = prepared_snapshot(
            &directory.path().join("rejected.sqlite3"),
            &fixture,
            identity,
            protected,
            10_000,
        )?;
        let command = expiry_command(identity, expected_revision, identity == 102, 8)?;
        let result = repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            context(110, fixture.administrator, 111, occurred_at, Some(4))?,
            &command,
        );
        match result {
            Err(error) => assert_eq!(error.to_string(), expected_error.to_string()),
            Ok(_) => return Err("invalid snapshot expiry request succeeded".into()),
        }
        assert_eq!(only_snapshot(&repository, fixture.volume)?.state, 1);
        assert_eq!(expiry_request_count(&repository, identity)?, 0);
    }

    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository = prepared_snapshot(
        &directory.path().join("due.sqlite3"),
        &fixture,
        103,
        false,
        10_000,
    )?;
    repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(112, fixture.administrator, 113, 10_000, Some(4))?,
        &expiry_command(103, 4, true, 9)?,
    )?;
    assert_eq!(only_snapshot(&repository, fixture.volume)?.state, 2);
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_snapshot_expiry_completely()
-> Result<(), Box<dyn std::error::Error>> {
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        let directory = tempdir()?;
        let fixture = fixture()?;
        let mut repository = prepared_snapshot(
            &directory.path().join("fault.sqlite3"),
            &fixture,
            120,
            false,
            10_000,
        )?;
        let command = expiry_command(120, 4, false, 10)?;
        let expiry_context = context(121, fixture.administrator, 122, 200, Some(4))?;
        let interrupted = apply_committed_with_fault(
            &mut repository.database,
            LogPosition { index: 5, term: 1 },
            expiry_context,
            &command,
            fault,
        );
        assert!(matches!(interrupted, Err(RepositoryError::InjectedFault)));
        assert_eq!(only_snapshot(&repository, fixture.volume)?.state, 1);
        assert_eq!(expiry_request_count(&repository, 120)?, 0);
        repository.apply_committed(LogPosition { index: 5, term: 1 }, expiry_context, &command)?;
        assert_eq!(only_snapshot(&repository, fixture.volume)?.state, 2);
    }
    Ok(())
}

fn prepared_snapshot(
    file_path: &std::path::Path,
    fixture: &super::volume_head_tests::HeadFixture,
    identity: u8,
    protected_from_expiry: bool,
    expires_at: i64,
) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
    let mut repository = open_and_prepare(file_path, fixture)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(130, fixture.administrator, 131, 102, Some(2))?,
        &publication_command(fixture, None, 30, 31, 32, 33, 34)?,
    )?;
    repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        context(132, fixture.administrator, 133, 103, Some(3))?,
        &AuthoritativeCommand::CreateVolumeSnapshot(CreateVolumeSnapshot {
            snapshot_id: SnapshotId::from_bytes([identity; 16])?,
            volume_id: fixture.volume,
            namespace_commit_id: commit(30)?,
            name: RecordName::new("Expiry candidate")?,
            expires_at: Some(UnixMicros::new(expires_at)),
            protected_from_expiry,
        }),
    )?;
    Ok(repository)
}

fn expiry_command(
    identity: u8,
    expected_revision: u64,
    automatic: bool,
    reason_code: u32,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::RequestVolumeSnapshotExpiry(
        RequestVolumeSnapshotExpiry {
            snapshot_id: SnapshotId::from_bytes([identity; 16])?,
            expected_snapshot_revision: Revision::new(expected_revision),
            automatic,
            reason_code,
        },
    ))
}

fn only_snapshot(
    repository: &AuthoritativeRepository,
    volume_id: meshspan_domain::VolumeId,
) -> Result<super::VolumeSnapshot, Box<dyn std::error::Error>> {
    let page = repository.volume_snapshots(volume_id, None, PageLimit::new(2)?)?;
    assert!(page.next.is_none());
    assert_eq!(page.items.len(), 1);
    Ok(page.items.into_iter().next().ok_or("snapshot missing")?)
}

fn expiry_request_count(
    repository: &AuthoritativeRepository,
    identity: u8,
) -> Result<i64, Box<dyn std::error::Error>> {
    Ok(repository.database.connection().query_row(
        "SELECT count(*) FROM snapshot_expiry_requests WHERE snapshot_id = ?1",
        params![
            SnapshotId::from_bytes([identity; 16])?
                .as_bytes()
                .as_slice()
        ],
        |row| row.get(0),
    )?)
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
