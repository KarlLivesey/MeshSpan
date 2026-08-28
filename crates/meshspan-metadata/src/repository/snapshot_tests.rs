// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::namespace_snapshot_restore_result_digest;
use meshspan_domain::{
    NamespaceCommitId, ObjectRevisionId, OperationId, Revision, SnapshotId, UnixMicros,
};
use rusqlite::params;
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::volume_head_tests::{commit, context, fixture, open_and_prepare, publication_command};
use super::{ApplyDisposition, AuthoritativeRepository, LogPosition, PageLimit, RepositoryError};
use crate::{
    AuthoritativeCommand, CreateVolumeSnapshot, RecordName, RemoveVolumeSnapshotRoot,
    RequestVolumeSnapshotExpiry, RestoreVolumeSnapshot, SnapshotExpiryReason,
};

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
    let command = expiry_command(90, 4, false)?;
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
    assert_eq!(request, (0, 1, 200, 5));
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
fn expiring_snapshot_root_removal_is_exact_audited_and_replayable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("remove-root.sqlite3");
    let fixture = fixture()?;
    let mut repository = prepared_snapshot(&file_path, &fixture, 93, false, 10_000)?;
    let expiry_context = context(94, fixture.administrator, 95, 200, Some(4))?;
    repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        expiry_context,
        &expiry_command(93, 4, false)?,
    )?;
    let command = remove_root_command(93, 5, 94, 30, 31)?;
    let remove_context = context(96, fixture.administrator, 97, 201, Some(5))?;
    let receipt =
        repository.apply_committed(LogPosition { index: 6, term: 1 }, remove_context, &command)?;
    assert!(
        repository
            .volume_snapshots(fixture.volume, None, PageLimit::new(2)?)?
            .items
            .is_empty()
    );
    let stored: (i64, i64, i64, Vec<u8>, Vec<u8>) = repository.database.connection().query_row(
        "SELECT s.state, s.removed_at, s.revision,
                    r.expiry_operation_id, r.root_object_revision_id
             FROM volume_snapshots s JOIN snapshot_root_removals r USING(snapshot_id)
             WHERE s.snapshot_id = ?1",
        [SnapshotId::from_bytes([93; 16])?.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    assert_eq!((stored.0, stored.1, stored.2), (3, 201, 6));
    assert_eq!(
        stored.3.as_slice(),
        OperationId::from_bytes([94; 16])?.as_bytes()
    );
    assert_eq!(
        stored.4.as_slice(),
        ObjectRevisionId::from_bytes([31; 16])?.as_bytes()
    );
    drop(repository);

    let database =
        crate::PartitionDatabase::open(&file_path, fixture.partition, UnixMicros::new(500))?;
    let mut reopened = AuthoritativeRepository::new(database);
    let replay =
        reopened.apply_committed(LogPosition { index: 7, term: 1 }, remove_context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    Ok(())
}

#[test]
fn root_removal_rejects_substitution_and_rolls_back_every_apply_boundary()
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
            &directory.path().join("remove-fault.sqlite3"),
            &fixture,
            98,
            false,
            10_000,
        )?;
        repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            context(99, fixture.administrator, 100, 200, Some(4))?,
            &expiry_command(98, 4, false)?,
        )?;
        let command = remove_root_command(98, 5, 99, 30, 31)?;
        let remove_context = context(101, fixture.administrator, 102, 201, Some(5))?;
        assert!(matches!(
            apply_committed_with_fault(
                &mut repository.database,
                LogPosition { index: 6, term: 1 },
                remove_context,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        assert_eq!(only_snapshot(&repository, fixture.volume)?.state, 2);
        let removals: i64 = repository.database.connection().query_row(
            "SELECT count(*) FROM snapshot_root_removals",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(removals, 0);
        repository.apply_committed(LogPosition { index: 6, term: 1 }, remove_context, &command)?;
    }

    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository = prepared_snapshot(
        &directory.path().join("remove-reject.sqlite3"),
        &fixture,
        103,
        false,
        10_000,
    )?;
    repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(104, fixture.administrator, 105, 200, Some(4))?,
        &expiry_command(103, 4, false)?,
    )?;
    for command in [
        remove_root_command(103, 4, 104, 30, 31)?,
        remove_root_command(103, 5, 106, 30, 31)?,
        remove_root_command(103, 5, 104, 107, 31)?,
        remove_root_command(103, 5, 104, 30, 108)?,
    ] {
        assert!(matches!(
            repository.apply_committed(
                LogPosition { index: 6, term: 1 },
                context(109, fixture.administrator, 110, 201, Some(5))?,
                &command,
            ),
            Err(RepositoryError::StaleSnapshot)
        ));
        assert_eq!(only_snapshot(&repository, fixture.volume)?.state, 2);
    }
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
        let command = expiry_command(identity, expected_revision, identity == 102)?;
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
        &expiry_command(103, 4, true)?,
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
        let command = expiry_command(120, 4, false)?;
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

#[test]
fn snapshot_restore_advances_to_a_new_head_and_replays_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("restore.sqlite3");
    let fixture = fixture()?;
    let mut repository = prepared_snapshot(&file_path, &fixture, 140, false, 10_000)?;
    repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(141, fixture.administrator, 142, 104, Some(4))?,
        &publication_command(&fixture, Some(commit(30)?), 143, 144, 145, 146, 147)?,
    )?;
    let command = restore_command(140, fixture.volume, 4, 30, 143, 150, 31, 151, 152)?;
    let restore_context = context(153, fixture.administrator, 154, 105, Some(5))?;
    let receipt =
        repository.apply_committed(LogPosition { index: 6, term: 1 }, restore_context, &command)?;
    let head = repository
        .converged_volume_head(fixture.volume)?
        .ok_or("restored head missing")?;
    assert_eq!(head.namespace_commit_id, commit(150)?);
    assert_eq!(head.root_object_revision_id.as_bytes(), [31; 16]);
    assert_eq!(head.sequence, 3);
    let restore_row: (Vec<u8>, Vec<u8>, i64) = repository.database.connection().query_row(
        "SELECT snapshot_id, previous_namespace_commit_id, revision
         FROM volume_snapshot_restores WHERE metadata_operation_id = ?1",
        [restore_context.operation_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(restore_row.0.as_slice(), [140; 16]);
    assert_eq!(restore_row.1.as_slice(), [143; 16]);
    assert_eq!(restore_row.2, 6);
    drop(repository);

    let database =
        crate::PartitionDatabase::open(&file_path, fixture.partition, UnixMicros::new(500))?;
    let mut reopened = AuthoritativeRepository::new(database);
    let replay =
        reopened.apply_committed(LogPosition { index: 7, term: 1 }, restore_context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    assert_eq!(
        reopened
            .converged_volume_head(fixture.volume)?
            .ok_or("restored head missing")?
            .sequence,
        3
    );
    Ok(())
}

#[test]
fn snapshot_restore_rejects_stale_snapshot_head_and_substituted_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository = prepared_snapshot(
        &directory.path().join("restore-reject.sqlite3"),
        &fixture,
        160,
        false,
        10_000,
    )?;
    repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(161, fixture.administrator, 162, 104, Some(4))?,
        &publication_command(&fixture, Some(commit(30)?), 163, 164, 165, 166, 167)?,
    )?;
    let valid = restore_command(160, fixture.volume, 4, 30, 163, 170, 31, 171, 172)?;
    let AuthoritativeCommand::RestoreVolumeSnapshot(valid) = valid else {
        return Err("restore helper returned wrong command".into());
    };
    let mut stale_snapshot = valid;
    stale_snapshot.expected_snapshot_revision = Revision::new(3);
    refresh_restore_result(&mut stale_snapshot);
    let mut stale_head = valid;
    stale_head.expected_namespace_commit_id = commit(30)?;
    refresh_restore_result(&mut stale_head);
    let mut wrong_root = valid;
    wrong_root.root_object_revision_id = ObjectRevisionId::from_bytes([164; 16])?;
    refresh_restore_result(&mut wrong_root);
    let mut corrupt_evidence = valid;
    corrupt_evidence.source_result_digest[0] ^= 1;
    for (identity, command, expected) in [
        (173, stale_snapshot, RepositoryError::StaleSnapshot),
        (174, stale_head, RepositoryError::StaleVolumeHead),
        (175, wrong_root, RepositoryError::InvalidCommand),
        (176, corrupt_evidence, RepositoryError::InvalidCommand),
    ] {
        let result = repository.apply_committed(
            LogPosition { index: 6, term: 1 },
            context(identity, fixture.administrator, identity + 1, 105, Some(5))?,
            &AuthoritativeCommand::RestoreVolumeSnapshot(command),
        );
        match result {
            Err(error) => assert_eq!(error.to_string(), expected.to_string()),
            Ok(_) => return Err("invalid snapshot restore succeeded".into()),
        }
    }
    assert_eq!(
        repository
            .converged_volume_head(fixture.volume)?
            .ok_or("head missing")?
            .namespace_commit_id,
        commit(163)?
    );
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_snapshot_restore_head_and_history()
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
            &directory.path().join("restore-fault.sqlite3"),
            &fixture,
            180,
            false,
            10_000,
        )?;
        repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            context(181, fixture.administrator, 182, 104, Some(4))?,
            &publication_command(&fixture, Some(commit(30)?), 183, 184, 185, 186, 187)?,
        )?;
        let command = restore_command(180, fixture.volume, 4, 30, 183, 190, 31, 191, 192)?;
        let restore_context = context(193, fixture.administrator, 194, 105, Some(5))?;
        let interrupted = apply_committed_with_fault(
            &mut repository.database,
            LogPosition { index: 6, term: 1 },
            restore_context,
            &command,
            fault,
        );
        assert!(matches!(interrupted, Err(RepositoryError::InjectedFault)));
        assert_eq!(
            repository
                .converged_volume_head(fixture.volume)?
                .ok_or("head missing")?
                .namespace_commit_id,
            commit(183)?
        );
        let restores: i64 = repository.database.connection().query_row(
            "SELECT count(*) FROM volume_snapshot_restores",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(restores, 0);
        repository.apply_committed(LogPosition { index: 6, term: 1 }, restore_context, &command)?;
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
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::RequestVolumeSnapshotExpiry(
        RequestVolumeSnapshotExpiry {
            snapshot_id: SnapshotId::from_bytes([identity; 16])?,
            expected_snapshot_revision: Revision::new(expected_revision),
            reason: if automatic {
                SnapshotExpiryReason::RetentionAge
            } else {
                SnapshotExpiryReason::Manual
            },
        },
    ))
}

fn remove_root_command(
    snapshot: u8,
    expected_revision: u64,
    expiry_operation: u8,
    namespace_commit: u8,
    root_revision: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::RemoveVolumeSnapshotRoot(
        RemoveVolumeSnapshotRoot {
            snapshot_id: SnapshotId::from_bytes([snapshot; 16])?,
            expected_snapshot_revision: Revision::new(expected_revision),
            expiry_operation_id: OperationId::from_bytes([expiry_operation; 16])?,
            namespace_commit_id: NamespaceCommitId::from_bytes([namespace_commit; 16])?,
            root_object_revision_id: ObjectRevisionId::from_bytes([root_revision; 16])?,
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

#[allow(clippy::too_many_arguments)]
fn restore_command(
    snapshot_byte: u8,
    volume_id: meshspan_domain::VolumeId,
    snapshot_revision: u64,
    snapshot_commit_byte: u8,
    expected_commit_byte: u8,
    commit_byte: u8,
    root_byte: u8,
    operation_byte: u8,
    request_byte: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let mut command = RestoreVolumeSnapshot {
        snapshot_id: SnapshotId::from_bytes([snapshot_byte; 16])?,
        expected_snapshot_revision: Revision::new(snapshot_revision),
        volume_id,
        snapshot_namespace_commit_id: NamespaceCommitId::from_bytes([snapshot_commit_byte; 16])?,
        expected_namespace_commit_id: NamespaceCommitId::from_bytes([expected_commit_byte; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([commit_byte; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([root_byte; 16])?,
        source_operation_id: OperationId::from_bytes([operation_byte; 16])?,
        source_request_digest: [request_byte; 32],
        source_result_digest: [0; 32],
    };
    refresh_restore_result(&mut command);
    Ok(AuthoritativeCommand::RestoreVolumeSnapshot(command))
}

fn refresh_restore_result(command: &mut RestoreVolumeSnapshot) {
    command.source_result_digest = namespace_snapshot_restore_result_digest(
        command.source_operation_id,
        command.source_request_digest,
        command.snapshot_id,
        command.snapshot_namespace_commit_id,
        command.expected_namespace_commit_id,
        command.namespace_commit_id,
        command.root_object_revision_id,
    );
}
