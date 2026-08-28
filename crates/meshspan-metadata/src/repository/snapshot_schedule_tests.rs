// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{DurationMicros, Revision, SnapshotId, SnapshotScheduleId, UnixMicros};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::volume_head_tests::{commit, context, fixture, open_and_prepare, publication_command};
use super::{ApplyDisposition, AuthoritativeRepository, LogPosition, PageLimit, RepositoryError};
use crate::{
    AuthoritativeCommand, ConfigureSnapshotSchedule, RecordName, RequestVolumeSnapshotExpiry,
    RunSnapshotSchedule, SnapshotExpiryReason,
};

#[test]
fn schedules_revise_immutably_page_due_work_and_replay_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("schedules.sqlite3");
    let fixture = fixture()?;
    let mut repository = prepared_head(&file_path, &fixture)?;
    for (offset, identity, next_due_at, enabled) in [
        (0_u64, 40_u8, 100_i64, true),
        (1, 41, 100, true),
        (2, 42, 200, true),
        (3, 43, 50, false),
    ] {
        repository.apply_committed(
            LogPosition {
                index: 4 + offset,
                term: 1,
            },
            context(
                identity.saturating_add(20),
                fixture.administrator,
                identity.saturating_add(40),
                103 + i64::try_from(offset)?,
                Some(3 + offset),
            )?,
            &configure_command(identity, fixture.volume, 0, next_due_at, enabled)?,
        )?;
    }
    let first =
        repository.due_snapshot_schedules(UnixMicros::new(250), None, PageLimit::new(2)?)?;
    assert_eq!(
        first
            .items
            .iter()
            .map(|schedule| schedule.schedule_id)
            .collect::<Vec<_>>(),
        [schedule_id(40)?, schedule_id(41)?]
    );
    let second = repository.due_snapshot_schedules(
        UnixMicros::new(250),
        first.next.as_ref(),
        PageLimit::new(2)?,
    )?;
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].schedule_id, schedule_id(42)?);
    assert!(second.next.is_none());

    let replay_context = context(60, fixture.administrator, 80, 103, Some(3))?;
    let replay = repository.apply_committed(
        LogPosition { index: 8, term: 1 },
        replay_context,
        &configure_command(40, fixture.volume, 0, 100, true)?,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    drop(repository);

    let database =
        crate::PartitionDatabase::open(&file_path, fixture.partition, UnixMicros::new(1_000))?;
    let mut reopened = AuthoritativeRepository::new(database);
    let schedule = reopened
        .snapshot_schedule(schedule_id(40)?)?
        .ok_or("missing schedule")?;
    assert_eq!(schedule.sequence, 1);
    assert_eq!(schedule.revision, Revision::new(4));
    reopened.apply_committed(
        LogPosition { index: 9, term: 1 },
        context(90, fixture.administrator, 91, 1_000, Some(7))?,
        &configure_command(40, fixture.volume, 1, 1_100, true)?,
    )?;
    assert_eq!(
        reopened
            .snapshot_schedule(schedule_id(40)?)?
            .ok_or("missing revised schedule")?
            .sequence,
        2
    );
    let revision_count: i64 = reopened.database.connection().query_row(
        "SELECT count(*) FROM snapshot_schedule_revisions WHERE schedule_id = ?1",
        [schedule_id(40)?.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(revision_count, 2);
    Ok(())
}

#[test]
fn due_run_captures_exact_head_and_skips_missed_intervals() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let file_path = directory.path().join("run.sqlite3");
    let fixture = fixture()?;
    let mut repository = prepared_schedule(&file_path, &fixture, true)?;
    let command = run_command(50, 100, 51, 30)?;
    let run_context = context(52, fixture.administrator, 53, 260, Some(4))?;
    let receipt =
        repository.apply_committed(LogPosition { index: 5, term: 1 }, run_context, &command)?;
    assert_eq!(
        receipt.entity,
        super::EntityReference {
            kind: super::EntityKind::VolumeSnapshot,
            id: SnapshotId::from_bytes([51; 16])?.as_bytes(),
        }
    );
    let schedule = repository
        .snapshot_schedule(schedule_id(50)?)?
        .ok_or("missing advanced schedule")?;
    assert_eq!(schedule.next_due_at, UnixMicros::new(300));
    assert_eq!(schedule.revision, Revision::new(5));
    assert!(
        repository
            .due_snapshot_schedules(UnixMicros::new(260), None, PageLimit::new(2)?)?
            .items
            .is_empty()
    );
    let snapshot = repository
        .volume_snapshots(fixture.volume, None, PageLimit::new(2)?)?
        .items
        .into_iter()
        .next()
        .ok_or("scheduled snapshot missing")?;
    assert_eq!(snapshot.namespace_commit_id, commit(30)?);
    assert_eq!(snapshot.expires_at, Some(UnixMicros::new(1_260)));
    let run: (i64, i64, i64) = repository.database.connection().query_row(
        "SELECT scheduled_for, created_at, revision FROM snapshot_schedule_runs
         WHERE schedule_id = ?1",
        [schedule_id(50)?.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(run, (100, 260, 5));
    drop(repository);

    let database =
        crate::PartitionDatabase::open(&file_path, fixture.partition, UnixMicros::new(2_000))?;
    let mut reopened = AuthoritativeRepository::new(database);
    let replay =
        reopened.apply_committed(LogPosition { index: 6, term: 1 }, run_context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    assert_eq!(
        reopened
            .volume_snapshots(fixture.volume, None, PageLimit::new(2)?)?
            .items
            .len(),
        1
    );
    Ok(())
}

#[test]
fn schedule_configuration_and_execution_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository = prepared_head(&directory.path().join("reject.sqlite3"), &fixture)?;
    for invalid in [
        ConfigureSnapshotSchedule {
            interval: DurationMicros::new(0),
            ..schedule_value(60, fixture.volume, 0, 100, true)?
        },
        ConfigureSnapshotSchedule {
            retention_count: Some(0),
            ..schedule_value(60, fixture.volume, 0, 100, true)?
        },
        ConfigureSnapshotSchedule {
            retention_duration: Some(DurationMicros::new(0)),
            ..schedule_value(60, fixture.volume, 0, 100, true)?
        },
    ] {
        assert!(matches!(
            repository.apply_committed(
                LogPosition { index: 4, term: 1 },
                context(61, fixture.administrator, 62, 103, Some(3))?,
                &AuthoritativeCommand::ConfigureSnapshotSchedule(invalid),
            ),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        context(63, fixture.administrator, 64, 103, Some(3))?,
        &configure_command(60, fixture.volume, 0, 100, true)?,
    )?;
    for (operation, now, command, expected) in [
        (67, 99, run_command(60, 100, 68, 30)?, "invalid"),
        (
            69,
            100,
            run_command_with_sequence(60, 0, 100, 70, 30)?,
            "stale_schedule",
        ),
        (71, 100, run_command(60, 100, 72, 80)?, "stale_head"),
    ] {
        let result = repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            context(
                operation,
                fixture.administrator,
                operation + 1,
                now,
                Some(4),
            )?,
            &command,
        );
        assert!(matches!(
            (expected, result),
            ("invalid", Err(RepositoryError::InvalidCommand))
                | (
                    "stale_schedule",
                    Err(RepositoryError::StaleSnapshotSchedule)
                )
                | ("stale_head", Err(RepositoryError::StaleVolumeHead))
        ));
    }
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            context(73, fixture.administrator, 74, 104, Some(4))?,
            &configure_command(60, fixture.volume, 0, 200, true)?,
        ),
        Err(RepositoryError::StaleSnapshotSchedule)
    ));
    repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(75, fixture.administrator, 76, 104, Some(4))?,
        &configure_command(60, fixture.volume, 1, 100, false)?,
    )?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 6, term: 1 },
            context(77, fixture.administrator, 78, 105, Some(5))?,
            &run_command_with_sequence(60, 2, 100, 79, 30)?,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert!(
        repository
            .volume_snapshots(fixture.volume, None, PageLimit::new(2)?)?
            .items
            .is_empty()
    );
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_the_complete_schedule_run() -> Result<(), Box<dyn std::error::Error>>
{
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        let directory = tempdir()?;
        let fixture = fixture()?;
        let mut repository =
            prepared_schedule(&directory.path().join("fault.sqlite3"), &fixture, true)?;
        let command = run_command(50, 100, 80, 30)?;
        let run_context = context(81, fixture.administrator, 82, 100, Some(4))?;
        let result = apply_committed_with_fault(
            &mut repository.database,
            LogPosition { index: 5, term: 1 },
            run_context,
            &command,
            fault,
        );
        assert!(matches!(result, Err(RepositoryError::InjectedFault)));
        assert_eq!(
            repository
                .snapshot_schedule(schedule_id(50)?)?
                .ok_or("missing rolled-back schedule")?
                .next_due_at,
            UnixMicros::new(100)
        );
        assert!(
            repository
                .volume_snapshots(fixture.volume, None, PageLimit::new(2)?)?
                .items
                .is_empty()
        );
        let runs: i64 = repository.database.connection().query_row(
            "SELECT count(*) FROM snapshot_schedule_runs",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(runs, 0);
        repository.apply_committed(LogPosition { index: 5, term: 1 }, run_context, &command)?;
    }
    Ok(())
}

#[test]
fn corrupted_schedule_head_fails_closed_for_every_consumer()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository =
        prepared_schedule(&directory.path().join("corrupt.sqlite3"), &fixture, true)?;
    repository.database.connection_mut().execute(
        "UPDATE snapshot_schedule_heads SET interval_micros = 60 WHERE schedule_id = ?1",
        [schedule_id(50)?.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        repository.snapshot_schedule(schedule_id(50)?),
        Err(RepositoryError::CorruptState)
    ));
    assert!(matches!(
        repository.due_snapshot_schedules(UnixMicros::new(100), None, PageLimit::new(2)?),
        Err(RepositoryError::CorruptState)
    ));
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            context(90, fixture.administrator, 91, 100, Some(4))?,
            &run_command(50, 100, 92, 30)?,
        ),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn indexed_age_and_count_retention_select_and_revalidate_exact_snapshots()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository =
        prepared_schedule(&directory.path().join("retention.sqlite3"), &fixture, true)?;
    for (offset, scheduled_for, snapshot_identity) in [
        (0_u64, 100_i64, 100_u8),
        (1, 150, 101),
        (2, 200, 102),
        (3, 250, 103),
    ] {
        repository.apply_committed(
            LogPosition {
                index: 5 + offset,
                term: 1,
            },
            context(
                snapshot_identity,
                fixture.administrator,
                snapshot_identity.saturating_add(20),
                scheduled_for,
                Some(4 + offset),
            )?,
            &run_command(50, scheduled_for, snapshot_identity, 30)?,
        )?;
    }
    let count_page =
        repository.due_snapshot_expiries(UnixMicros::new(300), None, PageLimit::new(2)?)?;
    assert_eq!(count_page.items.len(), 1);
    assert_eq!(
        count_page.items[0].snapshot_id,
        SnapshotId::from_bytes([100; 16])?
    );
    assert_eq!(count_page.items[0].revision, Revision::new(5));
    assert_eq!(
        count_page.items[0].reason,
        SnapshotExpiryReason::RetentionCount
    );

    repository.apply_committed(
        LogPosition { index: 9, term: 1 },
        context(230, fixture.administrator, 231, 300, Some(8))?,
        &expiry_command(100, 5, SnapshotExpiryReason::RetentionCount)?,
    )?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 10, term: 1 },
            context(232, fixture.administrator, 233, 300, Some(9))?,
            &expiry_command(103, 8, SnapshotExpiryReason::RetentionCount)?,
        ),
        Err(RepositoryError::InvalidCommand)
    ));

    let first_age =
        repository.due_snapshot_expiries(UnixMicros::new(1_200), None, PageLimit::new(1)?)?;
    assert_eq!(first_age.items.len(), 1);
    assert_eq!(
        first_age.items[0].snapshot_id,
        SnapshotId::from_bytes([101; 16])?
    );
    assert_eq!(
        first_age.items[0].reason,
        SnapshotExpiryReason::RetentionAge
    );
    assert!(first_age.next.is_some());
    let second_age = repository.due_snapshot_expiries(
        UnixMicros::new(1_200),
        first_age.next.as_ref(),
        PageLimit::new(1)?,
    )?;
    assert_eq!(second_age.items.len(), 1);
    assert_eq!(
        second_age.items[0].snapshot_id,
        SnapshotId::from_bytes([102; 16])?
    );
    assert!(second_age.next.is_none());

    repository.database.connection_mut().execute(
        "UPDATE snapshot_schedule_heads SET run_sequence = 5 WHERE schedule_id = ?1",
        [schedule_id(50)?.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        repository.due_snapshot_expiries(UnixMicros::new(300), None, PageLimit::new(2)?),
        Err(RepositoryError::CorruptState)
    ));
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 10, term: 1 },
            context(234, fixture.administrator, 235, 300, Some(9))?,
            &expiry_command(101, 6, SnapshotExpiryReason::RetentionCount)?,
        ),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

fn prepared_head(
    file_path: &std::path::Path,
    fixture: &super::volume_head_tests::HeadFixture,
) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
    let mut repository = open_and_prepare(file_path, fixture)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(30, fixture.administrator, 31, 102, Some(2))?,
        &publication_command(fixture, None, 30, 31, 32, 33, 34)?,
    )?;
    Ok(repository)
}

fn prepared_schedule(
    file_path: &std::path::Path,
    fixture: &super::volume_head_tests::HeadFixture,
    enabled: bool,
) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
    let mut repository = prepared_head(file_path, fixture)?;
    repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        context(40, fixture.administrator, 41, 103, Some(3))?,
        &configure_command(50, fixture.volume, 0, 100, enabled)?,
    )?;
    Ok(repository)
}

fn configure_command(
    identity: u8,
    volume_id: meshspan_domain::VolumeId,
    expected_sequence: u64,
    next_due_at: i64,
    enabled: bool,
) -> Result<AuthoritativeCommand, meshspan_domain::IdentifierError> {
    Ok(AuthoritativeCommand::ConfigureSnapshotSchedule(
        schedule_value(identity, volume_id, expected_sequence, next_due_at, enabled)?,
    ))
}

fn schedule_value(
    identity: u8,
    volume_id: meshspan_domain::VolumeId,
    expected_sequence: u64,
    next_due_at: i64,
    enabled: bool,
) -> Result<ConfigureSnapshotSchedule, meshspan_domain::IdentifierError> {
    Ok(ConfigureSnapshotSchedule {
        schedule_id: schedule_id(identity)?,
        volume_id,
        expected_schedule_sequence: expected_sequence,
        interval: DurationMicros::new(50),
        retention_count: Some(3),
        retention_duration: Some(DurationMicros::new(1_000)),
        enabled,
        next_due_at: UnixMicros::new(next_due_at),
    })
}

fn run_command(
    schedule_identity: u8,
    scheduled_for: i64,
    snapshot_identity: u8,
    commit_identity: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    run_command_with_sequence(
        schedule_identity,
        1,
        scheduled_for,
        snapshot_identity,
        commit_identity,
    )
}

fn run_command_with_sequence(
    schedule_identity: u8,
    sequence: u64,
    scheduled_for: i64,
    snapshot_identity: u8,
    commit_identity: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let name = format!("Scheduled {scheduled_for}");
    Ok(AuthoritativeCommand::RunSnapshotSchedule(
        RunSnapshotSchedule {
            schedule_id: schedule_id(schedule_identity)?,
            expected_schedule_sequence: sequence,
            scheduled_for: UnixMicros::new(scheduled_for),
            snapshot_id: SnapshotId::from_bytes([snapshot_identity; 16])?,
            namespace_commit_id: commit(commit_identity)?,
            name: RecordName::new(&name)?,
        },
    ))
}

fn expiry_command(
    snapshot_identity: u8,
    expected_revision: u64,
    reason: SnapshotExpiryReason,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::RequestVolumeSnapshotExpiry(
        RequestVolumeSnapshotExpiry {
            snapshot_id: SnapshotId::from_bytes([snapshot_identity; 16])?,
            expected_snapshot_revision: Revision::new(expected_revision),
            reason,
        },
    ))
}

fn schedule_id(value: u8) -> Result<SnapshotScheduleId, meshspan_domain::IdentifierError> {
    SnapshotScheduleId::from_bytes([value; 16])
}
