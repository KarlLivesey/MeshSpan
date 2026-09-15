// SPDX-License-Identifier: GPL-2.0-only

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn duplicate_admission_preserves_retry_and_readiness_across_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("retry.sqlite3");
    let mut fixture = Fixture::at(&path)?;
    let work = WorkId::from_bytes([24; 16])?;
    queue_then_retry(&mut fixture, work)?;
    let mut duplicate = fixture.queue(WorkId::from_bytes([25; 16])?, 1, false);
    duplicate.signals.access_heat = 50;
    duplicate.signals.instability = 10;
    duplicate.signals.due_at = Some(UnixMicros::new(500));
    duplicate.demand.in_flight_bytes = 8_192;
    fixture.apply(
        5,
        40,
        &AuthoritativeCommand::QueueMaintenanceWork(duplicate),
    )?;
    let record = fixture.record(work)?;
    assert_eq!(record.next_attempt_at, UnixMicros::new(200));
    assert_eq!(record.attempt_count, 1);
    assert!(record.claim.is_none());
    assert_eq!(record.signals.access_heat, 50);
    assert_eq!(record.demand.in_flight_bytes, 8_192);
    drop(fixture);

    let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &path,
        UnixMicros::new(40),
    )?);
    let budget = WorkBudget::new(1, 8_192, None)?;
    let usage = WorkUsage {
        active_jobs: 0,
        in_flight_bytes: 0,
    };
    assert!(
        repository
            .ready_maintenance_work(UnixMicros::new(199), budget, usage, None, 1,)?
            .work
            .is_empty()
    );
    let ready = repository.ready_maintenance_work(UnixMicros::new(200), budget, usage, None, 1)?;
    assert_eq!(ready.work.len(), 1);
    assert_eq!(ready.work[0].work_id, work);
    assert!(repository.maintenance_work(duplicate.work_id)?.is_none());
    Ok(())
}

#[test]
fn higher_urgency_or_earlier_deadline_can_advance_retry_eligibility() -> TestResult {
    for unavailable in [false, true] {
        let mut fixture = Fixture::new()?;
        let work = WorkId::from_bytes([24; 16])?;
        queue_then_retry(&mut fixture, work)?;
        let mut incoming = fixture.queue(work, 1, unavailable);
        incoming.next_attempt_at = UnixMicros::new(40);
        if !unavailable {
            incoming.signals.due_at = Some(UnixMicros::new(100));
        }
        fixture.apply(5, 40, &AuthoritativeCommand::QueueMaintenanceWork(incoming))?;
        assert_eq!(fixture.record(work)?.next_attempt_at, UnixMicros::new(40));
        fixture.apply(
            6,
            40,
            &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work, 2, 202, 100)),
        )?;
        assert_eq!(fixture.record(work)?.attempt_count, 2);
    }
    Ok(())
}

#[test]
fn duplicate_admission_can_advance_work_that_has_not_been_attempted() -> TestResult {
    let mut fixture = Fixture::new()?;
    let work = WorkId::from_bytes([24; 16])?;
    let mut queued = fixture.queue(work, 1, false);
    queued.next_attempt_at = UnixMicros::new(200);
    fixture.apply(2, 10, &AuthoritativeCommand::QueueMaintenanceWork(queued))?;
    queued.next_attempt_at = UnixMicros::new(40);
    fixture.apply(3, 40, &AuthoritativeCommand::QueueMaintenanceWork(queued))?;
    assert_eq!(fixture.record(work)?.next_attempt_at, UnixMicros::new(40));
    assert_eq!(fixture.record(work)?.attempt_count, 0);
    Ok(())
}

fn queue_then_retry(fixture: &mut Fixture, work: WorkId) -> TestResult {
    let mut queued = fixture.queue(work, 1, false);
    queued.signals.due_at = Some(UnixMicros::new(400));
    fixture.apply(2, 10, &AuthoritativeCommand::QueueMaintenanceWork(queued))?;
    fixture.apply(
        3,
        20,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work, 1, 101, 100)),
    )?;
    fixture.apply(
        4,
        30,
        &AuthoritativeCommand::CompleteMaintenanceWork(fixture.retry(work, 1, 101, 200)),
    )?;
    Ok(())
}
