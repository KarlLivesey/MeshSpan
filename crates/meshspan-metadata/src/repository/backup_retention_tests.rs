// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{RecordBackupReclamation, RepositoryError, RetireMetadataBackup};
use meshspan_contracts::{BackupDeleteReceipt, BackupObjectIdentity};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn retention_retires_only_excess_generations_and_reclaims_exact_receipts() -> TestResult {
    let (mut fixture, destination) = history(4)?;
    let candidate = fixture
        .repository
        .metadata_backup_retirement_candidate()?
        .ok_or("candidate missing")?;
    assert_eq!(candidate.backup_id, BackupId::from_bytes([60; 16])?);
    assert_eq!(candidate.retained_backups.len(), 3);
    let command = AuthoritativeCommand::RetireMetadataBackup(candidate.clone());
    let receipt = apply(&mut fixture, &command, 1_000)?;
    let backup = fixture
        .repository
        .metadata_backup(candidate.backup_id)?
        .ok_or("backup missing")?;
    assert_eq!(backup.state, MetadataBackupState::Retired);
    assert_eq!(backup.revision, receipt.committed_revision);
    assert_eq!(
        fixture.repository.metadata_backup_retirement_candidate()?,
        None
    );
    let page = fixture
        .repository
        .pending_backup_reclamations(None, PageLimit::new(1)?)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.next, None);
    let copy = page.items.first().ok_or("copy missing")?;
    assert_eq!(copy.state, BackupCopyState::Retired);
    assert_eq!(copy.revision, receipt.committed_revision);
    let deletion = deletion_receipt(copy)?;
    let mut substituted = deletion;
    substituted.object.digest = [99; 32];
    assert!(
        matches!(apply(&mut fixture, &AuthoritativeCommand::RecordBackupReclamation(
        RecordBackupReclamation { receipt: substituted }), 1_001), Err(error)
        if error.downcast_ref::<RepositoryError>().is_some_and(|error| matches!(error, RepositoryError::InvalidCommand)))
    );
    assert_eq!(
        fixture
            .repository
            .pending_backup_reclamations(None, PageLimit::new(1)?)?
            .items
            .len(),
        1
    );
    apply(
        &mut fixture,
        &AuthoritativeCommand::RecordBackupReclamation(RecordBackupReclamation {
            receipt: deletion,
        }),
        1_002,
    )?;
    assert!(
        fixture
            .repository
            .pending_backup_reclamations(None, PageLimit::new(1)?)?
            .items
            .is_empty()
    );
    assert_eq!(
        fixture
            .repository
            .backup_copy(candidate.backup_id, destination)?
            .ok_or("historical copy missing")?
            .state,
        BackupCopyState::Retired
    );
    Ok(())
}

#[test]
fn stale_schedule_duplicate_or_older_witnesses_cannot_retire() -> TestResult {
    let (mut fixture, _) = history(4)?;
    let candidate = fixture
        .repository
        .metadata_backup_retirement_candidate()?
        .ok_or("candidate missing")?;
    let mut stale = candidate.clone();
    stale.expected_schedule_sequence += 1;
    let mut repeated = candidate.clone();
    repeated.retained_backups = vec![candidate.retained_backups[0]; 3];
    let mut self_witness = candidate.clone();
    self_witness.retained_backups[0] = candidate.backup_id;
    let mut stale_revision = candidate.clone();
    stale_revision.expected_backup_revision = Revision::new(1);
    for invalid in [stale, repeated, self_witness, stale_revision] {
        let before = fixture.repository.current_revision()?;
        assert!(
            apply(
                &mut fixture,
                &AuthoritativeCommand::RetireMetadataBackup(invalid),
                1_000
            )
            .is_err()
        );
        assert_eq!(fixture.repository.current_revision()?, before);
        assert_eq!(
            fixture
                .repository
                .metadata_backup(candidate.backup_id)?
                .ok_or("backup missing")?
                .state,
            MetadataBackupState::Verified
        );
    }
    Ok(())
}

#[test]
fn retention_requires_current_copy_policy_not_historical_protected_label() -> TestResult {
    let (mut fixture, _) = history(4)?;
    let stale = fixture
        .repository
        .metadata_backup_retirement_candidate()?
        .ok_or("candidate missing")?;
    let schedule = fixture
        .repository
        .metadata_backup_schedule()?
        .ok_or("schedule missing")?;
    apply(
        &mut fixture,
        &AuthoritativeCommand::ConfigureMetadataBackupSchedule(ConfigureMetadataBackupSchedule {
            partition_id: schedule.partition_id,
            expected_schedule_sequence: schedule.sequence,
            interval: schedule.interval,
            retained_generations: 3,
            minimum_verified_copies: 2,
            minimum_independent_copies: 1,
            enabled: true,
            next_due_at: UnixMicros::new(1_001),
        }),
        1_000,
    )?;
    assert_eq!(
        fixture.repository.metadata_backup_retirement_candidate()?,
        None
    );
    let current = RetireMetadataBackup {
        expected_schedule_sequence: schedule.sequence + 1,
        ..stale
    };
    assert!(
        apply(
            &mut fixture,
            &AuthoritativeCommand::RetireMetadataBackup(current),
            1_002
        )
        .is_err()
    );
    assert!(
        fixture
            .repository
            .pending_backup_reclamations(None, PageLimit::new(1)?)?
            .items
            .is_empty()
    );
    Ok(())
}

#[test]
fn retired_copy_debt_pages_and_survives_database_reopen() -> TestResult {
    let (mut fixture, _) = history(5)?;
    for _ in 0..2 {
        let candidate = fixture
            .repository
            .metadata_backup_retirement_candidate()?
            .ok_or("candidate missing")?;
        apply(
            &mut fixture,
            &AuthoritativeCommand::RetireMetadataBackup(candidate),
            1_000,
        )?;
    }
    let partition = fixture.partition;
    let database_file = fixture.directory.path().join("backup-catalogue.sqlite3");
    drop(fixture.repository);
    let repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &database_file,
        partition,
        UnixMicros::new(2_000),
    )?);
    let first = repository.pending_backup_reclamations(None, PageLimit::new(1)?)?;
    assert_eq!(first.items.len(), 1);
    let second = repository
        .pending_backup_reclamations(Some(first.next.ok_or("next missing")?), PageLimit::new(1)?)?;
    assert_eq!(second.items.len(), 1);
    assert_ne!(first.items[0].backup_id, second.items[0].backup_id);
    assert_eq!(second.next, None);
    Ok(())
}

#[test]
fn incomplete_old_backup_is_reclaimed_only_after_newer_protected_generations() -> TestResult {
    let (mut fixture, destination) = history(0)?;
    add_generation(&mut fixture, destination, 0, false)?;
    assert_eq!(
        fixture.repository.metadata_backup_retirement_candidate()?,
        None
    );
    for generation in 1..=3 {
        add_generation(&mut fixture, destination, generation, true)?;
    }
    let candidate = fixture
        .repository
        .metadata_backup_retirement_candidate()?
        .ok_or("incomplete victim missing")?;
    assert_eq!(candidate.backup_id, BackupId::from_bytes([60; 16])?);
    apply(
        &mut fixture,
        &AuthoritativeCommand::RetireMetadataBackup(candidate),
        1000,
    )?;
    assert_eq!(
        fixture
            .repository
            .pending_backup_reclamations(None, PageLimit::new(1)?)?
            .items
            .len(),
        1
    );
    Ok(())
}

#[test]
fn retirement_faults_roll_back_generation_copies_and_receipts_together() -> TestResult {
    use crate::repository::apply::{ApplyFaultPoint, apply_committed_with_fault};
    let (mut fixture, destination) = history(4)?;
    let candidate = fixture
        .repository
        .metadata_backup_retirement_candidate()?
        .ok_or("candidate missing")?;
    let before = fixture.repository.current_revision()?;
    let command = AuthoritativeCommand::RetireMetadataBackup(candidate.clone());
    let context = context(240, fixture.administrator, 241, 1000, before.get())?;
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        assert!(
            apply_committed_with_fault(
                &mut fixture.repository.database,
                LogPosition {
                    index: before.get() + 1,
                    term: 1
                },
                context,
                &command,
                fault
            )
            .is_err()
        );
        assert_eq!(fixture.repository.current_revision()?, before);
        assert_eq!(
            fixture.repository.resolve_operation(context.operation_id)?,
            None
        );
        assert_eq!(
            fixture
                .repository
                .metadata_backup(candidate.backup_id)?
                .ok_or("backup missing")?
                .state,
            MetadataBackupState::Verified
        );
        assert_eq!(
            fixture
                .repository
                .backup_copy(candidate.backup_id, destination)?
                .ok_or("copy missing")?
                .state,
            BackupCopyState::Verified
        );
        assert!(
            fixture
                .repository
                .pending_backup_reclamations(None, PageLimit::new(1)?)?
                .items
                .is_empty()
        );
    }
    fixture.repository.apply_committed(
        LogPosition {
            index: before.get() + 1,
            term: 1,
        },
        context,
        &command,
    )?;
    let replay = fixture.repository.apply_committed(
        LogPosition {
            index: before.get() + 2,
            term: 1,
        },
        context,
        &command,
    )?;
    assert_eq!(replay.disposition, crate::ApplyDisposition::Replayed);
    assert_eq!(replay.committed_revision.get(), before.get() + 1);
    Ok(())
}

#[test]
fn retention_queries_use_ordered_indexes_without_temporary_sorting() -> TestResult {
    let (fixture, _) = history(0)?;
    for (sql, index) in [
        (
            "EXPLAIN QUERY PLAN SELECT backup_id FROM metadata_backups WHERE state = 2 ORDER BY state_revision DESC, backup_id LIMIT 3",
            "metadata_backups_retention",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT b.backup_id FROM metadata_backups b JOIN metadata_backup_runs r USING(backup_id) WHERE b.state = 1 AND b.state_revision < 30 AND r.state IN (4, 5) ORDER BY b.state_revision, b.backup_id DESC LIMIT 1",
            "metadata_backups_retention",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT c.backup_id, c.destination_id FROM backup_copies c WHERE c.state = 4 AND (c.backup_id, c.destination_id) > (x'00', x'00') AND NOT EXISTS (SELECT 1 FROM backup_copy_reclamations r WHERE r.backup_id = c.backup_id AND r.destination_id = c.destination_id) ORDER BY c.backup_id, c.destination_id LIMIT 2",
            "backup_copies_retired",
        ),
    ] {
        let mut statement = fixture.repository.database.connection().prepare(sql)?;
        let details = statement
            .query_map([], |row| row.get::<_, String>(3))?
            .collect::<Result<Vec<_>, _>>()?
            .join("\n");
        assert!(details.contains(index), "{details}");
        assert!(!details.contains("TEMP B-TREE"), "{details}");
    }
    Ok(())
}

fn history(count: u8) -> TestResult<(Fixture, BackupDestinationId)> {
    let mut fixture = fixture()?;
    let destination = BackupDestinationId::from_bytes([30; 16])?;
    configure_destination(&mut fixture, destination)?;
    let partition = fixture.partition;
    apply(
        &mut fixture,
        &AuthoritativeCommand::ConfigureMetadataBackupSchedule(ConfigureMetadataBackupSchedule {
            partition_id: partition,
            expected_schedule_sequence: 0,
            interval: DurationMicros::new(1),
            retained_generations: 3,
            minimum_verified_copies: 1,
            minimum_independent_copies: 1,
            enabled: true,
            next_due_at: UnixMicros::new(32),
        }),
        31,
    )?;
    for generation in 0..count {
        add_generation(&mut fixture, destination, generation, true)?;
    }
    Ok((fixture, destination))
}

fn add_generation(
    fixture: &mut Fixture,
    destination: BackupDestinationId,
    generation: u8,
    protected: bool,
) -> TestResult {
    let backup = BackupId::from_bytes([60 + generation; 16])?;
    let now = 32 + i64::from(generation) * 10;
    let schedule = fixture
        .repository
        .metadata_backup_schedule()?
        .ok_or("schedule missing")?;
    apply(
        fixture,
        &AuthoritativeCommand::QueueMetadataBackupRun(QueueMetadataBackupRun {
            backup_id: backup,
            partition_id: fixture.partition,
            expected_schedule_sequence: schedule.sequence,
            scheduled_for: schedule.next_due_at,
        }),
        now,
    )?;
    let claim = MetadataBackupRunClaim {
        claim_generation: 1,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        fence: 1,
    };
    apply(
        fixture,
        &AuthoritativeCommand::ClaimMetadataBackupRun(ClaimMetadataBackupRun {
            backup_id: backup,
            claim,
            lease_expires_at: UnixMicros::new(now + 9),
        }),
        now + 1,
    )?;
    let source_revision = fixture.repository.current_revision()?;
    apply(
        fixture,
        &AuthoritativeCommand::RecordMetadataBackup(RecordMetadataBackup {
            backup_id: backup,
            partition_id: fixture.partition,
            mesh_id: fixture.mesh,
            last_log_index: source_revision.get(),
            last_log_term: 1,
            state_revision: source_revision,
            schema_version: crate::migration::PARTITION_SCHEMA_VERSION,
            source_byte_length: 4_096,
            source_digest: [1; 32],
            manifest_digest: [2; 32],
            encrypted_byte_length: 4_512,
            encrypted_digest: [3; 32],
            claim,
            initial_copy: InitialBackupCopy {
                destination_id: destination,
                provider_generation: 1,
                object_reference: format!("backup/{generation}"),
                byte_length: 4_512,
                copy_digest: [3; 32],
            },
        }),
        now + 2,
    )?;
    if protected {
        apply(
            fixture,
            &AuthoritativeCommand::VerifyBackupCopy(VerifyBackupCopy {
                backup_id: backup,
                destination_id: destination,
                provider_generation: 1,
                copy_digest: [3; 32],
            }),
            now + 3,
        )?;
    }
    let evidence = fixture
        .repository
        .metadata_backup_protection_evidence(backup)?;
    apply(
        fixture,
        &AuthoritativeCommand::CompleteMetadataBackupRun(CompleteMetadataBackupRun {
            backup_id: backup,
            outcome: if protected {
                MetadataBackupRunCompletion::Protected {
                    result_digest: evidence.digest,
                }
            } else {
                MetadataBackupRunCompletion::Incomplete {
                    result_digest: evidence.digest,
                }
            },
        }),
        if protected { now + 4 } else { now + 9 },
    )?;
    Ok(())
}

fn apply(
    fixture: &mut Fixture,
    command: &AuthoritativeCommand,
    now: i64,
) -> TestResult<crate::CommandReceipt> {
    let revision = fixture.repository.current_revision()?.get();
    let identity = u8::try_from(revision + 100)?;
    Ok(fixture.repository.apply_committed(
        LogPosition {
            index: revision + 1,
            term: 1,
        },
        context(identity, fixture.administrator, identity, now, revision)?,
        command,
    )?)
}

fn deletion_receipt(copy: &crate::BackupCopyRecord) -> TestResult<BackupDeleteReceipt> {
    Ok(BackupDeleteReceipt {
        operation_id: OperationId::from_bytes([240; 16])?,
        object: BackupObjectIdentity {
            backup_id: copy.backup_id,
            destination_id: copy.destination_id,
            provider_generation: copy.provider_generation,
            byte_length: copy.byte_length,
            digest: copy.copy_digest,
        },
        retirement_revision: copy.revision,
    })
}
