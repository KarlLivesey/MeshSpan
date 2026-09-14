// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, BackupId, DurationMicros, HostId, MeshId, NodeId, OperationId, PartitionId,
    PrincipalId, Revision, RoleId, UnixMicros,
};
use tempfile::{TempDir, tempdir};

use super::tests::{mark_test_recovery_verified, protected_bootstrap};
use super::{AuthoritativeRepository, LogPosition, MetadataBackupRunState, RepositoryError};
use crate::{
    AuthoritativeCommand, BootstrapMesh, ClaimMetadataBackupRun, CommandContext,
    CompleteMetadataBackupRun, ConfigureMetadataBackupSchedule, MetadataBackupRunClaim,
    MetadataBackupRunCompletion, PartitionDatabase, QueueMetadataBackupRun, RecordName,
    RenewMetadataBackupRun,
};

const DAY_MICROS: u64 = 86_400_000_000;

#[path = "federated_backup_route_tests.rs"]
mod federated_routes;
#[path = "backup_history_tests.rs"]
mod history;

struct Fixture {
    directory: TempDir,
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    partition: PartitionId,
    node: NodeId,
}

#[test]
fn abandonment_fences_only_expired_unrecorded_claim_and_makes_new_capture_due()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let backup = BackupId::from_bytes([20; 16])?;
    queue_run(&mut fixture, backup)?;
    let expected_claim = claim(1, fixture.node, 21);
    apply_claim(&mut fixture, backup, expected_claim, 150, 4)?;
    let value = crate::AbandonUnrecordedMetadataBackupRun {
        backup_id: backup,
        expected_claim,
    };
    let command = AuthoritativeCommand::AbandonUnrecordedMetadataBackupRun(value);
    for (now, changed) in [
        (149, value),
        (
            150,
            crate::AbandonUnrecordedMetadataBackupRun {
                expected_claim: claim(2, fixture.node, 22),
                ..value
            },
        ),
    ] {
        assert!(matches!(
            fixture.repository.apply_committed(
                LogPosition { index: 5, term: 1 },
                context(30, fixture.administrator, 31, now, 4)?,
                &AuthoritativeCommand::AbandonUnrecordedMetadataBackupRun(changed)
            ),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    let context = context(32, fixture.administrator, 33, 150, 4)?;
    let receipt =
        fixture
            .repository
            .apply_committed(LogPosition { index: 5, term: 1 }, context, &command)?;
    assert_eq!(
        fixture
            .repository
            .metadata_backup_run(backup)?
            .ok_or("run")?
            .state,
        MetadataBackupRunState::Incomplete
    );
    assert!(
        fixture
            .repository
            .unfinished_metadata_backup_run()?
            .is_none()
    );
    assert!(fixture.repository.metadata_backup(backup)?.is_none());
    let due = fixture
        .repository
        .due_metadata_backup_schedule(UnixMicros::new(150))?
        .ok_or("replacement not due")?;
    assert_eq!(due.next_due_at, UnixMicros::new(150));
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &fixture.directory.path().join("backup-run.sqlite3"),
        fixture.partition,
        UnixMicros::new(151),
    )?);
    let replay =
        fixture
            .repository
            .apply_committed(LogPosition { index: 6, term: 1 }, context, &command)?;
    assert_eq!(receipt.request_digest, replay.request_digest);
    assert_eq!(receipt.committed_revision, replay.committed_revision);
    assert!(
        fixture
            .repository
            .unfinished_metadata_backup_run()?
            .is_none()
    );
    let replacement = BackupId::from_bytes([40; 16])?;
    fixture.repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        CommandContext {
            operation_id: OperationId::from_bytes([34; 16])?,
            audit_event_id: AuditEventId::from_bytes([35; 16])?,
            occurred_at: UnixMicros::new(151),
            expected_revision: Some(Revision::new(5)),
            ..context
        },
        &AuthoritativeCommand::QueueMetadataBackupRun(QueueMetadataBackupRun {
            backup_id: replacement,
            partition_id: fixture.partition,
            expected_schedule_sequence: due.sequence,
            scheduled_for: due.next_due_at,
        }),
    )?;
    let fresh = fixture
        .repository
        .unfinished_metadata_backup_run()?
        .ok_or("fresh occurrence")?;
    assert_eq!(fresh.backup_id, replacement);
    assert_eq!(fresh.run_sequence, 2);
    Ok(())
}

#[test]
fn unrecorded_abandonment_rolls_back_terminal_state_and_schedule_together()
-> Result<(), Box<dyn std::error::Error>> {
    use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        let mut fixture = fixture()?;
        let backup = BackupId::from_bytes([20; 16])?;
        queue_run(&mut fixture, backup)?;
        let expected_claim = claim(1, fixture.node, 21);
        apply_claim(&mut fixture, backup, expected_claim, 150, 4)?;
        let before = fixture.repository.metadata_backup_run(backup)?;
        let schedule_before = fixture.repository.metadata_backup_schedule()?;
        let command = AuthoritativeCommand::AbandonUnrecordedMetadataBackupRun(
            crate::AbandonUnrecordedMetadataBackupRun {
                backup_id: backup,
                expected_claim,
            },
        );
        let context = context(32, fixture.administrator, 33, 150, 4)?;
        assert!(matches!(
            apply_committed_with_fault(
                &mut fixture.repository.database,
                LogPosition { index: 5, term: 1 },
                context,
                &command,
                fault
            ),
            Err(RepositoryError::InjectedFault)
        ));
        assert_eq!(fixture.repository.metadata_backup_run(backup)?, before);
        assert_eq!(
            fixture.repository.metadata_backup_schedule()?,
            schedule_before
        );
        assert_eq!(fixture.repository.current_revision()?, Revision::new(4));
        assert_eq!(
            fixture
                .repository
                .metadata_backup_run_claim(backup)?
                .ok_or("claim")?
                .claim,
            expected_claim
        );
        fixture
            .repository
            .apply_committed(LogPosition { index: 5, term: 1 }, context, &command)?;
        assert!(
            fixture
                .repository
                .unfinished_metadata_backup_run()?
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn expired_claim_is_taken_over_and_old_worker_is_fenced() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fixture = fixture()?;
    let backup = BackupId::from_bytes([20; 16])?;
    queue_run(&mut fixture, backup)?;
    let first = claim(1, fixture.node, 21);
    apply_claim(&mut fixture, backup, first, 150, 4)?;
    assert_eq!(
        fixture
            .repository
            .unfinished_metadata_backup_run()?
            .ok_or("unfinished run missing")?
            .backup_id,
        backup
    );

    fixture.repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(22, fixture.administrator, 23, 150, 4)?,
        &AuthoritativeCommand::ClaimMetadataBackupRun(ClaimMetadataBackupRun {
            backup_id: backup,
            claim: claim(2, fixture.node, 24),
            lease_expires_at: UnixMicros::new(250),
        }),
    )?;
    assert!(matches!(
        fixture.repository.apply_committed(
            LogPosition { index: 6, term: 1 },
            context(25, fixture.administrator, 26, 160, 5)?,
            &AuthoritativeCommand::RenewMetadataBackupRun(RenewMetadataBackupRun {
                backup_id: backup,
                claim: first,
                lease_expires_at: UnixMicros::new(260),
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));

    let second = claim(2, fixture.node, 24);
    fixture.repository.apply_committed(
        LogPosition { index: 6, term: 1 },
        context(27, fixture.administrator, 28, 160, 5)?,
        &AuthoritativeCommand::RenewMetadataBackupRun(RenewMetadataBackupRun {
            backup_id: backup,
            claim: second,
            lease_expires_at: UnixMicros::new(280),
        }),
    )?;
    let stored = fixture
        .repository
        .metadata_backup_run_claim(backup)?
        .ok_or("replacement claim missing")?;
    assert_eq!(stored.claim, second);
    assert_eq!(stored.lease_expires_at, UnixMicros::new(280));
    Ok(())
}

#[test]
fn incomplete_run_waits_for_claim_expiry_and_advances_from_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let backup = BackupId::from_bytes([30; 16])?;
    queue_run(&mut fixture, backup)?;
    let worker = fixture.node;
    apply_claim(&mut fixture, backup, claim(1, worker, 31), 150, 4)?;
    let evidence = fixture
        .repository
        .metadata_backup_protection_evidence(backup)?;
    let completion = AuthoritativeCommand::CompleteMetadataBackupRun(CompleteMetadataBackupRun {
        backup_id: backup,
        outcome: MetadataBackupRunCompletion::Incomplete {
            result_digest: evidence.digest,
        },
    });

    assert!(matches!(
        fixture.repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            context(33, fixture.administrator, 34, 149, 4)?,
            &completion,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    let substituted = AuthoritativeCommand::CompleteMetadataBackupRun(CompleteMetadataBackupRun {
        backup_id: backup,
        outcome: MetadataBackupRunCompletion::Incomplete {
            result_digest: [99; 32],
        },
    });
    assert!(matches!(
        fixture.repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            context(37, fixture.administrator, 38, 150, 4)?,
            &substituted,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    fixture
        .repository
        .apply_committed(
            LogPosition { index: 5, term: 1 },
            context(35, fixture.administrator, 36, 150, 4)?,
            &completion,
        )
        .map_err(|error| format!("incomplete completion failed: {error:?}"))?;

    let run = fixture
        .repository
        .metadata_backup_run(backup)
        .map_err(|error| format!("completed run query failed: {error:?}"))?
        .ok_or("completed run missing")?;
    assert_eq!(run.state, MetadataBackupRunState::Incomplete);
    assert_eq!(run.completed_at, Some(UnixMicros::new(150)));
    assert_eq!(run.result_digest, Some(evidence.digest));
    assert_eq!(fixture.repository.unfinished_metadata_backup_run()?, None);
    assert_eq!(
        fixture
            .repository
            .metadata_backup_run_claim(backup)
            .map_err(|error| format!("claim query failed: {error:?}"))?,
        None
    );
    assert_eq!(
        fixture
            .repository
            .metadata_backup_schedule()
            .map_err(|error| format!("schedule query failed: {error:?}"))?
            .ok_or("schedule missing")?
            .next_due_at,
        UnixMicros::new(150 + i64::try_from(DAY_MICROS)?)
    );
    Ok(())
}

fn queue_run(fixture: &mut Fixture, backup_id: BackupId) -> Result<(), Box<dyn std::error::Error>> {
    fixture.repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context(10, fixture.administrator, 11, 10, 1)?,
        &AuthoritativeCommand::ConfigureMetadataBackupSchedule(ConfigureMetadataBackupSchedule {
            partition_id: fixture.partition,
            expected_schedule_sequence: 0,
            interval: DurationMicros::new(DAY_MICROS),
            retained_generations: 4,
            minimum_verified_copies: 3,
            minimum_independent_copies: 2,
            enabled: true,
            next_due_at: UnixMicros::new(100),
        }),
    )?;
    fixture.repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(12, fixture.administrator, 13, 100, 2)?,
        &AuthoritativeCommand::QueueMetadataBackupRun(QueueMetadataBackupRun {
            backup_id,
            partition_id: fixture.partition,
            expected_schedule_sequence: 1,
            scheduled_for: UnixMicros::new(100),
        }),
    )?;
    Ok(())
}

fn apply_claim(
    fixture: &mut Fixture,
    backup_id: BackupId,
    claim: MetadataBackupRunClaim,
    lease_expires_at: i64,
    expected_revision: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    fixture.repository.apply_committed(
        LogPosition {
            index: expected_revision,
            term: 1,
        },
        context(14, fixture.administrator, 15, 110, expected_revision - 1)?,
        &AuthoritativeCommand::ClaimMetadataBackupRun(ClaimMetadataBackupRun {
            backup_id,
            claim,
            lease_expires_at: UnixMicros::new(lease_expires_at),
        }),
    )?;
    Ok(())
}

fn claim(generation: u64, node: NodeId, fence: u64) -> MetadataBackupRunClaim {
    MetadataBackupRunClaim {
        claim_generation: generation,
        worker_node_id: node,
        worker_incarnation: 1,
        fence,
    }
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let partition = PartitionId::from_bytes([1; 16])?;
    let database = PartitionDatabase::open(
        &directory.path().join("backup-run.sqlite3"),
        partition,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let mesh = MeshId::from_bytes([3; 16])?;
    let node = NodeId::from_bytes([4; 16])?;
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(5, administrator, 6, 1, 0)?,
        &protected_bootstrap(BootstrapMesh {
            mesh_id: mesh,
            mesh_name: RecordName::new("Backup run mesh")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([7; 16])?,
            host_id: HostId::from_bytes([8; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: node,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        })?,
    )?;
    mark_test_recovery_verified(&mut repository, mesh, administrator)?;
    Ok(Fixture {
        directory,
        repository,
        administrator,
        partition,
        node,
    })
}

fn context(
    operation: u8,
    actor: PrincipalId,
    audit: u8,
    occurred_at: i64,
    expected_revision: u64,
) -> Result<CommandContext, meshspan_domain::IdentifierError> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([audit; 16])?,
        occurred_at: UnixMicros::new(occurred_at),
        expected_revision: Some(Revision::new(expected_revision)),
    })
}
