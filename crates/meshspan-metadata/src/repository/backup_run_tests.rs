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

struct Fixture {
    _directory: TempDir,
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    partition: PartitionId,
    node: NodeId,
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
        _directory: directory,
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
