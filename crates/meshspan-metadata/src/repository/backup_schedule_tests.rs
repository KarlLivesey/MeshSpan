// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, BackupId, DurationMicros, HostId, MeshId, NodeId, OperationId, PartitionId,
    PrincipalId, Revision, RoleId, UnixMicros,
};
use tempfile::{TempDir, tempdir};

use super::tests::{mark_test_recovery_verified, protected_bootstrap};
use super::{AuthoritativeRepository, EntityKind, LogPosition, RepositoryError};
use crate::{
    AuthoritativeCommand, BootstrapMesh, CommandContext, ConfigureMetadataBackupSchedule,
    PartitionDatabase, QueueMetadataBackupRun, RecordName,
};

const DAY_MICROS: u64 = 86_400_000_000;

struct Fixture {
    _directory: TempDir,
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    partition: PartitionId,
}

#[test]
fn due_schedule_materialises_one_exact_crash_safe_run() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let configured = fixture.repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context(20, fixture.administrator, 21, 10, 1)?,
        &AuthoritativeCommand::ConfigureMetadataBackupSchedule(schedule(
            fixture.partition,
            0,
            UnixMicros::new(100),
        )),
    )?;
    assert_eq!(configured.entity.kind, EntityKind::MetadataBackupSchedule);
    assert_eq!(
        fixture
            .repository
            .due_metadata_backup_schedule(UnixMicros::new(99))?,
        None
    );
    let due = fixture
        .repository
        .due_metadata_backup_schedule(UnixMicros::new(100))?
        .ok_or("schedule should be due")?;
    assert_eq!(due.sequence, 1);
    assert_eq!(due.retained_generations, 4);
    assert_eq!(due.minimum_verified_copies, 3);
    assert_eq!(due.minimum_independent_copies, 2);

    let backup_id = BackupId::from_bytes([22; 16])?;
    let queued = fixture.repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(23, fixture.administrator, 24, 100, 2)?,
        &AuthoritativeCommand::QueueMetadataBackupRun(QueueMetadataBackupRun {
            backup_id,
            partition_id: fixture.partition,
            expected_schedule_sequence: due.sequence,
            scheduled_for: due.next_due_at,
        }),
    )?;
    assert_eq!(queued.entity.kind, EntityKind::MetadataBackupRun);
    let run = fixture
        .repository
        .metadata_backup_run(backup_id)?
        .ok_or("backup run missing")?;
    assert_eq!(run.schedule_sequence, 1);
    assert_eq!(run.run_sequence, 1);
    assert_eq!(run.scheduled_for, UnixMicros::new(100));

    let head = fixture
        .repository
        .metadata_backup_schedule()?
        .ok_or("schedule head missing")?;
    assert_eq!(head.next_due_at, UnixMicros::new(100));
    assert_eq!(head.run_sequence, 1);
    assert_eq!(
        fixture
            .repository
            .due_metadata_backup_schedule(UnixMicros::new(101))?,
        None
    );
    assert!(matches!(
        fixture.repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            context(25, fixture.administrator, 26, 101, 3)?,
            &AuthoritativeCommand::QueueMetadataBackupRun(QueueMetadataBackupRun {
                backup_id: BackupId::from_bytes([27; 16])?,
                partition_id: fixture.partition,
                expected_schedule_sequence: 1,
                scheduled_for: UnixMicros::new(100),
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

#[test]
fn schedule_rejects_stale_unsafe_and_cross_partition_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    fixture.repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context(30, fixture.administrator, 31, 10, 1)?,
        &AuthoritativeCommand::ConfigureMetadataBackupSchedule(schedule(
            fixture.partition,
            0,
            UnixMicros::new(100),
        )),
    )?;
    let stale = AuthoritativeCommand::ConfigureMetadataBackupSchedule(schedule(
        fixture.partition,
        0,
        UnixMicros::new(200),
    ));
    assert!(matches!(
        fixture.repository.apply_committed(
            LogPosition { index: 3, term: 1 },
            context(32, fixture.administrator, 33, 20, 2)?,
            &stale,
        ),
        Err(RepositoryError::StaleMetadataBackupSchedule)
    ));

    let other_partition = PartitionId::from_bytes([34; 16])?;
    let cross_partition = AuthoritativeCommand::ConfigureMetadataBackupSchedule(schedule(
        other_partition,
        1,
        UnixMicros::new(200),
    ));
    assert!(matches!(
        fixture.repository.apply_committed(
            LogPosition { index: 3, term: 1 },
            context(35, fixture.administrator, 36, 20, 2)?,
            &cross_partition,
        ),
        Err(RepositoryError::InvalidCommand)
    ));

    let mut unsafe_policy = schedule(fixture.partition, 1, UnixMicros::new(200));
    unsafe_policy.minimum_independent_copies = 4;
    assert!(matches!(
        fixture.repository.apply_committed(
            LogPosition { index: 3, term: 1 },
            context(37, fixture.administrator, 38, 20, 2)?,
            &AuthoritativeCommand::ConfigureMetadataBackupSchedule(unsafe_policy),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let partition = PartitionId::from_bytes([1; 16])?;
    let database = PartitionDatabase::open(
        &directory.path().join("backup-schedule.sqlite3"),
        partition,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let mesh = MeshId::from_bytes([3; 16])?;
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(4, administrator, 5, 1, 0)?,
        &protected_bootstrap(BootstrapMesh {
            mesh_id: mesh,
            mesh_name: RecordName::new("Backup schedule mesh")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([6; 16])?,
            host_id: HostId::from_bytes([7; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([8; 16])?,
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
    })
}

fn schedule(
    partition_id: PartitionId,
    expected_schedule_sequence: u64,
    next_due_at: UnixMicros,
) -> ConfigureMetadataBackupSchedule {
    ConfigureMetadataBackupSchedule {
        partition_id,
        expected_schedule_sequence,
        interval: DurationMicros::new(DAY_MICROS),
        retained_generations: 4,
        minimum_verified_copies: 3,
        minimum_independent_copies: 2,
        enabled: true,
        next_due_at,
    }
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
