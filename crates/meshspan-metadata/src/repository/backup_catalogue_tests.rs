// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, BackupDestinationId, BackupId, ComponentInstanceId, DurationMicros, HostId,
    MeshId, NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId, TargetId, UnixMicros,
};
use sha2::{Digest, Sha256};

#[path = "backup_defaults_tests.rs"]
mod defaults;
#[path = "backup_destination_tests.rs"]
mod destination_administration;
#[path = "backup_retention_tests.rs"]
mod retention;
use tempfile::{TempDir, tempdir};

use super::tests::{mark_test_recovery_verified, protected_bootstrap};
use super::{
    AuthoritativeRepository, BackupCopyState, BackupDestinationState, EntityKind, LogPosition,
    MetadataBackupState, PageLimit,
};
use crate::{
    AuthoritativeCommand, BackupDestinationBinding, BackupFailureRelationship, BootstrapMesh,
    ClaimMetadataBackupRun, CommandContext, CompleteMetadataBackupRun, ConfigureBackupDestination,
    ConfigureMetadataBackupSchedule, CreateComponent, InitialBackupCopy, MetadataBackupRunClaim,
    MetadataBackupRunCompletion, PartitionDatabase, QueueMetadataBackupRun, RecordMetadataBackup,
    RecordName, RegisterStorageTarget, StorageUsageLimit, VerifyBackupCopy,
};

struct Fixture {
    directory: TempDir,
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    partition: PartitionId,
    mesh: MeshId,
    node: NodeId,
    target: TargetId,
}

#[test]
fn active_destinations_page_without_returning_paused_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    for (identity, enabled, log_index, expected_revision) in [
        (30_u8, true, 3_u64, 2_u64),
        (31, false, 4, 3),
        (32, true, 5, 4),
    ] {
        fixture.repository.apply_committed(
            LogPosition {
                index: log_index,
                term: 1,
            },
            context(
                identity,
                fixture.administrator,
                identity + 10,
                i64::from(identity),
                expected_revision,
            )?,
            &AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
                destination_id: BackupDestinationId::from_bytes([identity; 16])?,
                expected_destination_revision: Revision::new(0),
                name: RecordName::new(&format!("Backup destination {identity}"))?,
                binding: BackupDestinationBinding::RegisteredTarget {
                    target_id: fixture.target,
                    target_generation: 1,
                },
                failure_relationship: BackupFailureRelationship::Unknown,
                failure_evidence_digest: [identity + 20; 32],
                enabled,
            }),
        )?;
    }

    let first = fixture
        .repository
        .active_backup_destinations(None, PageLimit::new(1)?)?;
    assert_eq!(first.items.len(), 1);
    assert_eq!(
        first.items[0].destination_id,
        BackupDestinationId::from_bytes([30; 16])?
    );
    let second = fixture
        .repository
        .active_backup_destinations(first.next, PageLimit::new(1)?)?;
    assert_eq!(second.items.len(), 1);
    assert_eq!(
        second.items[0].destination_id,
        BackupDestinationId::from_bytes([32; 16])?
    );
    assert_eq!(second.next, None);
    Ok(())
}

#[test]
fn exact_backup_copy_is_catalogued_and_verified_after_read_back()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let destination = BackupDestinationId::from_bytes([30; 16])?;
    let backup = BackupId::from_bytes([31; 16])?;
    let encrypted_digest = [35; 32];
    configure_destination(&mut fixture, destination)?;
    let claim = queue_and_claim(&mut fixture, backup)?;
    record_and_verify_backup(&mut fixture, destination, backup, encrypted_digest, claim)?;
    assert_protected_backup(&fixture, destination, backup, encrypted_digest)?;
    Ok(())
}

fn configure_destination(
    fixture: &mut Fixture,
    destination: BackupDestinationId,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = fixture.repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(32, fixture.administrator, 33, 30, 2)?,
        &AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
            destination_id: destination,
            expected_destination_revision: Revision::new(0),
            name: RecordName::new("Independent backup folder")?,
            binding: BackupDestinationBinding::RegisteredTarget {
                target_id: fixture.target,
                target_generation: 1,
            },
            failure_relationship: BackupFailureRelationship::Independent,
            failure_evidence_digest: [34; 32],
            enabled: true,
        }),
    )?;
    assert_eq!(receipt.entity.kind, EntityKind::BackupDestination);
    Ok(())
}

fn record_and_verify_backup(
    fixture: &mut Fixture,
    destination: BackupDestinationId,
    backup: BackupId,
    encrypted_digest: [u8; 32],
    claim: MetadataBackupRunClaim,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = fixture.repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        context(36, fixture.administrator, 37, 40, 6)?,
        &AuthoritativeCommand::RecordMetadataBackup(RecordMetadataBackup {
            backup_id: backup,
            partition_id: fixture.partition,
            mesh_id: fixture.mesh,
            last_log_index: 6,
            last_log_term: 1,
            state_revision: Revision::new(6),
            schema_version: crate::migration::PARTITION_SCHEMA_VERSION,
            source_byte_length: 4_096,
            source_digest: [38; 32],
            manifest_digest: [39; 32],
            encrypted_byte_length: 4_512,
            encrypted_digest,
            claim,
            initial_copy: InitialBackupCopy {
                destination_id: destination,
                provider_generation: 1,
                object_reference: "backup/31".to_owned(),
                byte_length: 4_512,
                copy_digest: encrypted_digest,
            },
        }),
    )?;
    assert_eq!(receipt.entity.kind, EntityKind::MetadataBackup);
    assert_eq!(
        fixture
            .repository
            .metadata_backup_run_claim(backup)?
            .ok_or("placement claim missing after first copy")?
            .claim,
        claim
    );
    assert_eq!(
        fixture
            .repository
            .backup_copy(backup, destination)?
            .ok_or("copy missing")?
            .state,
        BackupCopyState::Stored
    );

    replace_expired_placement_claim(fixture, backup)?;

    fixture.repository.apply_committed(
        LogPosition { index: 9, term: 1 },
        context(44, fixture.administrator, 45, 110, 8)?,
        &AuthoritativeCommand::VerifyBackupCopy(VerifyBackupCopy {
            backup_id: backup,
            destination_id: destination,
            provider_generation: 1,
            copy_digest: encrypted_digest,
        }),
    )?;
    assert_eq!(
        fixture
            .repository
            .metadata_backup(backup)?
            .ok_or("backup missing before completion")?
            .state,
        MetadataBackupState::Recorded
    );
    let evidence = fixture
        .repository
        .metadata_backup_protection_evidence(backup)?;
    assert_eq!(evidence.verified_copies, 1);
    assert_eq!(evidence.independent_copies, 1);
    fixture.repository.apply_committed(
        LogPosition { index: 10, term: 1 },
        context(46, fixture.administrator, 47, 120, 9)?,
        &AuthoritativeCommand::CompleteMetadataBackupRun(CompleteMetadataBackupRun {
            backup_id: backup,
            outcome: MetadataBackupRunCompletion::Protected {
                result_digest: evidence.digest,
            },
        }),
    )?;
    assert_eq!(fixture.repository.metadata_backup_run_claim(backup)?, None);
    Ok(())
}

fn replace_expired_placement_claim(
    fixture: &mut Fixture,
    backup: BackupId,
) -> Result<(), Box<dyn std::error::Error>> {
    let replacement_claim = MetadataBackupRunClaim {
        claim_generation: 2,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        fence: 43,
    };
    fixture.repository.apply_committed(
        LogPosition { index: 8, term: 1 },
        context(40, fixture.administrator, 41, 100, 7)?,
        &AuthoritativeCommand::ClaimMetadataBackupRun(ClaimMetadataBackupRun {
            backup_id: backup,
            claim: replacement_claim,
            lease_expires_at: UnixMicros::new(200),
        }),
    )?;
    assert_eq!(
        fixture
            .repository
            .metadata_backup_run_claim(backup)?
            .ok_or("replacement placement claim missing")?
            .claim,
        replacement_claim
    );
    Ok(())
}

fn assert_protected_backup(
    fixture: &Fixture,
    destination: BackupDestinationId,
    backup: BackupId,
    encrypted_digest: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let stored_destination = fixture
        .repository
        .backup_destination(destination)?
        .ok_or("destination missing")?;
    assert_eq!(stored_destination.state, BackupDestinationState::Active);
    assert_eq!(stored_destination.created_at, UnixMicros::new(30));
    let stored_backup = fixture
        .repository
        .metadata_backup(backup)?
        .ok_or("backup missing")?;
    assert_eq!(stored_backup.state, MetadataBackupState::Verified);
    assert_eq!(stored_backup.verified_at, Some(UnixMicros::new(120)));
    let stored_copy = fixture
        .repository
        .backup_copy(backup, destination)?
        .ok_or("copy missing")?;
    assert_eq!(stored_copy.state, BackupCopyState::Verified);
    assert_eq!(stored_copy.verified_at, Some(UnixMicros::new(110)));
    assert_eq!(stored_copy.copy_digest, encrypted_digest);
    Ok(())
}

fn queue_and_claim(
    fixture: &mut Fixture,
    backup_id: BackupId,
) -> Result<MetadataBackupRunClaim, Box<dyn std::error::Error>> {
    fixture.repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        context(50, fixture.administrator, 51, 31, 3)?,
        &AuthoritativeCommand::ConfigureMetadataBackupSchedule(ConfigureMetadataBackupSchedule {
            partition_id: fixture.partition,
            expected_schedule_sequence: 0,
            interval: DurationMicros::new(86_400_000_000),
            retained_generations: 3,
            minimum_verified_copies: 1,
            minimum_independent_copies: 1,
            enabled: true,
            next_due_at: UnixMicros::new(32),
        }),
    )?;
    fixture.repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(52, fixture.administrator, 53, 32, 4)?,
        &AuthoritativeCommand::QueueMetadataBackupRun(QueueMetadataBackupRun {
            backup_id,
            partition_id: fixture.partition,
            expected_schedule_sequence: 1,
            scheduled_for: UnixMicros::new(32),
        }),
    )?;
    let claim = MetadataBackupRunClaim {
        claim_generation: 1,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        fence: 54,
    };
    fixture.repository.apply_committed(
        LogPosition { index: 6, term: 1 },
        context(55, fixture.administrator, 56, 33, 5)?,
        &AuthoritativeCommand::ClaimMetadataBackupRun(ClaimMetadataBackupRun {
            backup_id,
            claim,
            lease_expires_at: UnixMicros::new(100),
        }),
    )?;
    Ok(claim)
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let partition = PartitionId::from_bytes([1; 16])?;
    let database = PartitionDatabase::open(
        &directory.path().join("backup-catalogue.sqlite3"),
        partition,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let mesh = MeshId::from_bytes([3; 16])?;
    let host = HostId::from_bytes([4; 16])?;
    let node = NodeId::from_bytes([5; 16])?;
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(6, administrator, 7, 10, 0)?,
        &protected_bootstrap(BootstrapMesh {
            mesh_id: mesh,
            mesh_name: RecordName::new("Backup catalogue mesh")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([8; 16])?,
            host_id: host,
            host_name: RecordName::new("Host")?,
            node_id: node,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        })?,
    )?;
    mark_test_recovery_verified(&mut repository, mesh, administrator)?;
    let target = TargetId::from_bytes([9; 16])?;
    let configuration = b"{\"usage_limit\":\"per-target\"}".to_vec();
    repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context(10, administrator, 11, 20, 1)?,
        &AuthoritativeCommand::RegisterStorageTarget(RegisterStorageTarget {
            target_id: target,
            node_id: node,
            host_id: host,
            provider: CreateComponent {
                instance_id: ComponentInstanceId::from_bytes([12; 16])?,
                component_kind: 1,
                name: RecordName::new("Folder storage provider")?,
                implementation_id: "meshspan-folder".to_owned(),
                contract_major: 1,
                contract_minor: 0,
                schema_version: 1,
                configuration_digest: Sha256::digest(&configuration).into(),
                canonical_configuration: configuration,
            },
            name: RecordName::new("Backup folder")?,
            generation: 1,
            marker_fingerprint: [13; 32],
            backing_device_fingerprint: Some([14; 32]),
            filesystem_fingerprint: Some([15; 32]),
            usage_limit: StorageUsageLimit::Bytes(1024 * 1024),
        }),
    )?;
    Ok(Fixture {
        directory,
        repository,
        administrator,
        partition,
        mesh,
        node,
        target,
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
