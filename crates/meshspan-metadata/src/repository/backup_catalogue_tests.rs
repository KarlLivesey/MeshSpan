// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, BackupDestinationId, BackupId, ComponentInstanceId, HostId, MeshId, NodeId,
    OperationId, PartitionId, PrincipalId, Revision, RoleId, TargetId, UnixMicros,
};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

use super::tests::{mark_test_recovery_verified, protected_bootstrap};
use super::{
    AuthoritativeRepository, BackupCopyState, BackupDestinationState, EntityKind, LogPosition,
    MetadataBackupState,
};
use crate::{
    AuthoritativeCommand, BackupDestinationBinding, BackupFailureRelationship, BootstrapMesh,
    CommandContext, ConfigureBackupDestination, CreateComponent, InitialBackupCopy,
    PartitionDatabase, RecordMetadataBackup, RecordName, RegisterStorageTarget, StorageUsageLimit,
    VerifyBackupCopy,
};

struct Fixture {
    _directory: TempDir,
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    partition: PartitionId,
    mesh: MeshId,
    target: TargetId,
}

#[test]
fn exact_backup_copy_is_catalogued_and_verified_after_read_back()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let destination = BackupDestinationId::from_bytes([30; 16])?;
    let backup = BackupId::from_bytes([31; 16])?;
    let encrypted_digest = [35; 32];

    let destination_receipt = fixture.repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(32, fixture.administrator, 33, 30, 2)?,
        &AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
            destination_id: destination,
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
    assert_eq!(
        destination_receipt.entity.kind,
        EntityKind::BackupDestination
    );

    let backup_receipt = fixture.repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        context(36, fixture.administrator, 37, 40, 3)?,
        &AuthoritativeCommand::RecordMetadataBackup(RecordMetadataBackup {
            backup_id: backup,
            partition_id: fixture.partition,
            mesh_id: fixture.mesh,
            last_log_index: 3,
            last_log_term: 1,
            state_revision: Revision::new(3),
            schema_version: crate::migration::PARTITION_SCHEMA_VERSION,
            source_byte_length: 4_096,
            source_digest: [38; 32],
            manifest_digest: [39; 32],
            encrypted_byte_length: 4_512,
            encrypted_digest,
            initial_copy: InitialBackupCopy {
                destination_id: destination,
                provider_generation: 1,
                object_reference: "backup/31".to_owned(),
                byte_length: 4_512,
                copy_digest: encrypted_digest,
            },
        }),
    )?;
    assert_eq!(backup_receipt.entity.kind, EntityKind::MetadataBackup);
    assert_eq!(
        fixture
            .repository
            .backup_copy(backup, destination)?
            .ok_or("copy missing")?
            .state,
        BackupCopyState::Stored
    );

    fixture.repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(44, fixture.administrator, 45, 60, 4)?,
        &AuthoritativeCommand::VerifyBackupCopy(VerifyBackupCopy {
            backup_id: backup,
            destination_id: destination,
            provider_generation: 1,
            copy_digest: encrypted_digest,
        }),
    )?;

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
    assert_eq!(stored_backup.verified_at, Some(UnixMicros::new(60)));
    let stored_copy = fixture
        .repository
        .backup_copy(backup, destination)?
        .ok_or("copy missing")?;
    assert_eq!(stored_copy.state, BackupCopyState::Verified);
    assert_eq!(stored_copy.verified_at, Some(UnixMicros::new(60)));
    assert_eq!(stored_copy.copy_digest, encrypted_digest);
    Ok(())
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
        _directory: directory,
        repository,
        administrator,
        partition,
        mesh,
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
