// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{CommitConvergedVolumeHead, ConvergedHeadEvidence, CreateVolume};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{NamespaceCommitId, ObjectId, ObjectRevisionId, OwnerSetId, VolumeId};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn backup_root_migration_retains_surviving_legacy_history() -> TestResult {
    let (mut fixture, destination) = retention::history(0)?;
    let volume = create_volume(&mut fixture)?;
    advance(&mut fixture, volume, None, 200)?;
    retention::add_generation(&mut fixture, destination, 0, true)?;
    advance(&mut fixture, volume, Some(200), 201)?;
    // Remove every post-109 object, not merely its version label. This leaves
    // the actual prior schema and records without capture-window evidence.
    crate::migration::component_origins::restore_legacy_schema(
        fixture.repository.database.connection(),
    )?;
    fixture.repository.database.connection().execute_batch(
        "DROP TABLE partition_recovery_consensus_activation;
         ALTER TABLE consensus_active_quorum_plan DROP COLUMN activation_kind;
         DROP TABLE partition_recovery_consensus_permission;
         DROP TABLE partition_recovery_node_key_projection;
         DROP TABLE partition_recovery_state_installations;
         DROP TABLE partition_recovery_shards; DROP TABLE partition_recovery_restorations;
         DROP TABLE partition_recovery_targets;
         DROP TABLE backup_namespace_roots; DROP TABLE backup_capture_windows;
         DROP INDEX volume_head_transitions_root_identity;
         DELETE FROM schema_migrations WHERE version >= 110;
         UPDATE applied_state SET schema_version = 109;
         UPDATE metadata_backups SET schema_version = 109;
         PRAGMA user_version = 109;",
    )?;
    drop(fixture.repository);
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("backup-catalogue.sqlite3"),
        UnixMicros::new(100),
    )?);
    fixture.repository.database.check_integrity()?;
    // Exact old roots cannot be inferred; surviving history is conservatively
    // pinned until the old generation retires, including its later head here.
    assert_eq!(pinned(&fixture, volume)?, [200, 201]);
    Ok(())
}

#[test]
fn backup_keeps_snapshot_removed_after_capture() -> TestResult {
    use crate::{
        CreateVolumeSnapshot, RemoveVolumeSnapshotRoot, RequestVolumeSnapshotExpiry,
        SnapshotExpiryReason,
    };
    use meshspan_domain::SnapshotId;
    let mut fixture = fixture()?;
    let destination = BackupDestinationId::from_bytes([30; 16])?;
    configure_destination(&mut fixture, destination)?;
    let backup = BackupId::from_bytes([31; 16])?;
    let claim = queue_and_claim(&mut fixture, backup)?;
    let volume = create_volume(&mut fixture)?;
    advance(&mut fixture, volume, None, 200)?;
    let snapshot = SnapshotId::from_bytes([210; 16])?;
    apply(
        &mut fixture,
        &AuthoritativeCommand::CreateVolumeSnapshot(CreateVolumeSnapshot {
            snapshot_id: snapshot,
            volume_id: volume,
            namespace_commit_id: NamespaceCommitId::from_bytes([200; 16])?,
            name: RecordName::new("During capture")?,
            expires_at: None,
            protected_from_expiry: false,
        }),
    )?;
    let snapshot_revision = fixture.repository.current_revision()?;
    advance(&mut fixture, volume, Some(200), 201)?;
    let mut source = capture::captured(&fixture, backup, destination, claim);
    source.state_revision = fixture.repository.current_revision()?;
    source.last_log_index = source.state_revision.get();
    fixture.repository.database.connection().execute(
        "INSERT INTO consensus_log(log_index, term, entry_kind, entry_version, payload, payload_digest)
         VALUES (?1, 1, 1, 1, x'01', zeroblob(32))", [i64::try_from(source.last_log_index)?])?;
    apply(
        &mut fixture,
        &AuthoritativeCommand::RequestVolumeSnapshotExpiry(RequestVolumeSnapshotExpiry {
            snapshot_id: snapshot,
            expected_snapshot_revision: snapshot_revision,
            reason: SnapshotExpiryReason::Manual,
        }),
    )?;
    let expiry_revision = fixture.repository.current_revision()?;
    let expiry: Vec<u8> = fixture.repository.database.connection().query_row(
        "SELECT operation_id FROM snapshot_expiry_requests WHERE snapshot_id = ?1",
        [snapshot.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    apply(
        &mut fixture,
        &AuthoritativeCommand::RemoveVolumeSnapshotRoot(RemoveVolumeSnapshotRoot {
            snapshot_id: snapshot,
            expected_snapshot_revision: expiry_revision,
            expiry_operation_id: OperationId::from_bytes(
                expiry.try_into().map_err(|_| "expiry ID")?,
            )?,
            namespace_commit_id: NamespaceCommitId::from_bytes([200; 16])?,
            root_object_revision_id: ObjectRevisionId::from_bytes([200; 16])?,
        }),
    )?;
    apply(
        &mut fixture,
        &AuthoritativeCommand::RecordMetadataBackup(source),
    )?;
    assert_eq!(pinned(&fixture, volume)?, [200, 201]);
    let kinds: Vec<i64> = fixture
        .repository
        .database
        .connection()
        .prepare("SELECT source_kind FROM backup_namespace_roots WHERE namespace_commit_id = ?1")?
        .query_map([[200u8; 16].as_slice()], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    assert_eq!(
        kinds,
        [2],
        "only the archived snapshot keeps the superseded head"
    );
    Ok(())
}

#[test]
fn backup_admission_seals_exact_source_roots_and_survives_reopen() -> TestResult {
    let mut fixture = fixture()?;
    let destination = BackupDestinationId::from_bytes([30; 16])?;
    let backup = BackupId::from_bytes([31; 16])?;
    configure_destination(&mut fixture, destination)?;
    let claim = queue_and_claim(&mut fixture, backup)?;
    let volume = create_volume(&mut fixture)?;
    advance(&mut fixture, volume, None, 200)?;
    let mut source = capture::captured(&fixture, backup, destination, claim);
    source.state_revision = fixture.repository.current_revision()?;
    source.last_log_index = source.state_revision.get();
    // Direct command fixtures retain the exact historical log coordinate explicitly.
    fixture.repository.database.connection().execute(
        "INSERT INTO consensus_log(log_index, term, entry_kind, entry_version, payload, payload_digest)
         VALUES (?1, 1, 1, 1, x'01', zeroblob(32))", [i64::try_from(source.last_log_index)?])?;
    advance(&mut fixture, volume, Some(200), 201)?;
    advance(&mut fixture, volume, Some(201), 202)?;
    assert_eq!(pinned(&fixture, volume)?, [200, 201, 202]);
    let command = AuthoritativeCommand::RecordMetadataBackup(source);
    assert_capture_rollback(&mut fixture, &command)?;
    assert_eq!(pinned(&fixture, volume)?, [200, 201, 202]);
    apply(&mut fixture, &command)?;
    assert_eq!(pinned(&fixture, volume)?, [200]);
    advance(&mut fixture, volume, Some(202), 203)?;
    assert_eq!(pinned(&fixture, volume)?, [200]);
    drop(fixture.repository);
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &fixture.directory.path().join("backup-catalogue.sqlite3"),
        fixture.partition,
        UnixMicros::new(70),
    )?);
    assert_eq!(pinned(&fixture, volume)?, [200]);
    Ok(())
}

fn assert_capture_rollback(fixture: &mut Fixture, command: &AuthoritativeCommand) -> TestResult {
    use super::super::apply::{ApplyFaultPoint, apply_committed_with_fault};
    let revision = fixture.repository.current_revision()?.get();
    let result = apply_committed_with_fault(
        &mut fixture.repository.database,
        LogPosition {
            index: revision + 1,
            term: 1,
        },
        context(232, fixture.administrator, 233, 60, revision)?,
        command,
        ApplyFaultPoint::BeforeCommit,
    );
    assert!(matches!(result, Err(crate::RepositoryError::InjectedFault)));
    assert_eq!(fixture.repository.current_revision()?.get(), revision);
    Ok(())
}

#[test]
fn abandoning_unrecorded_backup_releases_capture_roots() -> TestResult {
    let mut fixture = fixture()?;
    configure_destination(&mut fixture, BackupDestinationId::from_bytes([30; 16])?)?;
    let backup = BackupId::from_bytes([31; 16])?;
    let claim = queue_and_claim(&mut fixture, backup)?;
    let volume = create_volume(&mut fixture)?;
    advance(&mut fixture, volume, None, 200)?;
    advance(&mut fixture, volume, Some(200), 201)?;
    assert_eq!(pinned(&fixture, volume)?, [200, 201]);
    let revision = fixture.repository.current_revision()?.get();
    fixture.repository.apply_committed(
        LogPosition {
            index: revision + 1,
            term: 1,
        },
        context(230, fixture.administrator, 231, 101, revision)?,
        &AuthoritativeCommand::AbandonUnrecordedMetadataBackupRun(
            crate::AbandonUnrecordedMetadataBackupRun {
                backup_id: backup,
                expected_claim: claim,
            },
        ),
    )?;
    assert!(pinned(&fixture, volume)?.is_empty());
    Ok(())
}

#[test]
fn backup_retirement_releases_only_its_own_roots_without_recursive_inheritance() -> TestResult {
    let (mut fixture, destination) = retention::history(0)?;
    let volume = create_volume(&mut fixture)?;
    advance(&mut fixture, volume, None, 200)?;
    retention::add_generation(&mut fixture, destination, 0, true)?;
    retention::add_generation(&mut fixture, destination, 1, true)?;
    advance(&mut fixture, volume, Some(200), 201)?;
    for generation in 2..4 {
        retention::add_generation(&mut fixture, destination, generation, true)?;
    }
    assert_eq!(pinned(&fixture, volume)?, [200, 201]);
    retire_candidate(&mut fixture)?;
    assert_eq!(pinned(&fixture, volume)?, [200, 201]);
    retention::add_generation(&mut fixture, destination, 4, true)?;
    retire_candidate(&mut fixture)?;
    assert_eq!(pinned(&fixture, volume)?, [201]);
    Ok(())
}

fn retire_candidate(fixture: &mut Fixture) -> TestResult {
    let candidate = fixture
        .repository
        .metadata_backup_retirement_candidate()?
        .ok_or("missing retirement candidate")?;
    apply(
        fixture,
        &AuthoritativeCommand::RetireMetadataBackup(candidate),
    )
}

fn pinned(fixture: &Fixture, volume: VolumeId) -> TestResult<Vec<u8>> {
    let mut commits = Vec::new();
    let mut after = None;
    loop {
        let page = fixture.repository.retained_namespace_roots(
            volume,
            fixture.repository.current_revision()?,
            after,
            PageLimit::new(1)?,
        )?;
        for root in page.roots {
            if let super::super::RetainedNamespaceRootSource::Backup(commit) = root.source {
                commits.push(commit.as_bytes()[0]);
            }
        }
        match page.next {
            Some(next) => after = Some(next),
            None => return Ok(commits),
        }
    }
}

#[test]
fn backup_capture_retains_heads_changed_before_catalogue_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let destination = BackupDestinationId::from_bytes([30; 16])?;
    configure_destination(&mut fixture, destination)?;
    queue_and_claim(&mut fixture, BackupId::from_bytes([31; 16])?)?;
    let volume = create_volume(&mut fixture)?;
    advance(&mut fixture, volume, None, 200)?;
    advance(&mut fixture, volume, Some(200), 201)?;
    let roots = fixture.repository.retained_namespace_roots(
        volume,
        fixture.repository.current_revision()?,
        None,
        PageLimit::new(10)?,
    )?;
    assert!(
        roots
            .roots
            .iter()
            .any(|root| root.namespace_commit_id.as_bytes() == [200; 16]),
        "the file root being copied must remain retained before backup admission"
    );
    assert!(
        roots
            .roots
            .iter()
            .any(|root| root.namespace_commit_id.as_bytes() == [201; 16])
    );
    Ok(())
}

fn create_volume(fixture: &mut Fixture) -> Result<VolumeId, Box<dyn std::error::Error>> {
    let volume = VolumeId::from_bytes([180; 16])?;
    apply(
        fixture,
        &AuthoritativeCommand::CreateVolume(CreateVolume {
            volume_id: volume,
            name: RecordName::new("Backup-pinned files")?,
            root_object_id: ObjectId::from_bytes([181; 16])?,
            owner_set_id: OwnerSetId::from_bytes([182; 16])?,
            owners: BoundedItems::new(vec![fixture.administrator], 1024)?,
            key_generation: super::super::tests::initial_test_volume_key(volume)?,
        }),
    )?;
    Ok(volume)
}

fn advance(
    fixture: &mut Fixture,
    volume: VolumeId,
    previous: Option<u8>,
    identity: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let publication = AuthoritativeCommand::CommitConvergedVolumeHead(CommitConvergedVolumeHead {
        volume_id: volume,
        expected_namespace_commit_id: previous
            .map(|byte| NamespaceCommitId::from_bytes([byte; 16]))
            .transpose()?,
        namespace_commit_id: NamespaceCommitId::from_bytes([identity; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([identity; 16])?,
        evidence: ConvergedHeadEvidence::Publication {
            operation_id: OperationId::from_bytes([identity; 16])?,
            request_digest: [identity; 32],
            result_digest: [identity; 32],
        },
    });
    apply(fixture, &publication)
}

fn apply(
    fixture: &mut Fixture,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let revision = fixture.repository.current_revision()?.get();
    let mut identity = [0xe1; 16];
    identity[..8].copy_from_slice(&revision.to_be_bytes());
    let command_context = CommandContext {
        operation_id: OperationId::from_bytes(identity)?,
        actor_principal_id: fixture.administrator,
        audit_event_id: AuditEventId::from_bytes(identity)?,
        occurred_at: UnixMicros::new(40 + i64::try_from(revision)?),
        expected_revision: Some(Revision::new(revision)),
    };
    fixture.repository.apply_committed(
        LogPosition {
            index: revision + 1,
            term: 1,
        },
        command_context,
        command,
    )?;
    Ok(())
}
