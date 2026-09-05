// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn captured_backup_survives_later_commits_without_rewriting_its_capture_time()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let destination = BackupDestinationId::from_bytes([30; 16])?;
    let backup = BackupId::from_bytes([31; 16])?;
    configure_destination(&mut fixture, destination)?;
    let claim = queue_and_claim(&mut fixture, backup)?;
    // Direct repository fixtures bypass Raft append. Retain the source log position
    // explicitly here; the real-process test exercises the actual committed log.
    fixture.repository.database.connection().execute("INSERT INTO consensus_log(log_index, term, entry_kind, entry_version, payload, payload_digest) VALUES (6, 1, 1, 1, x'01', zeroblob(32))", [])?;
    let source = captured(&fixture, backup, destination, claim);
    fixture.repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        context(90, fixture.administrator, 91, 45, 6)?,
        &AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
            destination_id: destination,
            expected_destination_revision: Revision::new(3),
            name: RecordName::new("Renamed while backup was uploading")?,
            binding: BackupDestinationBinding::RegisteredTarget {
                target_id: fixture.target,
                target_generation: 1,
            },
            failure_relationship: BackupFailureRelationship::Unknown,
            failure_evidence_digest: [34; 32],
            enabled: true,
        }),
    )?;
    for variant in 0..4 {
        let mut changed = source.clone();
        match variant {
            0 => changed.last_log_index = 8,
            1 => changed.last_log_term = 2,
            2 => changed.state_revision = Revision::new(5),
            _ => changed.source_created_at = UnixMicros::new(51),
        }
        assert!(matches!(
            fixture.repository.apply_committed(
                LogPosition { index: 8, term: 1 },
                context(92, fixture.administrator, 93, 50, 7)?,
                &AuthoritativeCommand::RecordMetadataBackup(changed)
            ),
            Err(super::super::RepositoryError::InvalidCommand)
        ));
        assert!(fixture.repository.metadata_backup(backup)?.is_none());
        assert_eq!(fixture.repository.current_revision()?, Revision::new(7));
    }
    fixture.repository.apply_committed(
        LogPosition { index: 8, term: 1 },
        context(94, fixture.administrator, 95, 50, 7)?,
        &AuthoritativeCommand::RecordMetadataBackup(source),
    )?;
    let stored = fixture
        .repository
        .metadata_backup(backup)?
        .ok_or("backup missing")?;
    assert_eq!(stored.last_log_index, 6);
    assert_eq!(stored.last_log_term, 1);
    assert_eq!(stored.state_revision, Revision::new(6));
    assert_eq!(stored.created_at, UnixMicros::new(40));
    assert_eq!(stored.revision, Revision::new(8));
    Ok(())
}

fn captured(
    fixture: &Fixture,
    backup: BackupId,
    destination: BackupDestinationId,
    claim: MetadataBackupRunClaim,
) -> RecordMetadataBackup {
    RecordMetadataBackup {
        source_created_at: UnixMicros::new(40),
        backup_id: backup,
        partition_id: fixture.partition,
        mesh_id: fixture.mesh,
        last_log_index: 6,
        last_log_term: 1,
        state_revision: Revision::new(6),
        schema_version: crate::migration::PARTITION_SCHEMA_VERSION,
        source_byte_length: 4096,
        source_digest: [38; 32],
        manifest_digest: [39; 32],
        encrypted_byte_length: 4512,
        encrypted_digest: [35; 32],
        claim,
        initial_copy: InitialBackupCopy {
            destination_id: destination,
            provider_generation: 1,
            object_reference: "backup/31".to_owned(),
            byte_length: 4512,
            copy_digest: [35; 32],
        },
    }
}
