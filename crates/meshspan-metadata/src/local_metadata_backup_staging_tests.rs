// SPDX-License-Identifier: GPL-2.0-only

use meshspan_backup::{BackupFileEvidence, BackupSourceManifest};
use meshspan_domain::{BackupId, MeshId, NodeId, PartitionId, UnixMicros};
use tempfile::tempdir;

use crate::{
    LocalDatabase, LocalMetadataBackupStaging, LocalMetadataBackupStagingDisposition,
    LocalMetadataBackupStagingError,
};

#[test]
fn staging_evidence_reopens_replays_and_removes_exactly() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let database_path = directory.path().join("local.sqlite3");
    let node_id = NodeId::from_bytes([1; 16])?;
    let expected = staging(2, "backup-02.msbackup")?;
    {
        let mut database = LocalDatabase::open(&database_path, node_id, UnixMicros::new(1))?;
        assert_eq!(
            database.record_metadata_backup_staging(&expected)?,
            LocalMetadataBackupStagingDisposition::Applied
        );
        assert_eq!(
            database.record_metadata_backup_staging(&expected)?,
            LocalMetadataBackupStagingDisposition::Replayed
        );
    }

    let mut reopened = LocalDatabase::open_existing(&database_path, UnixMicros::new(3))?;
    assert_eq!(
        reopened.metadata_backup_staging(expected.evidence.source.backup_id)?,
        Some(expected.clone())
    );
    assert_eq!(
        reopened.remove_metadata_backup_staging(&expected)?,
        LocalMetadataBackupStagingDisposition::Applied
    );
    assert_eq!(
        reopened.remove_metadata_backup_staging(&expected)?,
        LocalMetadataBackupStagingDisposition::Replayed
    );
    assert_eq!(
        reopened.metadata_backup_staging(expected.evidence.source.backup_id)?,
        None
    );
    Ok(())
}

#[test]
fn staging_rejects_changed_replays_and_unsafe_names() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        NodeId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let expected = staging(2, "backup-02.msbackup")?;
    database.record_metadata_backup_staging(&expected)?;
    let mut changed = expected.clone();
    changed.evidence.digest = [9; 32];
    assert!(matches!(
        database.record_metadata_backup_staging(&changed),
        Err(LocalMetadataBackupStagingError::Conflict)
    ));
    let unsafe_name = LocalMetadataBackupStaging {
        relative_file_name: "../escape".to_owned(),
        ..staging(3, "unused")?
    };
    assert!(matches!(
        database.record_metadata_backup_staging(&unsafe_name),
        Err(LocalMetadataBackupStagingError::Invalid)
    ));
    Ok(())
}

#[test]
fn staging_pages_seek_past_retained_or_deleted_entries() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let mut database =
        LocalDatabase::open(&file_path, NodeId::from_bytes([1; 16])?, UnixMicros::new(1))?;
    let first = staging(2, "backup-02.msbackup")?;
    let second = staging(3, "backup-03.msbackup")?;
    let third = staging(4, "backup-04.msbackup")?;
    for entry in [&third, &first, &second] {
        database.record_metadata_backup_staging(entry)?;
    }
    let page = database.metadata_backup_staging_page(None, 2)?;
    assert_eq!(page.items, vec![first.clone(), second.clone()]);
    assert_eq!(page.next, Some(second.evidence.source.backup_id));
    database.remove_metadata_backup_staging(&second)?;
    let tail = database.metadata_backup_staging_page(page.next, 2)?;
    assert_eq!(tail.items, vec![third.clone()]);
    assert!(tail.next.is_none());
    drop(database);
    let reopened = LocalDatabase::open_existing(&file_path, UnixMicros::new(3))?;
    assert_eq!(
        reopened.metadata_backup_staging_page(None, 2)?.items,
        vec![first, third]
    );
    for limit in [0, 129, usize::MAX] {
        assert!(matches!(
            reopened.metadata_backup_staging_page(None, limit),
            Err(LocalMetadataBackupStagingError::Invalid)
        ));
    }
    Ok(())
}

fn staging(
    identity: u8,
    relative_file_name: &str,
) -> Result<LocalMetadataBackupStaging, meshspan_domain::IdentifierError> {
    Ok(LocalMetadataBackupStaging {
        evidence: BackupFileEvidence {
            source: BackupSourceManifest {
                backup_id: BackupId::from_bytes([identity; 16])?,
                partition_id: PartitionId::from_bytes([4; 16])?,
                mesh_id: MeshId::from_bytes([5; 16])?,
                last_log_index: 10,
                last_log_term: 2,
                state_revision: 11,
                schema_version: 13,
                byte_length: 1_024,
                digest: [6; 32],
                created_at: UnixMicros::new(20),
            },
            byte_length: 2_048,
            digest: [7; 32],
        },
        relative_file_name: relative_file_name.to_owned(),
        prepared_at: UnixMicros::new(21),
        revision: 1,
    })
}
