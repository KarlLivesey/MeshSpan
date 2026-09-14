// SPDX-License-Identifier: GPL-2.0-only

//! One automatic archive binds the exact control snapshot to its surviving filesystem history.

use super::MetadataBackupCapturePaths;
use crate::backup_readiness_workspace::ReadinessWorkspace;
use meshspan_backup::{BackupFiles, BackupHistoryFiles, encrypt_backup_files};
use meshspan_domain::{BackupId, OperationId, RandomSource, UnixMicros};
use meshspan_filesystem::{DurableContentCatalog, VersionPublicationStore};
use meshspan_metadata::{
    AuthoritativeRepository, EncryptedPartitionBackupManifest, RepositoryError,
    restore_partition_backup,
};
use std::{fs, path::Path};

pub(super) fn capture(
    authority: &AuthoritativeRepository,
    paths: MetadataBackupCapturePaths<'_>,
    backup_id: BackupId,
    now: UnixMicros,
    random: &mut impl RandomSource,
) -> Result<EncryptedPartitionBackupManifest, RepositoryError> {
    let root = paths
        .metadata
        .plaintext_staging
        .parent()
        .ok_or(RepositoryError::BackupMismatch)?;
    let operation = OperationId::from_bytes(backup_id.as_bytes())
        .map_err(|_| RepositoryError::BackupMismatch)?;
    let workspace = ReadinessWorkspace::rebuild(root, operation)?;
    let captured = capture_members(authority, paths, backup_id, now, &workspace).and_then(
        |(partition, recipients)| {
            let encrypted = encrypt_backup_files(
                BackupFiles {
                    metadata: paths.metadata.plaintext_staging,
                    history: Some(BackupHistoryFiles {
                        namespace: &workspace.file("filesystem-branch.sqlite3"),
                        content: &workspace.file("filesystem-content.sqlite3"),
                    }),
                },
                paths.metadata.encrypted_destination,
                partition.source_manifest(),
                &recipients,
                random,
            )?;
            Ok(EncryptedPartitionBackupManifest {
                partition,
                encrypted,
            })
        },
    );
    // Capture is unpublished until both cleanup and the outer durable staging journal succeed.
    workspace.cleanup()?;
    match fs::remove_file(paths.metadata.plaintext_staging) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    captured
}

fn capture_members(
    authority: &AuthoritativeRepository,
    paths: MetadataBackupCapturePaths<'_>,
    backup_id: BackupId,
    now: UnixMicros,
    workspace: &ReadinessWorkspace,
) -> Result<
    (
        meshspan_metadata::PartitionBackupManifest,
        Vec<meshspan_secret_envelope::WrappingPublicKey>,
    ),
    RepositoryError,
> {
    let partition = authority.create_backup(backup_id, paths.metadata.plaintext_staging, now)?;
    // Query a separate restored copy so neither migration nor journal mode can change
    // the exact closed control bytes whose digest goes into the archive.
    let copied = AuthoritativeRepository::new(restore_partition_backup(
        paths.metadata.plaintext_staging,
        &workspace.file("restored.sqlite3"),
        partition,
        now,
    )?);
    let (mut history, catalog) =
        capture_history(paths.filesystem_directory, workspace.directory(), now)?;
    crate::recovery_preparation::verify_backup_history(&copied, &mut history, &catalog)
        .map_err(|_| RepositoryError::BackupMismatch)?;
    let recipients = copied.volume_key_recipients()?;
    drop(catalog);
    drop(history);
    Ok((partition, recipients))
}

fn capture_history(
    source: &Path,
    work: &Path,
    now: UnixMicros,
) -> Result<(VersionPublicationStore, DurableContentCatalog), RepositoryError> {
    let absent = ["filesystem-branch.sqlite3", "filesystem-content.sqlite3"]
        .into_iter()
        .all(|name| {
            matches!(fs::symlink_metadata(source.join(name)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        });
    if absent {
        // A never-used filesystem may not have journals yet. This empty private pair is
        // accepted only if the subsequent authoritative-root closure check also succeeds.
        Ok((
            VersionPublicationStore::open(work, now)
                .map_err(|_| RepositoryError::BackupMismatch)?,
            DurableContentCatalog::open(work, now).map_err(|_| RepositoryError::BackupMismatch)?,
        ))
    } else {
        meshspan_filesystem::snapshot_recovery_journals(source, work, now)
            .map_err(|_| RepositoryError::BackupMismatch)
    }
}
