// SPDX-License-Identifier: GPL-2.0-only

//! Revision windows retain data throughout capture, then pin only the selected backup state.

use super::{RepositoryError, apply::to_i64};
use meshspan_domain::{BackupId, NamespaceCommitId, Revision, VolumeId};
use rusqlite::{OptionalExtension, Transaction, params};

pub(super) fn open(
    transaction: &Transaction<'_>,
    backup: BackupId,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let changed = transaction.execute(
        "INSERT INTO backup_capture_windows(backup_id, opened_revision, sealed_revision)
         VALUES (?1, ?2, NULL) ON CONFLICT(backup_id) DO NOTHING",
        params![backup.as_bytes().as_slice(), to_i64(revision.get())?],
    )?;
    if changed == 0 {
        return Ok(());
    }
    transaction.execute(
        "INSERT INTO backup_namespace_roots(
            backup_id, volume_id, source_kind, source_id, namespace_commit_id, from_revision, until_revision
         ) SELECT ?1, volume_id, 1, volume_id, namespace_commit_id, ?2, NULL
           FROM volume_head_transitions h WHERE h.head_sequence = (
               SELECT max(current.head_sequence) FROM volume_head_transitions current WHERE current.volume_id = h.volume_id
           ) UNION ALL
           SELECT ?1, volume_id, 2, snapshot_id, namespace_commit_id, ?2, NULL
           FROM volume_snapshots WHERE state IN (1, 2)",
        params![backup.as_bytes().as_slice(), to_i64(revision.get())?],
    )?;
    Ok(())
}

pub(super) fn seal(
    transaction: &Transaction<'_>,
    backup: BackupId,
    source_revision: Revision,
) -> Result<(), RepositoryError> {
    let opening: Option<(i64, Option<i64>)> = transaction.query_row(
        "SELECT opened_revision, sealed_revision FROM backup_capture_windows WHERE backup_id = ?1",
        [backup.as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let source = to_i64(source_revision.get())?;
    if !matches!(opening, Some((opened, None)) if opened <= source) {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "DELETE FROM backup_namespace_roots WHERE backup_id = ?1
         AND (from_revision > ?2 OR until_revision <= ?2)",
        params![backup.as_bytes().as_slice(), source],
    )?;
    transaction.execute(
        "UPDATE backup_capture_windows SET sealed_revision = ?2 WHERE backup_id = ?1",
        params![backup.as_bytes().as_slice(), source],
    )?;
    Ok(())
}

pub(super) fn release(
    transaction: &Transaction<'_>,
    backup: BackupId,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "DELETE FROM backup_capture_windows WHERE backup_id = ?1",
        [backup.as_bytes().as_slice()],
    )?;
    Ok(())
}

pub(super) fn head_changed(
    transaction: &Transaction<'_>,
    command: &crate::CommitConvergedVolumeHead,
    revision: Revision,
) -> Result<(), RepositoryError> {
    changed(
        transaction,
        RootChange {
            volume: command.volume_id,
            kind: 1,
            id: command.volume_id.as_bytes(),
            next: Some(command.namespace_commit_id),
            revision,
        },
    )
}

pub(super) fn snapshot_created(
    transaction: &Transaction<'_>,
    command: &crate::CreateVolumeSnapshot,
    revision: Revision,
) -> Result<(), RepositoryError> {
    changed(
        transaction,
        RootChange {
            volume: command.volume_id,
            kind: 2,
            id: command.snapshot_id.as_bytes(),
            next: Some(command.namespace_commit_id),
            revision,
        },
    )
}

pub(super) fn snapshot_removed(
    transaction: &Transaction<'_>,
    snapshot: meshspan_domain::SnapshotId,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let bytes: Vec<u8> = transaction.query_row(
        "SELECT volume_id FROM volume_snapshots WHERE snapshot_id = ?1",
        [snapshot.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let volume = VolumeId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    changed(
        transaction,
        RootChange {
            volume,
            kind: 2,
            id: snapshot.as_bytes(),
            next: None,
            revision,
        },
    )
}

#[derive(Clone, Copy)]
struct RootChange {
    volume: VolumeId,
    kind: u8,
    id: [u8; 16],
    next: Option<NamespaceCommitId>,
    revision: Revision,
}

fn changed(transaction: &Transaction<'_>, change: RootChange) -> Result<(), RepositoryError> {
    let revision = to_i64(change.revision.get())?;
    transaction.execute(
        "UPDATE backup_namespace_roots SET until_revision = ?4
         WHERE volume_id = ?1 AND source_kind = ?2 AND source_id = ?3 AND until_revision IS NULL
           AND backup_id IN (SELECT backup_id FROM backup_capture_windows WHERE sealed_revision IS NULL)",
        params![change.volume.as_bytes().as_slice(), change.kind, change.id.as_slice(), revision],
    )?;
    if let Some(next) = change.next {
        transaction.execute(
            "INSERT INTO backup_namespace_roots(
                backup_id, volume_id, source_kind, source_id, namespace_commit_id, from_revision, until_revision
             ) SELECT backup_id, ?1, ?2, ?3, ?4, ?5, NULL
               FROM backup_capture_windows WHERE sealed_revision IS NULL",
            params![change.volume.as_bytes().as_slice(), change.kind, change.id.as_slice(), next.as_bytes().as_slice(), revision],
        )?;
    }
    Ok(())
}
