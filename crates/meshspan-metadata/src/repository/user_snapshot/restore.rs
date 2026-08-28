// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative whole-volume snapshot restore compare-and-swap.

use meshspan_contracts::namespace_snapshot_restore_result_digest;
use meshspan_domain::Revision;
use rusqlite::{OptionalExtension, Transaction, params};

use super::super::{EntityReference, RepositoryError, apply::to_i64, volume_head};
use crate::{
    CommandContext, CommitConvergedVolumeHead, ConvergedHeadEvidence, RestoreVolumeSnapshot,
};

type StoredSnapshotAuthority = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64);

pub(super) fn apply(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RestoreVolumeSnapshot,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_local_evidence(command)?;
    validate_snapshot(transaction, command)?;
    let head = CommitConvergedVolumeHead {
        volume_id: command.volume_id,
        expected_namespace_commit_id: Some(command.expected_namespace_commit_id),
        namespace_commit_id: command.namespace_commit_id,
        root_object_revision_id: command.root_object_revision_id,
        evidence: ConvergedHeadEvidence::Publication {
            operation_id: command.source_operation_id,
            request_digest: command.source_request_digest,
            result_digest: command.source_result_digest,
        },
    };
    let entity = volume_head::commit(transaction, context, &head, revision)?;
    transaction.execute(
        "INSERT INTO volume_snapshot_restores(
            metadata_operation_id, snapshot_id, snapshot_revision, volume_id,
            previous_namespace_commit_id, namespace_commit_id, source_operation_id,
            restored_by, restored_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            context.operation_id.as_bytes().as_slice(),
            command.snapshot_id.as_bytes().as_slice(),
            to_i64(command.expected_snapshot_revision.get())?,
            command.volume_id.as_bytes().as_slice(),
            command.expected_namespace_commit_id.as_bytes().as_slice(),
            command.namespace_commit_id.as_bytes().as_slice(),
            command.source_operation_id.as_bytes().as_slice(),
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(entity)
}

fn validate_local_evidence(command: RestoreVolumeSnapshot) -> Result<(), RepositoryError> {
    if command.expected_snapshot_revision == Revision::ZERO
        || command.namespace_commit_id == command.expected_namespace_commit_id
        || command.namespace_commit_id == command.snapshot_namespace_commit_id
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let expected = namespace_snapshot_restore_result_digest(
        command.source_operation_id,
        command.source_request_digest,
        command.snapshot_id,
        command.snapshot_namespace_commit_id,
        command.expected_namespace_commit_id,
        command.namespace_commit_id,
        command.root_object_revision_id,
    );
    if expected == command.source_result_digest {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_snapshot(
    transaction: &Transaction<'_>,
    command: RestoreVolumeSnapshot,
) -> Result<(), RepositoryError> {
    let stored: Option<StoredSnapshotAuthority> = transaction
        .query_row(
            "SELECT volume_id, namespace_commit_id, root_object_revision_id, state, revision
             FROM volume_snapshots WHERE snapshot_id = ?1",
            [command.snapshot_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((volume, source_commit, root, state, stored_revision)) = stored else {
        return Err(RepositoryError::InvalidCommand);
    };
    let snapshot_revision =
        u64::try_from(stored_revision).map_err(|_| RepositoryError::CorruptState)?;
    if volume.as_slice() != command.volume_id.as_bytes()
        || source_commit.as_slice() != command.snapshot_namespace_commit_id.as_bytes()
        || root.as_slice() != command.root_object_revision_id.as_bytes()
        || !matches!(state, 1 | 2)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    if snapshot_revision != command.expected_snapshot_revision.get() {
        return Err(RepositoryError::StaleSnapshot);
    }
    Ok(())
}
