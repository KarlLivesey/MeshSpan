// SPDX-License-Identifier: GPL-2.0-only

//! Durable marker and root-lineage checks for one namespace deletion intent.

use meshspan_domain::NamespaceCommitId;
use rusqlite::{Connection, Transaction};

use super::{StoredCommit, load_commit, load_object_revision};
use crate::{BranchMutation, BranchMutationIntent, PublicationError};

pub(super) fn validate_shape(intent: &BranchMutationIntent) -> Result<(), PublicationError> {
    if is_deletion(intent.mutation) && intent.rename.is_some() {
        Err(PublicationError::InvalidInput)
    } else {
        Ok(())
    }
}

pub(super) fn persist(
    transaction: &Transaction<'_>,
    intent: &BranchMutationIntent,
) -> Result<(), PublicationError> {
    if is_deletion(intent.mutation) {
        transaction.execute(
            "INSERT INTO namespace_commit_deletions(namespace_commit_id) VALUES (?1)",
            [intent.commit_id.as_bytes().as_slice()],
        )?;
    }
    Ok(())
}

pub(super) fn exists(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<bool, PublicationError> {
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM namespace_commit_deletions WHERE namespace_commit_id = ?1
         )",
        [commit_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    Ok(exists == 1)
}

pub(super) fn validate_loaded(
    connection: &Connection,
    commit: &StoredCommit,
    intent: &BranchMutationIntent,
) -> Result<(), PublicationError> {
    if !is_deletion(intent.mutation) {
        return Ok(());
    }
    let parent = load_commit(
        connection,
        commit.parent_id.ok_or(PublicationError::Corrupt)?,
    )?;
    let root = load_object_revision(connection, commit.root_object_revision_id)?;
    if parent.volume_id != commit.volume_id
        || parent.root_object_id != commit.root_object_id
        || root.volume_id != commit.volume_id
        || root.object_id != commit.root_object_id
        || root.kind != 1
        || root.directory_root.is_none()
        || root.file_version_id.is_some()
        || root.prior_revision_id != Some(parent.root_object_revision_id)
    {
        Err(PublicationError::Corrupt)
    } else {
        Ok(())
    }
}

const fn is_deletion(mutation: BranchMutation) -> bool {
    matches!(
        mutation,
        BranchMutation::DeleteFile { .. } | BranchMutation::DeleteDirectory
    )
}
