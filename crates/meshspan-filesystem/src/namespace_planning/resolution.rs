// SPDX-License-Identifier: GPL-2.0-only

//! One verified current-head path resolution shared by semantic mutation planners.

use meshspan_domain::{
    BranchId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{DirectoryEntryKind, HandleError, NamespacePath};

pub(super) struct ResolvedNamespacePath {
    pub(super) namespace_commit: NamespaceCommitId,
    pub(super) root_object: ObjectId,
    pub(super) parent_object: ObjectId,
    pub(super) ancestors: Vec<ResolvedAncestor>,
    pub(super) leaf: Option<ResolvedLeaf>,
}

#[derive(Clone, Copy)]
pub(super) struct ResolvedAncestor {
    pub(super) object: ObjectId,
    pub(super) revision: ObjectRevisionId,
}

#[derive(Clone, Copy)]
pub(super) struct ResolvedLeaf {
    pub(super) object: ObjectId,
    pub(super) revision: ObjectRevisionId,
    pub(super) kind: DirectoryEntryKind,
    pub(super) version: Option<FileVersionId>,
    pub(super) generation: u64,
}

pub(super) fn resolve(
    connection: &Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
    path: &NamespacePath,
) -> Result<ResolvedNamespacePath, HandleError> {
    type StoredHead = (Vec<u8>, Vec<u8>, Vec<u8>);
    if path.components().is_empty() {
        return Err(HandleError::InvalidInput);
    }
    let stored: Option<StoredHead> = connection
        .query_row(
            "SELECT h.namespace_commit_id, c.root_object_id, c.root_object_revision_id
             FROM branch_namespace_heads h JOIN namespace_commits c USING(namespace_commit_id)
             WHERE h.branch_id = ?1 AND h.volume_id = ?2",
            params![
                branch_id.as_bytes().as_slice(),
                volume_id.as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((commit, root_object, root_revision)) = stored else {
        return Err(HandleError::NotFound);
    };
    let namespace_commit = identifier(&commit, NamespaceCommitId::from_bytes)?;
    let root_object = identifier(&root_object, ObjectId::from_bytes)?;
    let mut selected_object = root_object;
    let mut selected_revision = identifier(&root_revision, ObjectRevisionId::from_bytes)?;
    let mut ancestors = Vec::with_capacity(path.components().len().saturating_sub(1));
    for (index, component) in path.components().iter().enumerate() {
        let parent = crate::handles::load_revision(connection, selected_revision)?;
        if parent.volume_id != volume_id
            || parent.object_id != selected_object
            || parent.kind != DirectoryEntryKind::Directory
        {
            return Err(HandleError::Corrupt);
        }
        let entry = crate::handles::lookup_entry(
            connection,
            parent.directory_root.ok_or(HandleError::Corrupt)?,
            component,
        )?;
        if index + 1 == path.components().len() {
            let leaf = entry
                .map(|entry| {
                    let revision =
                        crate::handles::load_revision(connection, entry.object_revision_id())?;
                    if revision.volume_id != volume_id
                        || revision.object_id != entry.object_id()
                        || revision.kind != entry.kind()
                    {
                        return Err(HandleError::Corrupt);
                    }
                    Ok(ResolvedLeaf {
                        object: entry.object_id(),
                        revision: entry.object_revision_id(),
                        kind: entry.kind(),
                        version: revision.file_version_id,
                        generation: entry.generation(),
                    })
                })
                .transpose()?;
            return Ok(ResolvedNamespacePath {
                namespace_commit,
                root_object,
                parent_object: selected_object,
                ancestors,
                leaf,
            });
        }
        let entry = entry.ok_or(HandleError::NotFound)?;
        if entry.kind() != DirectoryEntryKind::Directory {
            return Err(HandleError::NotFound);
        }
        ancestors.push(ResolvedAncestor {
            object: entry.object_id(),
            revision: entry.object_revision_id(),
        });
        selected_object = entry.object_id();
        selected_revision = entry.object_revision_id();
    }
    Err(HandleError::InvalidInput)
}

fn identifier<const N: usize, T>(
    bytes: &[u8],
    decode: impl FnOnce([u8; N]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, HandleError> {
    decode(bytes.try_into().map_err(|_| HandleError::Corrupt)?).map_err(|_| HandleError::Corrupt)
}
