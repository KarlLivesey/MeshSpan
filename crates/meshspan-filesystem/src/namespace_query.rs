// SPDX-License-Identifier: GPL-2.0-only

//! Immutable branch namespace stat queries over verified directory paths.

use meshspan_domain::{
    BranchId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

use crate::{
    DirectoryEntry, DirectoryEntryKind, DirectoryNodeDigest, DirectoryTrie, NamespaceComponent,
    NamespacePath,
};

/// Exact current-branch path selected for one metadata query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceStatRequest {
    /// Local/cell branch being observed.
    pub branch_id: BranchId,
    /// Volume containing the path.
    pub volume_id: VolumeId,
    /// Bounded canonical logical path.
    pub path: NamespacePath,
    /// Authoritative query instant used by access evaluation.
    pub observed_at: UnixMicros,
}

/// Protocol-neutral immutable attributes selected by one exact branch head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceObjectStat {
    /// Namespace commit under which the path resolved.
    pub namespace_commit_id: NamespaceCommitId,
    /// Stable logical object identity.
    pub object_id: ObjectId,
    /// Exact immutable object revision selected by the parent entry.
    pub object_revision_id: ObjectRevisionId,
    /// Case-preserved leaf name.
    pub name: NamespaceComponent,
    /// Stable name-reuse generation.
    pub entry_generation: u64,
    /// Directory or regular-file kind.
    pub kind: DirectoryEntryKind,
    /// Current immutable file version, absent for directories.
    pub file_version_id: Option<FileVersionId>,
    /// Logical file bytes, absent for directories.
    pub logical_length: Option<u64>,
}

/// Stable continuation bound to one immutable directory revision and last returned name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryListCursor {
    /// Namespace commit selected by the first page.
    pub namespace_commit_id: NamespaceCommitId,
    /// Stable directory identity.
    pub directory_object_id: ObjectId,
    /// Exact immutable directory revision.
    pub directory_object_revision_id: ObjectRevisionId,
    /// Last returned canonical hash in deterministic trie order.
    pub after_name_hash: [u8; 32],
    /// Last returned case-preserved/canonical component within a collision bucket.
    pub after_name: NamespaceComponent,
}

/// One bounded current-directory page request; `None` selects the volume root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceListRequest {
    /// Local/cell branch being observed.
    pub branch_id: BranchId,
    /// Volume containing the selected directory.
    pub volume_id: VolumeId,
    /// Directory path, or `None` for the volume root.
    pub directory_path: Option<NamespacePath>,
    /// Exact prior-page continuation.
    pub cursor: Option<DirectoryListCursor>,
    /// Positive result limit no greater than 1,024.
    pub maximum_results: u16,
    /// Authoritative query instant used by access evaluation.
    pub observed_at: UnixMicros,
}

/// Minimal child record authorised by list access on its containing directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceListEntry {
    /// Case-preserved child name.
    pub name: NamespaceComponent,
    /// Stable logical child identity.
    pub object_id: ObjectId,
    /// Exact immutable child revision selected by this directory.
    pub object_revision_id: ObjectRevisionId,
    /// Stable name-reuse generation.
    pub entry_generation: u64,
    /// Directory or regular-file kind.
    pub kind: DirectoryEntryKind,
    /// Current immutable file version, absent for directories.
    pub file_version_id: Option<FileVersionId>,
    /// Logical file bytes, absent for directories.
    pub logical_length: Option<u64>,
}

/// One immutable directory page with continuation only when another entry exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceListPage {
    /// Namespace commit under which every entry resolved.
    pub namespace_commit_id: NamespaceCommitId,
    /// Stable selected directory.
    pub directory_object_id: ObjectId,
    /// Exact immutable selected directory revision.
    pub directory_object_revision_id: ObjectRevisionId,
    /// Deterministically ordered bounded entries.
    pub entries: Vec<NamespaceListEntry>,
    /// Continuation bound to this immutable view, present only when another entry exists.
    pub next_cursor: Option<DirectoryListCursor>,
}

/// Stable failures from immutable namespace queries.
#[derive(Debug, Error)]
pub enum NamespaceQueryError {
    /// The current branch path does not exist or does not traverse directories.
    #[error("namespace query target was not found")]
    NotFound,
    /// Page bounds or continuation fields are malformed.
    #[error("namespace query input is invalid")]
    InvalidInput,
    /// Continuation belongs to another or no-longer-current immutable directory view.
    #[error("namespace query cursor is stale")]
    StaleCursor,
    /// Stored identities, revisions, trie records or file metadata violate an invariant.
    #[error("namespace query state is corrupt")]
    Corrupt,
    /// SQLite query failed.
    #[error("namespace query database operation failed")]
    Sqlite(#[from] rusqlite::Error),
    /// Immutable directory-node loading or verification failed.
    #[error("namespace query directory verification failed")]
    Directory(#[from] crate::PublicationError),
}

pub(crate) fn stat(
    connection: &Connection,
    request: &NamespaceStatRequest,
) -> Result<NamespaceObjectStat, NamespaceQueryError> {
    type StoredHead = (Vec<u8>, Vec<u8>, Vec<u8>);
    let head: Option<StoredHead> = connection
        .query_row(
            "SELECT h.namespace_commit_id, c.root_object_id, c.root_object_revision_id
             FROM branch_namespace_heads h
             JOIN namespace_commits c USING(namespace_commit_id)
             WHERE h.branch_id = ?1 AND h.volume_id = ?2",
            params![
                request.branch_id.as_bytes().as_slice(),
                request.volume_id.as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((commit, root_object, root_revision)) = head else {
        return Err(NamespaceQueryError::NotFound);
    };
    let namespace_commit_id = identifier(&commit, NamespaceCommitId::from_bytes)?;
    let mut object_id = identifier(&root_object, ObjectId::from_bytes)?;
    let mut revision_id = identifier(&root_revision, ObjectRevisionId::from_bytes)?;
    for (index, component) in request.path.components().iter().enumerate() {
        let revision = load_revision(connection, revision_id)?;
        if revision.volume_id != request.volume_id
            || revision.object_id != object_id
            || revision.kind != DirectoryEntryKind::Directory
        {
            return Err(NamespaceQueryError::Corrupt);
        }
        let entry = lookup_entry(
            connection,
            revision
                .directory_root
                .ok_or(NamespaceQueryError::Corrupt)?,
            component,
        )?
        .ok_or(NamespaceQueryError::NotFound)?;
        if index + 1 == request.path.components().len() {
            return build_stat(connection, namespace_commit_id, request.volume_id, &entry);
        }
        if entry.kind() != DirectoryEntryKind::Directory {
            return Err(NamespaceQueryError::NotFound);
        }
        object_id = entry.object_id();
        revision_id = entry.object_revision_id();
    }
    Err(NamespaceQueryError::NotFound)
}

pub(crate) fn list(
    connection: &Connection,
    request: &NamespaceListRequest,
) -> Result<NamespaceListPage, NamespaceQueryError> {
    if request.maximum_results == 0 || request.maximum_results > 1_024 {
        return Err(NamespaceQueryError::InvalidInput);
    }
    let directory = resolve_directory(connection, request)?;
    validate_cursor(request.cursor.as_ref(), directory)?;
    let revision = load_revision(connection, directory.revision)?;
    let root = revision
        .directory_root
        .ok_or(NamespaceQueryError::Corrupt)?;
    let mut entries = Vec::with_capacity(usize::from(request.maximum_results) + 1);
    collect_entries(
        connection,
        root,
        0,
        request.cursor.as_ref(),
        true,
        usize::from(request.maximum_results) + 1,
        &mut entries,
    )?;
    let has_more = entries.len() > usize::from(request.maximum_results);
    if has_more {
        entries.pop();
    }
    let results = entries
        .iter()
        .map(|entry| list_entry(connection, request.volume_id, entry))
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = if has_more {
        let last = entries.last().ok_or(NamespaceQueryError::Corrupt)?;
        Some(DirectoryListCursor {
            namespace_commit_id: directory.commit,
            directory_object_id: directory.object,
            directory_object_revision_id: directory.revision,
            after_name_hash: crate::directory::directory_name_hash(last.name()),
            after_name: last.name().clone(),
        })
    } else {
        None
    };
    Ok(NamespaceListPage {
        namespace_commit_id: directory.commit,
        directory_object_id: directory.object,
        directory_object_revision_id: directory.revision,
        entries: results,
        next_cursor,
    })
}

#[derive(Clone, Copy)]
pub(crate) struct ResolvedDirectory {
    pub commit: NamespaceCommitId,
    pub object: ObjectId,
    pub revision: ObjectRevisionId,
}

pub(crate) fn list_target(
    connection: &Connection,
    request: &NamespaceListRequest,
) -> Result<ResolvedDirectory, NamespaceQueryError> {
    resolve_directory(connection, request)
}

fn resolve_directory(
    connection: &Connection,
    request: &NamespaceListRequest,
) -> Result<ResolvedDirectory, NamespaceQueryError> {
    if let Some(path) = &request.directory_path {
        let stat = stat(
            connection,
            &NamespaceStatRequest {
                branch_id: request.branch_id,
                volume_id: request.volume_id,
                path: path.clone(),
                observed_at: request.observed_at,
            },
        )?;
        if stat.kind != DirectoryEntryKind::Directory {
            return Err(NamespaceQueryError::NotFound);
        }
        return Ok(ResolvedDirectory {
            commit: stat.namespace_commit_id,
            object: stat.object_id,
            revision: stat.object_revision_id,
        });
    }
    let stored: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT h.namespace_commit_id, c.root_object_id, c.root_object_revision_id
             FROM branch_namespace_heads h JOIN namespace_commits c USING(namespace_commit_id)
             WHERE h.branch_id = ?1 AND h.volume_id = ?2",
            params![
                request.branch_id.as_bytes().as_slice(),
                request.volume_id.as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((commit, object, revision)) = stored else {
        return Err(NamespaceQueryError::NotFound);
    };
    let directory = ResolvedDirectory {
        commit: identifier(&commit, NamespaceCommitId::from_bytes)?,
        object: identifier(&object, ObjectId::from_bytes)?,
        revision: identifier(&revision, ObjectRevisionId::from_bytes)?,
    };
    let stored_revision = load_revision(connection, directory.revision)?;
    if stored_revision.volume_id != request.volume_id
        || stored_revision.object_id != directory.object
        || stored_revision.kind != DirectoryEntryKind::Directory
    {
        Err(NamespaceQueryError::Corrupt)
    } else {
        Ok(directory)
    }
}

fn validate_cursor(
    cursor: Option<&DirectoryListCursor>,
    directory: ResolvedDirectory,
) -> Result<(), NamespaceQueryError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };
    if cursor.namespace_commit_id != directory.commit
        || cursor.directory_object_id != directory.object
        || cursor.directory_object_revision_id != directory.revision
        || cursor.after_name_hash != crate::directory::directory_name_hash(&cursor.after_name)
    {
        Err(NamespaceQueryError::StaleCursor)
    } else {
        Ok(())
    }
}

fn collect_entries(
    connection: &Connection,
    selected: DirectoryNodeDigest,
    depth: usize,
    cursor: Option<&DirectoryListCursor>,
    on_cursor_path: bool,
    maximum: usize,
    output: &mut Vec<DirectoryEntry>,
) -> Result<(), NamespaceQueryError> {
    if output.len() >= maximum {
        return Ok(());
    }
    let record = crate::publication::load_directory_node(connection, selected)?
        .ok_or(NamespaceQueryError::Corrupt)?;
    match record.view() {
        crate::directory::DirectoryNodeView::Internal {
            depth: stored_depth,
            children,
        } => {
            if usize::from(stored_depth) != depth || depth >= 64 {
                return Err(NamespaceQueryError::Corrupt);
            }
            let cursor_slot = cursor.map(|value| hash_nibble(&value.after_name_hash, depth));
            for (slot, child) in children {
                if on_cursor_path && cursor_slot.is_some_and(|cursor_slot| slot < cursor_slot) {
                    continue;
                }
                let child_on_path =
                    on_cursor_path && cursor_slot.is_some_and(|cursor_slot| slot == cursor_slot);
                collect_entries(
                    connection,
                    child,
                    depth + 1,
                    cursor,
                    child_on_path,
                    maximum,
                    output,
                )?;
                if output.len() >= maximum {
                    break;
                }
            }
            Ok(())
        }
        crate::directory::DirectoryNodeView::Leaf { key_hash, entries } => {
            if depth != 64 {
                return Err(NamespaceQueryError::Corrupt);
            }
            for entry in entries {
                let after_cursor = !on_cursor_path
                    || cursor.is_none_or(|cursor| {
                        key_hash > cursor.after_name_hash
                            || key_hash == cursor.after_name_hash
                                && entry.name().canonical() > cursor.after_name.canonical()
                    });
                if after_cursor {
                    output.push(entry);
                    if output.len() >= maximum {
                        break;
                    }
                }
            }
            Ok(())
        }
    }
}

const fn hash_nibble(hash: &[u8; 32], depth: usize) -> u8 {
    let byte = hash[depth / 2];
    if depth.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

fn list_entry(
    connection: &Connection,
    volume_id: VolumeId,
    entry: &DirectoryEntry,
) -> Result<NamespaceListEntry, NamespaceQueryError> {
    let revision = load_revision(connection, entry.object_revision_id())?;
    if revision.volume_id != volume_id
        || revision.object_id != entry.object_id()
        || revision.kind != entry.kind()
    {
        return Err(NamespaceQueryError::Corrupt);
    }
    let logical_length = revision
        .file_version_id
        .map(|version_id| load_file_length(connection, volume_id, entry.object_id(), version_id))
        .transpose()?;
    Ok(NamespaceListEntry {
        name: entry.name().clone(),
        object_id: entry.object_id(),
        object_revision_id: entry.object_revision_id(),
        entry_generation: entry.generation(),
        kind: entry.kind(),
        file_version_id: revision.file_version_id,
        logical_length,
    })
}

fn build_stat(
    connection: &Connection,
    namespace_commit_id: NamespaceCommitId,
    volume_id: VolumeId,
    entry: &DirectoryEntry,
) -> Result<NamespaceObjectStat, NamespaceQueryError> {
    let revision = load_revision(connection, entry.object_revision_id())?;
    if revision.volume_id != volume_id
        || revision.object_id != entry.object_id()
        || revision.kind != entry.kind()
    {
        return Err(NamespaceQueryError::Corrupt);
    }
    let logical_length = revision
        .file_version_id
        .map(|version_id| load_file_length(connection, volume_id, entry.object_id(), version_id))
        .transpose()?;
    Ok(NamespaceObjectStat {
        namespace_commit_id,
        object_id: entry.object_id(),
        object_revision_id: entry.object_revision_id(),
        name: entry.name().clone(),
        entry_generation: entry.generation(),
        kind: entry.kind(),
        file_version_id: revision.file_version_id,
        logical_length,
    })
}

fn load_file_length(
    connection: &Connection,
    volume_id: VolumeId,
    object_id: ObjectId,
    version_id: FileVersionId,
) -> Result<u64, NamespaceQueryError> {
    type Stored = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, Vec<u8>);
    let stored: Stored = connection.query_row(
        "SELECT v.volume_id, v.object_id, v.logical_length, m.logical_length,
                v.content_digest, m.content_digest
         FROM file_versions v JOIN content_manifests m USING(manifest_id)
         WHERE v.version_id = ?1",
        [version_id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    let length = u64::try_from(stored.2).map_err(|_| NamespaceQueryError::Corrupt)?;
    if stored.0.as_slice() != volume_id.as_bytes()
        || stored.1.as_slice() != object_id.as_bytes()
        || stored.2 != stored.3
        || stored.4 != stored.5
    {
        Err(NamespaceQueryError::Corrupt)
    } else {
        Ok(length)
    }
}

#[derive(Clone, Copy)]
struct StoredRevision {
    volume_id: VolumeId,
    object_id: ObjectId,
    kind: DirectoryEntryKind,
    directory_root: Option<DirectoryNodeDigest>,
    file_version_id: Option<FileVersionId>,
}

fn load_revision(
    connection: &Connection,
    revision_id: ObjectRevisionId,
) -> Result<StoredRevision, NamespaceQueryError> {
    type Stored = (Vec<u8>, Vec<u8>, i64, Option<Vec<u8>>, Option<Vec<u8>>);
    let stored: Stored = connection.query_row(
        "SELECT volume_id, object_id, object_kind, directory_root_digest, file_version_id
         FROM object_revisions WHERE object_revision_id = ?1",
        [revision_id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let kind = match stored.2 {
        1 => DirectoryEntryKind::Directory,
        2 => DirectoryEntryKind::File,
        _ => return Err(NamespaceQueryError::Corrupt),
    };
    let directory_root = stored
        .3
        .as_deref()
        .map(|bytes| array(bytes).map(DirectoryNodeDigest::from_bytes))
        .transpose()?;
    let file_version_id = stored
        .4
        .as_deref()
        .map(|bytes| identifier(bytes, FileVersionId::from_bytes))
        .transpose()?;
    if (kind == DirectoryEntryKind::Directory) != directory_root.is_some()
        || (kind == DirectoryEntryKind::File) != file_version_id.is_some()
    {
        return Err(NamespaceQueryError::Corrupt);
    }
    Ok(StoredRevision {
        volume_id: identifier(&stored.0, VolumeId::from_bytes)?,
        object_id: identifier(&stored.1, ObjectId::from_bytes)?,
        kind,
        directory_root,
        file_version_id,
    })
}

fn lookup_entry(
    connection: &Connection,
    root: DirectoryNodeDigest,
    name: &NamespaceComponent,
) -> Result<Option<DirectoryEntry>, NamespaceQueryError> {
    let mut selected = root;
    let mut records = Vec::new();
    for depth in 0..=64 {
        let record = crate::publication::load_directory_node(connection, selected)?
            .ok_or(NamespaceQueryError::Corrupt)?;
        let child = record
            .selected_child(name, depth)
            .map_err(|_| NamespaceQueryError::Corrupt)?;
        records.push(record);
        let Some(child) = child else {
            break;
        };
        selected = child;
    }
    DirectoryTrie::from_selected_records(root, records, name)
        .map_err(|_| NamespaceQueryError::Corrupt)?
        .lookup(name)
        .map_err(|_| NamespaceQueryError::Corrupt)
}

fn identifier<const N: usize, T>(
    bytes: &[u8],
    decode: impl FnOnce([u8; N]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, NamespaceQueryError> {
    decode(array(bytes)?).map_err(|_| NamespaceQueryError::Corrupt)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NamespaceQueryError> {
    bytes.try_into().map_err(|_| NamespaceQueryError::Corrupt)
}
