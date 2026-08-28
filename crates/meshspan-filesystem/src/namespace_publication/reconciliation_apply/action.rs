// SPDX-License-Identifier: GPL-2.0-only

//! Exact directory-path transitions and recovered file-version materialisation.

use meshspan_domain::{BranchId, FileVersionId, ObjectId, ObjectRevisionId, VolumeId};
use rusqlite::{Connection, Transaction};

use super::super::repository::{
    ObjectRevisionInsert, load_object_revision, persist_object_revision,
};
use super::super::{
    DirectoryRevisionResult, LoadedDirectory, load_directory, load_path_editor,
    mutate_namespace_path,
};
use crate::publication::{
    FilePublication, ManifestPublication, NamespaceReconciliationApplication, PublicationError,
    advance_file_head, persist_directory_node, persist_manifest, persist_version, prepare_file,
};
use crate::{
    BranchMutation, DirectoryEntry, DirectoryEntryKind, NamespacePublicationPath,
    NamespaceReplayAction,
};

#[derive(Clone, Copy)]
pub(super) struct ApplyContext {
    pub application: NamespaceReconciliationApplication,
    pub branch_id: BranchId,
    pub volume_id: VolumeId,
}

pub(super) fn apply_action(
    transaction: &Transaction<'_>,
    context: ApplyContext,
    root_object_id: ObjectId,
    current_root: ObjectRevisionId,
    action: &NamespaceReplayAction,
) -> Result<ObjectRevisionId, PublicationError> {
    let next_root = action
        .target_root_object_revision_id
        .ok_or(PublicationError::InvalidInput)?;
    let path =
        NamespacePublicationPath::new(action.target_path.clone(), action.target_ancestors.clone())
            .map_err(|_| PublicationError::InvalidInput)?;
    let directories = load_action_directories(
        transaction,
        context.volume_id,
        root_object_id,
        current_root,
        next_root,
        &path,
    )?;
    if action.disposition == crate::NamespaceReplayDisposition::Recovered
        && let BranchMutation::File { version_id } = action.mutation
    {
        crate::version_retention::record_conflict_protection(
            transaction,
            version_id,
            context.application.created_at,
        )?;
    }
    prepare_leaf_revision(transaction, context, action)?;
    let entry = DirectoryEntry::new(
        path.leaf_name()
            .ok_or(PublicationError::InvalidInput)?
            .clone(),
        action.target_object_id,
        action.target_object_revision_id,
        mutation_kind(action.mutation),
        action.target_entry_generation,
    )?;
    let mutation = mutate_namespace_path(
        directories,
        &path,
        entry,
        action.target_prior_object_revision_id,
    )?;
    for record in &mutation.created_nodes {
        persist_directory_node(transaction, record, context.application.created_at)?;
    }
    persist_directory_revisions(
        transaction,
        context.volume_id,
        context.application.created_by,
        context.application.created_at,
        &mutation.directories,
    )?;
    let selected = mutation
        .directories
        .first()
        .ok_or(PublicationError::Corrupt)?;
    if selected.new_revision_id != next_root {
        return Err(PublicationError::Corrupt);
    }
    Ok(next_root)
}

fn persist_directory_revisions(
    transaction: &Transaction<'_>,
    volume_id: VolumeId,
    created_by: meshspan_domain::PrincipalId,
    created_at: meshspan_domain::UnixMicros,
    directories: &[DirectoryRevisionResult],
) -> Result<(), PublicationError> {
    for directory in directories {
        let exists: i64 = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_revisions WHERE object_revision_id = ?1)",
            [directory.new_revision_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if exists != 0 {
            let stored = load_object_revision(transaction, directory.new_revision_id)?;
            if stored.volume_id != volume_id
                || stored.object_id != directory.object_id
                || stored.kind != 1
                || stored.prior_revision_id != directory.prior_revision_id
                || stored.directory_root != Some(directory.directory_root)
            {
                return Err(PublicationError::OperationConflict);
            }
            continue;
        }
        persist_object_revision(
            transaction,
            ObjectRevisionInsert {
                revision_id: directory.new_revision_id,
                volume_id,
                object_id: directory.object_id,
                kind: 1,
                prior_revision_id: directory.prior_revision_id,
                directory_root: Some(directory.directory_root),
                file_version_id: None,
                created_by,
                created_at,
            },
        )?;
    }
    Ok(())
}

fn load_action_directories(
    transaction: &Transaction<'_>,
    volume_id: VolumeId,
    root_object_id: ObjectId,
    current_root: ObjectRevisionId,
    next_root: ObjectRevisionId,
    path: &NamespacePublicationPath,
) -> Result<Vec<LoadedDirectory>, PublicationError> {
    let components = path.path().components();
    let first = components.first().ok_or(PublicationError::InvalidInput)?;
    let mut directories = vec![load_directory(
        transaction,
        current_root,
        root_object_id,
        next_root,
        volume_id,
        first,
    )?];
    for (index, transition) in path.ancestors().iter().enumerate() {
        let parent_name = components
            .get(index)
            .ok_or(PublicationError::InvalidInput)?;
        let next_name = components
            .get(index + 1)
            .ok_or(PublicationError::InvalidInput)?;
        let entry = directories
            .last()
            .ok_or(PublicationError::Corrupt)?
            .editor
            .lookup(parent_name)?
            .ok_or(PublicationError::StaleHead)?;
        if entry.kind() != DirectoryEntryKind::Directory
            || entry.object_id() != transition.object_id()
            || entry.object_revision_id() != transition.expected_revision_id()
        {
            return Err(PublicationError::StaleHead);
        }
        directories.push(load_directory(
            transaction,
            transition.expected_revision_id(),
            transition.object_id(),
            transition.new_revision_id(),
            volume_id,
            next_name,
        )?);
    }
    Ok(directories)
}

fn prepare_leaf_revision(
    transaction: &Transaction<'_>,
    context: ApplyContext,
    action: &NamespaceReplayAction,
) -> Result<(), PublicationError> {
    let source = load_object_revision(transaction, action.source_object_revision_id)?;
    if source.volume_id != context.volume_id
        || source.object_id != action.source_object_id
        || source.kind != kind_code(action.mutation)
    {
        return Err(PublicationError::Corrupt);
    }
    if action.target_object_id == action.source_object_id
        && action.target_object_revision_id == action.source_object_revision_id
    {
        return validate_direct_leaf(&source, action);
    }
    let BranchMutation::File { version_id } = action.mutation else {
        return Err(PublicationError::InvalidInput);
    };
    if source.file_version_id != Some(version_id) {
        return Err(PublicationError::Corrupt);
    }
    let target_version = action
        .target_file_version_id
        .ok_or(PublicationError::InvalidInput)?;
    let target_operation = action
        .target_publication_operation_id
        .ok_or(PublicationError::InvalidInput)?;
    clone_file_version(
        transaction,
        context,
        action,
        version_id,
        target_version,
        target_operation,
    )?;
    persist_object_revision(
        transaction,
        ObjectRevisionInsert {
            revision_id: action.target_object_revision_id,
            volume_id: context.volume_id,
            object_id: action.target_object_id,
            kind: 2,
            prior_revision_id: action.target_prior_object_revision_id,
            directory_root: None,
            file_version_id: Some(target_version),
            created_by: context.application.created_by,
            created_at: context.application.created_at,
        },
    )
}

fn validate_direct_leaf(
    source: &ObjectRevisionInsert,
    action: &NamespaceReplayAction,
) -> Result<(), PublicationError> {
    match action.mutation {
        BranchMutation::File { version_id }
            if source.file_version_id == Some(version_id)
                && action.target_file_version_id == Some(version_id)
                && action.target_publication_operation_id.is_none() =>
        {
            Ok(())
        }
        BranchMutation::CreateDirectory
            if source.directory_root.is_some()
                && action.target_file_version_id.is_none()
                && action.target_publication_operation_id.is_none() =>
        {
            Ok(())
        }
        _ => Err(PublicationError::InvalidInput),
    }
}

fn clone_file_version(
    transaction: &Transaction<'_>,
    context: ApplyContext,
    action: &NamespaceReplayAction,
    source_version_id: FileVersionId,
    target_version_id: FileVersionId,
    target_operation_id: meshspan_domain::OperationId,
) -> Result<(), PublicationError> {
    let manifest = load_source_manifest(transaction, source_version_id, action.source_object_id)?;
    let parent_version_id = action
        .target_prior_object_revision_id
        .map(|revision_id| load_object_revision(transaction, revision_id))
        .transpose()?
        .map(|revision| {
            if revision.object_id == action.target_object_id && revision.kind == 2 {
                revision.file_version_id.ok_or(PublicationError::Corrupt)
            } else {
                Err(PublicationError::Corrupt)
            }
        })
        .transpose()?;
    let publication = FilePublication {
        operation_id: target_operation_id,
        branch_id: context.branch_id,
        volume_id: context.volume_id,
        object_id: action.target_object_id,
        expected_current_version_id: parent_version_id,
        version_id: target_version_id,
        parent_version_id,
        retain_superseded_history: context.application.retain_superseded_history,
        retention_policy_sequence: context.application.retention_policy_sequence,
        manifest,
        created_by: context.application.created_by,
        created_at: context.application.created_at,
    };
    let head = prepare_file(transaction, publication)?;
    persist_manifest(transaction, manifest)?;
    persist_version(transaction, publication)?;
    crate::version_retention::record_supersession(transaction, publication)?;
    advance_file_head(transaction, publication, head.sequence)?;
    Ok(())
}

fn load_source_manifest(
    transaction: &Transaction<'_>,
    version_id: FileVersionId,
    object_id: ObjectId,
) -> Result<ManifestPublication, PublicationError> {
    type Stored = (Vec<u8>, Vec<u8>, i64, Vec<u8>, i64, i64, Vec<u8>, Vec<u8>);
    let stored: Stored = transaction.query_row(
        "SELECT f.object_id, f.manifest_id, f.logical_length, f.content_digest,
                m.format_version, m.logical_length, m.content_digest, m.root_digest
         FROM file_versions f JOIN content_manifests m ON m.manifest_id = f.manifest_id
         WHERE f.version_id = ?1 AND m.state = 1",
        [version_id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        },
    )?;
    if stored.0.as_slice() != object_id.as_bytes()
        || stored.2 < 0
        || stored.3.len() != 32
        || stored.4 <= 0
        || stored.2 != stored.5
        || stored.3 != stored.6
        || stored.7.len() != 32
    {
        return Err(PublicationError::Corrupt);
    }
    Ok(ManifestPublication {
        manifest_id: meshspan_domain::ContentManifestId::from_bytes(
            stored.1.try_into().map_err(|_| PublicationError::Corrupt)?,
        )
        .map_err(|_| PublicationError::Corrupt)?,
        format_version: u16::try_from(stored.4).map_err(|_| PublicationError::Corrupt)?,
        logical_length: u64::try_from(stored.2).map_err(|_| PublicationError::Corrupt)?,
        content_digest: stored.3.try_into().map_err(|_| PublicationError::Corrupt)?,
        root_digest: stored.7.try_into().map_err(|_| PublicationError::Corrupt)?,
    })
}

pub(super) fn verify_already_applied(
    transaction: &Transaction<'_>,
    volume_id: VolumeId,
    root_object_id: ObjectId,
    current_root: ObjectRevisionId,
    action: &NamespaceReplayAction,
) -> Result<(), PublicationError> {
    if action.target_root_object_revision_id != Some(current_root) {
        return Err(PublicationError::StaleHead);
    }
    let entry = load_selected_entry(
        transaction,
        volume_id,
        root_object_id,
        current_root,
        &action.target_path,
    )?
    .ok_or(PublicationError::StaleHead)?;
    if entry.object_id() == action.target_object_id
        && entry.object_revision_id() == action.target_object_revision_id
        && entry.kind() == mutation_kind(action.mutation)
        && entry.generation() == action.target_entry_generation
    {
        Ok(())
    } else {
        Err(PublicationError::StaleHead)
    }
}

fn load_selected_entry(
    connection: &Connection,
    volume_id: VolumeId,
    mut directory_object_id: ObjectId,
    mut directory_revision_id: ObjectRevisionId,
    path: &crate::NamespacePath,
) -> Result<Option<DirectoryEntry>, PublicationError> {
    for (index, component) in path.components().iter().enumerate() {
        let directory = load_object_revision(connection, directory_revision_id)?;
        if directory.kind != 1
            || directory.volume_id != volume_id
            || directory.object_id != directory_object_id
        {
            return Err(PublicationError::Corrupt);
        }
        let root = directory.directory_root.ok_or(PublicationError::Corrupt)?;
        let entry = load_path_editor(connection, root, component)?.lookup(component)?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        if index + 1 == path.components().len() {
            return Ok(Some(entry));
        }
        if entry.kind() != DirectoryEntryKind::Directory {
            return Ok(None);
        }
        directory_object_id = entry.object_id();
        directory_revision_id = entry.object_revision_id();
    }
    Ok(None)
}

const fn mutation_kind(mutation: BranchMutation) -> DirectoryEntryKind {
    match mutation {
        BranchMutation::File { .. } => DirectoryEntryKind::File,
        BranchMutation::CreateDirectory => DirectoryEntryKind::Directory,
    }
}

const fn kind_code(mutation: BranchMutation) -> u8 {
    match mutation {
        BranchMutation::File { .. } => 2,
        BranchMutation::CreateDirectory => 1,
    }
}
