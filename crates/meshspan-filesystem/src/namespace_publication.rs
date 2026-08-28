// SPDX-License-Identifier: GPL-2.0-only

//! Atomic immutable root-directory mutation and volume branch-head publication.

use std::collections::BTreeSet;

use meshspan_domain::{
    BranchId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{
    BranchNamespaceHead, DirectoryPublication, DirectoryPublicationReceipt,
    NamespacePublicationPath, NamespacePublicationReceipt, PublicationDisposition,
    PublicationError, RootFilePublication, advance_file_head, copy_array, decode_identifier,
    from_i64, load_directory_node, persist_directory_node, persist_manifest, persist_version,
    prepare_file, publication_request_digest, to_i64,
};
use crate::{
    DirectoryEntry, DirectoryEntryKind, DirectoryNodeDigest, DirectoryNodeRecord, DirectoryTrie,
};

pub(super) fn publish(
    connection: &mut Connection,
    publication: &RootFilePublication,
    fault: Option<NamespaceFaultPoint>,
) -> Result<NamespacePublicationReceipt, PublicationError> {
    validate(publication)?;
    let request_digest = request_digest(publication);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if load_directory_operation(
        &transaction,
        publication.file.operation_id,
        PublicationDisposition::Replayed,
    )?
    .is_some()
    {
        return Err(PublicationError::OperationConflict);
    }
    if let Some(receipt) = load_operation(
        &transaction,
        publication.file.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return if receipt.request_digest == request_digest {
            Ok(receipt)
        } else {
            Err(PublicationError::OperationConflict)
        };
    }

    let intent = NamespaceIntent::from_file(publication);
    let base = load_base(&transaction, intent)?;
    let leaf = base.directories.last().ok_or(PublicationError::Corrupt)?;
    validate_old_entry(&transaction, publication, &leaf.editor)?;
    let head_sequence = base.head_sequence;
    let namespace = mutate_directory_path(base.directories, publication)?;
    for record in &namespace.created_nodes {
        persist_directory_node(&transaction, record, publication.file.created_at)?;
    }
    inject(fault, NamespaceFaultPoint::DirectoryNodes)?;

    let file_head = prepare_file(&transaction, publication.file)?;
    persist_manifest(&transaction, publication.file.manifest)?;
    persist_version(&transaction, publication.file)?;
    advance_file_head(&transaction, publication.file, file_head.sequence)?;
    inject(fault, NamespaceFaultPoint::FileVersion)?;

    persist_object_revisions(&transaction, publication, &namespace.directories)?;
    inject(fault, NamespaceFaultPoint::ObjectRevisions)?;
    persist_commit(&transaction, intent, request_digest)?;
    inject(fault, NamespaceFaultPoint::NamespaceCommit)?;
    let head_sequence = advance_namespace_head(&transaction, intent, head_sequence)?;
    inject(fault, NamespaceFaultPoint::Heads)?;
    let receipt =
        persist_namespace_operation(&transaction, publication, request_digest, head_sequence)?;
    inject(fault, NamespaceFaultPoint::Operation)?;
    transaction.commit()?;
    Ok(receipt)
}

pub(super) fn create_directory(
    connection: &mut Connection,
    publication: &DirectoryPublication,
    fault: Option<NamespaceFaultPoint>,
) -> Result<DirectoryPublicationReceipt, PublicationError> {
    validate_directory_publication(publication)?;
    let request_digest = directory_request_digest(publication);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if load_operation_raw(
        &transaction,
        publication.operation_id,
        PublicationDisposition::Replayed,
    )?
    .is_some()
    {
        return Err(PublicationError::OperationConflict);
    }
    if let Some(receipt) = load_directory_operation(
        &transaction,
        publication.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return if receipt.request_digest == request_digest {
            Ok(receipt)
        } else {
            Err(PublicationError::OperationConflict)
        };
    }

    let intent = NamespaceIntent::from_directory(publication);
    let base = load_base(&transaction, intent)?;
    let parent = base.directories.last().ok_or(PublicationError::Corrupt)?;
    let leaf_name = publication
        .path
        .leaf_name()
        .ok_or(PublicationError::InvalidInput)?;
    if parent.editor.lookup(leaf_name)?.is_some() {
        return Err(PublicationError::StaleHead);
    }
    let empty = DirectoryTrie::empty();
    let empty_root = empty.root();
    let empty_record = empty.record(empty_root)?;
    let entry = DirectoryEntry::new(
        leaf_name.clone(),
        publication.directory_object_id,
        publication.directory_object_revision_id,
        DirectoryEntryKind::Directory,
        publication.entry_generation,
    )?;
    let head_sequence = base.head_sequence;
    let namespace = mutate_namespace_path(base.directories, &publication.path, entry, None)?;
    persist_directory_node(&transaction, &empty_record, publication.created_at)?;
    for record in &namespace.created_nodes {
        persist_directory_node(&transaction, record, publication.created_at)?;
    }
    inject(fault, NamespaceFaultPoint::DirectoryNodes)?;

    persist_object_revision(
        &transaction,
        ObjectRevisionInsert {
            revision_id: publication.directory_object_revision_id,
            volume_id: publication.volume_id,
            object_id: publication.directory_object_id,
            kind: 1,
            prior_revision_id: None,
            directory_root: Some(empty_root),
            file_version_id: None,
            created_by: publication.created_by,
            created_at: publication.created_at,
        },
    )?;
    persist_directory_path_revisions(
        &transaction,
        publication.volume_id,
        publication.created_by,
        publication.created_at,
        &namespace.directories,
    )?;
    inject(fault, NamespaceFaultPoint::ObjectRevisions)?;
    persist_commit(&transaction, intent, request_digest)?;
    inject(fault, NamespaceFaultPoint::NamespaceCommit)?;
    let head_sequence = advance_namespace_head(&transaction, intent, head_sequence)?;
    inject(fault, NamespaceFaultPoint::Heads)?;
    let receipt =
        persist_directory_operation(&transaction, publication, request_digest, head_sequence)?;
    inject(fault, NamespaceFaultPoint::Operation)?;
    transaction.commit()?;
    Ok(receipt)
}

pub(super) fn load_head(
    connection: &Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
) -> Result<Option<BranchNamespaceHead>, PublicationError> {
    let stored: Option<(Vec<u8>, i64)> = connection
        .query_row(
            "SELECT namespace_commit_id, head_sequence
             FROM branch_namespace_heads WHERE branch_id = ?1 AND volume_id = ?2",
            params![
                branch_id.as_bytes().as_slice(),
                volume_id.as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    stored
        .map(|(commit, sequence)| {
            let head = BranchNamespaceHead {
                branch_id,
                volume_id,
                namespace_commit_id: decode_identifier(&commit, NamespaceCommitId::from_bytes)?,
                sequence: from_i64(sequence)?,
            };
            let selected = load_commit(connection, head.namespace_commit_id)?;
            if selected.branch_id == branch_id && selected.volume_id == volume_id {
                Ok(head)
            } else {
                Err(PublicationError::Corrupt)
            }
        })
        .transpose()
}

pub(super) fn load_operation(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<NamespacePublicationReceipt>, PublicationError> {
    let receipt = load_operation_raw(connection, operation_id, disposition)?;
    if let Some(receipt) = receipt {
        let commit = load_commit(connection, receipt.namespace_commit_id)?;
        if commit.operation_id == operation_id {
            Ok(Some(receipt))
        } else {
            Err(PublicationError::Corrupt)
        }
    } else {
        Ok(None)
    }
}

fn load_operation_raw(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<NamespacePublicationReceipt>, PublicationError> {
    let stored: Option<StoredReceipt> = connection
        .query_row(
            "SELECT request_digest, namespace_commit_id, file_version_id,
                    head_sequence, result_digest
             FROM namespace_publication_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
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
    stored
        .map(|values| decode_receipt(operation_id, disposition, &values))
        .transpose()
}

pub(super) fn load_directory_operation(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<DirectoryPublicationReceipt>, PublicationError> {
    let receipt = load_directory_operation_raw(connection, operation_id, disposition)?;
    if let Some(receipt) = receipt {
        let commit = load_commit(connection, receipt.namespace_commit_id)?;
        if commit.operation_id == operation_id {
            Ok(Some(receipt))
        } else {
            Err(PublicationError::Corrupt)
        }
    } else {
        Ok(None)
    }
}

fn load_directory_operation_raw(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<DirectoryPublicationReceipt>, PublicationError> {
    let stored: Option<StoredDirectoryReceipt> = connection
        .query_row(
            "SELECT request_digest, namespace_commit_id, directory_object_revision_id,
                    head_sequence, result_digest
             FROM directory_publication_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
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
    stored
        .map(|values| decode_directory_receipt(operation_id, disposition, &values))
        .transpose()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NamespaceFaultPoint {
    DirectoryNodes,
    FileVersion,
    ObjectRevisions,
    NamespaceCommit,
    Heads,
    Operation,
}

struct NamespaceBase {
    directories: Vec<LoadedDirectory>,
    head_sequence: u64,
}

#[derive(Clone, Copy)]
struct NamespaceIntent<'a> {
    operation_id: OperationId,
    branch_id: BranchId,
    volume_id: VolumeId,
    root_object_id: ObjectId,
    expected_commit_id: Option<NamespaceCommitId>,
    root_revision_id: ObjectRevisionId,
    commit_id: NamespaceCommitId,
    path: &'a NamespacePublicationPath,
    created_by: meshspan_domain::PrincipalId,
    created_at: meshspan_domain::UnixMicros,
}

impl<'a> NamespaceIntent<'a> {
    const fn from_file(publication: &'a RootFilePublication) -> Self {
        Self {
            operation_id: publication.file.operation_id,
            branch_id: publication.file.branch_id,
            volume_id: publication.file.volume_id,
            root_object_id: publication.root_object_id,
            expected_commit_id: publication.expected_namespace_commit_id,
            root_revision_id: publication.root_object_revision_id,
            commit_id: publication.namespace_commit_id,
            path: &publication.path,
            created_by: publication.file.created_by,
            created_at: publication.file.created_at,
        }
    }

    const fn from_directory(publication: &'a DirectoryPublication) -> Self {
        Self {
            operation_id: publication.operation_id,
            branch_id: publication.branch_id,
            volume_id: publication.volume_id,
            root_object_id: publication.root_object_id,
            expected_commit_id: publication.expected_namespace_commit_id,
            root_revision_id: publication.root_object_revision_id,
            commit_id: publication.namespace_commit_id,
            path: &publication.path,
            created_by: publication.created_by,
            created_at: publication.created_at,
        }
    }
}

struct LoadedDirectory {
    editor: DirectoryTrie,
    object_id: ObjectId,
    prior_revision_id: Option<ObjectRevisionId>,
    new_revision_id: ObjectRevisionId,
}

fn validate(publication: &RootFilePublication) -> Result<(), PublicationError> {
    super::validate_publication(publication.file)?;
    if publication.root_object_id == publication.file.object_id
        || publication.root_object_revision_id == publication.file_object_revision_id
        || publication.entry_generation == 0
    {
        return Err(PublicationError::InvalidInput);
    }
    let mut object_ids = BTreeSet::from([publication.root_object_id, publication.file.object_id]);
    let mut new_revisions = BTreeSet::from([
        publication.root_object_revision_id,
        publication.file_object_revision_id,
    ]);
    let mut prior_revisions = publication
        .expected_file_object_revision_id
        .into_iter()
        .collect::<BTreeSet<_>>();
    for transition in publication.path.ancestors() {
        if !object_ids.insert(transition.object_id())
            || !new_revisions.insert(transition.new_revision_id())
        {
            return Err(PublicationError::InvalidInput);
        }
        prior_revisions.insert(transition.expected_revision_id());
    }
    if !new_revisions.is_disjoint(&prior_revisions) {
        return Err(PublicationError::InvalidInput);
    }
    Ok(())
}

fn validate_directory_publication(
    publication: &DirectoryPublication,
) -> Result<(), PublicationError> {
    if publication.root_object_id == publication.directory_object_id
        || publication.root_object_revision_id == publication.directory_object_revision_id
        || publication.entry_generation == 0
        || publication.path.leaf_name().is_none()
    {
        return Err(PublicationError::InvalidInput);
    }
    let mut object_ids =
        BTreeSet::from([publication.root_object_id, publication.directory_object_id]);
    let mut new_revisions = BTreeSet::from([
        publication.root_object_revision_id,
        publication.directory_object_revision_id,
    ]);
    let mut prior_revisions = BTreeSet::new();
    for transition in publication.path.ancestors() {
        if !object_ids.insert(transition.object_id())
            || !new_revisions.insert(transition.new_revision_id())
        {
            return Err(PublicationError::InvalidInput);
        }
        prior_revisions.insert(transition.expected_revision_id());
    }
    if new_revisions.is_disjoint(&prior_revisions) {
        Ok(())
    } else {
        Err(PublicationError::InvalidInput)
    }
}

fn load_base(
    transaction: &Transaction<'_>,
    intent: NamespaceIntent<'_>,
) -> Result<NamespaceBase, PublicationError> {
    let head = load_head(transaction, intent.branch_id, intent.volume_id)?;
    match (head, intent.expected_commit_id) {
        (None, None) => load_initial_base(intent),
        (Some(head), Some(expected)) if head.namespace_commit_id == expected => {
            load_existing_base(transaction, intent, head)
        }
        _ => Err(PublicationError::StaleHead),
    }
}

fn load_initial_base(intent: NamespaceIntent<'_>) -> Result<NamespaceBase, PublicationError> {
    if !intent.path.ancestors().is_empty() {
        return Err(PublicationError::StaleHead);
    }
    Ok(NamespaceBase {
        directories: vec![LoadedDirectory {
            editor: DirectoryTrie::empty(),
            object_id: intent.root_object_id,
            prior_revision_id: None,
            new_revision_id: intent.root_revision_id,
        }],
        head_sequence: 0,
    })
}

fn load_existing_base(
    transaction: &Transaction<'_>,
    intent: NamespaceIntent<'_>,
    head: BranchNamespaceHead,
) -> Result<NamespaceBase, PublicationError> {
    let commit = load_commit(transaction, head.namespace_commit_id)?;
    if commit.branch_id != intent.branch_id
        || commit.volume_id != intent.volume_id
        || commit.root_object_id != intent.root_object_id
    {
        return Err(PublicationError::Corrupt);
    }
    if intent.root_revision_id == commit.root_object_revision_id
        || intent
            .path
            .ancestors()
            .iter()
            .any(|transition| transition.new_revision_id() == commit.root_object_revision_id)
    {
        return Err(PublicationError::InvalidInput);
    }
    let components = intent.path.path().components();
    let selected = components.first().ok_or(PublicationError::InvalidInput)?;
    let mut directories = vec![load_directory(
        transaction,
        commit.root_object_revision_id,
        intent.root_object_id,
        intent.root_revision_id,
        intent.volume_id,
        selected,
    )?];
    for (index, transition) in intent.path.ancestors().iter().enumerate() {
        let parent_name = components
            .get(index)
            .ok_or(PublicationError::InvalidInput)?;
        let next_name = components
            .get(index.saturating_add(1))
            .ok_or(PublicationError::InvalidInput)?;
        let parent = directories.last().ok_or(PublicationError::Corrupt)?;
        let entry = parent
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
            intent.volume_id,
            next_name,
        )?);
    }
    Ok(NamespaceBase {
        directories,
        head_sequence: head.sequence,
    })
}

#[derive(Clone, Copy)]
struct StoredCommit {
    commit_id: NamespaceCommitId,
    branch_id: BranchId,
    volume_id: VolumeId,
    root_object_id: ObjectId,
    root_object_revision_id: ObjectRevisionId,
    parent_id: Option<NamespaceCommitId>,
    created_by: meshspan_domain::PrincipalId,
    operation_id: OperationId,
    created_at: meshspan_domain::UnixMicros,
}

fn load_commit(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<StoredCommit, PublicationError> {
    type StoredCommitColumns = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
    );
    let stored: StoredCommitColumns = connection.query_row(
        "SELECT branch_id, volume_id, root_object_id, root_object_revision_id,
                created_by, publication_operation_id, created_at, commit_digest
         FROM namespace_commits WHERE namespace_commit_id = ?1",
        [commit_id.as_bytes().as_slice()],
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
    let commit = StoredCommit {
        commit_id,
        branch_id: decode_identifier(&stored.0, BranchId::from_bytes)?,
        volume_id: decode_identifier(&stored.1, VolumeId::from_bytes)?,
        root_object_id: decode_identifier(&stored.2, ObjectId::from_bytes)?,
        root_object_revision_id: decode_identifier(&stored.3, ObjectRevisionId::from_bytes)?,
        parent_id: load_single_parent(connection, commit_id)?,
        created_by: decode_identifier(&stored.4, meshspan_domain::PrincipalId::from_bytes)?,
        operation_id: decode_identifier(&stored.5, OperationId::from_bytes)?,
        created_at: meshspan_domain::UnixMicros::new(stored.6),
    };
    let request_digest = load_commit_request_digest(connection, commit.operation_id, commit_id)?;
    if copy_array(&stored.7)? == commit_digest_fields(&commit, request_digest) {
        Ok(commit)
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn load_commit_request_digest(
    connection: &Connection,
    operation_id: OperationId,
    commit_id: NamespaceCommitId,
) -> Result<[u8; 32], PublicationError> {
    let file = load_operation_raw(connection, operation_id, PublicationDisposition::Replayed)?;
    let directory =
        load_directory_operation_raw(connection, operation_id, PublicationDisposition::Replayed)?;
    match (file, directory) {
        (Some(receipt), None) if receipt.namespace_commit_id == commit_id => {
            Ok(receipt.request_digest)
        }
        (None, Some(receipt)) if receipt.namespace_commit_id == commit_id => {
            Ok(receipt.request_digest)
        }
        _ => Err(PublicationError::Corrupt),
    }
}

fn load_single_parent(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<Option<NamespaceCommitId>, PublicationError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM namespace_commit_parents WHERE namespace_commit_id = ?1",
        [commit_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if count > 1 {
        return Err(PublicationError::Corrupt);
    }
    connection
        .query_row(
            "SELECT parent_commit_id FROM namespace_commit_parents
             WHERE namespace_commit_id = ?1 AND parent_ordinal = 0",
            [commit_id.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|bytes| decode_identifier(&bytes, NamespaceCommitId::from_bytes))
        .transpose()
}

fn load_directory(
    transaction: &Transaction<'_>,
    revision_id: ObjectRevisionId,
    object_id: ObjectId,
    new_revision_id: ObjectRevisionId,
    volume_id: VolumeId,
    selected_name: &crate::NamespaceComponent,
) -> Result<LoadedDirectory, PublicationError> {
    let stored = load_object_revision(transaction, revision_id)?;
    if stored.kind != 1
        || stored.object_id != object_id
        || stored.volume_id != volume_id
        || stored.revision_id != revision_id
    {
        return Err(PublicationError::Corrupt);
    }
    let root = stored.directory_root.ok_or(PublicationError::Corrupt)?;
    Ok(LoadedDirectory {
        editor: load_path_editor(transaction, root, selected_name)?,
        object_id,
        prior_revision_id: Some(revision_id),
        new_revision_id,
    })
}

fn load_path_editor(
    transaction: &Transaction<'_>,
    root: DirectoryNodeDigest,
    name: &crate::NamespaceComponent,
) -> Result<DirectoryTrie, PublicationError> {
    let mut selected = root;
    let mut records = Vec::new();
    for depth in 0..=64 {
        let record =
            load_directory_node(transaction, selected)?.ok_or(PublicationError::Corrupt)?;
        let child = record.selected_child(name, depth)?;
        records.push(record);
        let Some(child) = child else {
            break;
        };
        selected = child;
    }
    DirectoryTrie::from_selected_records(root, records, name).map_err(Into::into)
}

fn validate_old_entry(
    transaction: &Transaction<'_>,
    publication: &RootFilePublication,
    editor: &DirectoryTrie,
) -> Result<(), PublicationError> {
    let leaf_name = publication
        .path
        .leaf_name()
        .ok_or(PublicationError::InvalidInput)?;
    let old = editor.lookup(leaf_name)?;
    if old.as_ref().map(DirectoryEntry::object_revision_id)
        != publication.expected_file_object_revision_id
    {
        return Err(PublicationError::StaleHead);
    }
    let Some(old) = old else {
        return if publication.file.expected_current_version_id.is_none() {
            Ok(())
        } else {
            Err(PublicationError::StaleHead)
        };
    };
    if old.object_id() != publication.file.object_id || old.kind() != DirectoryEntryKind::File {
        return Err(PublicationError::StaleHead);
    }
    let stored = load_object_revision(transaction, old.object_revision_id())?;
    if stored.kind == 2
        && stored.object_id == publication.file.object_id
        && stored.volume_id == publication.file.volume_id
        && stored.file_version_id == publication.file.expected_current_version_id
    {
        Ok(())
    } else {
        Err(PublicationError::Corrupt)
    }
}

struct DirectoryPathMutation {
    directories: Vec<DirectoryRevisionResult>,
    created_nodes: Vec<DirectoryNodeRecord>,
}

struct DirectoryRevisionResult {
    object_id: ObjectId,
    prior_revision_id: Option<ObjectRevisionId>,
    new_revision_id: ObjectRevisionId,
    directory_root: DirectoryNodeDigest,
}

fn mutate_directory_path(
    directories: Vec<LoadedDirectory>,
    publication: &RootFilePublication,
) -> Result<DirectoryPathMutation, PublicationError> {
    let leaf_name = publication
        .path
        .leaf_name()
        .ok_or(PublicationError::InvalidInput)?;
    let entry = DirectoryEntry::new(
        leaf_name.clone(),
        publication.file.object_id,
        publication.file_object_revision_id,
        DirectoryEntryKind::File,
        publication.entry_generation,
    )?;
    mutate_namespace_path(
        directories,
        &publication.path,
        entry,
        publication.expected_file_object_revision_id,
    )
}

fn mutate_namespace_path(
    mut directories: Vec<LoadedDirectory>,
    path: &NamespacePublicationPath,
    leaf_entry: DirectoryEntry,
    expected_leaf_revision_id: Option<ObjectRevisionId>,
) -> Result<DirectoryPathMutation, PublicationError> {
    let last = directories
        .len()
        .checked_sub(1)
        .ok_or(PublicationError::Corrupt)?;
    let (mut child_root, mut created_nodes) = mutate_entry(
        &mut directories[last].editor,
        leaf_entry,
        expected_leaf_revision_id,
    )?;
    let mut results = Vec::with_capacity(directories.len());
    results.push(directory_result(&directories[last], child_root));

    let components = path.path().components();
    for parent_index in (0..last).rev() {
        let child_index = parent_index
            .checked_add(1)
            .ok_or(PublicationError::Corrupt)?;
        let child = directories
            .get(child_index)
            .ok_or(PublicationError::Corrupt)?;
        let name = components
            .get(parent_index)
            .ok_or(PublicationError::Corrupt)?;
        let old_entry = directories[parent_index]
            .editor
            .lookup(name)?
            .ok_or(PublicationError::Corrupt)?;
        let replacement = DirectoryEntry::new(
            name.clone(),
            child.object_id,
            child.new_revision_id,
            DirectoryEntryKind::Directory,
            old_entry.generation(),
        )?;
        let (parent_root, records) = mutate_entry(
            &mut directories[parent_index].editor,
            replacement,
            Some(old_entry.object_revision_id()),
        )?;
        created_nodes.extend(records);
        child_root = parent_root;
        results.push(directory_result(&directories[parent_index], child_root));
    }
    results.reverse();
    Ok(DirectoryPathMutation {
        directories: results,
        created_nodes,
    })
}

fn mutate_entry(
    editor: &mut DirectoryTrie,
    entry: DirectoryEntry,
    expected_revision_id: Option<ObjectRevisionId>,
) -> Result<(DirectoryNodeDigest, Vec<DirectoryNodeRecord>), PublicationError> {
    let mutation = editor.upsert(entry, expected_revision_id)?;
    let records = mutation
        .created_nodes
        .iter()
        .map(|digest| editor.record(*digest))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((mutation.new_root, records))
}

const fn directory_result(
    loaded: &LoadedDirectory,
    directory_root: DirectoryNodeDigest,
) -> DirectoryRevisionResult {
    DirectoryRevisionResult {
        object_id: loaded.object_id,
        prior_revision_id: loaded.prior_revision_id,
        new_revision_id: loaded.new_revision_id,
        directory_root,
    }
}

fn persist_object_revisions(
    transaction: &Transaction<'_>,
    publication: &RootFilePublication,
    directories: &[DirectoryRevisionResult],
) -> Result<(), PublicationError> {
    persist_object_revision(
        transaction,
        ObjectRevisionInsert {
            revision_id: publication.file_object_revision_id,
            volume_id: publication.file.volume_id,
            object_id: publication.file.object_id,
            kind: 2,
            prior_revision_id: publication.expected_file_object_revision_id,
            directory_root: None,
            file_version_id: Some(publication.file.version_id),
            created_by: publication.file.created_by,
            created_at: publication.file.created_at,
        },
    )?;
    persist_directory_path_revisions(
        transaction,
        publication.file.volume_id,
        publication.file.created_by,
        publication.file.created_at,
        directories,
    )
}

fn persist_directory_path_revisions(
    transaction: &Transaction<'_>,
    volume_id: VolumeId,
    created_by: meshspan_domain::PrincipalId,
    created_at: meshspan_domain::UnixMicros,
    directories: &[DirectoryRevisionResult],
) -> Result<(), PublicationError> {
    for directory in directories {
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

#[derive(Clone, Copy)]
struct ObjectRevisionInsert {
    revision_id: ObjectRevisionId,
    volume_id: VolumeId,
    object_id: ObjectId,
    kind: u8,
    prior_revision_id: Option<ObjectRevisionId>,
    directory_root: Option<DirectoryNodeDigest>,
    file_version_id: Option<FileVersionId>,
    created_by: meshspan_domain::PrincipalId,
    created_at: meshspan_domain::UnixMicros,
}

fn persist_object_revision(
    transaction: &Transaction<'_>,
    revision: ObjectRevisionInsert,
) -> Result<(), PublicationError> {
    let digest = object_revision_digest(&revision);
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM object_revisions WHERE object_revision_id = ?1)",
        [revision.revision_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision != 0 {
        return Err(PublicationError::OperationConflict);
    }
    let prior = revision.prior_revision_id.map(ObjectRevisionId::as_bytes);
    let directory = revision.directory_root.map(DirectoryNodeDigest::as_bytes);
    let version = revision.file_version_id.map(FileVersionId::as_bytes);
    transaction.execute(
        "INSERT INTO object_revisions(
            object_revision_id, volume_id, object_id, object_kind, prior_revision_id,
            directory_root_digest, file_version_id, revision_digest, created_by, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            revision.revision_id.as_bytes().as_slice(),
            revision.volume_id.as_bytes().as_slice(),
            revision.object_id.as_bytes().as_slice(),
            revision.kind,
            prior.as_ref().map(<[u8; 16]>::as_slice),
            directory.as_ref().map(<[u8; 32]>::as_slice),
            version.as_ref().map(<[u8; 16]>::as_slice),
            digest.as_slice(),
            revision.created_by.as_bytes().as_slice(),
            revision.created_at.get()
        ],
    )?;
    Ok(())
}

fn load_object_revision(
    transaction: &Transaction<'_>,
    revision_id: ObjectRevisionId,
) -> Result<ObjectRevisionInsert, PublicationError> {
    type StoredObjectRevision = (
        Vec<u8>,
        Vec<u8>,
        i64,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        i64,
    );
    let stored: StoredObjectRevision = transaction.query_row(
        "SELECT volume_id, object_id, object_kind, prior_revision_id,
                directory_root_digest, file_version_id, revision_digest,
                created_by, created_at
         FROM object_revisions WHERE object_revision_id = ?1",
        [revision_id.as_bytes().as_slice()],
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
                row.get(8)?,
            ))
        },
    )?;
    let revision = ObjectRevisionInsert {
        revision_id,
        volume_id: decode_identifier(&stored.0, VolumeId::from_bytes)?,
        object_id: decode_identifier(&stored.1, ObjectId::from_bytes)?,
        kind: u8::try_from(stored.2).map_err(|_| PublicationError::Corrupt)?,
        prior_revision_id: decode_optional(stored.3.as_deref(), ObjectRevisionId::from_bytes)?,
        directory_root: stored
            .4
            .as_deref()
            .map(|bytes| copy_array(bytes).map(DirectoryNodeDigest::from_bytes))
            .transpose()?,
        file_version_id: decode_optional(stored.5.as_deref(), FileVersionId::from_bytes)?,
        created_by: decode_identifier(&stored.7, meshspan_domain::PrincipalId::from_bytes)?,
        created_at: meshspan_domain::UnixMicros::new(stored.8),
    };
    if copy_array(&stored.6)? == object_revision_digest(&revision) {
        Ok(revision)
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn decode_optional<T, E>(
    stored: Option<&[u8]>,
    constructor: impl FnOnce([u8; 16]) -> Result<T, E>,
) -> Result<Option<T>, PublicationError> {
    stored
        .map(|bytes| decode_identifier(bytes, constructor))
        .transpose()
}

fn persist_commit(
    transaction: &Transaction<'_>,
    intent: NamespaceIntent<'_>,
    request_digest: [u8; 32],
) -> Result<(), PublicationError> {
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM namespace_commits WHERE namespace_commit_id = ?1
         )",
        [intent.commit_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision != 0 {
        return Err(PublicationError::OperationConflict);
    }
    let commit_digest = commit_digest(intent, request_digest);
    transaction.execute(
        "INSERT INTO namespace_commits(
            namespace_commit_id, branch_id, volume_id, root_object_id,
            root_object_revision_id, created_by, publication_operation_id,
            created_at, commit_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            intent.commit_id.as_bytes().as_slice(),
            intent.branch_id.as_bytes().as_slice(),
            intent.volume_id.as_bytes().as_slice(),
            intent.root_object_id.as_bytes().as_slice(),
            intent.root_revision_id.as_bytes().as_slice(),
            intent.created_by.as_bytes().as_slice(),
            intent.operation_id.as_bytes().as_slice(),
            intent.created_at.get(),
            commit_digest.as_slice()
        ],
    )?;
    if let Some(parent) = intent.expected_commit_id {
        transaction.execute(
            "INSERT INTO namespace_commit_parents(
                namespace_commit_id, parent_ordinal, parent_commit_id
             ) VALUES (?1, 0, ?2)",
            params![
                intent.commit_id.as_bytes().as_slice(),
                parent.as_bytes().as_slice()
            ],
        )?;
    }
    Ok(())
}

fn advance_namespace_head(
    transaction: &Transaction<'_>,
    intent: NamespaceIntent<'_>,
    previous_sequence: u64,
) -> Result<u64, PublicationError> {
    let sequence = previous_sequence
        .checked_add(1)
        .ok_or(PublicationError::InvalidInput)?;
    let changed = if let Some(expected) = intent.expected_commit_id {
        transaction.execute(
            "UPDATE branch_namespace_heads
             SET namespace_commit_id = ?1, head_sequence = ?2
             WHERE branch_id = ?3 AND volume_id = ?4
               AND namespace_commit_id = ?5 AND head_sequence = ?6",
            params![
                intent.commit_id.as_bytes().as_slice(),
                to_i64(sequence)?,
                intent.branch_id.as_bytes().as_slice(),
                intent.volume_id.as_bytes().as_slice(),
                expected.as_bytes().as_slice(),
                to_i64(previous_sequence)?
            ],
        )?
    } else {
        transaction.execute(
            "INSERT INTO branch_namespace_heads(
                branch_id, volume_id, namespace_commit_id, head_sequence
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                intent.branch_id.as_bytes().as_slice(),
                intent.volume_id.as_bytes().as_slice(),
                intent.commit_id.as_bytes().as_slice(),
                to_i64(sequence)?
            ],
        )?
    };
    if changed == 1 {
        Ok(sequence)
    } else {
        Err(PublicationError::StaleHead)
    }
}

fn persist_namespace_operation(
    transaction: &Transaction<'_>,
    publication: &RootFilePublication,
    request_digest: [u8; 32],
    head_sequence: u64,
) -> Result<NamespacePublicationReceipt, PublicationError> {
    let result_digest = result_digest(
        publication.file.operation_id,
        request_digest,
        publication.file.version_id,
        publication.namespace_commit_id,
        head_sequence,
    );
    transaction.execute(
        "INSERT INTO namespace_publication_operations(
            operation_id, request_digest, namespace_commit_id, file_version_id,
            head_sequence, result_digest, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            publication.file.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            publication.namespace_commit_id.as_bytes().as_slice(),
            publication.file.version_id.as_bytes().as_slice(),
            to_i64(head_sequence)?,
            result_digest.as_slice(),
            publication.file.created_at.get()
        ],
    )?;
    Ok(NamespacePublicationReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: publication.file.operation_id,
        request_digest,
        file_version_id: publication.file.version_id,
        namespace_commit_id: publication.namespace_commit_id,
        head_sequence,
        result_digest,
    })
}

fn persist_directory_operation(
    transaction: &Transaction<'_>,
    publication: &DirectoryPublication,
    request_digest: [u8; 32],
    head_sequence: u64,
) -> Result<DirectoryPublicationReceipt, PublicationError> {
    let result_digest = directory_result_digest(
        publication.operation_id,
        request_digest,
        publication.directory_object_revision_id,
        publication.namespace_commit_id,
        head_sequence,
    );
    transaction.execute(
        "INSERT INTO directory_publication_operations(
            operation_id, request_digest, namespace_commit_id, directory_object_revision_id,
            head_sequence, result_digest, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            publication.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            publication.namespace_commit_id.as_bytes().as_slice(),
            publication
                .directory_object_revision_id
                .as_bytes()
                .as_slice(),
            to_i64(head_sequence)?,
            result_digest.as_slice(),
            publication.created_at.get()
        ],
    )?;
    Ok(DirectoryPublicationReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: publication.operation_id,
        request_digest,
        directory_object_revision_id: publication.directory_object_revision_id,
        namespace_commit_id: publication.namespace_commit_id,
        head_sequence,
        result_digest,
    })
}

type StoredReceipt = (Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);
type StoredDirectoryReceipt = (Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);

fn decode_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredReceipt,
) -> Result<NamespacePublicationReceipt, PublicationError> {
    let request_digest = copy_array(&stored.0)?;
    let namespace_commit_id = decode_identifier(&stored.1, NamespaceCommitId::from_bytes)?;
    let file_version_id = decode_identifier(&stored.2, FileVersionId::from_bytes)?;
    let head_sequence = from_i64(stored.3)?;
    let result_digest = copy_array(&stored.4)?;
    if result_digest
        != self::result_digest(
            operation_id,
            request_digest,
            file_version_id,
            namespace_commit_id,
            head_sequence,
        )
    {
        return Err(PublicationError::Corrupt);
    }
    Ok(NamespacePublicationReceipt {
        disposition,
        operation_id,
        request_digest,
        file_version_id,
        namespace_commit_id,
        head_sequence,
        result_digest,
    })
}

fn decode_directory_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredDirectoryReceipt,
) -> Result<DirectoryPublicationReceipt, PublicationError> {
    let request_digest = copy_array(&stored.0)?;
    let namespace_commit_id = decode_identifier(&stored.1, NamespaceCommitId::from_bytes)?;
    let directory_object_revision_id = decode_identifier(&stored.2, ObjectRevisionId::from_bytes)?;
    let head_sequence = from_i64(stored.3)?;
    let result_digest = copy_array(&stored.4)?;
    if result_digest
        != directory_result_digest(
            operation_id,
            request_digest,
            directory_object_revision_id,
            namespace_commit_id,
            head_sequence,
        )
    {
        return Err(PublicationError::Corrupt);
    }
    Ok(DirectoryPublicationReceipt {
        disposition,
        operation_id,
        request_digest,
        directory_object_revision_id,
        namespace_commit_id,
        head_sequence,
        result_digest,
    })
}

fn request_digest(publication: &RootFilePublication) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.path-file-publication.v1\0");
    digest.update(&publication_request_digest(publication.file));
    digest.update(&publication.root_object_id.as_bytes());
    update_optional_commit(&mut digest, publication.expected_namespace_commit_id);
    update_optional_revision(&mut digest, publication.expected_file_object_revision_id);
    digest.update(&publication.file_object_revision_id.as_bytes());
    digest.update(&publication.root_object_revision_id.as_bytes());
    digest.update(&publication.namespace_commit_id.as_bytes());
    update_publication_path(&mut digest, &publication.path);
    digest.update(&publication.entry_generation.to_be_bytes());
    digest.finalize().into()
}

fn directory_request_digest(publication: &DirectoryPublication) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.directory-publication.v1\0");
    digest.update(&publication.operation_id.as_bytes());
    digest.update(&publication.branch_id.as_bytes());
    digest.update(&publication.volume_id.as_bytes());
    digest.update(&publication.root_object_id.as_bytes());
    update_optional_commit(&mut digest, publication.expected_namespace_commit_id);
    digest.update(&publication.directory_object_id.as_bytes());
    digest.update(&publication.directory_object_revision_id.as_bytes());
    digest.update(&publication.root_object_revision_id.as_bytes());
    digest.update(&publication.namespace_commit_id.as_bytes());
    update_publication_path(&mut digest, &publication.path);
    digest.update(&publication.entry_generation.to_be_bytes());
    digest.update(&publication.created_by.as_bytes());
    digest.update(&publication.created_at.get().to_be_bytes());
    digest.finalize().into()
}

fn update_publication_path(digest: &mut blake3::Hasher, path: &NamespacePublicationPath) {
    digest.update(
        &u16::try_from(path.path().components().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    for component in path.path().components() {
        update_text(digest, component.canonical());
        update_text(digest, component.display());
    }
    for transition in path.ancestors() {
        digest.update(&transition.object_id().as_bytes());
        digest.update(&transition.expected_revision_id().as_bytes());
        digest.update(&transition.new_revision_id().as_bytes());
    }
}

fn commit_digest(intent: NamespaceIntent<'_>, request_digest: [u8; 32]) -> [u8; 32] {
    commit_digest_fields(
        &StoredCommit {
            commit_id: intent.commit_id,
            branch_id: intent.branch_id,
            volume_id: intent.volume_id,
            root_object_id: intent.root_object_id,
            root_object_revision_id: intent.root_revision_id,
            parent_id: intent.expected_commit_id,
            created_by: intent.created_by,
            operation_id: intent.operation_id,
            created_at: intent.created_at,
        },
        request_digest,
    )
}

fn commit_digest_fields(commit: &StoredCommit, request_digest: [u8; 32]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.namespace-commit.v1\0");
    digest.update(&commit.commit_id.as_bytes());
    digest.update(&commit.branch_id.as_bytes());
    digest.update(&commit.volume_id.as_bytes());
    digest.update(&commit.root_object_id.as_bytes());
    digest.update(&commit.root_object_revision_id.as_bytes());
    update_optional_commit(&mut digest, commit.parent_id);
    digest.update(&commit.created_by.as_bytes());
    digest.update(&commit.operation_id.as_bytes());
    digest.update(&commit.created_at.get().to_be_bytes());
    digest.update(&request_digest);
    digest.finalize().into()
}

fn object_revision_digest(revision: &ObjectRevisionInsert) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.object-revision.v1\0");
    digest.update(&revision.revision_id.as_bytes());
    digest.update(&revision.volume_id.as_bytes());
    digest.update(&revision.object_id.as_bytes());
    digest.update(&[revision.kind]);
    update_optional_revision(&mut digest, revision.prior_revision_id);
    update_optional_digest(&mut digest, revision.directory_root);
    update_optional_version(&mut digest, revision.file_version_id);
    digest.update(&revision.created_by.as_bytes());
    digest.update(&revision.created_at.get().to_be_bytes());
    digest.finalize().into()
}

fn result_digest(
    operation_id: OperationId,
    request_digest: [u8; 32],
    file_version_id: FileVersionId,
    namespace_commit_id: NamespaceCommitId,
    head_sequence: u64,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.namespace-publication-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&file_version_id.as_bytes());
    digest.update(&namespace_commit_id.as_bytes());
    digest.update(&head_sequence.to_be_bytes());
    digest.finalize().into()
}

fn directory_result_digest(
    operation_id: OperationId,
    request_digest: [u8; 32],
    directory_object_revision_id: ObjectRevisionId,
    namespace_commit_id: NamespaceCommitId,
    head_sequence: u64,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.directory-publication-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&directory_object_revision_id.as_bytes());
    digest.update(&namespace_commit_id.as_bytes());
    digest.update(&head_sequence.to_be_bytes());
    digest.finalize().into()
}

fn update_optional_commit(digest: &mut blake3::Hasher, value: Option<NamespaceCommitId>) {
    update_optional_bytes(digest, value.map(NamespaceCommitId::as_bytes).as_ref());
}

fn update_optional_revision(digest: &mut blake3::Hasher, value: Option<ObjectRevisionId>) {
    update_optional_bytes(digest, value.map(ObjectRevisionId::as_bytes).as_ref());
}

fn update_optional_version(digest: &mut blake3::Hasher, value: Option<FileVersionId>) {
    update_optional_bytes(digest, value.map(FileVersionId::as_bytes).as_ref());
}

fn update_optional_digest(digest: &mut blake3::Hasher, value: Option<DirectoryNodeDigest>) {
    update_optional_bytes(digest, value.map(DirectoryNodeDigest::as_bytes).as_ref());
}

fn update_optional_bytes<const LENGTH: usize>(
    digest: &mut blake3::Hasher,
    value: Option<&[u8; LENGTH]>,
) {
    if let Some(value) = value {
        digest.update(&[1]);
        digest.update(value);
    } else {
        digest.update(&[0]);
    }
}

fn update_text(digest: &mut blake3::Hasher, value: &str) {
    digest.update(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    digest.update(value.as_bytes());
}

fn inject(
    selected: Option<NamespaceFaultPoint>,
    current: NamespaceFaultPoint,
) -> Result<(), PublicationError> {
    if selected == Some(current) {
        Err(PublicationError::InjectedFault)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "namespace_publication_tests.rs"]
mod tests;
