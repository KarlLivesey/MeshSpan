// SPDX-License-Identifier: GPL-2.0-only

//! Atomic immutable root-directory mutation and volume branch-head publication.

#[path = "namespace_publication/digest.rs"]
mod digest;
#[path = "namespace_publication/reconciliation_apply.rs"]
mod reconciliation_apply;
#[path = "namespace_publication/repository.rs"]
mod repository;
#[path = "namespace_publication/snapshot_restore.rs"]
mod snapshot_restore;

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{
    BranchId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId, VolumeId,
};
use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::{
    BranchNamespaceHead, DirectoryPublication, DirectoryPublicationReceipt,
    NamespacePublicationPath, NamespacePublicationReceipt, PublicationDisposition,
    PublicationError, RootFilePublication, advance_file_head, load_directory_node,
    persist_directory_node, persist_manifest, persist_version, prepare_file,
    publication_request_digest,
};
use crate::{
    DirectoryEntry, DirectoryEntryKind, DirectoryNodeDigest, DirectoryNodeRecord, DirectoryTrie,
    NamespaceReplayBase, NamespaceReplayEntry, ReconciliationCommit,
};

use digest::{directory_request as directory_request_digest, file_request as request_digest};
use repository::{
    ObjectRevisionInsert, advance_namespace_head, load_commit,
    load_file_operation_raw as load_operation_raw, load_object_revision, persist_commit,
    persist_directory_intent, persist_directory_operation, persist_directory_path_revisions,
    persist_file_intent, persist_file_operation as persist_namespace_operation,
    persist_object_revision,
};
pub(super) use repository::{
    load_branch_intent, load_directory_operation, load_file_operation as load_operation, load_head,
    load_reconciliation_commit,
};

pub(super) fn prepare_snapshot_restore(
    connection: &mut Connection,
    publication: super::SnapshotRestorePublication,
    fault: Option<NamespaceFaultPoint>,
) -> Result<super::SnapshotRestoreReceipt, PublicationError> {
    snapshot_restore::prepare(connection, publication, fault)
}

#[cfg(test)]
pub(super) fn prepare_snapshot_restore_with_fault(
    connection: &mut Connection,
    publication: super::SnapshotRestorePublication,
    fault: NamespaceFaultPoint,
) -> Result<super::SnapshotRestoreReceipt, PublicationError> {
    snapshot_restore::prepare(connection, publication, Some(fault))
}

pub(super) fn activate_snapshot_restore(
    connection: &mut Connection,
    receipt: super::SnapshotRestoreReceipt,
    activated_at: meshspan_domain::UnixMicros,
) -> Result<super::BranchNamespaceHead, PublicationError> {
    snapshot_restore::activate(connection, receipt, activated_at)
}

pub(super) fn load_snapshot_restore(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<super::SnapshotRestoreReceipt>, PublicationError> {
    snapshot_restore::load_receipt(connection, operation_id, disposition)
}

pub(super) fn verify_snapshot_restore_head(
    connection: &Connection,
    volume_id: VolumeId,
    receipt: super::SnapshotRestoreReceipt,
) -> Result<super::VerifiedSnapshotRestoreHead, PublicationError> {
    snapshot_restore::verify_head(connection, volume_id, receipt)
}

pub(super) fn apply_reconciliation(
    connection: &mut Connection,
    application: super::NamespaceReconciliationApplication,
    prepared: &crate::PreparedNamespaceReconciliation,
) -> Result<super::NamespaceReconciliationReceipt, PublicationError> {
    reconciliation_apply::apply(connection, application, prepared, None)
}

#[cfg(test)]
pub(super) fn apply_reconciliation_with_fault(
    connection: &mut Connection,
    application: super::NamespaceReconciliationApplication,
    prepared: &crate::PreparedNamespaceReconciliation,
    fault: NamespaceFaultPoint,
) -> Result<super::NamespaceReconciliationReceipt, PublicationError> {
    reconciliation_apply::apply(connection, application, prepared, Some(fault))
}

pub(super) fn load_reconciliation_receipt(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<super::NamespaceReconciliationReceipt>, PublicationError> {
    let receipt = reconciliation_apply::load_receipt(
        connection,
        operation_id,
        PublicationDisposition::Replayed,
    )?;
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    let commit = repository::load_reconciliation_commit(connection, receipt.namespace_commit_id)?
        .ok_or(PublicationError::Corrupt)?;
    if commit.operation_id == operation_id
        && commit.root_object_revision_id == receipt.root_object_revision_id
        && commit.payload
            == (crate::ReconciliationCommitPayload::Merge {
                replay_digest: receipt.replay_plan_digest,
            })
    {
        Ok(Some(receipt))
    } else {
        Err(PublicationError::Corrupt)
    }
}

pub(super) fn verify_reconciliation_head(
    connection: &Connection,
    volume_id: VolumeId,
    expected_namespace_commit_id: NamespaceCommitId,
    receipt: super::NamespaceReconciliationReceipt,
) -> Result<super::VerifiedReconciliationHead, PublicationError> {
    let durable = load_reconciliation_receipt(connection, receipt.operation_id)?
        .ok_or(PublicationError::InvalidInput)?;
    if !same_reconciliation_outcome(durable, receipt) {
        return Err(PublicationError::OperationConflict);
    }
    let commit = repository::load_reconciliation_commit(connection, receipt.namespace_commit_id)?
        .ok_or(PublicationError::Corrupt)?;
    if commit.volume_id != volume_id
        || commit.root_object_revision_id != receipt.root_object_revision_id
        || !commit.parents.contains(&expected_namespace_commit_id)
        || !matches!(
            commit.payload,
            crate::ReconciliationCommitPayload::Merge { .. }
        )
    {
        return Err(PublicationError::InvalidInput);
    }
    Ok(super::VerifiedReconciliationHead::new(
        durable,
        volume_id,
        expected_namespace_commit_id,
    ))
}

fn same_reconciliation_outcome(
    left: super::NamespaceReconciliationReceipt,
    right: super::NamespaceReconciliationReceipt,
) -> bool {
    left.operation_id == right.operation_id
        && left.request_digest == right.request_digest
        && left.causal_plan_digest == right.causal_plan_digest
        && left.replay_plan_digest == right.replay_plan_digest
        && left.namespace_commit_id == right.namespace_commit_id
        && left.root_object_revision_id == right.root_object_revision_id
        && left.result_digest == right.result_digest
}

pub(super) fn publish(
    connection: &mut Connection,
    publication: &RootFilePublication,
    fault: Option<NamespaceFaultPoint>,
) -> Result<NamespacePublicationReceipt, PublicationError> {
    publish_inner(connection, publication, None, fault)
        .map(|result| result.0)
        .map_err(|error| match error {
            crate::HandleError::Namespace(error) => error,
            _ => PublicationError::Corrupt,
        })
}

pub(super) fn publish_and_open(
    connection: &mut Connection,
    publication: &RootFilePublication,
    open: &crate::OpenHandleRequest,
) -> Result<(NamespacePublicationReceipt, crate::OpenHandleReceipt), crate::HandleError> {
    let (namespace, handle) = publish_inner(connection, publication, Some(open), None)?;
    Ok((namespace, handle.ok_or(crate::HandleError::Corrupt)?))
}

fn publish_inner(
    connection: &mut Connection,
    publication: &RootFilePublication,
    open: Option<&crate::OpenHandleRequest>,
    fault: Option<NamespaceFaultPoint>,
) -> Result<
    (
        NamespacePublicationReceipt,
        Option<crate::OpenHandleReceipt>,
    ),
    crate::HandleError,
> {
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
        return Err(PublicationError::OperationConflict.into());
    }
    if let Some(receipt) = load_operation(
        &transaction,
        publication.file.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return if receipt.request_digest == request_digest {
            let handle = open
                .map(|request| {
                    crate::handles::load_open_receipt(
                        &transaction,
                        request.operation_id,
                        PublicationDisposition::Replayed,
                    )?
                    .ok_or(crate::HandleError::Corrupt)
                })
                .transpose()?;
            Ok((receipt, handle))
        } else {
            Err(PublicationError::OperationConflict.into())
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
    crate::version_retention::record_supersession(&transaction, publication.file)?;
    advance_file_head(&transaction, publication.file, file_head.sequence)?;
    inject(fault, NamespaceFaultPoint::FileVersion)?;

    persist_object_revisions(&transaction, publication, &namespace.directories)?;
    inject(fault, NamespaceFaultPoint::ObjectRevisions)?;
    persist_commit(&transaction, intent, request_digest)?;
    persist_file_intent(&transaction, publication)?;
    inject(fault, NamespaceFaultPoint::NamespaceCommit)?;
    let head_sequence = advance_namespace_head(&transaction, intent, head_sequence)?;
    inject(fault, NamespaceFaultPoint::Heads)?;
    crate::handles::advance_flush_progress(&transaction, publication)?;
    let handle = open
        .map(|request| {
            crate::handles::open_created(
                &transaction,
                request,
                crate::handles::ResolvedFile::created(
                    publication.namespace_commit_id,
                    publication.file.object_id,
                    publication.file_object_revision_id,
                    publication.file.version_id,
                ),
            )
        })
        .transpose()?;
    let receipt =
        persist_namespace_operation(&transaction, publication, request_digest, head_sequence)?;
    inject(fault, NamespaceFaultPoint::Operation)?;
    transaction.commit()?;
    Ok((receipt, handle))
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
    persist_directory_intent(&transaction, publication)?;
    inject(fault, NamespaceFaultPoint::NamespaceCommit)?;
    let head_sequence = advance_namespace_head(&transaction, intent, head_sequence)?;
    inject(fault, NamespaceFaultPoint::Heads)?;
    let receipt =
        persist_directory_operation(&transaction, publication, request_digest, head_sequence)?;
    inject(fault, NamespaceFaultPoint::Operation)?;
    transaction.commit()?;
    Ok(receipt)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NamespaceFaultPoint {
    DirectoryNodes,
    FileVersion,
    ObjectRevisions,
    NamespaceCommit,
    Heads,
    Operation,
    ReconciliationLeaf,
    ReconciliationDirectories,
    ReconciliationCommit,
    ReconciliationOperation,
    SnapshotRestoreCommit,
    SnapshotRestoreOperation,
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
    if commit.volume_id != intent.volume_id || commit.root_object_id != intent.root_object_id {
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
    transaction: &Connection,
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

pub(super) fn load_replay_base(
    connection: &Connection,
    converged: &ReconciliationCommit,
    intents: &[crate::BranchMutationIntent],
) -> Result<NamespaceReplayBase, PublicationError> {
    let root = load_object_revision(connection, converged.root_object_revision_id)?;
    if root.kind != 1
        || root.volume_id != converged.volume_id
        || root.object_id != converged.root_object_id
    {
        return Err(PublicationError::Corrupt);
    }
    let mut entries = BTreeMap::new();
    for intent in intents {
        load_replay_path(
            connection,
            converged.volume_id,
            converged.root_object_id,
            converged.root_object_revision_id,
            &intent.path,
            &mut entries,
        )?;
    }
    Ok(NamespaceReplayBase {
        root_object_revision_id: Some(converged.root_object_revision_id),
        entries: entries.into_values().collect(),
    })
}

fn load_replay_path(
    connection: &Connection,
    volume_id: VolumeId,
    mut directory_object_id: ObjectId,
    mut directory_revision_id: ObjectRevisionId,
    path: &crate::NamespacePath,
    entries: &mut BTreeMap<Vec<String>, NamespaceReplayEntry>,
) -> Result<(), PublicationError> {
    let mut selected_path = Vec::with_capacity(path.components().len());
    for (index, component) in path.components().iter().enumerate() {
        let directory = load_object_revision(connection, directory_revision_id)?;
        if directory.kind != 1
            || directory.volume_id != volume_id
            || directory.object_id != directory_object_id
        {
            return Err(PublicationError::Corrupt);
        }
        let root = directory.directory_root.ok_or(PublicationError::Corrupt)?;
        let editor = load_path_editor(connection, root, component)?;
        let Some(entry) = editor.lookup(component)? else {
            break;
        };
        selected_path.push(entry.name().clone());
        let selected = crate::NamespacePath::from_stored_components(selected_path.clone())
            .map_err(|_| PublicationError::Corrupt)?;
        let replay_entry = NamespaceReplayEntry {
            path: selected,
            object_id: entry.object_id(),
            object_revision_id: entry.object_revision_id(),
            kind: entry.kind(),
            entry_generation: entry.generation(),
        };
        let key = replay_entry
            .path
            .components()
            .iter()
            .map(|component| component.canonical().to_owned())
            .collect::<Vec<_>>();
        if entries
            .insert(key, replay_entry.clone())
            .is_some_and(|existing| existing != replay_entry)
        {
            return Err(PublicationError::Corrupt);
        }
        if index + 1 == path.components().len() {
            break;
        }
        if entry.kind() != DirectoryEntryKind::Directory {
            break;
        }
        directory_object_id = entry.object_id();
        directory_revision_id = entry.object_revision_id();
    }
    Ok(())
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
