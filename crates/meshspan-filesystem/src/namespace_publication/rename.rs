// SPDX-License-Identifier: GPL-2.0-only

//! Atomic branch-local same-volume rename and move transaction.

use std::collections::BTreeSet;

use meshspan_domain::{FederatedMutationAcknowledgement, ObjectRevisionId, OperationId};
use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::super::load_file_head;
use super::repository::{
    advance_namespace_head, load_commit, load_object_revision, persist_branch_intent,
    persist_commit, persist_directory_path_revisions, rename_operation,
};
use super::{
    NamespaceFaultPoint, NamespaceIntent, inject, load_head, load_path_directories,
    mutate_namespace_path, persist_directory_node, remove_namespace_path,
};
use crate::{
    BranchMutation, BranchMutationIntent, BranchRenameIntent, DirectoryEntry, DirectoryEntryKind,
    FederatedNamespaceMutationProposal, HandleError, NamespaceRenamePublication,
    NamespaceRenameReceipt, PublicationDisposition, PublicationError,
};

pub(super) fn apply(
    connection: &mut Connection,
    publication: &NamespaceRenamePublication,
    acknowledgement: Option<&FederatedMutationAcknowledgement>,
    fault: Option<NamespaceFaultPoint>,
) -> Result<NamespaceRenameReceipt, HandleError> {
    validate_shape(publication)?;
    let request_digest = super::digest::rename_request(publication);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = rename_operation::load(
        &transaction,
        publication.operation_id,
        PublicationDisposition::Replayed,
    )? {
        let receipt = validate_receipt(&transaction, receipt)?;
        return if receipt.request_digest == request_digest {
            super::federated_mutation::ensure_exact(
                &transaction,
                publication.namespace_commit_id,
                acknowledgement,
            )?;
            Ok(receipt)
        } else {
            Err(HandleError::OperationConflict)
        };
    }
    reject_operation_collision(&transaction, publication.operation_id)?;
    let (current_root, head_sequence) = load_expected_head(&transaction, publication)?;
    let revision = persist_namespace_move(&transaction, publication, current_root, fault)?;

    let intent = rename_intent(publication, &revision)?;
    let namespace = NamespaceIntent {
        operation_id: publication.operation_id,
        branch_id: publication.branch_id,
        volume_id: publication.volume_id,
        root_object_id: publication.root_object_id,
        expected_commit_id: Some(publication.expected_namespace_commit_id),
        root_revision_id: publication.root_object_revision_id,
        commit_id: publication.namespace_commit_id,
        path: &publication.target,
        created_by: publication.created_by,
        created_at: publication.created_at,
    };
    persist_commit(&transaction, namespace, request_digest)?;
    persist_branch_intent(&transaction, &intent)?;
    inject(fault, NamespaceFaultPoint::RenameCommit)?;
    let head_sequence = advance_namespace_head(&transaction, namespace, head_sequence)?;
    crate::handles::relocate_handle_paths(
        &transaction,
        publication.branch_id,
        publication.volume_id,
        publication.expected_object_id,
        publication.source.path(),
        publication.target.path(),
    )?;
    inject(fault, NamespaceFaultPoint::RenameHandles)?;
    let receipt =
        rename_operation::persist(&transaction, publication, request_digest, head_sequence)?;
    if let Some(acknowledgement) = acknowledgement {
        super::federated_mutation::persist(
            &transaction,
            publication.namespace_commit_id,
            acknowledgement,
        )?;
    }
    inject(fault, NamespaceFaultPoint::RenameOperation)?;
    transaction.commit()?;
    Ok(receipt)
}

pub(super) fn federated_mutation_digest(
    connection: &Connection,
    publication: &NamespaceRenamePublication,
) -> Result<[u8; 32], HandleError> {
    Ok(federated_mutation_proposal(connection, publication)?.payload_digest())
}

pub(super) fn federated_mutation_proposal(
    connection: &Connection,
    publication: &NamespaceRenamePublication,
) -> Result<FederatedNamespaceMutationProposal, HandleError> {
    validate_shape(publication)?;
    let (current_root, _) = load_expected_head(connection, publication)?;
    let directories = load_path_directories(
        connection,
        publication.volume_id,
        publication.root_object_id,
        current_root,
        publication.intermediate_root_object_revision_id,
        &publication.source,
    )?;
    let revision = validate_source(connection, publication, &directories)?;
    reject_cycle(publication, revision.kind)?;
    let intent = rename_intent(publication, &revision)?;
    let namespace = NamespaceIntent {
        operation_id: publication.operation_id,
        branch_id: publication.branch_id,
        volume_id: publication.volume_id,
        root_object_id: publication.root_object_id,
        expected_commit_id: Some(publication.expected_namespace_commit_id),
        root_revision_id: publication.root_object_revision_id,
        commit_id: publication.namespace_commit_id,
        path: &publication.target,
        created_by: publication.created_by,
        created_at: publication.created_at,
    };
    Ok(super::federated_mutation::mutation_proposal(
        namespace,
        super::digest::rename_request(publication),
        intent,
    )?)
}

fn persist_namespace_move(
    transaction: &Transaction<'_>,
    publication: &NamespaceRenamePublication,
    current_root: ObjectRevisionId,
    fault: Option<NamespaceFaultPoint>,
) -> Result<super::repository::ObjectRevisionInsert, HandleError> {
    let source_directories = load_path_directories(
        transaction,
        publication.volume_id,
        publication.root_object_id,
        current_root,
        publication.intermediate_root_object_revision_id,
        &publication.source,
    )?;
    let revision = validate_source(transaction, publication, &source_directories)?;
    reject_cycle(publication, revision.kind)?;
    crate::handles::prepare_rename(
        transaction,
        publication.branch_id,
        publication.volume_id,
        publication.expected_object_id,
        publication.requesting_handle_id,
        publication.created_at,
    )?;
    let source_mutation = remove_namespace_path(
        source_directories,
        &publication.source,
        publication.expected_object_revision_id,
    )?;
    persist_path_mutation(transaction, publication, &source_mutation)?;
    inject(fault, NamespaceFaultPoint::RenameSource)?;

    let target_directories = load_path_directories(
        transaction,
        publication.volume_id,
        publication.root_object_id,
        publication.intermediate_root_object_revision_id,
        publication.root_object_revision_id,
        &publication.target,
    )?;
    let target_name = publication
        .target
        .leaf_name()
        .ok_or(PublicationError::InvalidInput)?;
    if target_directories
        .last()
        .ok_or(PublicationError::Corrupt)?
        .editor
        .lookup(target_name)
        .map_err(PublicationError::from)?
        .is_some()
    {
        return Err(HandleError::AlreadyExists);
    }
    let entry = DirectoryEntry::new(
        target_name.clone(),
        publication.expected_object_id,
        publication.expected_object_revision_id,
        revision_kind(revision.kind)?,
        publication.target_entry_generation,
    )
    .map_err(PublicationError::from)?;
    let target_mutation =
        mutate_namespace_path(target_directories, &publication.target, entry, None)?;
    persist_path_mutation(transaction, publication, &target_mutation)?;
    inject(fault, NamespaceFaultPoint::RenameTarget)?;
    Ok(revision)
}

pub(super) fn resolve(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<NamespaceRenameReceipt>, PublicationError> {
    let receipt =
        rename_operation::load(connection, operation_id, PublicationDisposition::Replayed)?;
    receipt
        .map(|receipt| validate_receipt(connection, receipt))
        .transpose()
}

fn validate_receipt(
    connection: &Connection,
    receipt: NamespaceRenameReceipt,
) -> Result<NamespaceRenameReceipt, PublicationError> {
    let commit = load_commit(connection, receipt.namespace_commit_id)?;
    let intent = super::load_branch_intent(connection, receipt.namespace_commit_id)?
        .ok_or(PublicationError::Corrupt)?;
    if commit.operation_id == receipt.operation_id
        && intent.object_id == receipt.object_id
        && intent.object_revision_id == receipt.object_revision_id
        && intent.rename.is_some()
    {
        Ok(receipt)
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn validate_shape(publication: &NamespaceRenamePublication) -> Result<(), PublicationError> {
    if publication.source.path() == publication.target.path()
        || publication.expected_source_entry_generation == 0
        || publication.target_entry_generation == 0
        || publication.root_object_id == publication.expected_object_id
        || publication.intermediate_root_object_revision_id == publication.root_object_revision_id
        || publication.intermediate_root_object_revision_id
            == publication.expected_object_revision_id
        || publication.root_object_revision_id == publication.expected_object_revision_id
    {
        return Err(PublicationError::InvalidInput);
    }
    let mut new_revisions = BTreeSet::from([
        publication.intermediate_root_object_revision_id,
        publication.root_object_revision_id,
    ]);
    for transition in publication
        .source
        .ancestors()
        .iter()
        .chain(publication.target.ancestors())
    {
        if !new_revisions.insert(transition.new_revision_id()) {
            return Err(PublicationError::InvalidInput);
        }
    }
    Ok(())
}

fn load_expected_head(
    transaction: &Connection,
    publication: &NamespaceRenamePublication,
) -> Result<(ObjectRevisionId, u64), PublicationError> {
    let head = load_head(transaction, publication.branch_id, publication.volume_id)?
        .ok_or(PublicationError::StaleHead)?;
    if head.namespace_commit_id != publication.expected_namespace_commit_id {
        return Err(PublicationError::StaleHead);
    }
    let commit = load_commit(transaction, head.namespace_commit_id)?;
    if commit.volume_id != publication.volume_id
        || commit.root_object_id != publication.root_object_id
    {
        return Err(PublicationError::Corrupt);
    }
    Ok((commit.root_object_revision_id, head.sequence))
}

fn validate_source(
    transaction: &Connection,
    publication: &NamespaceRenamePublication,
    directories: &[super::LoadedDirectory],
) -> Result<super::repository::ObjectRevisionInsert, HandleError> {
    let source_name = publication
        .source
        .leaf_name()
        .ok_or(PublicationError::InvalidInput)?;
    let entry = directories
        .last()
        .ok_or(PublicationError::Corrupt)?
        .editor
        .lookup(source_name)
        .map_err(PublicationError::from)?
        .ok_or(HandleError::NotFound)?;
    if entry.object_id() != publication.expected_object_id
        || entry.object_revision_id() != publication.expected_object_revision_id
        || entry.generation() != publication.expected_source_entry_generation
    {
        return Err(PublicationError::StaleHead.into());
    }
    let revision = load_object_revision(transaction, publication.expected_object_revision_id)?;
    if revision.volume_id != publication.volume_id
        || revision.object_id != publication.expected_object_id
        || revision.kind != kind_code(entry.kind())
    {
        return Err(PublicationError::Corrupt.into());
    }
    if let Some(version_id) = revision.file_version_id {
        let head = load_file_head(
            transaction,
            publication.branch_id,
            publication.expected_object_id,
        )?
        .ok_or(PublicationError::Corrupt)?;
        if head.volume_id != publication.volume_id || head.current_version_id != Some(version_id) {
            return Err(PublicationError::StaleHead.into());
        }
    }
    Ok(revision)
}

fn reject_cycle(
    publication: &NamespaceRenamePublication,
    object_kind: u8,
) -> Result<(), PublicationError> {
    if object_kind != 1 {
        return Ok(());
    }
    let source = publication
        .source
        .path()
        .components()
        .iter()
        .map(crate::NamespaceComponent::canonical)
        .collect::<Vec<_>>();
    let target = publication
        .target
        .path()
        .components()
        .iter()
        .map(crate::NamespaceComponent::canonical)
        .collect::<Vec<_>>();
    if source.len() < target.len() && target.starts_with(&source) {
        Err(PublicationError::InvalidInput)
    } else {
        Ok(())
    }
}

fn persist_path_mutation(
    transaction: &Transaction<'_>,
    publication: &NamespaceRenamePublication,
    mutation: &super::DirectoryPathMutation,
) -> Result<(), PublicationError> {
    for record in &mutation.created_nodes {
        persist_directory_node(transaction, record, publication.created_at)?;
    }
    persist_directory_path_revisions(
        transaction,
        publication.volume_id,
        publication.created_by,
        publication.created_at,
        &mutation.directories,
    )
}

pub(super) fn rename_intent(
    publication: &NamespaceRenamePublication,
    revision: &super::repository::ObjectRevisionInsert,
) -> Result<BranchMutationIntent, PublicationError> {
    let mutation = match (revision.kind, revision.file_version_id) {
        (1, None) => BranchMutation::CreateDirectory,
        (2, Some(version_id)) => BranchMutation::File { version_id },
        _ => return Err(PublicationError::Corrupt),
    };
    Ok(BranchMutationIntent {
        commit_id: publication.namespace_commit_id,
        path: publication.target.path().clone(),
        ancestors: publication.target.ancestors().to_vec(),
        object_id: publication.expected_object_id,
        object_revision_id: publication.expected_object_revision_id,
        prior_object_revision_id: revision.prior_revision_id,
        entry_generation: publication.target_entry_generation,
        mutation,
        rename: Some(BranchRenameIntent {
            source_path: publication.source.path().clone(),
            source_ancestors: publication.source.ancestors().to_vec(),
            source_entry_generation: publication.expected_source_entry_generation,
            intermediate_root_object_revision_id: publication.intermediate_root_object_revision_id,
        }),
    })
}

fn reject_operation_collision(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<(), PublicationError> {
    let collision: i64 = transaction.query_row(
        "SELECT (
            EXISTS(SELECT 1 FROM namespace_publication_operations WHERE operation_id = ?1)
          + EXISTS(SELECT 1 FROM directory_publication_operations WHERE operation_id = ?1)
          + EXISTS(SELECT 1 FROM namespace_snapshot_restore_operations WHERE operation_id = ?1)
          + EXISTS(SELECT 1 FROM namespace_reconciliation_operations WHERE operation_id = ?1)
          + EXISTS(SELECT 1 FROM namespace_unlink_operations WHERE operation_id = ?1)
         )",
        [operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision == 0 {
        Ok(())
    } else {
        Err(PublicationError::OperationConflict)
    }
}

const fn revision_kind(kind: u8) -> Result<DirectoryEntryKind, PublicationError> {
    match kind {
        1 => Ok(DirectoryEntryKind::Directory),
        2 => Ok(DirectoryEntryKind::File),
        _ => Err(PublicationError::Corrupt),
    }
}

const fn kind_code(kind: DirectoryEntryKind) -> u8 {
    match kind {
        DirectoryEntryKind::Directory => 1,
        DirectoryEntryKind::File => 2,
    }
}
