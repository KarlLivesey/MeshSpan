// SPDX-License-Identifier: GPL-2.0-only

//! Atomic logical unlink with direct or durable delete-on-close authority.

use std::collections::BTreeSet;

use meshspan_domain::{FederatedMutationAcknowledgement, ObjectRevisionId, OperationId};
use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::super::load_file_head;
use super::repository::{
    advance_namespace_head, load_commit, load_object_revision, persist_branch_intent,
    persist_commit, persist_directory_path_revisions, unlink_operation,
};
use super::{
    NamespaceFaultPoint, NamespaceIntent, inject, load_head, load_path_directories,
    persist_directory_node, remove_namespace_path,
};
use crate::{
    BranchMutation, BranchMutationIntent, DirectoryEntryKind, FederatedNamespaceMutationProposal,
    HandleError, NamespaceUnlinkAuthority, NamespaceUnlinkPublication, NamespaceUnlinkReceipt,
    PublicationDisposition, PublicationError,
};

pub(super) fn apply(
    connection: &mut Connection,
    publication: &NamespaceUnlinkPublication,
    acknowledgement: Option<&FederatedMutationAcknowledgement>,
    fault: Option<NamespaceFaultPoint>,
) -> Result<NamespaceUnlinkReceipt, HandleError> {
    validate_shape(publication)?;
    let request_digest = super::digest::unlink_request(publication);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = unlink_operation::load(
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
    let directories = load_path_directories(
        &transaction,
        publication.volume_id,
        publication.root_object_id,
        current_root,
        publication.root_object_revision_id,
        &publication.path,
    )?;
    let revision = validate_target(&transaction, publication, &directories)?;
    crate::handles::prepare_unlink(&transaction, publication)?;
    let mutation = remove_namespace_path(
        directories,
        &publication.path,
        publication.expected_object_revision_id,
    )?;
    persist_path_mutation(&transaction, publication, &mutation)?;
    inject(fault, NamespaceFaultPoint::UnlinkPath)?;

    let intent = unlink_intent(publication, &revision)?;
    let namespace = NamespaceIntent {
        operation_id: publication.operation_id,
        branch_id: publication.branch_id,
        volume_id: publication.volume_id,
        root_object_id: publication.root_object_id,
        expected_commit_id: Some(publication.expected_namespace_commit_id),
        root_revision_id: publication.root_object_revision_id,
        commit_id: publication.namespace_commit_id,
        path: &publication.path,
        created_by: publication.created_by,
        created_at: publication.created_at,
    };
    persist_commit(&transaction, namespace, request_digest)?;
    persist_branch_intent(&transaction, &intent)?;
    inject(fault, NamespaceFaultPoint::UnlinkCommit)?;
    let head_sequence = advance_namespace_head(&transaction, namespace, head_sequence)?;
    crate::handles::consume_unlink_authority(&transaction, publication)?;
    inject(fault, NamespaceFaultPoint::UnlinkPendingDelete)?;
    let receipt =
        unlink_operation::persist(&transaction, publication, request_digest, head_sequence)?;
    if let Some(acknowledgement) = acknowledgement {
        super::federated_mutation::persist(
            &transaction,
            publication.namespace_commit_id,
            acknowledgement,
        )?;
    }
    inject(fault, NamespaceFaultPoint::UnlinkOperation)?;
    transaction.commit()?;
    Ok(receipt)
}

pub(super) fn federated_mutation_digest(
    connection: &Connection,
    publication: &NamespaceUnlinkPublication,
) -> Result<[u8; 32], HandleError> {
    Ok(federated_mutation_proposal(connection, publication)?.payload_digest())
}

pub(super) fn federated_mutation_proposal(
    connection: &Connection,
    publication: &NamespaceUnlinkPublication,
) -> Result<FederatedNamespaceMutationProposal, HandleError> {
    validate_shape(publication)?;
    let (current_root, _) = load_expected_head(connection, publication)?;
    let directories = load_path_directories(
        connection,
        publication.volume_id,
        publication.root_object_id,
        current_root,
        publication.root_object_revision_id,
        &publication.path,
    )?;
    let revision = validate_target(connection, publication, &directories)?;
    let intent = unlink_intent(publication, &revision)?;
    let namespace = NamespaceIntent {
        operation_id: publication.operation_id,
        branch_id: publication.branch_id,
        volume_id: publication.volume_id,
        root_object_id: publication.root_object_id,
        expected_commit_id: Some(publication.expected_namespace_commit_id),
        root_revision_id: publication.root_object_revision_id,
        commit_id: publication.namespace_commit_id,
        path: &publication.path,
        created_by: publication.created_by,
        created_at: publication.created_at,
    };
    Ok(super::federated_mutation::mutation_proposal(
        namespace,
        super::digest::unlink_request(publication),
        intent,
    )?)
}

pub(super) fn resolve(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<NamespaceUnlinkReceipt>, PublicationError> {
    let receipt =
        unlink_operation::load(connection, operation_id, PublicationDisposition::Replayed)?;
    receipt
        .map(|receipt| validate_receipt(connection, receipt))
        .transpose()
}

fn validate_receipt(
    connection: &Connection,
    receipt: NamespaceUnlinkReceipt,
) -> Result<NamespaceUnlinkReceipt, PublicationError> {
    let commit = load_commit(connection, receipt.namespace_commit_id)?;
    let intent = super::load_branch_intent(connection, receipt.namespace_commit_id)?
        .ok_or(PublicationError::Corrupt)?;
    let mutation_matches = matches!(
        (receipt.object_kind, intent.mutation),
        (
            DirectoryEntryKind::Directory,
            BranchMutation::DeleteDirectory
        ) | (DirectoryEntryKind::File, BranchMutation::DeleteFile { .. })
    );
    if commit.operation_id == receipt.operation_id
        && intent.object_id == receipt.object_id
        && intent.object_revision_id == receipt.object_revision_id
        && mutation_matches
    {
        Ok(receipt)
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn validate_shape(publication: &NamespaceUnlinkPublication) -> Result<(), PublicationError> {
    let kind_matches_version = match publication.expected_kind {
        DirectoryEntryKind::Directory => publication.expected_file_version_id.is_none(),
        DirectoryEntryKind::File => publication.expected_file_version_id.is_some(),
    };
    let authority_is_valid = match publication.authority {
        NamespaceUnlinkAuthority::Direct { .. } => true,
        NamespaceUnlinkAuthority::DeleteOnClose {
            requested_at,
            ready_at,
            ..
        } => publication.expected_kind == DirectoryEntryKind::File && ready_at >= requested_at,
    };
    if publication.expected_entry_generation == 0
        || publication.root_object_id == publication.expected_object_id
        || publication.root_object_revision_id == publication.expected_object_revision_id
        || !kind_matches_version
        || !authority_is_valid
    {
        return Err(PublicationError::InvalidInput);
    }
    let mut new_revisions = BTreeSet::from([publication.root_object_revision_id]);
    for transition in publication.path.ancestors() {
        if !new_revisions.insert(transition.new_revision_id()) {
            return Err(PublicationError::InvalidInput);
        }
    }
    Ok(())
}

fn load_expected_head(
    transaction: &Connection,
    publication: &NamespaceUnlinkPublication,
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

fn validate_target(
    transaction: &Connection,
    publication: &NamespaceUnlinkPublication,
    directories: &[super::LoadedDirectory],
) -> Result<super::repository::ObjectRevisionInsert, HandleError> {
    let leaf_name = publication
        .path
        .leaf_name()
        .ok_or(PublicationError::InvalidInput)?;
    let entry = directories
        .last()
        .ok_or(PublicationError::Corrupt)?
        .editor
        .lookup(leaf_name)
        .map_err(PublicationError::from)?
        .ok_or(HandleError::NotFound)?;
    if entry.object_id() != publication.expected_object_id
        || entry.object_revision_id() != publication.expected_object_revision_id
        || entry.kind() != publication.expected_kind
        || entry.generation() != publication.expected_entry_generation
    {
        return Err(PublicationError::StaleHead.into());
    }
    let revision = load_object_revision(transaction, publication.expected_object_revision_id)?;
    if revision.volume_id != publication.volume_id
        || revision.object_id != publication.expected_object_id
        || revision.kind != kind_code(publication.expected_kind)
    {
        return Err(PublicationError::Corrupt.into());
    }
    match publication.expected_kind {
        DirectoryEntryKind::Directory => {
            if revision.file_version_id.is_some() || revision.directory_root.is_none() {
                return Err(PublicationError::Corrupt.into());
            }
            if revision.directory_root != Some(crate::DirectoryTrie::empty().root()) {
                return Err(HandleError::DirectoryNotEmpty);
            }
        }
        DirectoryEntryKind::File => {
            if revision.directory_root.is_some() || revision.file_version_id.is_none() {
                return Err(PublicationError::Corrupt.into());
            }
            if revision.file_version_id != publication.expected_file_version_id {
                return Err(PublicationError::StaleHead.into());
            }
            validate_file_head(transaction, publication)?;
        }
    }
    Ok(revision)
}

fn validate_file_head(
    transaction: &Connection,
    publication: &NamespaceUnlinkPublication,
) -> Result<(), HandleError> {
    let expected_version = publication
        .expected_file_version_id
        .ok_or(PublicationError::InvalidInput)?;
    let head = load_file_head(
        transaction,
        publication.branch_id,
        publication.expected_object_id,
    )?
    .ok_or(PublicationError::Corrupt)?;
    if head.volume_id == publication.volume_id && head.current_version_id == Some(expected_version)
    {
        Ok(())
    } else {
        Err(PublicationError::StaleHead.into())
    }
}

fn persist_path_mutation(
    transaction: &Transaction<'_>,
    publication: &NamespaceUnlinkPublication,
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

pub(super) fn unlink_intent(
    publication: &NamespaceUnlinkPublication,
    revision: &super::repository::ObjectRevisionInsert,
) -> Result<BranchMutationIntent, PublicationError> {
    let mutation = match (
        publication.expected_kind,
        publication.expected_file_version_id,
    ) {
        (DirectoryEntryKind::Directory, None) => BranchMutation::DeleteDirectory,
        (DirectoryEntryKind::File, Some(version_id)) => BranchMutation::DeleteFile { version_id },
        _ => return Err(PublicationError::Corrupt),
    };
    Ok(BranchMutationIntent {
        commit_id: publication.namespace_commit_id,
        path: publication.path.path().clone(),
        ancestors: publication.path.ancestors().to_vec(),
        object_id: publication.expected_object_id,
        object_revision_id: publication.expected_object_revision_id,
        prior_object_revision_id: revision.prior_revision_id,
        entry_generation: publication.expected_entry_generation,
        mutation,
        rename: None,
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
          + EXISTS(SELECT 1 FROM namespace_rename_operations WHERE operation_id = ?1)
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

const fn kind_code(kind: DirectoryEntryKind) -> u8 {
    match kind {
        DirectoryEntryKind::Directory => 1,
        DirectoryEntryKind::File => 2,
    }
}
