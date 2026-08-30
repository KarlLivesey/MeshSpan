// SPDX-License-Identifier: GPL-2.0-only

//! Atomic immutable root-directory mutation and volume branch-head publication.

#[path = "namespace_publication/digest.rs"]
mod digest;
#[path = "namespace_publication/federated_admission.rs"]
pub(super) mod federated_admission;
#[path = "namespace_publication/federated_mutation.rs"]
mod federated_mutation;
#[path = "namespace_publication/history_export.rs"]
mod history_export;
#[path = "namespace_publication/history_import.rs"]
mod history_import;
#[path = "namespace_publication/history_records.rs"]
mod history_records;
#[path = "namespace_publication/lazy_file_head.rs"]
mod lazy_file_head;
#[path = "namespace_publication/reconciliation_apply.rs"]
mod reconciliation_apply;
#[path = "namespace_publication/rename.rs"]
mod rename;
#[path = "namespace_publication/repository.rs"]
pub(super) mod repository;
#[path = "namespace_publication/snapshot_restore.rs"]
mod snapshot_restore;
#[path = "namespace_publication/transfer.rs"]
pub(super) mod transfer;
#[path = "namespace_publication/unlink.rs"]
mod unlink;

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{
    BranchId, FederatedMutationAcknowledgement, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, VolumeId,
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
pub use history_export::{
    NamespaceHistoryObjectRequest, NamespaceHistoryPage, NamespaceHistoryPageRequest,
};
pub use history_import::{
    NamespaceHistoryMutationDecision, NamespaceHistoryReceiveCompletion,
    NamespaceHistoryReceivePreparation, NamespaceHistoryReceiveRequest,
    NamespaceHistoryReceiveStatus,
};
pub use history_records::{
    FederatedNamespaceMutationProposal, NamespaceHistoryCommitRecord,
    NamespaceHistoryImmutableKind, NamespaceHistoryImmutableRecord,
    NamespaceHistoryMutationAuthority, NamespaceHistoryRecordError,
};
use repository::{
    ObjectRevisionInsert, advance_namespace_head, load_commit, load_object_revision,
    persist_commit, persist_directory_intent, persist_directory_operation,
    persist_directory_path_revisions, persist_file_intent,
    persist_file_operation as persist_namespace_operation, persist_object_revision,
};
pub(super) use repository::{
    load_branch_intent, load_directory_operation, load_file_operation as load_operation, load_head,
    load_reconciliation_commit,
};

pub(super) fn namespace_history_page(
    connection: &mut Connection,
    request: NamespaceHistoryPageRequest,
) -> Result<NamespaceHistoryPage, PublicationError> {
    history_export::page(connection, request)
}

pub(super) fn namespace_history_object(
    connection: &Connection,
    request: NamespaceHistoryObjectRequest,
) -> Result<NamespaceHistoryImmutableRecord, PublicationError> {
    history_export::history_object(connection, request)
}

pub(super) fn begin_namespace_history_receive(
    connection: &mut Connection,
    request: &NamespaceHistoryReceiveRequest,
) -> Result<NamespaceHistoryReceiveStatus, PublicationError> {
    history_import::begin(connection, request)
}

pub(super) fn receive_namespace_history_page(
    connection: &mut Connection,
    session_id: [u8; 32],
    input_cursor: &[u8],
    page: &NamespaceHistoryPage,
    now: meshspan_domain::UnixMicros,
) -> Result<NamespaceHistoryReceiveStatus, PublicationError> {
    history_import::accept_page(connection, session_id, input_cursor, page, now)
}

pub(super) fn receive_namespace_history_object(
    connection: &mut Connection,
    session_id: [u8; 32],
    record: &NamespaceHistoryImmutableRecord,
    now: meshspan_domain::UnixMicros,
) -> Result<NamespaceHistoryReceiveStatus, PublicationError> {
    history_import::accept_object(connection, session_id, record, now)
}

pub(super) fn complete_namespace_history_receive(
    connection: &mut Connection,
    session_id: [u8; 32],
    now: meshspan_domain::UnixMicros,
) -> Result<NamespaceHistoryReceiveCompletion, PublicationError> {
    history_import::complete(connection, session_id, now, None)
}

pub(super) fn prepare_namespace_history_receive(
    connection: &Connection,
    session_id: [u8; 32],
    now: meshspan_domain::UnixMicros,
) -> Result<NamespaceHistoryReceivePreparation, PublicationError> {
    history_import::prepare(connection, session_id, now)
}

pub(super) fn complete_federated_namespace_history_receive(
    connection: &mut Connection,
    session_id: [u8; 32],
    decisions: &[NamespaceHistoryMutationDecision],
    now: meshspan_domain::UnixMicros,
) -> Result<NamespaceHistoryReceiveCompletion, PublicationError> {
    history_import::complete(connection, session_id, now, Some(decisions))
}

pub(super) fn prepare_snapshot_restore(
    connection: &mut Connection,
    publication: super::SnapshotRestorePublication,
    fault: Option<NamespaceFaultPoint>,
) -> Result<super::SnapshotRestoreReceipt, PublicationError> {
    snapshot_restore::prepare(connection, publication, fault)
}

pub(super) fn ensure_branch(
    connection: &mut Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
    base_commit_id: NamespaceCommitId,
) -> Result<BranchNamespaceHead, PublicationError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let base = repository::load_commit(&transaction, base_commit_id)?;
    if base.volume_id != volume_id {
        return Err(PublicationError::InvalidInput);
    }
    if let Some(existing) = repository::load_head(&transaction, branch_id, volume_id)? {
        return if existing.namespace_commit_id == base_commit_id {
            Ok(existing)
        } else {
            Err(PublicationError::OperationConflict)
        };
    }
    transaction.execute(
        "INSERT INTO branch_namespace_heads(
            branch_id, volume_id, namespace_commit_id, head_sequence
         ) VALUES (?1, ?2, ?3, 1)",
        rusqlite::params![
            branch_id.as_bytes().as_slice(),
            volume_id.as_bytes().as_slice(),
            base_commit_id.as_bytes().as_slice(),
        ],
    )?;
    transaction.commit()?;
    Ok(BranchNamespaceHead {
        branch_id,
        volume_id,
        namespace_commit_id: base_commit_id,
        sequence: 1,
    })
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
    publish_inner(connection, publication, None, None, fault)
        .map(|result| result.0)
        .map_err(|error| match error {
            crate::HandleError::Namespace(error) => error,
            _ => PublicationError::Corrupt,
        })
}

pub(super) fn publish_federated(
    connection: &mut Connection,
    publication: &RootFilePublication,
    acknowledgement: &FederatedMutationAcknowledgement,
) -> Result<NamespacePublicationReceipt, PublicationError> {
    publish_inner(connection, publication, None, Some(acknowledgement), None)
        .map(|result| result.0)
        .map_err(|error| match error {
            crate::HandleError::Namespace(error) => error,
            _ => PublicationError::Corrupt,
        })
}

#[cfg(test)]
pub(super) fn publish_federated_with_fault(
    connection: &mut Connection,
    publication: &RootFilePublication,
    acknowledgement: &FederatedMutationAcknowledgement,
    fault: NamespaceFaultPoint,
) -> Result<NamespacePublicationReceipt, PublicationError> {
    publish_inner(
        connection,
        publication,
        None,
        Some(acknowledgement),
        Some(fault),
    )
    .map(|result| result.0)
    .map_err(|error| match error {
        crate::HandleError::Namespace(error) => error,
        _ => PublicationError::Corrupt,
    })
}

pub(super) fn file_federated_mutation_digest(
    publication: &RootFilePublication,
) -> Result<[u8; 32], PublicationError> {
    validate(publication)?;
    federated_mutation::mutation_digest(
        NamespaceIntent::from_file(publication),
        request_digest(publication),
        repository::file_intent(publication),
    )
}

pub(super) fn file_federated_mutation_proposal(
    publication: &RootFilePublication,
) -> Result<crate::FederatedNamespaceMutationProposal, PublicationError> {
    validate(publication)?;
    federated_mutation::mutation_proposal(
        NamespaceIntent::from_file(publication),
        request_digest(publication),
        repository::file_intent(publication),
    )
}

pub(super) fn publish_and_open(
    connection: &mut Connection,
    publication: &RootFilePublication,
    open: &crate::OpenHandleRequest,
) -> Result<(NamespacePublicationReceipt, crate::OpenHandleReceipt), crate::HandleError> {
    let (namespace, handle) = publish_inner(connection, publication, Some(open), None, None)?;
    Ok((namespace, handle.ok_or(crate::HandleError::Corrupt)?))
}

fn publish_inner(
    connection: &mut Connection,
    publication: &RootFilePublication,
    open: Option<&crate::OpenHandleRequest>,
    acknowledgement: Option<&FederatedMutationAcknowledgement>,
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
    reject_file_operation_collision(&transaction, publication.file.operation_id)?;
    if let Some(receipt) = load_operation(
        &transaction,
        publication.file.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return if receipt.request_digest == request_digest {
            federated_mutation::ensure_exact(
                &transaction,
                publication.namespace_commit_id,
                acknowledgement,
            )?;
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
    lazy_file_head::materialize(&transaction, publication.file)?;
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
    if let Some(acknowledgement) = acknowledgement {
        federated_mutation::persist(
            &transaction,
            publication.namespace_commit_id,
            acknowledgement,
        )?;
    }
    inject(fault, NamespaceFaultPoint::Operation)?;
    transaction.commit()?;
    Ok((receipt, handle))
}

pub(super) fn create_directory(
    connection: &mut Connection,
    publication: &DirectoryPublication,
    fault: Option<NamespaceFaultPoint>,
) -> Result<DirectoryPublicationReceipt, PublicationError> {
    create_directory_inner(connection, publication, None, fault)
}

pub(super) fn create_federated_directory(
    connection: &mut Connection,
    publication: &DirectoryPublication,
    acknowledgement: &FederatedMutationAcknowledgement,
) -> Result<DirectoryPublicationReceipt, PublicationError> {
    create_directory_inner(connection, publication, Some(acknowledgement), None)
}

pub(super) fn directory_federated_mutation_digest(
    publication: &DirectoryPublication,
) -> Result<[u8; 32], PublicationError> {
    validate_directory_publication(publication)?;
    federated_mutation::mutation_digest(
        NamespaceIntent::from_directory(publication),
        directory_request_digest(publication),
        repository::directory_intent(publication),
    )
}

pub(super) fn directory_federated_mutation_proposal(
    publication: &DirectoryPublication,
) -> Result<crate::FederatedNamespaceMutationProposal, PublicationError> {
    validate_directory_publication(publication)?;
    federated_mutation::mutation_proposal(
        NamespaceIntent::from_directory(publication),
        directory_request_digest(publication),
        repository::directory_intent(publication),
    )
}

fn create_directory_inner(
    connection: &mut Connection,
    publication: &DirectoryPublication,
    acknowledgement: Option<&FederatedMutationAcknowledgement>,
    fault: Option<NamespaceFaultPoint>,
) -> Result<DirectoryPublicationReceipt, PublicationError> {
    validate_directory_publication(publication)?;
    let request_digest = directory_request_digest(publication);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    reject_directory_operation_collision(&transaction, publication.operation_id)?;
    if let Some(receipt) = load_directory_operation(
        &transaction,
        publication.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return if receipt.request_digest == request_digest {
            federated_mutation::ensure_exact(
                &transaction,
                publication.namespace_commit_id,
                acknowledgement,
            )?;
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
    if let Some(acknowledgement) = acknowledgement {
        federated_mutation::persist(
            &transaction,
            publication.namespace_commit_id,
            acknowledgement,
        )?;
    }
    inject(fault, NamespaceFaultPoint::Operation)?;
    transaction.commit()?;
    Ok(receipt)
}

fn reject_file_operation_collision(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<(), PublicationError> {
    reject_operation_receipts(transaction, operation_id, PublicationOperationKind::File)
}

fn reject_directory_operation_collision(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<(), PublicationError> {
    reject_operation_receipts(
        transaction,
        operation_id,
        PublicationOperationKind::Directory,
    )
}

#[derive(Clone, Copy)]
enum PublicationOperationKind {
    File,
    Directory,
}

fn reject_operation_receipts(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
    allowed: PublicationOperationKind,
) -> Result<(), PublicationError> {
    let collisions: (i64, i64, i64, i64, i64, i64) = transaction.query_row(
        "SELECT
            EXISTS(SELECT 1 FROM namespace_publication_operations WHERE operation_id = ?1),
            EXISTS(SELECT 1 FROM directory_publication_operations WHERE operation_id = ?1),
            EXISTS(SELECT 1 FROM namespace_rename_operations WHERE operation_id = ?1),
            EXISTS(SELECT 1 FROM namespace_unlink_operations WHERE operation_id = ?1),
            EXISTS(
                SELECT 1 FROM namespace_snapshot_restore_operations WHERE operation_id = ?1
            ),
            EXISTS(SELECT 1 FROM namespace_reconciliation_operations WHERE operation_id = ?1)",
        [operation_id.as_bytes().as_slice()],
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
    let collision = match allowed {
        PublicationOperationKind::File => {
            collisions.1 + collisions.2 + collisions.3 + collisions.4 + collisions.5
        }
        PublicationOperationKind::Directory => {
            collisions.0 + collisions.2 + collisions.3 + collisions.4 + collisions.5
        }
    };
    if collision == 0 {
        Ok(())
    } else {
        Err(PublicationError::OperationConflict)
    }
}

pub(super) fn rename_namespace(
    connection: &mut Connection,
    publication: &super::NamespaceRenamePublication,
    fault: Option<NamespaceFaultPoint>,
) -> Result<super::NamespaceRenameReceipt, crate::HandleError> {
    rename::apply(connection, publication, None, fault)
}

pub(super) fn rename_federated_namespace(
    connection: &mut Connection,
    publication: &super::NamespaceRenamePublication,
    acknowledgement: &FederatedMutationAcknowledgement,
) -> Result<super::NamespaceRenameReceipt, crate::HandleError> {
    rename::apply(connection, publication, Some(acknowledgement), None)
}

pub(super) fn rename_federated_mutation_digest(
    connection: &Connection,
    publication: &super::NamespaceRenamePublication,
) -> Result<[u8; 32], crate::HandleError> {
    rename::federated_mutation_digest(connection, publication)
}

pub(super) fn rename_federated_mutation_proposal(
    connection: &Connection,
    publication: &super::NamespaceRenamePublication,
) -> Result<FederatedNamespaceMutationProposal, crate::HandleError> {
    rename::federated_mutation_proposal(connection, publication)
}

pub(super) fn load_rename(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<super::NamespaceRenameReceipt>, PublicationError> {
    rename::resolve(connection, operation_id)
}

pub(super) fn unlink_namespace(
    connection: &mut Connection,
    publication: &super::NamespaceUnlinkPublication,
    fault: Option<NamespaceFaultPoint>,
) -> Result<super::NamespaceUnlinkReceipt, crate::HandleError> {
    unlink::apply(connection, publication, None, fault)
}

pub(super) fn unlink_federated_namespace(
    connection: &mut Connection,
    publication: &super::NamespaceUnlinkPublication,
    acknowledgement: &FederatedMutationAcknowledgement,
) -> Result<super::NamespaceUnlinkReceipt, crate::HandleError> {
    unlink::apply(connection, publication, Some(acknowledgement), None)
}

pub(super) fn unlink_federated_mutation_digest(
    connection: &Connection,
    publication: &super::NamespaceUnlinkPublication,
) -> Result<[u8; 32], crate::HandleError> {
    unlink::federated_mutation_digest(connection, publication)
}

pub(super) fn unlink_federated_mutation_proposal(
    connection: &Connection,
    publication: &super::NamespaceUnlinkPublication,
) -> Result<FederatedNamespaceMutationProposal, crate::HandleError> {
    unlink::federated_mutation_proposal(connection, publication)
}

pub(super) fn load_unlink(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<super::NamespaceUnlinkReceipt>, PublicationError> {
    unlink::resolve(connection, operation_id)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NamespaceFaultPoint {
    DirectoryNodes,
    FileVersion,
    ObjectRevisions,
    NamespaceCommit,
    Heads,
    Operation,
    RenameSource,
    RenameTarget,
    RenameCommit,
    RenameHandles,
    RenameOperation,
    UnlinkPath,
    UnlinkCommit,
    UnlinkPendingDelete,
    UnlinkOperation,
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
    transaction: &Connection,
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

fn load_path_directories(
    transaction: &Connection,
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
        if let Some(rename) = &intent.rename {
            load_replay_path(
                connection,
                converged.volume_id,
                converged.root_object_id,
                converged.root_object_revision_id,
                &rename.source_path,
                &mut entries,
            )?;
        }
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
        let selected_revision = load_object_revision(connection, entry.object_revision_id())?;
        if selected_revision.volume_id != volume_id
            || selected_revision.object_id != entry.object_id()
            || (selected_revision.kind == 1) != (entry.kind() == DirectoryEntryKind::Directory)
        {
            return Err(PublicationError::Corrupt);
        }
        let file_version_id = match entry.kind() {
            DirectoryEntryKind::Directory if selected_revision.file_version_id.is_none() => None,
            DirectoryEntryKind::File => selected_revision
                .file_version_id
                .ok_or(PublicationError::Corrupt)
                .map(Some)?,
            DirectoryEntryKind::Directory => return Err(PublicationError::Corrupt),
        };
        let replay_entry = NamespaceReplayEntry {
            path: selected,
            object_id: entry.object_id(),
            object_revision_id: entry.object_revision_id(),
            kind: entry.kind(),
            file_version_id,
            directory_is_empty: match entry.kind() {
                DirectoryEntryKind::Directory => Some(
                    selected_revision.directory_root == Some(crate::DirectoryTrie::empty().root()),
                ),
                DirectoryEntryKind::File => None,
            },
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
    let (child_root, created_nodes) = mutate_entry(
        &mut directories[last].editor,
        leaf_entry,
        expected_leaf_revision_id,
    )?;
    propagate_directory_change(directories, path, child_root, created_nodes)
}

fn remove_namespace_path(
    mut directories: Vec<LoadedDirectory>,
    path: &NamespacePublicationPath,
    expected_leaf_revision_id: ObjectRevisionId,
) -> Result<DirectoryPathMutation, PublicationError> {
    let last = directories
        .len()
        .checked_sub(1)
        .ok_or(PublicationError::Corrupt)?;
    let leaf_name = path.leaf_name().ok_or(PublicationError::InvalidInput)?;
    let mutation = directories[last]
        .editor
        .remove(leaf_name, expected_leaf_revision_id)?;
    let created_nodes = mutation
        .created_nodes
        .iter()
        .map(|digest| directories[last].editor.record(*digest))
        .collect::<Result<Vec<_>, _>>()?;
    propagate_directory_change(directories, path, mutation.new_root, created_nodes)
}

fn propagate_directory_change(
    mut directories: Vec<LoadedDirectory>,
    path: &NamespacePublicationPath,
    mut child_root: DirectoryNodeDigest,
    mut created_nodes: Vec<DirectoryNodeRecord>,
) -> Result<DirectoryPathMutation, PublicationError> {
    let last = directories
        .len()
        .checked_sub(1)
        .ok_or(PublicationError::Corrupt)?;
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
