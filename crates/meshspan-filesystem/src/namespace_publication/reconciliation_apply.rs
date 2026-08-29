// SPDX-License-Identifier: GPL-2.0-only

//! Atomic application of one exact affected-path replay and its durable merge receipt.

use meshspan_contracts::namespace_reconciliation_result_digest;
use meshspan_domain::{NamespaceCommitId, ObjectRevisionId, OperationId};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::digest::{
    MergeCommitDigest, merge_commit as merge_commit_digest, reconciliation_request,
};
use super::repository::load_reconciliation_commit;
use super::{NamespaceFaultPoint, inject};
use crate::publication::{
    NamespaceReconciliationApplication, NamespaceReconciliationReceipt, PublicationDisposition,
    PublicationError,
};
use crate::{NamespaceReplayDisposition, PreparedNamespaceReconciliation, ReconciliationPlan};

#[path = "reconciliation_apply/action.rs"]
mod action;

use action::{ApplyContext, apply_action, verify_already_applied};

type StoredReceipt = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

pub(super) fn apply(
    connection: &mut Connection,
    application: NamespaceReconciliationApplication,
    prepared: &PreparedNamespaceReconciliation,
    fault: Option<NamespaceFaultPoint>,
) -> Result<NamespaceReconciliationReceipt, PublicationError> {
    validate(application, prepared)?;
    let request_digest = reconciliation_request(application, prepared);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = load_receipt(
        &transaction,
        application.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return if receipt.request_digest == request_digest {
            Ok(receipt)
        } else {
            Err(PublicationError::OperationConflict)
        };
    }
    reject_operation_collision(&transaction, application.operation_id)?;

    let causal = prepared.causal_plan();
    validate_durable_plan(&transaction, causal)?;
    let replay = prepared.replay_plan();
    let context = ApplyContext {
        application,
        branch_id: causal
            .converged_branch_id()
            .ok_or(PublicationError::InvalidInput)?,
        volume_id: causal.volume_id(),
    };
    let mut current_root = causal
        .converged_head()
        .map(|commit_id| load_commit_root(&transaction, commit_id))
        .transpose()?
        .ok_or(PublicationError::InvalidInput)?;
    for action in replay.actions() {
        if action.disposition == NamespaceReplayDisposition::AlreadyApplied {
            verify_already_applied(
                &transaction,
                causal.volume_id(),
                causal.root_object_id(),
                current_root,
                action,
            )?;
            continue;
        }
        current_root = apply_action(
            &transaction,
            context,
            causal.root_object_id(),
            current_root,
            action,
        )?;
        inject(fault, NamespaceFaultPoint::ReconciliationLeaf)?;
    }
    if replay.final_root_object_revision_id() != Some(current_root) {
        return Err(PublicationError::StaleHead);
    }
    inject(fault, NamespaceFaultPoint::ReconciliationDirectories)?;
    persist_merge_commit(
        &transaction,
        application,
        prepared,
        request_digest,
        current_root,
    )?;
    inject(fault, NamespaceFaultPoint::ReconciliationCommit)?;
    let receipt = persist_receipt(
        &transaction,
        application,
        prepared,
        request_digest,
        current_root,
    )?;
    inject(fault, NamespaceFaultPoint::ReconciliationOperation)?;
    transaction.commit()?;
    Ok(receipt)
}

fn validate_durable_plan(
    transaction: &Transaction<'_>,
    causal: &ReconciliationPlan,
) -> Result<(), PublicationError> {
    let commits = causal
        .commit_ids()
        .map(|commit_id| {
            load_reconciliation_commit(transaction, commit_id)?.ok_or(PublicationError::Corrupt)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if causal.validates_commits(&commits) {
        Ok(())
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn validate(
    application: NamespaceReconciliationApplication,
    prepared: &PreparedNamespaceReconciliation,
) -> Result<(), PublicationError> {
    let causal = prepared.causal_plan();
    if causal.converged_head().is_none()
        || causal.converged_branch_id().is_none()
        || application.retention_policy_sequence == 0
        || causal.merge_parents().len() < 2
        || prepared
            .replay_plan()
            .final_root_object_revision_id()
            .is_none()
        || prepared.replay_plan().actions().is_empty()
        || causal
            .merge_parents()
            .contains(&application.namespace_commit_id)
    {
        return Err(PublicationError::InvalidInput);
    }
    Ok(())
}

fn persist_merge_commit(
    transaction: &Transaction<'_>,
    application: NamespaceReconciliationApplication,
    prepared: &PreparedNamespaceReconciliation,
    request_digest: [u8; 32],
    root_revision_id: ObjectRevisionId,
) -> Result<(), PublicationError> {
    let causal = prepared.causal_plan();
    let branch_id = causal
        .converged_branch_id()
        .ok_or(PublicationError::InvalidInput)?;
    let commit = MergeCommitDigest {
        commit_id: application.namespace_commit_id,
        branch_id,
        volume_id: causal.volume_id(),
        root_object_id: causal.root_object_id(),
        root_revision_id,
        parents: causal.merge_parents(),
        created_by: application.created_by,
        operation_id: application.operation_id,
        created_at: application.created_at,
        request_digest,
        replay_digest: prepared.replay_plan().digest(),
    };
    transaction.execute(
        "INSERT INTO namespace_commits(
            namespace_commit_id, branch_id, volume_id, root_object_id,
            root_object_revision_id, created_by, publication_operation_id,
            created_at, commit_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            application.namespace_commit_id.as_bytes().as_slice(),
            branch_id.as_bytes().as_slice(),
            causal.volume_id().as_bytes().as_slice(),
            causal.root_object_id().as_bytes().as_slice(),
            root_revision_id.as_bytes().as_slice(),
            application.created_by.as_bytes().as_slice(),
            application.operation_id.as_bytes().as_slice(),
            application.created_at.get(),
            merge_commit_digest(&commit).as_slice(),
        ],
    )?;
    for (ordinal, parent) in causal.merge_parents().iter().enumerate() {
        transaction.execute(
            "INSERT INTO namespace_commit_parents(
                namespace_commit_id, parent_ordinal, parent_commit_id
             ) VALUES (?1, ?2, ?3)",
            params![
                application.namespace_commit_id.as_bytes().as_slice(),
                i64::try_from(ordinal).map_err(|_| PublicationError::InvalidInput)?,
                parent.as_bytes().as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn persist_receipt(
    transaction: &Transaction<'_>,
    application: NamespaceReconciliationApplication,
    prepared: &PreparedNamespaceReconciliation,
    request_digest: [u8; 32],
    root_revision_id: ObjectRevisionId,
) -> Result<NamespaceReconciliationReceipt, PublicationError> {
    let causal_digest = prepared.causal_plan().digest();
    let replay_digest = prepared.replay_plan().digest();
    let result_digest = namespace_reconciliation_result_digest(
        application.operation_id,
        application.namespace_commit_id,
        request_digest,
        causal_digest,
        replay_digest,
        root_revision_id,
    );
    transaction.execute(
        "INSERT INTO namespace_reconciliation_operations(
            operation_id, request_digest, causal_plan_digest, replay_plan_digest,
            namespace_commit_id, root_object_revision_id, result_digest, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            application.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            causal_digest.as_slice(),
            replay_digest.as_slice(),
            application.namespace_commit_id.as_bytes().as_slice(),
            root_revision_id.as_bytes().as_slice(),
            result_digest.as_slice(),
            application.created_at.get(),
        ],
    )?;
    Ok(NamespaceReconciliationReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: application.operation_id,
        request_digest,
        causal_plan_digest: causal_digest,
        replay_plan_digest: replay_digest,
        namespace_commit_id: application.namespace_commit_id,
        root_object_revision_id: root_revision_id,
        result_digest,
    })
}

pub(super) fn load_receipt(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<NamespaceReconciliationReceipt>, PublicationError> {
    let stored: Option<StoredReceipt> = connection
        .query_row(
            "SELECT request_digest, causal_plan_digest, replay_plan_digest,
                    namespace_commit_id, root_object_revision_id, result_digest
             FROM namespace_reconciliation_operations WHERE operation_id = ?1",
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
        )
        .optional()?;
    stored
        .map(|stored| decode_receipt(operation_id, disposition, stored))
        .transpose()
}

fn decode_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: StoredReceipt,
) -> Result<NamespaceReconciliationReceipt, PublicationError> {
    let request_digest = stored.0.try_into().map_err(|_| PublicationError::Corrupt)?;
    let causal_plan_digest = stored.1.try_into().map_err(|_| PublicationError::Corrupt)?;
    let replay_plan_digest = stored.2.try_into().map_err(|_| PublicationError::Corrupt)?;
    let namespace_commit_id =
        NamespaceCommitId::from_bytes(stored.3.try_into().map_err(|_| PublicationError::Corrupt)?)
            .map_err(|_| PublicationError::Corrupt)?;
    let root_object_revision_id =
        ObjectRevisionId::from_bytes(stored.4.try_into().map_err(|_| PublicationError::Corrupt)?)
            .map_err(|_| PublicationError::Corrupt)?;
    let result_digest = stored.5.try_into().map_err(|_| PublicationError::Corrupt)?;
    let expected = namespace_reconciliation_result_digest(
        operation_id,
        namespace_commit_id,
        request_digest,
        causal_plan_digest,
        replay_plan_digest,
        root_object_revision_id,
    );
    if expected != result_digest {
        return Err(PublicationError::Corrupt);
    }
    Ok(NamespaceReconciliationReceipt {
        disposition,
        operation_id,
        request_digest,
        causal_plan_digest,
        replay_plan_digest,
        namespace_commit_id,
        root_object_revision_id,
        result_digest,
    })
}

fn reject_operation_collision(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<(), PublicationError> {
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_publication_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM directory_publication_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM namespace_rename_operations WHERE operation_id = ?1)
             OR EXISTS(
                SELECT 1 FROM namespace_snapshot_restore_operations WHERE operation_id = ?1
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

fn load_commit_root(
    transaction: &Transaction<'_>,
    commit_id: NamespaceCommitId,
) -> Result<ObjectRevisionId, PublicationError> {
    let bytes: Vec<u8> = transaction.query_row(
        "SELECT root_object_revision_id FROM namespace_commits WHERE namespace_commit_id = ?1",
        [commit_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    ObjectRevisionId::from_bytes(bytes.try_into().map_err(|_| PublicationError::Corrupt)?)
        .map_err(|_| PublicationError::Corrupt)
}
