// SPDX-License-Identifier: GPL-2.0-only

//! Persist validated mutation or merge evidence without advancing any branch or authority head.

use rusqlite::{Transaction, params};

use super::super::repository::{StoredCommit, persist_branch_intent, persist_stored_commit};
use super::{CommitEvidence, TransferredNamespaceCommit, imported_evidence_digest};
use crate::{PublicationError, ReconciliationCommitPayload};

pub(super) fn persist(
    transaction: &Transaction<'_>,
    record: &TransferredNamespaceCommit,
) -> Result<(), PublicationError> {
    match &record.evidence {
        CommitEvidence::Mutation { intent, .. } => {
            let commit = &record.commit;
            persist_stored_commit(
                transaction,
                &StoredCommit {
                    commit_id: commit.commit_id,
                    branch_id: commit.branch_id,
                    volume_id: commit.volume_id,
                    root_object_id: commit.root_object_id,
                    root_object_revision_id: commit.root_object_revision_id,
                    parent_id: commit.parents.first().copied(),
                    created_by: record.created_by,
                    operation_id: commit.operation_id,
                    created_at: record.created_at,
                },
                commit.request_digest,
            )?;
            let intent_digest = intent.digest();
            let evidence_digest =
                imported_evidence_digest(commit.commit_id, commit.request_digest, intent_digest);
            transaction.execute(
                "INSERT INTO imported_namespace_commit_evidence(namespace_commit_id, request_digest, intent_digest, evidence_digest)
                 VALUES (?1, ?2, ?3, ?4)",
                params![commit.commit_id.as_bytes().as_slice(), commit.request_digest.as_slice(), intent_digest.as_slice(), evidence_digest.as_slice()],
            )?;
            persist_branch_intent(transaction, intent)
        }
        CommitEvidence::Merge {
            causal_plan_digest,
            result_digest,
        } => persist_merge(transaction, record, *causal_plan_digest, *result_digest),
        CommitEvidence::Restore { .. } => persist_restore(transaction, record),
    }
}

fn persist_restore(
    transaction: &Transaction<'_>,
    record: &TransferredNamespaceCommit,
) -> Result<(), PublicationError> {
    let publication = record.restore_publication()?;
    super::super::snapshot_restore::reject_operation_collision(
        transaction,
        publication.operation_id,
    )?;
    persist_stored_commit(
        transaction,
        &StoredCommit {
            commit_id: publication.namespace_commit_id,
            branch_id: publication.branch_id,
            volume_id: publication.volume_id,
            root_object_id: publication.root_object_id,
            root_object_revision_id: publication.root_object_revision_id,
            parent_id: Some(publication.expected_namespace_commit_id),
            created_by: publication.created_by,
            operation_id: publication.operation_id,
            created_at: publication.created_at,
        },
        record.commit.request_digest,
    )?;
    // Reuse the exact receipt shape but do not activate the destination head. Import
    // is immutable history delivery, never a metadata restore decision.
    let receipt = super::super::snapshot_restore::persist_receipt(
        transaction,
        publication,
        record.commit.request_digest,
    )?;
    super::super::snapshot_restore::validate_receipt_source(
        transaction,
        receipt,
        publication.volume_id,
        publication.root_object_id,
    )
}

fn persist_merge(
    transaction: &Transaction<'_>,
    record: &TransferredNamespaceCommit,
    causal_plan_digest: [u8; 32],
    result_digest: [u8; 32],
) -> Result<(), PublicationError> {
    let commit = &record.commit;
    let ReconciliationCommitPayload::Merge { replay_digest } = commit.payload else {
        return Err(PublicationError::InvalidInput);
    };
    super::super::reconciliation_apply::reject_operation_collision(
        transaction,
        commit.operation_id,
    )?;
    transaction.execute(
        "INSERT INTO namespace_commits(namespace_commit_id, branch_id, volume_id,
             root_object_id, root_object_revision_id, created_by, publication_operation_id,
             created_at, commit_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            commit.commit_id.as_bytes().as_slice(),
            commit.branch_id.as_bytes().as_slice(),
            commit.volume_id.as_bytes().as_slice(),
            commit.root_object_id.as_bytes().as_slice(),
            commit.root_object_revision_id.as_bytes().as_slice(),
            record.created_by.as_bytes().as_slice(),
            commit.operation_id.as_bytes().as_slice(),
            record.created_at.get(),
            record.commit_digest.as_slice()
        ],
    )?;
    for (index, parent) in commit.parents.iter().enumerate() {
        transaction.execute(
            "INSERT INTO namespace_commit_parents(namespace_commit_id, parent_ordinal, parent_commit_id)
             VALUES (?1, ?2, ?3)",
            params![commit.commit_id.as_bytes().as_slice(), i64::try_from(index).map_err(|_| PublicationError::InvalidInput)?, parent.as_bytes().as_slice()],
        )?;
    }
    transaction.execute(
        "INSERT INTO namespace_reconciliation_operations(operation_id, request_digest,
             causal_plan_digest, replay_plan_digest, namespace_commit_id, root_object_revision_id,
             result_digest, committed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            commit.operation_id.as_bytes().as_slice(),
            commit.request_digest.as_slice(),
            causal_plan_digest.as_slice(),
            replay_digest.as_slice(),
            commit.commit_id.as_bytes().as_slice(),
            commit.root_object_revision_id.as_bytes().as_slice(),
            result_digest.as_slice(),
            record.created_at.get()
        ],
    )?;
    Ok(())
}
