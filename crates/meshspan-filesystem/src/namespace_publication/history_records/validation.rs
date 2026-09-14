// SPDX-License-Identifier: GPL-2.0-only

//! Identity validation shared by canonical decoding and transactional history import.

use super::super::digest::{MergeCommitDigest, merge_commit};
use super::super::repository::{StoredCommit, stored_commit_digest};
use super::super::transfer::{CommitEvidence, TransferredNamespaceCommit};
use super::{MAXIMUM_COMMIT_PARENTS, NamespaceHistoryRecordError};
use crate::ReconciliationCommitPayload;

pub(in crate::publication) fn validate(
    record: &TransferredNamespaceCommit,
) -> Result<(), NamespaceHistoryRecordError> {
    let commit = &record.commit;
    let valid = match (&commit.payload, &record.evidence) {
        (
            ReconciliationCommitPayload::Mutation { intent_digest },
            CommitEvidence::Mutation { intent, .. },
        ) => {
            let stored = StoredCommit {
                commit_id: commit.commit_id,
                branch_id: commit.branch_id,
                volume_id: commit.volume_id,
                root_object_id: commit.root_object_id,
                root_object_revision_id: commit.root_object_revision_id,
                parent_id: commit.parents.first().copied(),
                created_by: record.created_by,
                operation_id: commit.operation_id,
                created_at: record.created_at,
            };
            commit.parents.len() <= 1
                && intent.commit_id == commit.commit_id
                && intent.digest() == *intent_digest
                && stored_commit_digest(&stored, commit.request_digest) == record.commit_digest
        }
        (
            ReconciliationCommitPayload::Merge { replay_digest },
            CommitEvidence::Merge {
                causal_plan_digest,
                result_digest,
            },
        ) => {
            let digest = merge_commit(&MergeCommitDigest {
                commit_id: commit.commit_id,
                branch_id: commit.branch_id,
                volume_id: commit.volume_id,
                root_object_id: commit.root_object_id,
                root_revision_id: commit.root_object_revision_id,
                parents: &commit.parents,
                created_by: record.created_by,
                operation_id: commit.operation_id,
                created_at: record.created_at,
                request_digest: commit.request_digest,
                replay_digest: *replay_digest,
            });
            (2..=MAXIMUM_COMMIT_PARENTS).contains(&commit.parents.len())
                && commit.parents.windows(2).all(|pair| pair[0] < pair[1])
                && digest == record.commit_digest
                && meshspan_contracts::namespace_reconciliation_result_digest(
                    commit.operation_id,
                    commit.commit_id,
                    commit.request_digest,
                    *causal_plan_digest,
                    *replay_digest,
                    commit.root_object_revision_id,
                ) == *result_digest
        }
        (
            ReconciliationCommitPayload::Restore { .. },
            CommitEvidence::Restore { result_digest },
        ) => validate_restore(record, *result_digest)?,
        (
            ReconciliationCommitPayload::Mutation { .. }
            | ReconciliationCommitPayload::Merge { .. }
            | ReconciliationCommitPayload::Restore { .. },
            _,
        ) => false,
    };
    if valid && !commit.parents.contains(&commit.commit_id) {
        Ok(())
    } else {
        Err(NamespaceHistoryRecordError::Invalid)
    }
}

fn validate_restore(
    record: &TransferredNamespaceCommit,
    result_digest: [u8; 32],
) -> Result<bool, NamespaceHistoryRecordError> {
    let publication = record
        .restore_publication()
        .map_err(|_| NamespaceHistoryRecordError::Invalid)?;
    let commit = &record.commit;
    let stored = StoredCommit {
        commit_id: commit.commit_id,
        branch_id: commit.branch_id,
        volume_id: commit.volume_id,
        root_object_id: commit.root_object_id,
        root_object_revision_id: commit.root_object_revision_id,
        parent_id: Some(publication.expected_namespace_commit_id),
        created_by: record.created_by,
        operation_id: commit.operation_id,
        created_at: record.created_at,
    };
    Ok(
        publication.namespace_commit_id != publication.snapshot_namespace_commit_id
            && super::super::digest::snapshot_restore_request(publication) == commit.request_digest
            && stored_commit_digest(&stored, commit.request_digest) == record.commit_digest
            && meshspan_contracts::namespace_snapshot_restore_result_digest(
                publication.operation_id,
                commit.request_digest,
                publication.snapshot_id,
                publication.snapshot_namespace_commit_id,
                publication.expected_namespace_commit_id,
                publication.namespace_commit_id,
                publication.root_object_revision_id,
            ) == result_digest,
    )
}
