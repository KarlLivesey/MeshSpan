// SPDX-License-Identifier: GPL-2.0-only

//! Source-side causal traversal and exact immutable-record collection.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{NamespaceCommitId, PrincipalId, UnixMicros, VolumeId};
use rusqlite::Connection;

use super::super::repository::{load_branch_intent, load_reconciliation_commit};
use super::{CommitEvidence, TransferredNamespaceCommit, export_graph};
use crate::publication::{copy_array, decode_identifier};
use crate::{
    NamespaceHistoryBundle, NamespaceHistoryLimits, PublicationError, ReconciliationCommitPayload,
};

pub(in crate::publication) fn export_history(
    connection: &Connection,
    volume_id: VolumeId,
    heads: &[NamespaceCommitId],
    known_commits: &[NamespaceCommitId],
    limits: NamespaceHistoryLimits,
) -> Result<NamespaceHistoryBundle, PublicationError> {
    validate_request(heads, known_commits, limits)?;
    let known = known_commits.iter().copied().collect::<BTreeSet<_>>();
    let commits = collect_commits(connection, volume_id, heads, &known, limits)?;
    let objects = export_graph::collect(connection, volume_id, &commits, limits)?;
    super::import::ensure_record_limit(
        commits
            .len()
            .checked_add(objects.object_revisions.len())
            .and_then(|count| count.checked_add(objects.directory_nodes.len()))
            .and_then(|count| count.checked_add(objects.file_versions.len()))
            .and_then(|count| count.checked_add(objects.manifests.len())),
        limits,
    )?;
    Ok(NamespaceHistoryBundle {
        volume_id,
        heads: heads.to_vec(),
        commits,
        directory_nodes: objects.directory_nodes,
        manifests: objects.manifests,
        file_versions: objects.file_versions,
        object_revisions: objects.object_revisions,
    })
}

pub(super) fn validate_request(
    heads: &[NamespaceCommitId],
    known_commits: &[NamespaceCommitId],
    limits: NamespaceHistoryLimits,
) -> Result<(), PublicationError> {
    if heads.is_empty()
        || heads.len() > limits.maximum_heads
        || known_commits.len() > limits.maximum_commits
        || limits.maximum_heads == 0
        || limits.maximum_commits == 0
        || limits.maximum_immutable_records == 0
        || heads.iter().copied().collect::<BTreeSet<_>>().len() != heads.len()
        || known_commits.iter().copied().collect::<BTreeSet<_>>().len() != known_commits.len()
    {
        return Err(PublicationError::InvalidInput);
    }
    Ok(())
}

fn collect_commits(
    connection: &Connection,
    volume_id: VolumeId,
    heads: &[NamespaceCommitId],
    known: &BTreeSet<NamespaceCommitId>,
    limits: NamespaceHistoryLimits,
) -> Result<Vec<TransferredNamespaceCommit>, PublicationError> {
    let mut pending = heads.to_vec();
    let mut visited = BTreeSet::new();
    let mut commits = BTreeMap::new();
    while let Some(commit_id) = pending.pop() {
        if known.contains(&commit_id) || !visited.insert(commit_id) {
            continue;
        }
        if visited.len() > limits.maximum_commits {
            return Err(PublicationError::InvalidInput);
        }
        let record = load_commit_record(connection, volume_id, commit_id)?;
        pending.extend(record.dependencies());
        commits.insert(commit_id, record);
    }
    Ok(commits.into_values().collect())
}

pub(in crate::publication) fn load_commit_record(
    connection: &Connection,
    volume_id: VolumeId,
    commit_id: NamespaceCommitId,
) -> Result<TransferredNamespaceCommit, PublicationError> {
    let mut record = load_bare_commit_record(connection, volume_id, commit_id)?;
    if let CommitEvidence::Mutation {
        acknowledgement, ..
    } = &mut record.evidence
    {
        *acknowledgement =
            super::super::federated_mutation::load(connection, commit_id)?.map(Box::new);
    }
    Ok(record)
}

pub(in crate::publication) fn load_bare_commit_record(
    connection: &Connection,
    volume_id: VolumeId,
    commit_id: NamespaceCommitId,
) -> Result<TransferredNamespaceCommit, PublicationError> {
    let commit =
        load_reconciliation_commit(connection, commit_id)?.ok_or(PublicationError::InvalidInput)?;
    if commit.volume_id != volume_id {
        return Err(PublicationError::InvalidInput);
    }
    let evidence = match commit.payload {
        ReconciliationCommitPayload::Mutation { intent_digest } => {
            let intent =
                load_branch_intent(connection, commit_id)?.ok_or(PublicationError::Corrupt)?;
            if intent.digest() != intent_digest || commit.parents.len() > 1 {
                return Err(PublicationError::Corrupt);
            }
            CommitEvidence::Mutation {
                intent,
                acknowledgement: None,
            }
        }
        ReconciliationCommitPayload::Merge { .. } => {
            let receipt = super::super::reconciliation_apply::load_receipt(
                connection,
                commit.operation_id,
                crate::PublicationDisposition::Replayed,
            )?
            .ok_or(PublicationError::Corrupt)?;
            CommitEvidence::Merge {
                causal_plan_digest: receipt.causal_plan_digest,
                result_digest: receipt.result_digest,
            }
        }
        ReconciliationCommitPayload::Restore { .. } => {
            let receipt = super::super::snapshot_restore::load_receipt(
                connection,
                commit.operation_id,
                crate::PublicationDisposition::Replayed,
            )?
            .ok_or(PublicationError::Corrupt)?;
            CommitEvidence::Restore {
                result_digest: receipt.result_digest,
            }
        }
    };
    let (created_by, created_at, commit_digest) = load_commit_origin(connection, commit_id)?;
    Ok(TransferredNamespaceCommit {
        commit,
        created_by,
        created_at,
        commit_digest,
        evidence,
    })
}

fn load_commit_origin(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<(PrincipalId, UnixMicros, [u8; 32]), PublicationError> {
    let stored: (Vec<u8>, i64, Vec<u8>) = connection.query_row(
        "SELECT created_by, created_at, commit_digest
         FROM namespace_commits WHERE namespace_commit_id = ?1",
        [commit_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok((
        decode_identifier(&stored.0, PrincipalId::from_bytes)?,
        UnixMicros::new(stored.1),
        copy_array(&stored.2)?,
    ))
}
