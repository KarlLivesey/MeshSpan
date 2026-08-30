// SPDX-License-Identifier: GPL-2.0-only

//! Receiver-side shape validation and all-or-nothing immutable import.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::super::repository::{
    ObjectRevisionInsert, StoredCommit, load_branch_intent, load_object_revision,
    load_reconciliation_commit, persist_branch_intent, persist_object_revision,
    persist_stored_commit, stored_commit_digest,
};
use super::{TransferredFileVersion, TransferredMutationCommit, imported_evidence_digest};
use crate::NamespaceHistoryMutationDecision;
use crate::publication::{
    copy_array, decode_identifier, from_i64, persist_directory_node, persist_manifest, to_i64,
};
use crate::{
    DirectoryNodeRecord, ManifestPublication, NamespaceHistoryBundle, NamespaceHistoryImport,
    NamespaceHistoryLimits, PublicationError, ReconciliationCommitPayload,
};

pub(in crate::publication) fn import_history(
    connection: &mut Connection,
    bundle: &NamespaceHistoryBundle,
    limits: NamespaceHistoryLimits,
) -> Result<NamespaceHistoryImport, PublicationError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = import_history_transaction(&transaction, bundle, limits, None)?;
    transaction.commit()?;
    Ok(result)
}

pub(in crate::publication) fn import_federated_history(
    connection: &mut Connection,
    bundle: &NamespaceHistoryBundle,
    limits: NamespaceHistoryLimits,
    decisions: &[NamespaceHistoryMutationDecision],
) -> Result<NamespaceHistoryImport, PublicationError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = import_history_transaction(&transaction, bundle, limits, Some(decisions))?;
    transaction.commit()?;
    Ok(result)
}

pub(in crate::publication) fn import_history_transaction(
    transaction: &Transaction<'_>,
    bundle: &NamespaceHistoryBundle,
    limits: NamespaceHistoryLimits,
    decisions: Option<&[NamespaceHistoryMutationDecision]>,
) -> Result<NamespaceHistoryImport, PublicationError> {
    validate_bundle_shape(bundle, limits)?;
    let decisions = validate_decisions(&bundle.commits, decisions)?;
    persist_nodes(transaction, &bundle.directory_nodes)?;
    persist_manifests(transaction, &bundle.manifests)?;
    persist_versions(transaction, &bundle.file_versions)?;
    persist_revisions(transaction, &bundle.object_revisions)?;
    let imported_commits = persist_commits(transaction, &bundle.commits, &decisions)?;
    verify_heads(transaction, bundle)?;
    Ok(NamespaceHistoryImport {
        imported_commits,
        supplied_commits: bundle.commits.len(),
        immutable_records: bundle.immutable_record_count(),
    })
}

fn validate_decisions(
    commits: &[TransferredMutationCommit],
    decisions: Option<&[NamespaceHistoryMutationDecision]>,
) -> Result<BTreeMap<NamespaceCommitId, NamespaceHistoryMutationDecision>, PublicationError> {
    let Some(decisions) = decisions else {
        return if commits
            .iter()
            .all(|record| record.acknowledgement.is_none())
        {
            Ok(BTreeMap::new())
        } else {
            Err(PublicationError::InvalidInput)
        };
    };
    if decisions.len() != commits.len()
        || commits
            .iter()
            .any(|record| record.acknowledgement.is_none())
    {
        return Err(PublicationError::InvalidInput);
    }
    let mut indexed = BTreeMap::new();
    for decision in decisions {
        if indexed.insert(decision.commit_id(), *decision).is_some() {
            return Err(PublicationError::InvalidInput);
        }
    }
    for record in commits {
        let decision = indexed
            .get(&record.commit.commit_id)
            .ok_or(PublicationError::InvalidInput)?;
        if decision.classified_at() < record.created_at {
            return Err(PublicationError::InvalidInput);
        }
    }
    Ok(indexed)
}

fn validate_bundle_shape(
    bundle: &NamespaceHistoryBundle,
    limits: NamespaceHistoryLimits,
) -> Result<(), PublicationError> {
    super::export::validate_request(&bundle.heads, &[], limits)?;
    if bundle.commits.len() > limits.maximum_commits {
        return Err(PublicationError::InvalidInput);
    }
    ensure_record_limit(Some(bundle.immutable_record_count()), limits)?;
    if bundle
        .commits
        .iter()
        .map(|record| record.commit.commit_id)
        .collect::<BTreeSet<_>>()
        .len()
        != bundle.commits.len()
        || bundle
            .directory_nodes
            .iter()
            .map(DirectoryNodeRecord::digest)
            .collect::<BTreeSet<_>>()
            .len()
            != bundle.directory_nodes.len()
        || bundle
            .manifests
            .iter()
            .map(|record| record.manifest_id)
            .collect::<BTreeSet<_>>()
            .len()
            != bundle.manifests.len()
        || bundle
            .file_versions
            .iter()
            .map(|record| record.version_id)
            .collect::<BTreeSet<_>>()
            .len()
            != bundle.file_versions.len()
        || bundle
            .object_revisions
            .iter()
            .map(|record| record.revision_id)
            .collect::<BTreeSet<_>>()
            .len()
            != bundle.object_revisions.len()
    {
        return Err(PublicationError::InvalidInput);
    }
    if bundle.commits.iter().any(|record| {
        record.commit.volume_id != bundle.volume_id
            || record.commit.commit_id != record.intent.commit_id
            || record.commit.parents.len() > 1
            || record.intent.digest()
                != match record.commit.payload {
                    ReconciliationCommitPayload::Mutation { intent_digest } => intent_digest,
                    _ => return true,
                }
    }) || bundle
        .file_versions
        .iter()
        .any(|record| record.volume_id != bundle.volume_id)
        || bundle
            .object_revisions
            .iter()
            .any(|record| record.volume_id != bundle.volume_id)
    {
        return Err(PublicationError::InvalidInput);
    }
    Ok(())
}

pub(super) fn ensure_record_limit(
    count: Option<usize>,
    limits: NamespaceHistoryLimits,
) -> Result<(), PublicationError> {
    if count.is_some_and(|count| count <= limits.maximum_immutable_records) {
        Ok(())
    } else {
        Err(PublicationError::InvalidInput)
    }
}

fn persist_nodes(
    transaction: &Transaction<'_>,
    nodes: &[DirectoryNodeRecord],
) -> Result<(), PublicationError> {
    for node in nodes {
        persist_directory_node(transaction, node, UnixMicros::new(0))?;
    }
    Ok(())
}

fn persist_manifests(
    transaction: &Transaction<'_>,
    manifests: &[ManifestPublication],
) -> Result<(), PublicationError> {
    for manifest in manifests {
        persist_manifest(transaction, *manifest)?;
    }
    Ok(())
}

fn persist_versions(
    transaction: &Transaction<'_>,
    versions: &[TransferredFileVersion],
) -> Result<(), PublicationError> {
    let mut pending = versions
        .iter()
        .copied()
        .map(|record| (record.version_id, record))
        .collect::<BTreeMap<_, _>>();
    while !pending.is_empty() {
        let before = pending.len();
        let identifiers = pending.keys().copied().collect::<Vec<_>>();
        for version_id in identifiers {
            let record = pending[&version_id];
            if let Some(parent) = record.parent_version_id
                && !version_exists(transaction, parent)?
            {
                continue;
            }
            persist_file_version(transaction, record)?;
            pending.remove(&version_id);
        }
        if pending.len() == before {
            return Err(PublicationError::InvalidInput);
        }
    }
    Ok(())
}

fn version_exists(
    connection: &Connection,
    version_id: FileVersionId,
) -> Result<bool, PublicationError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM file_versions WHERE version_id = ?1)",
        [version_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn persist_file_version(
    transaction: &Transaction<'_>,
    record: TransferredFileVersion,
) -> Result<(), PublicationError> {
    let existing = load_file_version(transaction, record.version_id)?;
    if let Some(existing) = existing {
        return if existing == record {
            Ok(())
        } else {
            Err(PublicationError::OperationConflict)
        };
    }
    transaction.execute(
        "INSERT OR IGNORE INTO branch_files(branch_id, object_id, volume_id, current_version_id, head_sequence)
         VALUES (?1, ?2, ?3, NULL, 0)",
        params![record.branch_id.as_bytes().as_slice(), record.object_id.as_bytes().as_slice(), record.volume_id.as_bytes().as_slice()],
    )?;
    let parent = record.parent_version_id.map(FileVersionId::as_bytes);
    transaction.execute(
        "INSERT INTO file_versions(version_id, branch_id, volume_id, object_id, parent_version_id,
            manifest_id, logical_length, content_digest, created_by, created_at, publication_operation_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![record.version_id.as_bytes().as_slice(), record.branch_id.as_bytes().as_slice(),
            record.volume_id.as_bytes().as_slice(), record.object_id.as_bytes().as_slice(),
            parent.as_ref().map(<[u8; 16]>::as_slice), record.manifest_id.as_bytes().as_slice(),
            to_i64(record.logical_length)?, record.content_digest.as_slice(), record.created_by.as_bytes().as_slice(),
            record.created_at.get(), record.operation_id.as_bytes().as_slice()],
    )?;
    Ok(())
}

fn load_file_version(
    connection: &Connection,
    version_id: FileVersionId,
) -> Result<Option<TransferredFileVersion>, PublicationError> {
    type Stored = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
    );
    let stored: Option<Stored> = connection.query_row(
        "SELECT branch_id, volume_id, object_id, parent_version_id, manifest_id, logical_length,
                content_digest, created_by, created_at, publication_operation_id
         FROM file_versions WHERE version_id = ?1", [version_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?)),
    ).optional()?;
    stored
        .map(|stored| {
            Ok(TransferredFileVersion {
                version_id,
                branch_id: decode_identifier(&stored.0, BranchId::from_bytes)?,
                volume_id: decode_identifier(&stored.1, VolumeId::from_bytes)?,
                object_id: decode_identifier(&stored.2, ObjectId::from_bytes)?,
                parent_version_id: stored
                    .3
                    .as_deref()
                    .map(|value| decode_identifier(value, FileVersionId::from_bytes))
                    .transpose()?,
                manifest_id: decode_identifier(&stored.4, ContentManifestId::from_bytes)?,
                logical_length: from_i64(stored.5)?,
                content_digest: copy_array(&stored.6)?,
                created_by: decode_identifier(&stored.7, PrincipalId::from_bytes)?,
                created_at: UnixMicros::new(stored.8),
                operation_id: decode_identifier(&stored.9, OperationId::from_bytes)?,
            })
        })
        .transpose()
}

fn persist_revisions(
    transaction: &Transaction<'_>,
    revisions: &[ObjectRevisionInsert],
) -> Result<(), PublicationError> {
    let mut pending = revisions
        .iter()
        .copied()
        .map(|record| (record.revision_id, record))
        .collect::<BTreeMap<_, _>>();
    while !pending.is_empty() {
        let before = pending.len();
        let identifiers = pending.keys().copied().collect::<Vec<_>>();
        for revision_id in identifiers {
            let record = pending[&revision_id];
            if let Some(prior) = record.prior_revision_id
                && !revision_exists(transaction, prior)?
            {
                continue;
            }
            match load_object_revision(transaction, revision_id) {
                Ok(existing) if existing == record => {}
                Ok(_) => return Err(PublicationError::OperationConflict),
                Err(PublicationError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                    persist_object_revision(transaction, record)?;
                }
                Err(error) => return Err(error),
            }
            pending.remove(&revision_id);
        }
        if pending.len() == before {
            return Err(PublicationError::InvalidInput);
        }
    }
    Ok(())
}

fn revision_exists(
    connection: &Connection,
    revision_id: ObjectRevisionId,
) -> Result<bool, PublicationError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM object_revisions WHERE object_revision_id = ?1)",
        [revision_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn persist_commits(
    transaction: &Transaction<'_>,
    commits: &[TransferredMutationCommit],
    decisions: &BTreeMap<NamespaceCommitId, NamespaceHistoryMutationDecision>,
) -> Result<usize, PublicationError> {
    let mut pending = commits
        .iter()
        .map(|record| (record.commit.commit_id, record))
        .collect::<BTreeMap<_, _>>();
    let mut imported = 0;
    while !pending.is_empty() {
        let before = pending.len();
        let identifiers = pending.keys().copied().collect::<Vec<_>>();
        for commit_id in identifiers {
            let record = pending[&commit_id];
            if !all_commits_exist(transaction, &record.commit.parents)? {
                continue;
            }
            if let Some(existing) = load_reconciliation_commit(transaction, commit_id)? {
                let expected_decision = decisions.get(&commit_id).copied();
                if existing != record.commit
                    || load_branch_intent(transaction, commit_id)?.as_ref() != Some(&record.intent)
                    || super::super::federated_mutation::load(transaction, commit_id)?
                        != record.acknowledgement
                    || super::super::federated_admission::load(transaction, commit_id)?
                        != expected_decision
                {
                    return Err(PublicationError::OperationConflict);
                }
            } else {
                let stored = StoredCommit {
                    commit_id,
                    branch_id: record.commit.branch_id,
                    volume_id: record.commit.volume_id,
                    root_object_id: record.commit.root_object_id,
                    root_object_revision_id: record.commit.root_object_revision_id,
                    parent_id: record.commit.parents.first().copied(),
                    created_by: record.created_by,
                    operation_id: record.commit.operation_id,
                    created_at: record.created_at,
                };
                if stored_commit_digest(&stored, record.commit.request_digest)
                    != record.commit_digest
                {
                    return Err(PublicationError::Corrupt);
                }
                persist_stored_commit(transaction, &stored, record.commit.request_digest)?;
                persist_imported_evidence(transaction, record)?;
                persist_branch_intent(transaction, &record.intent)?;
                if let Some(acknowledgement) = record.acknowledgement {
                    super::super::federated_mutation::persist(
                        transaction,
                        commit_id,
                        &acknowledgement,
                    )?;
                    let decision = decisions
                        .get(&commit_id)
                        .copied()
                        .ok_or(PublicationError::InvalidInput)?;
                    super::super::federated_admission::persist(
                        transaction,
                        decision,
                        &acknowledgement,
                    )?;
                }
                if load_reconciliation_commit(transaction, commit_id)?.as_ref()
                    != Some(&record.commit)
                {
                    return Err(PublicationError::Corrupt);
                }
                imported += 1;
            }
            pending.remove(&commit_id);
        }
        if pending.len() == before {
            return Err(PublicationError::InvalidInput);
        }
    }
    Ok(imported)
}

fn all_commits_exist(
    connection: &Connection,
    commit_ids: &[NamespaceCommitId],
) -> Result<bool, PublicationError> {
    for commit_id in commit_ids {
        if !commit_exists(connection, *commit_id)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn commit_exists(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<bool, PublicationError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_commits WHERE namespace_commit_id = ?1)",
        [commit_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn persist_imported_evidence(
    transaction: &Transaction<'_>,
    record: &TransferredMutationCommit,
) -> Result<(), PublicationError> {
    let intent_digest = record.intent.digest();
    let evidence_digest = imported_evidence_digest(
        record.commit.commit_id,
        record.commit.request_digest,
        intent_digest,
    );
    transaction.execute(
        "INSERT INTO imported_namespace_commit_evidence(namespace_commit_id, request_digest, intent_digest, evidence_digest)
         VALUES (?1, ?2, ?3, ?4)", params![record.commit.commit_id.as_bytes().as_slice(), record.commit.request_digest.as_slice(),
            intent_digest.as_slice(), evidence_digest.as_slice()])?;
    Ok(())
}

fn verify_heads(
    connection: &Connection,
    bundle: &NamespaceHistoryBundle,
) -> Result<(), PublicationError> {
    for head in &bundle.heads {
        let commit =
            load_reconciliation_commit(connection, *head)?.ok_or(PublicationError::InvalidInput)?;
        if commit.volume_id != bundle.volume_id {
            return Err(PublicationError::InvalidInput);
        }
    }
    Ok(())
}
