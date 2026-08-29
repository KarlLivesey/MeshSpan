// SPDX-License-Identifier: GPL-2.0-only

//! Source-side causal traversal and immutable-record collection.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, UnixMicros, VolumeId,
};
use rusqlite::Connection;

use super::super::repository::{
    ObjectRevisionInsert, load_branch_intent, load_object_revision, load_reconciliation_commit,
};
use super::{TransferredFileVersion, TransferredMutationCommit};
use crate::publication::{copy_array, decode_identifier, from_i64, load_directory_node};
use crate::{
    DirectoryNodeRecord, ManifestPublication, NamespaceHistoryBundle, NamespaceHistoryLimits,
    PublicationError, ReconciliationCommitPayload,
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
    let object_revisions = load_volume_revisions(connection, volume_id, limits)?;
    let directory_nodes = load_revision_directory_nodes(connection, &object_revisions, limits)?;
    let file_versions = load_volume_versions(connection, volume_id, limits)?;
    let manifests = load_manifests(connection, &file_versions, limits)?;
    super::import::ensure_record_limit(
        commits
            .len()
            .checked_add(object_revisions.len())
            .and_then(|count| count.checked_add(directory_nodes.len()))
            .and_then(|count| count.checked_add(file_versions.len()))
            .and_then(|count| count.checked_add(manifests.len())),
        limits,
    )?;
    Ok(NamespaceHistoryBundle {
        volume_id,
        heads: heads.to_vec(),
        commits,
        directory_nodes,
        manifests,
        file_versions,
        object_revisions,
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
) -> Result<Vec<TransferredMutationCommit>, PublicationError> {
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
        let commit = load_reconciliation_commit(connection, commit_id)?
            .ok_or(PublicationError::InvalidInput)?;
        let ReconciliationCommitPayload::Mutation { intent_digest } = commit.payload else {
            return Err(PublicationError::InvalidInput);
        };
        if commit.volume_id != volume_id || commit.parents.len() > 1 {
            return Err(PublicationError::InvalidInput);
        }
        let intent = load_branch_intent(connection, commit_id)?.ok_or(PublicationError::Corrupt)?;
        if intent.digest() != intent_digest {
            return Err(PublicationError::Corrupt);
        }
        let (created_by, created_at, commit_digest) = load_commit_origin(connection, commit_id)?;
        pending.extend(commit.parents.iter().copied());
        commits.insert(
            commit_id,
            TransferredMutationCommit {
                commit,
                created_by,
                created_at,
                commit_digest,
                intent,
            },
        );
    }
    Ok(commits.into_values().collect())
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

fn load_volume_revisions(
    connection: &Connection,
    volume_id: VolumeId,
    limits: NamespaceHistoryLimits,
) -> Result<Vec<ObjectRevisionInsert>, PublicationError> {
    let mut statement = connection.prepare(
        "SELECT object_revision_id FROM object_revisions
         WHERE volume_id = ?1 ORDER BY created_at, object_revision_id",
    )?;
    let rows = statement.query_map([volume_id.as_bytes().as_slice()], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    let mut records = Vec::new();
    for row in rows {
        if records.len() >= limits.maximum_immutable_records {
            return Err(PublicationError::InvalidInput);
        }
        let revision_id = decode_identifier(&row?, ObjectRevisionId::from_bytes)?;
        records.push(load_object_revision(connection, revision_id)?);
    }
    Ok(records)
}

fn load_revision_directory_nodes(
    connection: &Connection,
    revisions: &[ObjectRevisionInsert],
    limits: NamespaceHistoryLimits,
) -> Result<Vec<DirectoryNodeRecord>, PublicationError> {
    let mut pending = revisions
        .iter()
        .filter_map(|revision| revision.directory_root)
        .collect::<Vec<_>>();
    let mut visited = BTreeSet::new();
    let mut records = Vec::new();
    while let Some(digest) = pending.pop() {
        if !visited.insert(digest) {
            continue;
        }
        if visited.len() > limits.maximum_immutable_records {
            return Err(PublicationError::InvalidInput);
        }
        let record = load_directory_node(connection, digest)?.ok_or(PublicationError::Corrupt)?;
        if let crate::directory::DirectoryNodeView::Internal { children, .. } = record.view() {
            pending.extend(children.into_iter().map(|(_, child)| child));
        }
        records.push(record);
    }
    records.sort_by_key(DirectoryNodeRecord::digest);
    Ok(records)
}

fn load_volume_versions(
    connection: &Connection,
    volume_id: VolumeId,
    limits: NamespaceHistoryLimits,
) -> Result<Vec<TransferredFileVersion>, PublicationError> {
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
    let mut statement = connection.prepare(
        "SELECT version_id, branch_id, object_id, parent_version_id, manifest_id,
                logical_length, content_digest, created_by, created_at, publication_operation_id
         FROM file_versions WHERE volume_id = ?1 ORDER BY created_at, version_id",
    )?;
    let rows = statement.query_map([volume_id.as_bytes().as_slice()], |row| {
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
            row.get(9)?,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        if records.len() >= limits.maximum_immutable_records {
            return Err(PublicationError::InvalidInput);
        }
        let stored: Stored = row?;
        records.push(TransferredFileVersion {
            version_id: decode_identifier(&stored.0, FileVersionId::from_bytes)?,
            branch_id: decode_identifier(&stored.1, BranchId::from_bytes)?,
            volume_id,
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
        });
    }
    Ok(records)
}

fn load_manifests(
    connection: &Connection,
    versions: &[TransferredFileVersion],
    limits: NamespaceHistoryLimits,
) -> Result<Vec<ManifestPublication>, PublicationError> {
    let identifiers = versions
        .iter()
        .map(|version| version.manifest_id)
        .collect::<BTreeSet<_>>();
    if identifiers.len() > limits.maximum_immutable_records {
        return Err(PublicationError::InvalidInput);
    }
    identifiers
        .into_iter()
        .map(|manifest_id| {
            let stored: (i64, i64, Vec<u8>, Vec<u8>, i64) = connection.query_row(
                "SELECT format_version, logical_length, content_digest, root_digest, state
             FROM content_manifests WHERE manifest_id = ?1",
                [manifest_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )?;
            if stored.4 != 1 {
                return Err(PublicationError::Corrupt);
            }
            Ok(ManifestPublication {
                manifest_id,
                format_version: u16::try_from(stored.0).map_err(|_| PublicationError::Corrupt)?,
                logical_length: from_i64(stored.1)?,
                content_digest: copy_array(&stored.2)?,
                root_digest: copy_array(&stored.3)?,
            })
        })
        .collect()
}
