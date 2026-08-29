// SPDX-License-Identifier: GPL-2.0-only

//! Incremental traversal and durable materialisation of namespace-history work.

use meshspan_domain::{FileVersionId, NamespaceCommitId, ObjectRevisionId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::super::history_records::{
    NamespaceHistoryCommitRecord, NamespaceHistoryImmutableRecord,
};
use super::super::repository::load_object_revision;
use super::super::transfer::{export, export_graph};
use super::{ValidatedQuery, to_i64};
use crate::directory::DirectoryReachabilityReference;
use crate::publication::load_directory_node;
use crate::{DirectoryNodeDigest, PublicationError};

pub(super) const WORK_COMMIT: i64 = 1;
const WORK_REVISION: i64 = 2;
const WORK_DIRECTORY_NODE: i64 = 3;
const WORK_FILE_VERSION: i64 = 4;
const WORK_MANIFEST: i64 = 5;
pub(super) const WORK_LAST: i64 = WORK_MANIFEST;
pub(super) const RECORD_COMMIT: i64 = 1;
pub(super) const RECORD_IMMUTABLE: i64 = 2;

pub(super) fn process_until(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
    target: u64,
) -> Result<(), PublicationError> {
    let (mut next, mut complete) = load_progress(transaction, query.digest)?;
    while next < target && !complete {
        let Some(work) = next_work(transaction, query.digest)? else {
            complete = true;
            break;
        };
        if process_work(transaction, query, &work, next)? {
            next = next.checked_add(1).ok_or(PublicationError::InvalidInput)?;
        }
        mark_processed(transaction, query.digest, &work)?;
    }
    if !complete && next_work(transaction, query.digest)?.is_none() {
        complete = true;
    }
    transaction.execute(
        "UPDATE namespace_history_exports
         SET next_record_ordinal = ?1, complete = ?2
         WHERE request_digest = ?3",
        params![to_i64(next)?, i64::from(complete), query.digest.as_slice()],
    )?;
    Ok(())
}

pub(super) fn enqueue_commit(
    transaction: &Transaction<'_>,
    digest: [u8; 32],
    commit_id: NamespaceCommitId,
) -> Result<(), PublicationError> {
    enqueue(transaction, digest, WORK_COMMIT, &commit_id.as_bytes())
}

struct WorkItem {
    kind: i64,
    identity: Vec<u8>,
}

fn load_progress(
    transaction: &Transaction<'_>,
    digest: [u8; 32],
) -> Result<(u64, bool), PublicationError> {
    let stored: (i64, i64) = transaction.query_row(
        "SELECT next_record_ordinal, complete FROM namespace_history_exports
         WHERE request_digest = ?1",
        [digest.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((from_i64(stored.0)?, parse_bool(stored.1)?))
}

fn next_work(
    transaction: &Transaction<'_>,
    digest: [u8; 32],
) -> Result<Option<WorkItem>, PublicationError> {
    transaction
        .query_row(
            "SELECT work_kind, identity FROM namespace_history_export_work
             INDEXED BY namespace_history_export_pending
             WHERE request_digest = ?1 AND processed = 0
             ORDER BY work_kind, identity LIMIT 1",
            [digest.as_slice()],
            |row| {
                Ok(WorkItem {
                    kind: row.get(0)?,
                    identity: row.get(1)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn process_work(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
    work: &WorkItem,
    ordinal: u64,
) -> Result<bool, PublicationError> {
    match work.kind {
        WORK_COMMIT => process_commit(transaction, query, work, ordinal),
        WORK_REVISION => process_revision(transaction, query, work, ordinal),
        WORK_DIRECTORY_NODE => process_directory(transaction, query, work, ordinal),
        WORK_FILE_VERSION => process_version(transaction, query, work, ordinal),
        WORK_MANIFEST => process_manifest(transaction, query, work, ordinal),
        _ => Err(PublicationError::Corrupt),
    }
}

fn process_commit(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
    work: &WorkItem,
    ordinal: u64,
) -> Result<bool, PublicationError> {
    let commit_id = identifier(&work.identity, NamespaceCommitId::from_bytes)?;
    if known_commit(transaction, query.digest, commit_id)? {
        return Ok(false);
    }
    let source = export::load_commit_record(transaction, query.volume_id, commit_id)?;
    let record = NamespaceHistoryCommitRecord::from_commit(&source)
        .map_err(|_| PublicationError::Corrupt)?;
    append_record(
        transaction,
        query.digest,
        ordinal,
        RECORD_COMMIT,
        work,
        record.digest(),
    )?;
    for parent in &source.commit.parents {
        enqueue_commit(transaction, query.digest, *parent)?;
    }
    let references = export_graph::commit_references(&source);
    for revision in references.revisions {
        enqueue(
            transaction,
            query.digest,
            WORK_REVISION,
            &revision.as_bytes(),
        )?;
    }
    for version in references.versions {
        enqueue(
            transaction,
            query.digest,
            WORK_FILE_VERSION,
            &version.as_bytes(),
        )?;
    }
    Ok(true)
}

fn process_revision(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
    work: &WorkItem,
    ordinal: u64,
) -> Result<bool, PublicationError> {
    let revision_id = identifier(&work.identity, ObjectRevisionId::from_bytes)?;
    let source = load_object_revision(transaction, revision_id)?;
    if source.volume_id != query.volume_id {
        return Err(PublicationError::Corrupt);
    }
    let record = NamespaceHistoryImmutableRecord::object_revision(source)
        .map_err(|_| PublicationError::Corrupt)?;
    append_record(
        transaction,
        query.digest,
        ordinal,
        RECORD_IMMUTABLE,
        work,
        record.digest(),
    )?;
    if let Some(prior) = source.prior_revision_id {
        enqueue(transaction, query.digest, WORK_REVISION, &prior.as_bytes())?;
    }
    if let Some(root) = source.directory_root {
        enqueue(
            transaction,
            query.digest,
            WORK_DIRECTORY_NODE,
            &root.as_bytes(),
        )?;
    }
    if let Some(version) = source.file_version_id {
        enqueue(
            transaction,
            query.digest,
            WORK_FILE_VERSION,
            &version.as_bytes(),
        )?;
    }
    Ok(true)
}

fn process_directory(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
    work: &WorkItem,
    ordinal: u64,
) -> Result<bool, PublicationError> {
    let digest = DirectoryNodeDigest::from_bytes(array(&work.identity)?);
    let source = load_directory_node(transaction, digest)?.ok_or(PublicationError::Corrupt)?;
    let record = NamespaceHistoryImmutableRecord::directory(&source)
        .map_err(|_| PublicationError::Corrupt)?;
    append_record(
        transaction,
        query.digest,
        ordinal,
        RECORD_IMMUTABLE,
        work,
        record.digest(),
    )?;
    for reference in source.reachability_references() {
        match reference {
            DirectoryReachabilityReference::Node(child) => enqueue(
                transaction,
                query.digest,
                WORK_DIRECTORY_NODE,
                &child.as_bytes(),
            )?,
            DirectoryReachabilityReference::ObjectRevision(revision) => enqueue(
                transaction,
                query.digest,
                WORK_REVISION,
                &revision.as_bytes(),
            )?,
        }
    }
    Ok(true)
}

fn process_version(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
    work: &WorkItem,
    ordinal: u64,
) -> Result<bool, PublicationError> {
    let version_id = identifier(&work.identity, FileVersionId::from_bytes)?;
    let source = export_graph::load_file_version(transaction, version_id)?;
    if source.volume_id != query.volume_id {
        return Err(PublicationError::Corrupt);
    }
    let record = NamespaceHistoryImmutableRecord::file_version(source)
        .map_err(|_| PublicationError::Corrupt)?;
    append_record(
        transaction,
        query.digest,
        ordinal,
        RECORD_IMMUTABLE,
        work,
        record.digest(),
    )?;
    if let Some(parent) = source.parent_version_id {
        enqueue(
            transaction,
            query.digest,
            WORK_FILE_VERSION,
            &parent.as_bytes(),
        )?;
    }
    enqueue(
        transaction,
        query.digest,
        WORK_MANIFEST,
        &source.manifest_id.as_bytes(),
    )?;
    Ok(true)
}

fn process_manifest(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
    work: &WorkItem,
    ordinal: u64,
) -> Result<bool, PublicationError> {
    let manifest_id = identifier(
        &work.identity,
        meshspan_domain::ContentManifestId::from_bytes,
    )?;
    let source = export_graph::load_manifest(transaction, manifest_id)?;
    let record =
        NamespaceHistoryImmutableRecord::manifest(source).map_err(|_| PublicationError::Corrupt)?;
    append_record(
        transaction,
        query.digest,
        ordinal,
        RECORD_IMMUTABLE,
        work,
        record.digest(),
    )?;
    Ok(true)
}

fn append_record(
    transaction: &Transaction<'_>,
    digest: [u8; 32],
    ordinal: u64,
    record_kind: i64,
    work: &WorkItem,
    transfer_digest: [u8; 32],
) -> Result<(), PublicationError> {
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM namespace_history_export_records
            WHERE request_digest = ?1 AND record_kind = ?2 AND transfer_digest = ?3)",
        params![digest.as_slice(), record_kind, transfer_digest.as_slice()],
        |row| row.get(0),
    )?;
    if collision != 0 {
        return Err(PublicationError::Corrupt);
    }
    transaction.execute(
        "INSERT INTO namespace_history_export_records(
            request_digest, record_ordinal, record_kind, source_kind,
            source_identity, transfer_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            digest.as_slice(),
            to_i64(ordinal)?,
            record_kind,
            work.kind,
            work.identity,
            transfer_digest.as_slice()
        ],
    )?;
    Ok(())
}

fn known_commit(
    transaction: &Transaction<'_>,
    digest: [u8; 32],
    commit_id: NamespaceCommitId,
) -> Result<bool, PublicationError> {
    Ok(transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM namespace_history_export_known_commits
            WHERE request_digest = ?1 AND namespace_commit_id = ?2)",
        params![digest.as_slice(), commit_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )? == 1)
}

fn enqueue(
    transaction: &Transaction<'_>,
    digest: [u8; 32],
    kind: i64,
    identity: &[u8],
) -> Result<(), PublicationError> {
    let valid_length = match kind {
        WORK_DIRECTORY_NODE => identity.len() == 32,
        WORK_COMMIT | WORK_REVISION | WORK_FILE_VERSION | WORK_MANIFEST => identity.len() == 16,
        _ => false,
    };
    if !valid_length {
        return Err(PublicationError::Corrupt);
    }
    transaction.execute(
        "INSERT OR IGNORE INTO namespace_history_export_work(
            request_digest, work_kind, identity, processed)
         VALUES (?1, ?2, ?3, 0)",
        params![digest.as_slice(), kind, identity],
    )?;
    Ok(())
}

fn mark_processed(
    transaction: &Transaction<'_>,
    digest: [u8; 32],
    work: &WorkItem,
) -> Result<(), PublicationError> {
    let changed = transaction.execute(
        "UPDATE namespace_history_export_work SET processed = 1
         WHERE request_digest = ?1 AND work_kind = ?2 AND identity = ?3 AND processed = 0",
        params![digest.as_slice(), work.kind, work.identity],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn identifier<T, E>(
    bytes: &[u8],
    constructor: impl FnOnce([u8; 16]) -> Result<T, E>,
) -> Result<T, PublicationError> {
    constructor(bytes.try_into().map_err(|_| PublicationError::Corrupt)?)
        .map_err(|_| PublicationError::Corrupt)
}

fn array(bytes: &[u8]) -> Result<[u8; 32], PublicationError> {
    bytes.try_into().map_err(|_| PublicationError::Corrupt)
}

fn from_i64(value: i64) -> Result<u64, PublicationError> {
    u64::try_from(value).map_err(|_| PublicationError::Corrupt)
}

fn parse_bool(value: i64) -> Result<bool, PublicationError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PublicationError::Corrupt),
    }
}
