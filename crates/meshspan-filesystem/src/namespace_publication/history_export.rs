// SPDX-License-Identifier: GPL-2.0-only

//! Durable incremental paging of one exact immutable namespace-history graph.

use std::collections::BTreeSet;

use meshspan_domain::{NamespaceCommitId, UnixMicros, VolumeId};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::history_records::NamespaceHistoryCommitRecord;
use super::history_records::NamespaceHistoryImmutableRecord;
use crate::PublicationError;

#[path = "history_export/object.rs"]
mod object;
#[path = "history_export/output.rs"]
mod output;
#[path = "history_export/work.rs"]
mod work;

const MAXIMUM_HEADS: usize = 64;
const MAXIMUM_KNOWN_COMMITS: usize = 4_096;
const MAXIMUM_PAGE_RECORDS: usize = 4_096;
const MAXIMUM_SESSION_MICROS: i64 = 86_400_000_000;

/// Exact authorised scope and causal state for one resumable history page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryPageRequest {
    /// Digest of the current external grant, authority revisions and resource scope.
    pub scope_binding: [u8; 32],
    /// Volume selected by the authorised resource.
    pub volume_id: VolumeId,
    /// Exact source heads whose missing causal graph is requested.
    pub requested_heads: Vec<NamespaceCommitId>,
    /// Commit identities already held by the receiver.
    pub known_commits: Vec<NamespaceCommitId>,
    /// Empty for the first page or an exact previously issued continuation.
    pub cursor: Vec<u8>,
    /// Positive maximum combined commit and immutable identities in this page.
    pub limit: usize,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
    /// Bounded instant after which this durable export may no longer resume.
    pub expires_at: UnixMicros,
}

/// One bounded page of canonical commits and separately retrievable immutable identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryPage {
    /// Stable source-side export identity required for separately fetched immutable bodies.
    pub export_token: [u8; 32],
    /// Canonical independently validated mutation commits.
    pub commits: Vec<NamespaceHistoryCommitRecord>,
    /// Canonical transfer digests for immutable bodies carried on data streams.
    pub immutable_object_digests: Vec<[u8; 32]>,
    /// Exact continuation, empty only when this export is terminal.
    pub next_cursor: Vec<u8>,
}

/// Exact active export and advertised immutable body selected for a bounded fetch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryObjectRequest {
    /// Digest of the current external grant, authority revisions and resource scope.
    pub scope_binding: [u8; 32],
    /// Export token returned by the signed history page which advertised the object.
    pub export_token: [u8; 32],
    /// Exact immutable transfer digest advertised by that export.
    pub object_digest: [u8; 32],
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

pub(super) fn page(
    connection: &mut Connection,
    request: NamespaceHistoryPageRequest,
) -> Result<NamespaceHistoryPage, PublicationError> {
    let query = ValidatedQuery::new(request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    initialise(&transaction, &query)?;
    require_cursor(&transaction, query.digest, query.start_ordinal)?;
    let target = query
        .start_ordinal
        .checked_add(u64::try_from(query.limit).map_err(|_| PublicationError::InvalidInput)?)
        .ok_or(PublicationError::InvalidInput)?;
    work::process_until(&transaction, &query, target)?;
    let result = output::load_page(&transaction, &query)?;
    transaction.commit()?;
    Ok(result)
}

pub(super) fn history_object(
    connection: &Connection,
    request: NamespaceHistoryObjectRequest,
) -> Result<NamespaceHistoryImmutableRecord, PublicationError> {
    object::load(connection, request)
}

struct ValidatedQuery {
    digest: [u8; 32],
    scope_binding: [u8; 32],
    volume_id: VolumeId,
    heads: Vec<NamespaceCommitId>,
    known: Vec<NamespaceCommitId>,
    start_ordinal: u64,
    limit: usize,
    now: UnixMicros,
    expires_at: UnixMicros,
    has_cursor: bool,
}

impl ValidatedQuery {
    fn new(request: NamespaceHistoryPageRequest) -> Result<Self, PublicationError> {
        let heads = unique_sorted(request.requested_heads, MAXIMUM_HEADS, false)?;
        let known = unique_sorted(request.known_commits, MAXIMUM_KNOWN_COMMITS, true)?;
        let lifetime = request
            .expires_at
            .get()
            .checked_sub(request.now.get())
            .ok_or(PublicationError::InvalidInput)?;
        if request.limit == 0
            || request.limit > MAXIMUM_PAGE_RECORDS
            || lifetime <= 0
            || lifetime > MAXIMUM_SESSION_MICROS
        {
            return Err(PublicationError::InvalidInput);
        }
        let digest = request_digest(request.scope_binding, request.volume_id, &heads, &known)?;
        let has_cursor = !request.cursor.is_empty();
        let start_ordinal = if has_cursor {
            output::decode_cursor(&request.cursor, digest)?
        } else {
            0
        };
        Ok(Self {
            digest,
            scope_binding: request.scope_binding,
            volume_id: request.volume_id,
            heads,
            known,
            start_ordinal,
            limit: request.limit,
            now: request.now,
            expires_at: request.expires_at,
            has_cursor,
        })
    }
}

fn unique_sorted<T: Copy + Ord>(
    values: Vec<T>,
    maximum: usize,
    allow_empty: bool,
) -> Result<Vec<T>, PublicationError> {
    if values.len() > maximum || (!allow_empty && values.is_empty()) {
        return Err(PublicationError::InvalidInput);
    }
    let supplied = values.len();
    let unique = values.into_iter().collect::<BTreeSet<_>>();
    if unique.len() != supplied || (unique.is_empty() && !allow_empty) {
        Err(PublicationError::InvalidInput)
    } else {
        Ok(unique.into_iter().collect())
    }
}

fn request_digest(
    scope_binding: [u8; 32],
    volume_id: VolumeId,
    heads: &[NamespaceCommitId],
    known: &[NamespaceCommitId],
) -> Result<[u8; 32], PublicationError> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.history-export.v1\0");
    digest.update(&scope_binding);
    digest.update(&volume_id.as_bytes());
    update_identifiers(&mut digest, heads)?;
    update_identifiers(&mut digest, known)?;
    Ok(digest.finalize().into())
}

fn update_identifiers(
    digest: &mut blake3::Hasher,
    values: &[NamespaceCommitId],
) -> Result<(), PublicationError> {
    digest.update(
        &u32::try_from(values.len())
            .map_err(|_| PublicationError::InvalidInput)?
            .to_be_bytes(),
    );
    for value in values {
        digest.update(&value.as_bytes());
    }
    Ok(())
}

fn initialise(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
) -> Result<(), PublicationError> {
    let existing: Option<(Vec<u8>, Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT volume_id, scope_binding, expires_at FROM namespace_history_exports
             WHERE request_digest = ?1",
            [query.digest.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((volume, scope_binding, expires_at)) = existing {
        if volume.as_slice() != query.volume_id.as_bytes()
            || scope_binding.as_slice() != query.scope_binding
        {
            return Err(PublicationError::Corrupt);
        }
        if expires_at > query.now.get() {
            return Ok(());
        }
        if query.has_cursor {
            return Err(PublicationError::InvalidInput);
        }
        transaction.execute(
            "DELETE FROM namespace_history_exports WHERE request_digest = ?1",
            [query.digest.as_slice()],
        )?;
    }
    transaction.execute(
        "INSERT INTO namespace_history_exports(
            request_digest, volume_id, next_record_ordinal, complete, created_at, expires_at,
            scope_binding
         ) VALUES (?1, ?2, 0, 0, ?3, ?4, ?5)",
        params![
            query.digest.as_slice(),
            query.volume_id.as_bytes().as_slice(),
            query.now.get(),
            query.expires_at.get(),
            query.scope_binding.as_slice()
        ],
    )?;
    for commit_id in &query.known {
        transaction.execute(
            "INSERT INTO namespace_history_export_known_commits(
                request_digest, namespace_commit_id) VALUES (?1, ?2)",
            params![query.digest.as_slice(), commit_id.as_bytes().as_slice()],
        )?;
    }
    for head in &query.heads {
        work::enqueue_commit(transaction, query.digest, *head)?;
    }
    output::issue_cursor(transaction, query.digest, 0)
}

fn require_cursor(
    transaction: &Transaction<'_>,
    digest: [u8; 32],
    start: u64,
) -> Result<(), PublicationError> {
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM namespace_history_export_cursors
            WHERE request_digest = ?1 AND start_ordinal = ?2)",
        params![digest.as_slice(), to_i64(start)?],
        |row| row.get(0),
    )?;
    if exists == 1 {
        Ok(())
    } else {
        Err(PublicationError::InvalidInput)
    }
}

fn to_i64(value: u64) -> Result<i64, PublicationError> {
    i64::try_from(value).map_err(|_| PublicationError::InvalidInput)
}
