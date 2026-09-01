// SPDX-License-Identifier: GPL-2.0-only

//! Durable receiver staging for hostile, incrementally fetched namespace history.

use std::collections::BTreeSet;

use meshspan_domain::{
    BranchId, FederatedMutationAdmission, NamespaceCommitId, ObjectRevisionId, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::history_export::NamespaceHistoryPage;
use super::history_records::{NamespaceHistoryImmutableRecord, NamespaceHistoryRecordError};
use crate::{
    BranchNamespaceHead, NamespaceHistoryImport, NamespaceHistoryLimits, PublicationDisposition,
    PublicationError,
};

#[path = "history_import/complete.rs"]
mod complete;
#[path = "history_import/repository.rs"]
mod repository;

use repository::{
    StoredSession, insert_session, load_session, require_same_request, status, usize_value,
};

const RECORD_COMMIT: i64 = 1;
const RECORD_IMMUTABLE: i64 = 2;
const MAXIMUM_CURSOR_BYTES: usize = 256;
const MAXIMUM_SESSION_MICROS: i64 = 86_400_000_000;

/// Immutable authority and resource bounds for one durable receive transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryReceiveRequest {
    /// Receiver-selected idempotency identity for the transaction.
    pub session_id: [u8; 32],
    /// Digest of the exact grant, resource and authority revisions authorising the exchange.
    pub scope_binding: [u8; 32],
    /// Volume into which the immutable history may be imported.
    pub volume_id: VolumeId,
    /// Exact source heads which must become verifiable before import commits.
    pub requested_heads: Vec<NamespaceCommitId>,
    /// Hard cumulative bounds for the complete receive transaction.
    pub limits: NamespaceHistoryLimits,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
    /// Time after which an incomplete transaction must fail closed.
    pub expires_at: UnixMicros,
}

/// Durable progress of one receiver-side history transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryReceiveStatus {
    /// Stable source export identity once the first page has been accepted.
    pub export_token: Option<[u8; 32]>,
    /// Exact cursor which must be used for the next source request.
    pub next_cursor: Vec<u8>,
    /// Whether the source has supplied its terminal page.
    pub terminal: bool,
    /// Number of independently validated mutation commits staged so far.
    pub commits: usize,
    /// Number of immutable identities advertised so far.
    pub immutable_records: usize,
    /// Number of advertised immutable bodies not yet received.
    pub missing_immutable_records: usize,
    /// Oldest advertised body still required, allowing exact restart without replaying pages.
    pub next_missing_immutable_record: Option<[u8; 32]>,
    /// Whether the entire history was already atomically imported.
    pub completed: bool,
}

/// Idempotent result of atomically publishing one complete received history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryReceiveCompletion {
    /// Whether this call committed the import or replayed its durable receipt.
    pub disposition: PublicationDisposition,
    /// Exact original import counts, including on replay after restart.
    pub import: NamespaceHistoryImport,
}

/// One owner-side decision for an exact signed federated namespace commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryMutationDecision {
    commit_id: NamespaceCommitId,
    admission: FederatedMutationAdmission,
    classified_at: UnixMicros,
}

impl NamespaceHistoryMutationDecision {
    /// Binds one authoritative classification to its exact immutable commit.
    #[must_use]
    pub const fn new(
        commit_id: NamespaceCommitId,
        admission: FederatedMutationAdmission,
        classified_at: UnixMicros,
    ) -> Self {
        Self {
            commit_id,
            admission,
            classified_at,
        }
    }

    /// Returns the exact commit which was classified.
    #[must_use]
    pub const fn commit_id(self) -> NamespaceCommitId {
        self.commit_id
    }

    /// Returns whether the commit may affect namespace state or remains quarantined.
    #[must_use]
    pub const fn admission(self) -> FederatedMutationAdmission {
        self.admission
    }

    /// Returns the authoritative mesh time used for classification.
    #[must_use]
    pub const fn classified_at(self) -> UnixMicros {
        self.classified_at
    }
}

/// Complete, validated commit records awaiting owner-side federation admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryReceivePreparation {
    admission_at: UnixMicros,
    commits: Vec<super::history_records::NamespaceHistoryCommitRecord>,
}

pub(super) fn adopt_head(
    connection: &mut Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
    namespace_commit_id: NamespaceCommitId,
    root_object_revision_id: ObjectRevisionId,
) -> Result<BranchNamespaceHead, PublicationError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let selected = super::repository::load_commit(&transaction, namespace_commit_id)?;
    if selected.volume_id != volume_id
        || selected.root_object_revision_id != root_object_revision_id
    {
        return Err(PublicationError::InvalidInput);
    }
    let existing = super::repository::load_head(&transaction, branch_id, volume_id)?;
    let sequence = match existing {
        Some(head) if head.namespace_commit_id == namespace_commit_id => {
            transaction.commit()?;
            return Ok(head);
        }
        Some(head) => {
            if !is_ancestor(&transaction, head.namespace_commit_id, namespace_commit_id)? {
                return Err(PublicationError::StaleHead);
            }
            let next = head
                .sequence
                .checked_add(1)
                .ok_or(PublicationError::InvalidInput)?;
            let changed = transaction.execute(
                "UPDATE branch_namespace_heads SET namespace_commit_id = ?1, head_sequence = ?2
                 WHERE branch_id = ?3 AND volume_id = ?4
                   AND namespace_commit_id = ?5 AND head_sequence = ?6",
                params![
                    namespace_commit_id.as_bytes().as_slice(),
                    i64::try_from(next).map_err(|_| PublicationError::InvalidInput)?,
                    branch_id.as_bytes().as_slice(),
                    volume_id.as_bytes().as_slice(),
                    head.namespace_commit_id.as_bytes().as_slice(),
                    i64::try_from(head.sequence).map_err(|_| PublicationError::InvalidInput)?,
                ],
            )?;
            if changed != 1 {
                return Err(PublicationError::StaleHead);
            }
            next
        }
        None => {
            transaction.execute(
                "INSERT INTO branch_namespace_heads(
                    branch_id, volume_id, namespace_commit_id, head_sequence
                 ) VALUES (?1, ?2, ?3, 1)",
                params![
                    branch_id.as_bytes().as_slice(),
                    volume_id.as_bytes().as_slice(),
                    namespace_commit_id.as_bytes().as_slice(),
                ],
            )?;
            1
        }
    };
    transaction.commit()?;
    Ok(BranchNamespaceHead {
        branch_id,
        volume_id,
        namespace_commit_id,
        sequence,
    })
}

fn is_ancestor(
    connection: &Connection,
    ancestor: NamespaceCommitId,
    descendant: NamespaceCommitId,
) -> Result<bool, PublicationError> {
    Ok(connection.query_row(
        "WITH RECURSIVE lineage(namespace_commit_id) AS (
            SELECT ?1
            UNION
            SELECT parent.parent_commit_id
            FROM namespace_commit_parents AS parent
            JOIN lineage ON parent.namespace_commit_id = lineage.namespace_commit_id
         )
         SELECT EXISTS(SELECT 1 FROM lineage WHERE namespace_commit_id = ?2)",
        params![
            descendant.as_bytes().as_slice(),
            ancestor.as_bytes().as_slice(),
        ],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

impl NamespaceHistoryReceivePreparation {
    /// Returns the durable receive-session instant used by every admission retry.
    #[must_use]
    pub const fn admission_at(&self) -> UnixMicros {
        self.admission_at
    }

    /// Returns every exact signed mutation which must receive one decision.
    #[must_use]
    pub fn commits(&self) -> &[super::history_records::NamespaceHistoryCommitRecord] {
        &self.commits
    }

    pub(super) const fn new(
        admission_at: UnixMicros,
        commits: Vec<super::history_records::NamespaceHistoryCommitRecord>,
    ) -> Self {
        Self {
            admission_at,
            commits,
        }
    }
}

pub(super) fn begin(
    connection: &mut Connection,
    request: &NamespaceHistoryReceiveRequest,
) -> Result<NamespaceHistoryReceiveStatus, PublicationError> {
    validate_request(request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(existing) = load_session(&transaction, request.session_id)? {
        require_same_request(&transaction, &existing, request)?;
    } else {
        insert_session(&transaction, request)?;
    }
    let result = status(&transaction, request.session_id)?;
    transaction.commit()?;
    Ok(result)
}

pub(super) fn accept_page(
    connection: &mut Connection,
    session_id: [u8; 32],
    input_cursor: &[u8],
    page: &NamespaceHistoryPage,
    now: UnixMicros,
) -> Result<NamespaceHistoryReceiveStatus, PublicationError> {
    validate_cursor(input_cursor)?;
    validate_cursor(&page.next_cursor)?;
    let digest = page_digest(input_cursor, page)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let session = require_live_session(&transaction, session_id, now)?;
    if replayed_page(&transaction, session_id, input_cursor, digest)? {
        let result = status(&transaction, session_id)?;
        transaction.commit()?;
        return Ok(result);
    }
    require_next_page(&session, input_cursor, page.export_token)?;
    validate_page_records(page, session.volume_id)?;
    require_capacity(&transaction, session_id, &session, page)?;
    insert_page_records(&transaction, session_id, page)?;
    transaction.execute(
        "INSERT INTO namespace_history_import_pages(
            session_id, input_cursor, page_digest, output_cursor
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            session_id.as_slice(),
            input_cursor,
            digest.as_slice(),
            page.next_cursor
        ],
    )?;
    transaction.execute(
        "UPDATE namespace_history_imports
         SET export_token = COALESCE(export_token, ?2), current_cursor = ?3, terminal = ?4
         WHERE session_id = ?1",
        params![
            session_id.as_slice(),
            page.export_token.as_slice(),
            page.next_cursor,
            i64::from(page.next_cursor.is_empty())
        ],
    )?;
    let result = status(&transaction, session_id)?;
    transaction.commit()?;
    Ok(result)
}

pub(super) fn accept_object(
    connection: &mut Connection,
    session_id: [u8; 32],
    record: &NamespaceHistoryImmutableRecord,
    now: UnixMicros,
) -> Result<NamespaceHistoryReceiveStatus, PublicationError> {
    NamespaceHistoryImmutableRecord::from_expected_digest(
        record.digest(),
        record.canonical_bytes().to_vec(),
    )
    .map_err(record_error)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_live_session(&transaction, session_id, now)?;
    let stored: Option<Option<Vec<u8>>> = transaction
        .query_row(
            "SELECT canonical_bytes FROM namespace_history_import_records
             WHERE session_id = ?1 AND record_kind = ?2 AND record_digest = ?3",
            params![
                session_id.as_slice(),
                RECORD_IMMUTABLE,
                record.digest().as_slice()
            ],
            |row| row.get(0),
        )
        .optional()?;
    match stored {
        None => return Err(PublicationError::InvalidInput),
        Some(Some(bytes)) if bytes != record.canonical_bytes() => {
            return Err(PublicationError::OperationConflict);
        }
        Some(Some(_)) => {}
        Some(None) => {
            transaction.execute(
                "UPDATE namespace_history_import_records SET canonical_bytes = ?4
                 WHERE session_id = ?1 AND record_kind = ?2 AND record_digest = ?3",
                params![
                    session_id.as_slice(),
                    RECORD_IMMUTABLE,
                    record.digest().as_slice(),
                    record.canonical_bytes()
                ],
            )?;
        }
    }
    let result = status(&transaction, session_id)?;
    transaction.commit()?;
    Ok(result)
}

pub(super) fn complete(
    connection: &mut Connection,
    session_id: [u8; 32],
    now: UnixMicros,
    decisions: Option<&[NamespaceHistoryMutationDecision]>,
) -> Result<NamespaceHistoryReceiveCompletion, PublicationError> {
    complete::run(connection, session_id, now, decisions)
}

pub(super) fn prepare(
    connection: &Connection,
    session_id: [u8; 32],
    now: UnixMicros,
) -> Result<NamespaceHistoryReceivePreparation, PublicationError> {
    complete::prepare(connection, session_id, now)
}

fn validate_request(request: &NamespaceHistoryReceiveRequest) -> Result<(), PublicationError> {
    let lifetime = request
        .expires_at
        .get()
        .checked_sub(request.now.get())
        .ok_or(PublicationError::InvalidInput)?;
    let distinct = request
        .requested_heads
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if request.requested_heads.is_empty()
        || request.requested_heads.len() > request.limits.maximum_heads
        || distinct.len() != request.requested_heads.len()
        || request.limits.maximum_heads == 0
        || request.limits.maximum_commits == 0
        || request.limits.maximum_immutable_records == 0
        || lifetime <= 0
        || lifetime > MAXIMUM_SESSION_MICROS
    {
        Err(PublicationError::InvalidInput)
    } else {
        Ok(())
    }
}

fn require_live_session(
    connection: &Connection,
    session_id: [u8; 32],
    now: UnixMicros,
) -> Result<StoredSession, PublicationError> {
    let session = load_session(connection, session_id)?.ok_or(PublicationError::InvalidInput)?;
    if session.completion.is_none() && now.get() < session.expires_at.get() {
        Ok(session)
    } else {
        Err(PublicationError::InvalidInput)
    }
}

fn replayed_page(
    connection: &Connection,
    session_id: [u8; 32],
    input_cursor: &[u8],
    digest: [u8; 32],
) -> Result<bool, PublicationError> {
    let stored: Option<Vec<u8>> = connection
        .query_row(
            "SELECT page_digest FROM namespace_history_import_pages
         WHERE session_id = ?1 AND input_cursor = ?2",
            params![session_id.as_slice(), input_cursor],
            |row| row.get(0),
        )
        .optional()?;
    match stored {
        None => Ok(false),
        Some(value) if value.as_slice() == digest => Ok(true),
        Some(_) => Err(PublicationError::OperationConflict),
    }
}

fn require_next_page(
    session: &StoredSession,
    input_cursor: &[u8],
    export_token: [u8; 32],
) -> Result<(), PublicationError> {
    if session.completion.is_some()
        || session.terminal
        || session.current_cursor != input_cursor
        || session
            .export_token
            .is_some_and(|token| token != export_token)
    {
        Err(PublicationError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_page_records(
    page: &NamespaceHistoryPage,
    volume_id: VolumeId,
) -> Result<(), PublicationError> {
    let mut commits = BTreeSet::new();
    for record in &page.commits {
        let decoded = record.decoded().map_err(record_error)?;
        if decoded.commit.volume_id != volume_id || !commits.insert(record.digest()) {
            return Err(PublicationError::InvalidInput);
        }
    }
    let immutable = page
        .immutable_object_digests
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if immutable.len() != page.immutable_object_digests.len()
        || (page.commits.is_empty()
            && page.immutable_object_digests.is_empty()
            && !page.next_cursor.is_empty())
    {
        Err(PublicationError::InvalidInput)
    } else {
        Ok(())
    }
}

fn require_capacity(
    connection: &Connection,
    session_id: [u8; 32],
    session: &StoredSession,
    page: &NamespaceHistoryPage,
) -> Result<(), PublicationError> {
    let (commits, immutable): (i64, i64) = connection.query_row(
        "SELECT COUNT(*) FILTER (WHERE record_kind = 1),
                COUNT(*) FILTER (WHERE record_kind = 2)
         FROM namespace_history_import_records WHERE session_id = ?1",
        [session_id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if usize_value(commits)?
        .checked_add(page.commits.len())
        .is_none_or(|count| count > session.limits.maximum_commits)
        || usize_value(immutable)?
            .checked_add(page.immutable_object_digests.len())
            .is_none_or(|count| count > session.limits.maximum_immutable_records)
    {
        Err(PublicationError::InvalidInput)
    } else {
        Ok(())
    }
}

fn insert_page_records(
    transaction: &Transaction<'_>,
    session_id: [u8; 32],
    page: &NamespaceHistoryPage,
) -> Result<(), PublicationError> {
    let mut ordinal: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM namespace_history_import_records WHERE session_id = ?1",
        [session_id.as_slice()],
        |row| row.get(0),
    )?;
    for record in &page.commits {
        insert_record(
            transaction,
            session_id,
            ordinal,
            RECORD_COMMIT,
            record.digest(),
            Some(record.canonical_bytes()),
        )?;
        ordinal = ordinal
            .checked_add(1)
            .ok_or(PublicationError::InvalidInput)?;
    }
    for digest in &page.immutable_object_digests {
        insert_record(
            transaction,
            session_id,
            ordinal,
            RECORD_IMMUTABLE,
            *digest,
            None,
        )?;
        ordinal = ordinal
            .checked_add(1)
            .ok_or(PublicationError::InvalidInput)?;
    }
    Ok(())
}

fn insert_record(
    transaction: &Transaction<'_>,
    session_id: [u8; 32],
    ordinal: i64,
    kind: i64,
    digest: [u8; 32],
    bytes: Option<&[u8]>,
) -> Result<(), PublicationError> {
    transaction.execute(
        "INSERT INTO namespace_history_import_records(
            session_id, record_ordinal, record_kind, record_digest, canonical_bytes
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            session_id.as_slice(),
            ordinal,
            kind,
            digest.as_slice(),
            bytes
        ],
    )?;
    Ok(())
}

fn page_digest(
    input_cursor: &[u8],
    page: &NamespaceHistoryPage,
) -> Result<[u8; 32], PublicationError> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.history-import-page.v1\0");
    variable_digest(&mut digest, input_cursor)?;
    digest.update(&page.export_token);
    digest.update(&repository::integer(page.commits.len())?.to_be_bytes());
    for record in &page.commits {
        digest.update(&record.digest());
    }
    digest.update(&repository::integer(page.immutable_object_digests.len())?.to_be_bytes());
    for value in &page.immutable_object_digests {
        digest.update(value);
    }
    variable_digest(&mut digest, &page.next_cursor)?;
    Ok(digest.finalize().into())
}

fn variable_digest(digest: &mut blake3::Hasher, bytes: &[u8]) -> Result<(), PublicationError> {
    digest.update(
        &u32::try_from(bytes.len())
            .map_err(|_| PublicationError::InvalidInput)?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Ok(())
}

fn validate_cursor(cursor: &[u8]) -> Result<(), PublicationError> {
    if cursor.len() <= MAXIMUM_CURSOR_BYTES {
        Ok(())
    } else {
        Err(PublicationError::InvalidInput)
    }
}

fn record_error(error: NamespaceHistoryRecordError) -> PublicationError {
    match error {
        NamespaceHistoryRecordError::BoundsExceeded | NamespaceHistoryRecordError::Invalid => {
            PublicationError::InvalidInput
        }
    }
}
