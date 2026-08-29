// SPDX-License-Identifier: GPL-2.0-only

//! Reconstruction of bounded export pages and issued continuation cursors.

use meshspan_domain::NamespaceCommitId;
use rusqlite::{Transaction, params};

use super::super::history_records::NamespaceHistoryCommitRecord;
use super::super::transfer::export;
use super::work::{RECORD_COMMIT, RECORD_IMMUTABLE, WORK_COMMIT, WORK_LAST};
use super::{NamespaceHistoryPage, ValidatedQuery, to_i64};
use crate::PublicationError;
use crate::publication::copy_array;

const CURSOR_DOMAIN: &[u8] = b"MSHE";
const CURSOR_VERSION: u8 = 1;
const CURSOR_BYTES: usize = 45;

pub(super) fn load_page(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
) -> Result<NamespaceHistoryPage, PublicationError> {
    let stored = load_stored_records(transaction, query)?;
    let mut commits = Vec::new();
    let mut immutable_object_digests = Vec::new();
    for (record_kind, source_kind, source_identity, digest) in &stored {
        let expected = copy_array(digest)?;
        match (*record_kind, *source_kind) {
            (RECORD_COMMIT, WORK_COMMIT) => {
                commits.push(load_commit(transaction, query, source_identity, expected)?);
            }
            (RECORD_IMMUTABLE, 2..=WORK_LAST) => immutable_object_digests.push(expected),
            _ => return Err(PublicationError::Corrupt),
        }
    }
    let next = query
        .start_ordinal
        .checked_add(u64::try_from(stored.len()).map_err(|_| PublicationError::Corrupt)?)
        .ok_or(PublicationError::Corrupt)?;
    let next_cursor = next_cursor(transaction, query, next, stored.is_empty())?;
    Ok(NamespaceHistoryPage {
        export_token: query.digest,
        commits,
        immutable_object_digests,
        next_cursor,
    })
}

type StoredRecord = (i64, i64, Vec<u8>, Vec<u8>);

fn load_stored_records(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
) -> Result<Vec<StoredRecord>, PublicationError> {
    let mut statement = transaction.prepare(
        "SELECT record_kind, source_kind, source_identity, transfer_digest
         FROM namespace_history_export_records
         WHERE request_digest = ?1 AND record_ordinal >= ?2
         ORDER BY record_ordinal LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            query.digest.as_slice(),
            to_i64(query.start_ordinal)?,
            i64::try_from(query.limit).map_err(|_| PublicationError::InvalidInput)?
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn load_commit(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
    identity: &[u8],
    expected_digest: [u8; 32],
) -> Result<NamespaceHistoryCommitRecord, PublicationError> {
    let commit_id =
        NamespaceCommitId::from_bytes(identity.try_into().map_err(|_| PublicationError::Corrupt)?)
            .map_err(|_| PublicationError::Corrupt)?;
    let source = export::load_commit_record(transaction, query.volume_id, commit_id)?;
    let record = NamespaceHistoryCommitRecord::from_commit(&source)
        .map_err(|_| PublicationError::Corrupt)?;
    if record.digest() == expected_digest {
        Ok(record)
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn next_cursor(
    transaction: &Transaction<'_>,
    query: &ValidatedQuery,
    next: u64,
    page_is_empty: bool,
) -> Result<Vec<u8>, PublicationError> {
    if !has_more(transaction, query.digest, next)? {
        return Ok(Vec::new());
    }
    if page_is_empty {
        return Err(PublicationError::Corrupt);
    }
    issue_cursor(transaction, query.digest, next)?;
    Ok(encode_cursor(query.digest, next))
}

fn has_more(
    transaction: &Transaction<'_>,
    digest: [u8; 32],
    next: u64,
) -> Result<bool, PublicationError> {
    let state: (i64, i64) = transaction.query_row(
        "SELECT
            EXISTS(SELECT 1 FROM namespace_history_export_records
                   WHERE request_digest = ?1 AND record_ordinal >= ?2),
            complete
         FROM namespace_history_exports WHERE request_digest = ?1",
        params![digest.as_slice(), to_i64(next)?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(state.0 == 1 || !parse_bool(state.1)?)
}

pub(super) fn issue_cursor(
    transaction: &Transaction<'_>,
    digest: [u8; 32],
    start: u64,
) -> Result<(), PublicationError> {
    transaction.execute(
        "INSERT OR IGNORE INTO namespace_history_export_cursors(request_digest, start_ordinal)
         VALUES (?1, ?2)",
        params![digest.as_slice(), to_i64(start)?],
    )?;
    Ok(())
}

fn encode_cursor(digest: [u8; 32], start: u64) -> Vec<u8> {
    let mut cursor = Vec::with_capacity(CURSOR_BYTES);
    cursor.extend_from_slice(CURSOR_DOMAIN);
    cursor.push(CURSOR_VERSION);
    cursor.extend_from_slice(&digest);
    cursor.extend_from_slice(&start.to_be_bytes());
    cursor
}

pub(super) fn decode_cursor(
    cursor: &[u8],
    expected_digest: [u8; 32],
) -> Result<u64, PublicationError> {
    if cursor.len() != CURSOR_BYTES
        || &cursor[..CURSOR_DOMAIN.len()] != CURSOR_DOMAIN
        || cursor[CURSOR_DOMAIN.len()] != CURSOR_VERSION
        || cursor[5..37] != expected_digest
    {
        return Err(PublicationError::InvalidInput);
    }
    Ok(u64::from_be_bytes(
        cursor[37..45]
            .try_into()
            .map_err(|_| PublicationError::InvalidInput)?,
    ))
}

fn parse_bool(value: i64) -> Result<bool, PublicationError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PublicationError::Corrupt),
    }
}
