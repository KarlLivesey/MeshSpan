// SPDX-License-Identifier: GPL-2.0-only

//! SQLite representation and exact replay state for received history.

use meshspan_domain::{NamespaceCommitId, UnixMicros, VolumeId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{NamespaceHistoryReceiveRequest, NamespaceHistoryReceiveStatus};
use crate::publication::{copy_array, decode_identifier};
use crate::{NamespaceHistoryImport, NamespaceHistoryLimits, PublicationError};

#[derive(Debug)]
pub(super) struct StoredSession {
    pub(super) scope_binding: [u8; 32],
    pub(super) export_token: Option<[u8; 32]>,
    pub(super) volume_id: VolumeId,
    pub(super) current_cursor: Vec<u8>,
    pub(super) terminal: bool,
    pub(super) limits: NamespaceHistoryLimits,
    pub(super) expires_at: UnixMicros,
    pub(super) completion: Option<NamespaceHistoryImport>,
}

struct StoredSessionRow {
    scope_binding: Vec<u8>,
    export_token: Option<Vec<u8>>,
    volume_id: Vec<u8>,
    current_cursor: Vec<u8>,
    terminal: i64,
    maximum_heads: i64,
    maximum_commits: i64,
    maximum_immutable_records: i64,
    expires_at: i64,
    imported_commits: Option<i64>,
    supplied_commits: Option<i64>,
    immutable_records: Option<i64>,
}

pub(super) fn load_session(
    connection: &Connection,
    session_id: [u8; 32],
) -> Result<Option<StoredSession>, PublicationError> {
    let row = connection
        .query_row(
            "SELECT scope_binding, export_token, volume_id, current_cursor, terminal,
                    maximum_heads, maximum_commits, maximum_immutable_records, expires_at,
                    imported_commits, supplied_commits, immutable_records
             FROM namespace_history_imports WHERE session_id = ?1",
            [session_id.as_slice()],
            |row| {
                Ok(StoredSessionRow {
                    scope_binding: row.get(0)?,
                    export_token: row.get(1)?,
                    volume_id: row.get(2)?,
                    current_cursor: row.get(3)?,
                    terminal: row.get(4)?,
                    maximum_heads: row.get(5)?,
                    maximum_commits: row.get(6)?,
                    maximum_immutable_records: row.get(7)?,
                    expires_at: row.get(8)?,
                    imported_commits: row.get(9)?,
                    supplied_commits: row.get(10)?,
                    immutable_records: row.get(11)?,
                })
            },
        )
        .optional()?;
    row.map(decode_session).transpose()
}

pub(super) fn insert_session(
    transaction: &Transaction<'_>,
    request: &NamespaceHistoryReceiveRequest,
) -> Result<(), PublicationError> {
    transaction.execute(
        "INSERT INTO namespace_history_imports(
            session_id, scope_binding, volume_id, current_cursor, terminal, maximum_heads,
            maximum_commits, maximum_immutable_records, created_at, expires_at
         ) VALUES (?1, ?2, ?3, X'', 0, ?4, ?5, ?6, ?7, ?8)",
        params![
            request.session_id.as_slice(),
            request.scope_binding.as_slice(),
            request.volume_id.as_bytes().as_slice(),
            integer(request.limits.maximum_heads)?,
            integer(request.limits.maximum_commits)?,
            integer(request.limits.maximum_immutable_records)?,
            request.now.get(),
            request.expires_at.get()
        ],
    )?;
    for (ordinal, head) in request.requested_heads.iter().enumerate() {
        transaction.execute(
            "INSERT INTO namespace_history_import_heads(
                session_id, head_ordinal, namespace_commit_id) VALUES (?1, ?2, ?3)",
            params![
                request.session_id.as_slice(),
                integer(ordinal)?,
                head.as_bytes().as_slice()
            ],
        )?;
    }
    Ok(())
}

pub(super) fn require_same_request(
    connection: &Connection,
    session: &StoredSession,
    request: &NamespaceHistoryReceiveRequest,
) -> Result<(), PublicationError> {
    let heads = load_heads(connection, request.session_id)?;
    if session.scope_binding == request.scope_binding
        && session.volume_id == request.volume_id
        && session.limits == request.limits
        && session.expires_at == request.expires_at
        && heads == request.requested_heads
    {
        Ok(())
    } else {
        Err(PublicationError::OperationConflict)
    }
}

pub(super) fn status(
    connection: &Connection,
    session_id: [u8; 32],
) -> Result<NamespaceHistoryReceiveStatus, PublicationError> {
    let session = load_session(connection, session_id)?.ok_or(PublicationError::InvalidInput)?;
    let (commits, immutable, missing): (i64, i64, i64) = connection.query_row(
        "SELECT COUNT(*) FILTER (WHERE record_kind = 1),
                COUNT(*) FILTER (WHERE record_kind = 2),
                COUNT(*) FILTER (WHERE record_kind = 2 AND canonical_bytes IS NULL)
         FROM namespace_history_import_records WHERE session_id = ?1",
        [session_id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let next_missing: Option<Vec<u8>> = connection
        .query_row(
            "SELECT record_digest FROM namespace_history_import_records
             WHERE session_id = ?1 AND record_kind = 2 AND canonical_bytes IS NULL
             ORDER BY record_ordinal LIMIT 1",
            [session_id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(NamespaceHistoryReceiveStatus {
        export_token: session.export_token,
        next_cursor: session.current_cursor,
        terminal: session.terminal,
        commits: usize_value(commits)?,
        immutable_records: usize_value(immutable)?,
        missing_immutable_records: usize_value(missing)?,
        next_missing_immutable_record: next_missing.as_deref().map(copy_array).transpose()?,
        completed: session.completion.is_some(),
    })
}

pub(super) fn load_heads(
    connection: &Connection,
    session_id: [u8; 32],
) -> Result<Vec<NamespaceCommitId>, PublicationError> {
    let mut statement = connection.prepare(
        "SELECT namespace_commit_id FROM namespace_history_import_heads
         WHERE session_id = ?1 ORDER BY head_ordinal",
    )?;
    let rows = statement.query_map([session_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))?;
    rows.map(|row| {
        let bytes = row?;
        decode_identifier(&bytes, NamespaceCommitId::from_bytes)
    })
    .collect()
}

fn decode_session(row: StoredSessionRow) -> Result<StoredSession, PublicationError> {
    let completion = match (
        row.imported_commits,
        row.supplied_commits,
        row.immutable_records,
    ) {
        (None, None, None) => None,
        (Some(imported), Some(supplied), Some(immutable)) => Some(NamespaceHistoryImport {
            imported_commits: usize_value(imported)?,
            supplied_commits: usize_value(supplied)?,
            immutable_records: usize_value(immutable)?,
        }),
        _ => return Err(PublicationError::Corrupt),
    };
    Ok(StoredSession {
        scope_binding: copy_array(&row.scope_binding)?,
        export_token: row.export_token.as_deref().map(copy_array).transpose()?,
        volume_id: decode_identifier(&row.volume_id, VolumeId::from_bytes)?,
        current_cursor: row.current_cursor,
        terminal: bool_value(row.terminal)?,
        limits: NamespaceHistoryLimits {
            maximum_heads: usize_value(row.maximum_heads)?,
            maximum_commits: usize_value(row.maximum_commits)?,
            maximum_immutable_records: usize_value(row.maximum_immutable_records)?,
        },
        expires_at: UnixMicros::new(row.expires_at),
        completion,
    })
}

pub(super) fn integer(value: usize) -> Result<i64, PublicationError> {
    i64::try_from(value).map_err(|_| PublicationError::InvalidInput)
}

pub(super) fn usize_value(value: i64) -> Result<usize, PublicationError> {
    usize::try_from(value).map_err(|_| PublicationError::Corrupt)
}

fn bool_value(value: i64) -> Result<bool, PublicationError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PublicationError::Corrupt),
    }
}
