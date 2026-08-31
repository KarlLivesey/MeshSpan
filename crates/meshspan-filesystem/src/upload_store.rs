// SPDX-License-Identifier: GPL-2.0-only

//! SQLite-backed authority journal for protocol-neutral resumable uploads.

use std::fs;
use std::path::Path;

use meshspan_domain::{
    FileVersionId, OperationId, PrincipalId, Revision, StageId, UnixMicros, UploadId, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

use crate::{
    NamespaceComponent, NamespacePath, UploadAbortRequest, UploadBeginRequest, UploadDisposition,
    UploadSession, UploadState,
};

const DATABASE_FILE: &str = "filesystem-uploads.sqlite3";
const SCHEMA: &str = include_str!("../schema/upload/001_initial.sql");
const SCHEMA_VERSION: u32 = 1;
const MAXIMUM_SQLITE_INTEGER: u64 = 9_223_372_036_854_775_807;

const STATE_PREPARING: u8 = 1;
const STATE_ACTIVE: u8 = 2;
const STATE_ABORTING: u8 = 3;
const STATE_ABORTED: u8 = 4;
const STATE_COMMITTING: u8 = 5;
const STATE_COMMITTED: u8 = 6;

pub(crate) struct UploadSessionStore {
    connection: Connection,
}

impl UploadSessionStore {
    pub(crate) fn open(
        state_directory: &Path,
        opened_at: UnixMicros,
    ) -> Result<Self, UploadStoreError> {
        fs::create_dir_all(state_directory)?;
        let mut connection = Connection::open(state_directory.join(DATABASE_FILE))?;
        configure(&connection)?;
        migrate(&mut connection, opened_at)?;
        verify_database(&connection)?;
        Ok(Self { connection })
    }

    pub(crate) fn prepare(&mut self, request: &UploadBeginRequest) -> Result<(), UploadStoreError> {
        validate_begin(request)?;
        let digest = begin_digest(request);
        if let Some(stored) = load_stored(&self.connection, request.upload_id)? {
            return validate_begin_replay(&self.connection, request, digest, &stored);
        }
        let operation_collision: i64 = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM upload_sessions WHERE begin_operation_id = ?1
             )",
            [request.operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if operation_collision != 0 {
            return Err(UploadStoreError::OperationConflict);
        }
        let result_digest = begin_result_digest(request, digest);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO upload_sessions(
                upload_id, begin_operation_id, request_digest, stage_id, stage_fence, volume_id,
                principal_id, authorization_revision, disposition, expected_version_id,
                maximum_bytes, state, created_at, expires_at, path_depth, result_digest
             ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11, ?12, ?13, ?14)",
            params![
                request.upload_id.as_bytes().as_slice(),
                request.operation_id.as_bytes().as_slice(),
                digest.as_slice(),
                request.stage_id.as_bytes().as_slice(),
                request.volume_id.as_bytes().as_slice(),
                request.principal_id.as_bytes().as_slice(),
                to_i64(request.authorization_revision.get())?,
                request.disposition.code(),
                request
                    .disposition
                    .expected_version()
                    .map(FileVersionId::as_bytes),
                to_i64(request.maximum_bytes)?,
                request.created_at.get(),
                request.expires_at.get(),
                i64::try_from(request.path.components().len())
                    .map_err(|_| UploadStoreError::InvalidInput)?,
                result_digest.as_slice(),
            ],
        )?;
        let mut statement = transaction.prepare(
            "INSERT INTO upload_path_components(
                upload_id, component_ordinal, display_name, canonical_name
             ) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for (ordinal, component) in request.path.components().iter().enumerate() {
            statement.execute(params![
                request.upload_id.as_bytes().as_slice(),
                i64::try_from(ordinal).map_err(|_| UploadStoreError::InvalidInput)?,
                component.display(),
                component.canonical(),
            ])?;
        }
        drop(statement);
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn activate(&mut self, upload_id: UploadId) -> Result<(), UploadStoreError> {
        let stored = load_stored(&self.connection, upload_id)?.ok_or(UploadStoreError::Stale)?;
        match stored.state {
            STATE_ACTIVE => Ok(()),
            STATE_PREPARING => {
                let updated = self.connection.execute(
                    "UPDATE upload_sessions SET state = 2 WHERE upload_id = ?1 AND state = 1",
                    [upload_id.as_bytes().as_slice()],
                )?;
                if updated == 1 {
                    Ok(())
                } else {
                    Err(UploadStoreError::Unavailable)
                }
            }
            _ => Err(UploadStoreError::Stale),
        }
    }

    pub(crate) fn load(&self, upload_id: UploadId) -> Result<UploadSession, UploadStoreError> {
        let stored = load_stored(&self.connection, upload_id)?.ok_or(UploadStoreError::Stale)?;
        decode_session(&self.connection, &stored)
    }

    pub(crate) fn begin_abort(
        &mut self,
        request: UploadAbortRequest,
    ) -> Result<UploadSession, UploadStoreError> {
        validate_abort(request)?;
        let stored =
            load_stored(&self.connection, request.upload_id)?.ok_or(UploadStoreError::Stale)?;
        let digest = abort_digest(request);
        if matches!(stored.state, STATE_ABORTING | STATE_ABORTED) {
            validate_abort_replay(request, digest, &stored)?;
            return decode_session_allow_transition(&self.connection, &stored);
        }
        if stored.state != STATE_ACTIVE
            || identifier(&stored.principal, PrincipalId::from_bytes)? != request.principal_id
            || positive(stored.stage_fence)? != request.stage_fence
            || UnixMicros::new(stored.expires_at) <= request.observed_at
        {
            return Err(UploadStoreError::Stale);
        }
        let updated = self.connection.execute(
            "UPDATE upload_sessions
             SET state = 3, abort_operation_id = ?1, abort_request_digest = ?2, aborted_at = ?3
             WHERE upload_id = ?4 AND state = 2 AND stage_fence = ?5 AND expires_at > ?3",
            params![
                request.operation_id.as_bytes().as_slice(),
                digest.as_slice(),
                request.observed_at.get(),
                request.upload_id.as_bytes().as_slice(),
                to_i64(request.stage_fence)?,
            ],
        )?;
        if updated != 1 {
            return Err(UploadStoreError::Unavailable);
        }
        self.load_transition(request.upload_id)
    }

    pub(crate) fn finish_abort(
        &mut self,
        request: UploadAbortRequest,
    ) -> Result<UploadSession, UploadStoreError> {
        let stored =
            load_stored(&self.connection, request.upload_id)?.ok_or(UploadStoreError::Stale)?;
        validate_abort_replay(request, abort_digest(request), &stored)?;
        match stored.state {
            STATE_ABORTED => decode_session(&self.connection, &stored),
            STATE_ABORTING => {
                let updated = self.connection.execute(
                    "UPDATE upload_sessions SET state = 4 WHERE upload_id = ?1 AND state = 3",
                    [request.upload_id.as_bytes().as_slice()],
                )?;
                if updated == 1 {
                    self.load(request.upload_id)
                } else {
                    Err(UploadStoreError::Unavailable)
                }
            }
            _ => Err(UploadStoreError::Stale),
        }
    }

    fn load_transition(&self, upload_id: UploadId) -> Result<UploadSession, UploadStoreError> {
        let stored = load_stored(&self.connection, upload_id)?.ok_or(UploadStoreError::Stale)?;
        decode_session_allow_transition(&self.connection, &stored)
    }
}

#[derive(Debug)]
struct StoredSession {
    upload: Vec<u8>,
    operation: Vec<u8>,
    request_digest: Vec<u8>,
    stage: Vec<u8>,
    stage_fence: i64,
    volume: Vec<u8>,
    principal: Vec<u8>,
    authorization_revision: i64,
    disposition: u8,
    expected_version: Option<Vec<u8>>,
    maximum_bytes: i64,
    state: u8,
    created_at: i64,
    expires_at: i64,
    path_depth: i64,
    result_digest: Vec<u8>,
    abort_operation: Option<Vec<u8>>,
    abort_request_digest: Option<Vec<u8>>,
    aborted_at: Option<i64>,
}

fn load_stored(
    connection: &Connection,
    upload_id: UploadId,
) -> Result<Option<StoredSession>, UploadStoreError> {
    connection
        .query_row(
            "SELECT upload_id, begin_operation_id, request_digest, stage_id, stage_fence,
                    volume_id, principal_id, authorization_revision, disposition,
                    expected_version_id, maximum_bytes, state, created_at, expires_at, path_depth,
                    result_digest, abort_operation_id, abort_request_digest, aborted_at
             FROM upload_sessions WHERE upload_id = ?1",
            [upload_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredSession {
                    upload: row.get(0)?,
                    operation: row.get(1)?,
                    request_digest: row.get(2)?,
                    stage: row.get(3)?,
                    stage_fence: row.get(4)?,
                    volume: row.get(5)?,
                    principal: row.get(6)?,
                    authorization_revision: row.get(7)?,
                    disposition: row.get(8)?,
                    expected_version: row.get(9)?,
                    maximum_bytes: row.get(10)?,
                    state: row.get(11)?,
                    created_at: row.get(12)?,
                    expires_at: row.get(13)?,
                    path_depth: row.get(14)?,
                    result_digest: row.get(15)?,
                    abort_operation: row.get(16)?,
                    abort_request_digest: row.get(17)?,
                    aborted_at: row.get(18)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn decode_session(
    connection: &Connection,
    stored: &StoredSession,
) -> Result<UploadSession, UploadStoreError> {
    if matches!(stored.state, STATE_PREPARING | STATE_ABORTING) {
        return Err(UploadStoreError::Unavailable);
    }
    decode_session_allow_transition(connection, stored)
}

fn decode_session_allow_transition(
    connection: &Connection,
    stored: &StoredSession,
) -> Result<UploadSession, UploadStoreError> {
    let upload_id = identifier(&stored.upload, UploadId::from_bytes)?;
    let path = load_path(connection, upload_id, stored.path_depth)?;
    let disposition = decode_disposition(stored.disposition, stored.expected_version.as_deref())?;
    validate_stored_digest(stored, &path, disposition)?;
    Ok(UploadSession {
        upload_id,
        stage_id: identifier(&stored.stage, StageId::from_bytes)?,
        stage_fence: positive(stored.stage_fence)?,
        volume_id: identifier(&stored.volume, VolumeId::from_bytes)?,
        path,
        principal_id: identifier(&stored.principal, PrincipalId::from_bytes)?,
        authorization_revision: Revision::new(positive(stored.authorization_revision)?),
        disposition,
        maximum_bytes: positive(stored.maximum_bytes)?,
        state: decode_state(stored.state)?,
        created_at: UnixMicros::new(stored.created_at),
        expires_at: UnixMicros::new(stored.expires_at),
    })
}

fn load_path(
    connection: &Connection,
    upload_id: UploadId,
    depth: i64,
) -> Result<NamespacePath, UploadStoreError> {
    let mut statement = connection.prepare(
        "SELECT display_name, canonical_name FROM upload_path_components
         WHERE upload_id = ?1 ORDER BY component_ordinal",
    )?;
    let rows = statement.query_map([upload_id.as_bytes().as_slice()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let components = rows
        .map(|row| {
            let (display, canonical) = row?;
            NamespaceComponent::from_stored(&display, &canonical)
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if i64::try_from(components.len()) != Ok(depth) {
        return Err(UploadStoreError::Corrupt);
    }
    NamespacePath::from_stored_components(components).map_err(|_| UploadStoreError::Corrupt)
}

fn validate_begin(request: &UploadBeginRequest) -> Result<(), UploadStoreError> {
    if request.authorization_revision == Revision::ZERO
        || request.maximum_bytes == 0
        || request.maximum_bytes > MAXIMUM_SQLITE_INTEGER
        || request.expires_at <= request.created_at
        || request.path.components().is_empty()
    {
        Err(UploadStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_begin_replay(
    connection: &Connection,
    request: &UploadBeginRequest,
    digest: [u8; 32],
    stored: &StoredSession,
) -> Result<(), UploadStoreError> {
    let stored_upload = identifier(&stored.upload, UploadId::from_bytes)?;
    let path = load_path(connection, stored_upload, stored.path_depth)?;
    let disposition = decode_disposition(stored.disposition, stored.expected_version.as_deref())?;
    validate_stored_digest(stored, &path, disposition)?;
    if stored.request_digest.as_slice() == digest
        && identifier(&stored.operation, OperationId::from_bytes)? == request.operation_id
    {
        Ok(())
    } else {
        Err(UploadStoreError::OperationConflict)
    }
}

fn validate_stored_digest(
    stored: &StoredSession,
    path: &NamespacePath,
    disposition: UploadDisposition,
) -> Result<(), UploadStoreError> {
    let request = UploadBeginRequest {
        operation_id: identifier(&stored.operation, OperationId::from_bytes)?,
        upload_id: identifier(&stored.upload, UploadId::from_bytes)?,
        stage_id: identifier(&stored.stage, StageId::from_bytes)?,
        volume_id: identifier(&stored.volume, VolumeId::from_bytes)?,
        path: path.clone(),
        principal_id: identifier(&stored.principal, PrincipalId::from_bytes)?,
        authorization_revision: Revision::new(positive(stored.authorization_revision)?),
        disposition,
        maximum_bytes: positive(stored.maximum_bytes)?,
        created_at: UnixMicros::new(stored.created_at),
        expires_at: UnixMicros::new(stored.expires_at),
    };
    let digest = begin_digest(&request);
    if stored.request_digest.as_slice() == digest
        && stored.result_digest.as_slice() == begin_result_digest(&request, digest)
    {
        Ok(())
    } else {
        Err(UploadStoreError::Corrupt)
    }
}

fn validate_abort(request: UploadAbortRequest) -> Result<(), UploadStoreError> {
    if request.stage_fence == 0 || request.authorization_revision == Revision::ZERO {
        Err(UploadStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_abort_replay(
    request: UploadAbortRequest,
    digest: [u8; 32],
    stored: &StoredSession,
) -> Result<(), UploadStoreError> {
    let operation = stored
        .abort_operation
        .as_deref()
        .ok_or(UploadStoreError::Corrupt)?;
    let request_digest = stored
        .abort_request_digest
        .as_deref()
        .ok_or(UploadStoreError::Corrupt)?;
    if identifier(operation, OperationId::from_bytes)? == request.operation_id
        && request_digest == digest
        && stored.aborted_at == Some(request.observed_at.get())
    {
        Ok(())
    } else {
        Err(UploadStoreError::OperationConflict)
    }
}

fn decode_disposition(
    code: u8,
    version: Option<&[u8]>,
) -> Result<UploadDisposition, UploadStoreError> {
    match (code, version) {
        (1, None) => Ok(UploadDisposition::CreateNew),
        (2, Some(value)) => Ok(UploadDisposition::ReplaceIfVersion(identifier(
            value,
            FileVersionId::from_bytes,
        )?)),
        (3, None) => Ok(UploadDisposition::ReplaceCurrent),
        _ => Err(UploadStoreError::Corrupt),
    }
}

fn decode_state(code: u8) -> Result<UploadState, UploadStoreError> {
    match code {
        STATE_ACTIVE => Ok(UploadState::Active),
        STATE_COMMITTING => Ok(UploadState::Committing),
        STATE_COMMITTED => Ok(UploadState::Committed),
        STATE_ABORTED | STATE_ABORTING => Ok(UploadState::Aborted),
        STATE_PREPARING => Err(UploadStoreError::Unavailable),
        _ => Err(UploadStoreError::Corrupt),
    }
}

fn begin_digest(request: &UploadBeginRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.upload-begin.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.upload_id.as_bytes());
    digest.update(&request.stage_id.as_bytes());
    digest.update(&request.volume_id.as_bytes());
    digest.update(&request.principal_id.as_bytes());
    digest.update(&request.authorization_revision.get().to_be_bytes());
    digest.update(&request.authorization_revision.get().to_be_bytes());
    digest.update(&[request.disposition.code()]);
    digest.update(
        &request
            .disposition
            .expected_version()
            .map_or([0; 16], FileVersionId::as_bytes),
    );
    digest.update(&request.maximum_bytes.to_be_bytes());
    digest.update(&request.created_at.get().to_be_bytes());
    digest.update(&request.expires_at.get().to_be_bytes());
    for component in request.path.components() {
        digest.update(component.display().as_bytes());
        digest.update(&[0]);
        digest.update(component.canonical().as_bytes());
        digest.update(&[0]);
    }
    digest.finalize().into()
}

fn begin_result_digest(request: &UploadBeginRequest, request_digest: [u8; 32]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.upload-session.v1\0");
    digest.update(&request.upload_id.as_bytes());
    digest.update(&request.stage_id.as_bytes());
    digest.update(&request_digest);
    digest.finalize().into()
}

fn abort_digest(request: UploadAbortRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.upload-abort.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.upload_id.as_bytes());
    digest.update(&request.principal_id.as_bytes());
    digest.update(&request.stage_fence.to_be_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn configure(connection: &Connection) -> Result<(), UploadStoreError> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

fn migrate(connection: &mut Connection, applied_at: UnixMicros) -> Result<(), UploadStoreError> {
    let current: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let schema_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'schema_migrations' LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if current > SCHEMA_VERSION
        || (current == 0 && schema_exists)
        || (current != 0 && !schema_exists)
    {
        return Err(UploadStoreError::Corrupt);
    }
    let digest: [u8; 32] = blake3::hash(SCHEMA.as_bytes()).into();
    if current == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, migration_digest, applied_at)
             VALUES (1, ?1, ?2)",
            params![digest.as_slice(), applied_at.get()],
        )?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    } else {
        let stored: Vec<u8> = connection.query_row(
            "SELECT migration_digest FROM schema_migrations WHERE version = 1",
            [],
            |row| row.get(0),
        )?;
        if stored.as_slice() != digest {
            return Err(UploadStoreError::Corrupt);
        }
    }
    Ok(())
}

fn verify_database(connection: &Connection) -> Result<(), UploadStoreError> {
    let quick: String = connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
    let foreign_key_violation = connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some();
    if quick == "ok" && !foreign_key_violation {
        Ok(())
    } else {
        Err(UploadStoreError::Corrupt)
    }
}

fn identifier<T>(
    value: &[u8],
    constructor: impl FnOnce([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, UploadStoreError> {
    constructor(value.try_into().map_err(|_| UploadStoreError::Corrupt)?)
        .map_err(|_| UploadStoreError::Corrupt)
}

fn positive(value: i64) -> Result<u64, UploadStoreError> {
    let converted = u64::try_from(value).map_err(|_| UploadStoreError::Corrupt)?;
    if converted == 0 {
        Err(UploadStoreError::Corrupt)
    } else {
        Ok(converted)
    }
}

fn to_i64(value: u64) -> Result<i64, UploadStoreError> {
    i64::try_from(value).map_err(|_| UploadStoreError::InvalidInput)
}

#[derive(Debug, Error)]
pub(crate) enum UploadStoreError {
    #[error("upload session input is invalid")]
    InvalidInput,
    #[error("upload session identity conflicts with durable state")]
    OperationConflict,
    #[error("upload session authority is stale")]
    Stale,
    #[error("upload session transition is temporarily unavailable")]
    Unavailable,
    #[error("upload session state is corrupt")]
    Corrupt,
    #[error("upload session filesystem operation failed")]
    Io(#[from] std::io::Error),
    #[error("upload session database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}
