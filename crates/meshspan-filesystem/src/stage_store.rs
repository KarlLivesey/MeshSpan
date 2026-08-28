// SPDX-License-Identifier: GPL-2.0-only

//! WAL/FULL-sync stage journal plus immutable capability-scoped range parts.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use meshspan_contracts::BoundedBytes;
use meshspan_domain::{OperationId, StageId, UnixMicros};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

use crate::staging::{covers, insert_range};
use crate::{Checkpoint, StageWrite, StageWriteOutcome};

const SCHEMA_VERSION: u32 = 1;
const MAXIMUM_SQLITE_INTEGER: u64 = 9_223_372_036_854_775_807;
const MIGRATION: &str = include_str!("../schema/stage/001_initial.sql");
const STAGE_DIRECTORY: &str = "stages";
const DATABASE_FILE: &str = "filesystem-stages.sqlite3";
const COPY_BUFFER_BYTES: usize = 64 * 1_024;
const COPY_BUFFER_BYTES_U64: u64 = 65_536;

/// Durable identity, bounds and expiry for one private write stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageRegistration {
    /// Stable stage identity.
    pub stage_id: StageId,
    /// Positive writer generation.
    pub stage_fence: u64,
    /// Maximum logical bytes admitted for this stage.
    pub maximum_bytes: u64,
    /// Stage creation instant.
    pub created_at: UnixMicros,
    /// Exclusive inactivity/authority expiry.
    pub expires_at: UnixMicros,
}

/// Exact fenced checkpoint selected for one streaming completion attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageCompletionRequest {
    /// Idempotency identity of the later publication operation.
    pub operation_id: OperationId,
    /// Stage to complete.
    pub stage_id: StageId,
    /// Exact writer generation.
    pub stage_fence: u64,
    /// Exact checkpoint sequence; later writes make this request stale.
    pub expected_sequence: u64,
    /// Exact final logical length.
    pub final_length: u64,
    /// Whether uninitialised ranges are explicit logical zeroes.
    pub sparse: bool,
    /// Authoritative time used for expiry validation.
    pub observed_at: UnixMicros,
}

/// Independently verified content identity produced by streaming stage completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletedStage {
    /// Exact number of streamed logical bytes.
    pub logical_length: u64,
    /// BLAKE3 digest of the complete logical byte stream.
    pub content_digest: [u8; 32],
}

/// Durable stage journal and immutable part storage beneath one daemon state directory.
pub struct DurableStageStore {
    connection: Connection,
    stages: Dir,
}

impl DurableStageStore {
    /// Opens or creates the stage database and capability-scoped private part directory.
    ///
    /// # Errors
    ///
    /// Rejects migration drift, newer schemas, integrity failure and filesystem/SQLite errors.
    pub fn open(state_directory: &Path, opened_at: UnixMicros) -> Result<Self, StageStoreError> {
        fs::create_dir_all(state_directory)?;
        let root = Dir::open_ambient_dir(state_directory, ambient_authority())?;
        match root.create_dir(STAGE_DIRECTORY) {
            Ok(()) => sync_directory(&root)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let stages = root.open_dir(STAGE_DIRECTORY)?;
        let mut connection = Connection::open(state_directory.join(DATABASE_FILE))?;
        configure(&connection)?;
        migrate(&mut connection, opened_at)?;
        verify_database(&connection)?;
        Ok(Self { connection, stages })
    }

    /// Registers one new stage or resolves an exact idempotent replay.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds/time, conflicting identity reuse and persistence failure.
    pub fn register(&mut self, stage: StageRegistration) -> Result<(), StageStoreError> {
        validate_registration(stage)?;
        let identifier = stage.stage_id.as_bytes();
        let expected = (
            to_i64(stage.stage_fence)?,
            to_i64(stage.maximum_bytes)?,
            stage.created_at.get(),
            stage.expires_at.get(),
        );
        let existing: Option<(i64, i64, i64, i64)> = self
            .connection
            .query_row(
                "SELECT stage_fence, maximum_bytes, created_at, expires_at
                 FROM stages WHERE stage_id = ?1",
                [identifier.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing == expected {
                create_stage_directory(&self.stages, stage.stage_id)
            } else {
                Err(StageStoreError::OperationConflict)
            };
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO stages(
                stage_id, stage_fence, maximum_bytes, state, mutation_sequence,
                logical_extent, created_at, expires_at
             ) VALUES (?1, ?2, ?3, 1, 0, 0, ?4, ?5)",
            params![
                identifier.as_slice(),
                expected.0,
                expected.1,
                expected.2,
                expected.3
            ],
        )?;
        transaction.commit()?;
        create_stage_directory(&self.stages, stage.stage_id)
    }

    /// Durably installs one immutable part before journalling its ordered acceptance.
    ///
    /// # Errors
    ///
    /// Rejects stale/expired stages, malformed writes, conflicting replay, corrupt parts and IO.
    pub fn write(
        &mut self,
        stage_id: StageId,
        write: &StageWrite,
        observed_at: UnixMicros,
    ) -> Result<StageWriteOutcome, StageStoreError> {
        let stage = load_stage(&self.connection, stage_id)?;
        validate_live_write(stage, write, observed_at)?;
        if let Some(existing) = load_write(&self.connection, write.operation_id)? {
            if existing.stage_id != stage_id || !existing.matches(write)? {
                return Err(StageStoreError::OperationConflict);
            }
            verify_part(&self.stages, &existing, write.bytes.as_slice())?;
            return Ok(StageWriteOutcome::Replayed);
        }
        let part_name = install_part(&self.stages, stage_id, write)?;
        self.record_write(stage_id, stage, write, observed_at, &part_name)
    }

    /// Returns the exact ordered range coverage persisted in the stage journal.
    ///
    /// # Errors
    ///
    /// Rejects absent/corrupt stage state or SQLite failure.
    pub fn checkpoint(&self, stage_id: StageId) -> Result<Checkpoint, StageStoreError> {
        let stage = load_stage(&self.connection, stage_id)?;
        let writes = load_stage_writes(&self.connection, stage_id)?;
        let ranges = ranges(&writes)?;
        Ok(Checkpoint {
            sequence: stage.sequence,
            logical_extent: stage.logical_extent,
            initialised_ranges: ranges,
        })
    }

    /// Reconstructs exact ordered acknowledged bytes for publication without changing stage state.
    ///
    /// # Errors
    ///
    /// Rejects holes unless sparse was explicit, configured excess and every missing/corrupt part.
    pub fn complete_bytes(
        &self,
        stage_id: StageId,
        final_length: u64,
        sparse: bool,
    ) -> Result<BoundedBytes, StageStoreError> {
        let stage = load_stage(&self.connection, stage_id)?;
        if final_length > stage.maximum_bytes {
            return Err(StageStoreError::InvalidInput);
        }
        let writes = load_stage_writes(&self.connection, stage_id)?;
        if !sparse && !covers(&ranges(&writes)?, final_length) {
            return Err(StageStoreError::Incomplete);
        }
        let length = usize::try_from(final_length).map_err(|_| StageStoreError::InvalidInput)?;
        let mut complete = vec![0_u8; length];
        for write in writes {
            apply_part(&self.stages, stage_id, &write, &mut complete)?;
        }
        BoundedBytes::copy_from(&complete, length).map_err(|_| StageStoreError::InvalidInput)
    }

    /// Streams one exact fenced checkpoint through a bounded buffer without allocating file size.
    ///
    /// A private sparse completion image is assembled in journal order, synced, rewound and
    /// independently hashed while it is copied to `destination`. It is never a published file and
    /// is removed after success. A failed destination leaves no metadata publication; its private
    /// temporary image is discarded on exact retry.
    ///
    /// # Errors
    ///
    /// Rejects stale fence/sequence/time, holes without explicit sparse intent, corrupt/missing
    /// parts, range excess and every source/destination filesystem error.
    pub fn stream_complete(
        &mut self,
        request: StageCompletionRequest,
        destination: &mut impl Write,
    ) -> Result<CompletedStage, StageStoreError> {
        let stage = load_stage(&self.connection, request.stage_id)?;
        validate_completion(stage, request)?;
        let writes = load_stage_writes(&self.connection, request.stage_id)?;
        if !request.sparse && !covers(&ranges(&writes)?, request.final_length) {
            return Err(StageStoreError::Incomplete);
        }
        let directory = self.stages.open_dir(request.stage_id.to_string())?;
        let pending_name = format!("{}.completion.pending", request.operation_id);
        remove_private_file(&directory, &pending_name)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        let mut image = directory.open_with(&pending_name, &options)?;
        image.set_len(request.final_length)?;
        for write in &writes {
            apply_part_to_image(&directory, write, request.final_length, &mut image)?;
        }
        image.sync_all()?;
        image.seek(SeekFrom::Start(0))?;
        let content_digest = copy_complete_image(&mut image, request.final_length, destination)?;
        drop(image);
        directory.remove_file(&pending_name)?;
        sync_directory(&directory)?;
        Ok(CompletedStage {
            logical_length: request.final_length,
            content_digest,
        })
    }

    fn record_write(
        &mut self,
        stage_id: StageId,
        stage: StoredStage,
        write: &StageWrite,
        observed_at: UnixMicros,
        part_name: &str,
    ) -> Result<StageWriteOutcome, StageStoreError> {
        let length = u64::try_from(write.bytes.len()).map_err(|_| StageStoreError::InvalidInput)?;
        let extent = write
            .offset
            .checked_add(length)
            .ok_or(StageStoreError::InvalidInput)?;
        let sequence = stage
            .sequence
            .checked_add(1)
            .ok_or(StageStoreError::InvalidInput)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO stage_writes(
                operation_id, stage_id, mutation_sequence, stage_fence, byte_offset,
                byte_length, content_digest, part_name, applied_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                write.operation_id.as_bytes().as_slice(),
                stage_id.as_bytes().as_slice(),
                to_i64(sequence)?,
                to_i64(write.stage_fence)?,
                to_i64(write.offset)?,
                to_i64(length)?,
                write.digest.as_slice(),
                part_name,
                observed_at.get()
            ],
        )?;
        let updated = transaction.execute(
            "UPDATE stages
             SET mutation_sequence = ?1, logical_extent = MAX(logical_extent, ?2)
             WHERE stage_id = ?3 AND state = 1 AND mutation_sequence = ?4",
            params![
                to_i64(sequence)?,
                to_i64(extent)?,
                stage_id.as_bytes().as_slice(),
                to_i64(stage.sequence)?
            ],
        )?;
        if updated != 1 {
            return Err(StageStoreError::Unavailable);
        }
        transaction.commit()?;
        Ok(StageWriteOutcome::Applied)
    }
}

#[derive(Clone, Copy)]
struct StoredStage {
    fence: u64,
    maximum_bytes: u64,
    state: u8,
    sequence: u64,
    logical_extent: u64,
    expires_at: UnixMicros,
}

#[derive(Clone)]
struct StoredWrite {
    operation_id: OperationId,
    stage_id: StageId,
    fence: u64,
    offset: u64,
    length: u64,
    digest: [u8; 32],
    part_name: String,
}

impl StoredWrite {
    fn matches(&self, write: &StageWrite) -> Result<bool, StageStoreError> {
        Ok(self.fence == write.stage_fence
            && self.offset == write.offset
            && self.length
                == u64::try_from(write.bytes.len()).map_err(|_| StageStoreError::InvalidInput)?
            && self.digest == write.digest)
    }

    fn end(&self) -> Result<u64, StageStoreError> {
        self.offset
            .checked_add(self.length)
            .ok_or(StageStoreError::Corrupt)
    }
}

/// Stable durable-stage failure categories.
#[derive(Debug, Error)]
pub enum StageStoreError {
    /// Input, bounds or time relation is invalid.
    #[error("durable stage input is invalid")]
    InvalidInput,
    /// Stage or operation identity already belongs to different canonical input.
    #[error("durable stage operation conflicts with existing input")]
    OperationConflict,
    /// Stage fence or lifetime no longer authorises mutation.
    #[error("durable stage authority is stale")]
    Stale,
    /// Requested non-sparse completion contains uninitialised ranges.
    #[error("durable stage is incomplete")]
    Incomplete,
    /// Journal or immutable part bytes violate an internal invariant.
    #[error("durable stage state is corrupt")]
    Corrupt,
    /// A concurrent/local persistence transition prevented this operation.
    #[error("durable stage state is unavailable")]
    Unavailable,
    /// Capability-scoped filesystem IO failed.
    #[error("durable stage filesystem operation failed")]
    Io(#[from] std::io::Error),
    /// SQLite persistence failed.
    #[error("durable stage database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

fn validate_registration(stage: StageRegistration) -> Result<(), StageStoreError> {
    if stage.stage_fence == 0
        || stage.maximum_bytes == 0
        || stage.maximum_bytes > MAXIMUM_SQLITE_INTEGER
        || stage.expires_at <= stage.created_at
    {
        Err(StageStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_live_write(
    stage: StoredStage,
    write: &StageWrite,
    observed_at: UnixMicros,
) -> Result<(), StageStoreError> {
    if stage.state != 1 || stage.fence != write.stage_fence || observed_at >= stage.expires_at {
        return Err(StageStoreError::Stale);
    }
    if write.bytes.is_empty() || blake3::hash(write.bytes.as_slice()).as_bytes() != &write.digest {
        return Err(StageStoreError::InvalidInput);
    }
    let length = u64::try_from(write.bytes.len()).map_err(|_| StageStoreError::InvalidInput)?;
    let end = write
        .offset
        .checked_add(length)
        .ok_or(StageStoreError::InvalidInput)?;
    if end > stage.maximum_bytes {
        Err(StageStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_completion(
    stage: StoredStage,
    request: StageCompletionRequest,
) -> Result<(), StageStoreError> {
    if request.final_length > stage.maximum_bytes {
        return Err(StageStoreError::InvalidInput);
    }
    if stage.state != 1
        || stage.fence != request.stage_fence
        || stage.sequence != request.expected_sequence
        || request.observed_at >= stage.expires_at
    {
        Err(StageStoreError::Stale)
    } else {
        Ok(())
    }
}

fn load_stage(connection: &Connection, stage_id: StageId) -> Result<StoredStage, StageStoreError> {
    let identifier = stage_id.as_bytes();
    let values: (i64, i64, u8, i64, i64, i64) = connection
        .query_row(
            "SELECT stage_fence, maximum_bytes, state, mutation_sequence,
                    logical_extent, expires_at
             FROM stages WHERE stage_id = ?1",
            [identifier.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(StageStoreError::Stale)?;
    Ok(StoredStage {
        fence: from_i64(values.0)?,
        maximum_bytes: from_i64(values.1)?,
        state: values.2,
        sequence: from_i64(values.3)?,
        logical_extent: from_i64(values.4)?,
        expires_at: UnixMicros::new(values.5),
    })
}

fn load_write(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<StoredWrite>, StageStoreError> {
    let identifier = operation_id.as_bytes();
    connection
        .query_row(
            "SELECT stage_id, stage_fence, byte_offset,
                    byte_length, content_digest, part_name
             FROM stage_writes WHERE operation_id = ?1",
            [identifier.as_slice()],
            |row| decode_write_row(operation_id, row),
        )
        .optional()
        .map_err(Into::into)
}

fn load_stage_writes(
    connection: &Connection,
    stage_id: StageId,
) -> Result<Vec<StoredWrite>, StageStoreError> {
    let identifier = stage_id.as_bytes();
    let mut statement = connection.prepare(
        "SELECT operation_id, stage_fence, byte_offset,
                byte_length, content_digest, part_name
         FROM stage_writes WHERE stage_id = ?1 ORDER BY mutation_sequence, operation_id",
    )?;
    let rows = statement.query_map([identifier.as_slice()], |row| {
        let operation_id = decode_operation_id(row, 0)?;
        decode_write_columns(operation_id, stage_id, row, 1)
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn decode_write_row(
    operation_id: OperationId,
    row: &rusqlite::Row<'_>,
) -> Result<StoredWrite, rusqlite::Error> {
    let stage: Vec<u8> = row.get(0)?;
    let stage_id = StageId::from_bytes(
        stage
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    decode_write_columns(operation_id, stage_id, row, 1)
}

fn decode_write_columns(
    operation_id: OperationId,
    stage_id: StageId,
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> Result<StoredWrite, rusqlite::Error> {
    let digest: Vec<u8> = row.get(offset + 3)?;
    let stored = StoredWrite {
        operation_id,
        stage_id,
        fence: from_sql_i64(row.get(offset)?)?,
        offset: from_sql_i64(row.get(offset + 1)?)?,
        length: from_sql_i64(row.get(offset + 2)?)?,
        digest: digest
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        part_name: row.get(offset + 4)?,
    };
    if stored.part_name == format!("{}.part", stored.operation_id) {
        Ok(stored)
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

fn decode_operation_id(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> Result<OperationId, rusqlite::Error> {
    let identifier: Vec<u8> = row.get(offset)?;
    OperationId::from_bytes(
        identifier
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn ranges(writes: &[StoredWrite]) -> Result<Vec<Range<u64>>, StageStoreError> {
    let mut ranges = Vec::new();
    for write in writes {
        insert_range(&mut ranges, write.offset..write.end()?);
    }
    Ok(ranges)
}

fn install_part(
    root: &Dir,
    stage_id: StageId,
    write: &StageWrite,
) -> Result<String, StageStoreError> {
    let directory = root.open_dir(stage_id.to_string())?;
    let final_name = format!("{}.part", write.operation_id);
    if let Ok(mut existing) = directory.open(&final_name) {
        verify_open_file(&mut existing, write.bytes.as_slice(), write.digest)?;
        return Ok(final_name);
    }
    let pending_name = format!("{}.pending", write.operation_id);
    match directory.remove_file(&pending_name) {
        Ok(()) => sync_directory(&directory)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut pending = directory.open_with(&pending_name, &options)?;
    pending.write_all(write.bytes.as_slice())?;
    pending.sync_all()?;
    directory.rename(&pending_name, &directory, &final_name)?;
    sync_directory(&directory)?;
    Ok(final_name)
}

fn verify_part(root: &Dir, stored: &StoredWrite, expected: &[u8]) -> Result<(), StageStoreError> {
    let directory = root.open_dir(stored.stage_id.to_string())?;
    let mut file = directory.open(&stored.part_name)?;
    verify_open_file(&mut file, expected, stored.digest)
}

fn verify_open_file(
    file: &mut cap_std::fs::File,
    expected: &[u8],
    digest: [u8; 32],
) -> Result<(), StageStoreError> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes != expected || blake3::hash(&bytes).as_bytes() != &digest {
        Err(StageStoreError::Corrupt)
    } else {
        Ok(())
    }
}

fn apply_part(
    root: &Dir,
    stage_id: StageId,
    stored: &StoredWrite,
    complete: &mut [u8],
) -> Result<(), StageStoreError> {
    let directory = root.open_dir(stage_id.to_string())?;
    let mut file = directory.open(&stored.part_name)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() != usize::try_from(stored.length).map_err(|_| StageStoreError::Corrupt)?
        || blake3::hash(&bytes).as_bytes() != &stored.digest
    {
        return Err(StageStoreError::Corrupt);
    }
    let start = usize::try_from(stored.offset).map_err(|_| StageStoreError::Corrupt)?;
    if start < complete.len() {
        let copied = bytes.len().min(complete.len() - start);
        complete[start..start + copied].copy_from_slice(&bytes[..copied]);
    }
    Ok(())
}

fn apply_part_to_image(
    directory: &Dir,
    stored: &StoredWrite,
    final_length: u64,
    image: &mut cap_std::fs::File,
) -> Result<(), StageStoreError> {
    let mut source = directory.open(&stored.part_name)?;
    image.seek(SeekFrom::Start(stored.offset.min(final_length)))?;
    let mut digest = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        let read_u64 = u64::try_from(read).map_err(|_| StageStoreError::Corrupt)?;
        let chunk_start = stored
            .offset
            .checked_add(total)
            .ok_or(StageStoreError::Corrupt)?;
        if chunk_start < final_length {
            let writable = usize::try_from((final_length - chunk_start).min(read_u64))
                .map_err(|_| StageStoreError::Corrupt)?;
            image.write_all(&buffer[..writable])?;
        }
        total = total
            .checked_add(read_u64)
            .ok_or(StageStoreError::Corrupt)?;
    }
    if total == stored.length && digest.finalize().as_bytes() == &stored.digest {
        Ok(())
    } else {
        Err(StageStoreError::Corrupt)
    }
}

fn copy_complete_image(
    image: &mut cap_std::fs::File,
    logical_length: u64,
    destination: &mut impl Write,
) -> Result<[u8; 32], StageStoreError> {
    let mut remaining = logical_length;
    let mut digest = blake3::Hasher::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    while remaining != 0 {
        let requested = usize::try_from(remaining.min(COPY_BUFFER_BYTES_U64))
            .map_err(|_| StageStoreError::Corrupt)?;
        let read = image.read(&mut buffer[..requested])?;
        if read == 0 {
            return Err(StageStoreError::Corrupt);
        }
        digest.update(&buffer[..read]);
        destination.write_all(&buffer[..read])?;
        remaining -= u64::try_from(read).map_err(|_| StageStoreError::Corrupt)?;
    }
    Ok(digest.finalize().into())
}

fn remove_private_file(directory: &Dir, name: &str) -> Result<(), StageStoreError> {
    match directory.remove_file(name) {
        Ok(()) => sync_directory(directory).map_err(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn create_stage_directory(root: &Dir, stage_id: StageId) -> Result<(), StageStoreError> {
    match root.create_dir(stage_id.to_string()) {
        Ok(()) => sync_directory(root).map_err(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn configure(connection: &Connection) -> Result<(), StageStoreError> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

fn migrate(connection: &mut Connection, applied_at: UnixMicros) -> Result<(), StageStoreError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'schema_migrations' LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let digest: [u8; 32] = blake3::hash(MIGRATION.as_bytes()).into();
    if !exists {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(MIGRATION)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, migration_digest, applied_at)
             VALUES (?1, ?2, ?3)",
            params![SCHEMA_VERSION, digest.as_slice(), applied_at.get()],
        )?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
        return Ok(());
    }
    let stored: Vec<u8> = connection.query_row(
        "SELECT migration_digest FROM schema_migrations WHERE version = ?1",
        [SCHEMA_VERSION],
        |row| row.get(0),
    )?;
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if stored.as_slice() != digest || version != SCHEMA_VERSION {
        return Err(StageStoreError::Corrupt);
    }
    Ok(())
}

fn verify_database(connection: &Connection) -> Result<(), StageStoreError> {
    let quick: String = connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
    let foreign_key_violation = connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some();
    if quick == "ok" && !foreign_key_violation {
        Ok(())
    } else {
        Err(StageStoreError::Corrupt)
    }
}

fn sync_directory(directory: &Dir) -> Result<(), std::io::Error> {
    directory.open(".")?.into_std().sync_all()
}

fn to_i64(value: u64) -> Result<i64, StageStoreError> {
    i64::try_from(value).map_err(|_| StageStoreError::InvalidInput)
}

fn from_i64(value: i64) -> Result<u64, StageStoreError> {
    u64::try_from(value).map_err(|_| StageStoreError::Corrupt)
}

fn from_sql_i64(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use meshspan_contracts::BoundedBytes;
    use meshspan_domain::{OperationId, StageId, UnixMicros};
    use tempfile::tempdir;

    use super::{
        CompletedStage, DurableStageStore, StageCompletionRequest, StageRegistration,
        StageStoreError, install_part,
    };
    use crate::{StageWrite, StageWriteOutcome};

    #[test]
    fn restart_replays_parts_and_reconstructs_acknowledged_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([1; 16])?;
        let registration = registration(stage_id, 3, 100);
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration)?;
        let suffix = write(2, 3, 5, b"world")?;
        assert_eq!(
            store.write(stage_id, &suffix, UnixMicros::new(2))?,
            StageWriteOutcome::Applied
        );
        store.write(stage_id, &write(3, 3, 0, b"hello")?, UnixMicros::new(3))?;
        drop(store);

        let mut reopened = DurableStageStore::open(directory.path(), UnixMicros::new(4))?;
        reopened.register(registration)?;
        assert_eq!(
            reopened.write(stage_id, &suffix, UnixMicros::new(5))?,
            StageWriteOutcome::Replayed
        );
        assert_eq!(
            reopened.complete_bytes(stage_id, 10, false)?.as_slice(),
            b"helloworld"
        );
        assert_eq!(
            reopened.checkpoint(stage_id)?.initialised_ranges,
            vec![0..10]
        );
        Ok(())
    }

    #[test]
    fn holes_expiry_and_corrupt_parts_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([4; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 5, 10))?;
        store.write(stage_id, &write(6, 5, 4, b"part")?, UnixMicros::new(2))?;
        assert!(matches!(
            store.complete_bytes(stage_id, 8, false),
            Err(StageStoreError::Incomplete)
        ));
        assert_eq!(
            store.complete_bytes(stage_id, 8, true)?.as_slice(),
            b"\0\0\0\0part"
        );
        assert!(matches!(
            store.write(stage_id, &write(7, 5, 0, b"late")?, UnixMicros::new(10)),
            Err(StageStoreError::Stale)
        ));
        std::fs::write(
            directory
                .path()
                .join("stages")
                .join(stage_id.to_string())
                .join(format!("{}.part", OperationId::from_bytes([6; 16])?)),
            b"evil",
        )?;
        assert!(matches!(
            store.complete_bytes(stage_id, 8, true),
            Err(StageStoreError::Corrupt)
        ));
        Ok(())
    }

    #[test]
    fn crash_after_part_sync_before_journal_recovers_exactly_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([8; 16])?;
        let registration = registration(stage_id, 9, 100);
        let staged_write = write(10, 9, 0, b"durable")?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration)?;

        std::fs::remove_dir(directory.path().join("stages").join(stage_id.to_string()))?;
        drop(store);

        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(2))?;
        store.register(registration)?;

        install_part(&store.stages, stage_id, &staged_write)?;
        drop(store);

        let mut reopened = DurableStageStore::open(directory.path(), UnixMicros::new(3))?;
        reopened.register(registration)?;
        assert_eq!(
            reopened.write(stage_id, &staged_write, UnixMicros::new(4))?,
            StageWriteOutcome::Applied
        );
        assert_eq!(
            reopened.write(stage_id, &staged_write, UnixMicros::new(5))?,
            StageWriteOutcome::Replayed
        );
        assert_eq!(
            reopened.complete_bytes(stage_id, 7, false)?.as_slice(),
            b"durable"
        );
        Ok(())
    }

    #[test]
    fn streaming_completion_is_fenced_exact_and_retryable_after_sink_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([11; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 12, 100))?;
        store.write(stage_id, &write(13, 12, 5, b"world")?, UnixMicros::new(2))?;
        store.write(stage_id, &write(14, 12, 0, b"hello")?, UnixMicros::new(3))?;
        let request = StageCompletionRequest {
            operation_id: OperationId::from_bytes([15; 16])?,
            stage_id,
            stage_fence: 12,
            expected_sequence: 2,
            final_length: 10,
            sparse: false,
            observed_at: UnixMicros::new(4),
        };
        let mut failing = FailingWriter;
        assert!(matches!(
            store.stream_complete(request, &mut failing),
            Err(StageStoreError::Io(_))
        ));
        let mut completed = Vec::new();
        assert_eq!(
            store.stream_complete(request, &mut completed)?,
            CompletedStage {
                logical_length: 10,
                content_digest: blake3::hash(b"helloworld").into(),
            }
        );
        assert_eq!(completed, b"helloworld");
        let stale = StageCompletionRequest {
            expected_sequence: 1,
            ..request
        };
        assert!(matches!(
            store.stream_complete(stale, &mut Vec::new()),
            Err(StageStoreError::Stale)
        ));
        Ok(())
    }

    #[test]
    fn sparse_completion_streams_large_logical_extent_in_bounded_chunks()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([16; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(StageRegistration {
            stage_id,
            stage_fence: 17,
            maximum_bytes: 2 * 1_024 * 1_024,
            created_at: UnixMicros::new(1),
            expires_at: UnixMicros::new(100),
        })?;
        store.write(
            stage_id,
            &write(18, 17, 1_048_575, b"x")?,
            UnixMicros::new(2),
        )?;
        let mut counter = CountingWriter::default();
        let completed = store.stream_complete(
            StageCompletionRequest {
                operation_id: OperationId::from_bytes([19; 16])?,
                stage_id,
                stage_fence: 17,
                expected_sequence: 1,
                final_length: 1_048_576,
                sparse: true,
                observed_at: UnixMicros::new(3),
            },
            &mut counter,
        )?;
        assert_eq!(completed.logical_length, 1_048_576);
        assert_eq!(counter.written, 1_048_576);
        assert!(counter.maximum_write <= 64 * 1_024);
        Ok(())
    }

    #[test]
    fn streaming_completion_accepts_an_empty_checkpoint() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([20; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 21, 100))?;
        let mut completed_bytes = Vec::new();
        let completed = store.stream_complete(
            StageCompletionRequest {
                operation_id: OperationId::from_bytes([22; 16])?,
                stage_id,
                stage_fence: 21,
                expected_sequence: 0,
                final_length: 0,
                sparse: false,
                observed_at: UnixMicros::new(2),
            },
            &mut completed_bytes,
        )?;
        assert_eq!(completed.logical_length, 0);
        assert_eq!(completed.content_digest, *blake3::hash(&[]).as_bytes());
        assert!(completed_bytes.is_empty());
        Ok(())
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected destination failure",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingWriter {
        written: usize,
        maximum_write: usize,
    }

    impl Write for CountingWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.written = self.written.saturating_add(buffer.len());
            self.maximum_write = self.maximum_write.max(buffer.len());
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn registration(stage_id: StageId, fence: u64, expiry: i64) -> StageRegistration {
        StageRegistration {
            stage_id,
            stage_fence: fence,
            maximum_bytes: 64,
            created_at: UnixMicros::new(1),
            expires_at: UnixMicros::new(expiry),
        }
    }

    fn write(
        operation: u8,
        fence: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<StageWrite, Box<dyn std::error::Error>> {
        Ok(StageWrite {
            operation_id: OperationId::from_bytes([operation; 16])?,
            stage_fence: fence,
            offset,
            bytes: BoundedBytes::copy_from(bytes, 64)?,
            digest: blake3::hash(bytes).into(),
        })
    }
}
