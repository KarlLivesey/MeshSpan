// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe local evidence for encrypted metadata-backup staging files.

use meshspan_backup::{BackupFileEvidence, BackupSourceManifest};
use meshspan_domain::{BackupId, MeshId, PartitionId, UnixMicros};
use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;

use crate::LocalDatabase;

const MAXIMUM_RELATIVE_FILE_NAME_BYTES: usize = 128;
const COLUMNS: &str = "backup_id, partition_id, mesh_id, relative_file_name,
    last_log_index, last_log_term, state_revision, source_schema_version, source_byte_length,
    source_digest, encrypted_byte_length, encrypted_digest, created_at, prepared_at, revision";

/// Exact non-secret evidence required to resume publication of one local encrypted container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalMetadataBackupStaging {
    /// Exact source and encrypted-container evidence.
    pub evidence: BackupFileEvidence,
    /// Application-derived filename beneath the private backup staging directory.
    pub relative_file_name: String,
    /// Local time at which the complete container evidence became durable.
    pub prepared_at: UnixMicros,
    /// Monotonic local journal revision.
    pub revision: u64,
}

/// Whether a staging-journal mutation changed durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalMetadataBackupStagingDisposition {
    /// This call made the transition durable.
    Applied,
    /// The exact requested state was already durable.
    Replayed,
}

/// Closed local encrypted-backup staging failures.
#[derive(Debug, Error)]
pub enum LocalMetadataBackupStagingError {
    /// SQLite or durable IO failed.
    #[error("local metadata backup staging database operation failed")]
    Sqlite(#[from] rusqlite::Error),
    /// Input or persisted evidence violated the staging contract.
    #[error("local metadata backup staging evidence was invalid")]
    Invalid,
    /// The backup identity was reused with different bytes or source state.
    #[error("local metadata backup staging evidence conflicts with durable state")]
    Conflict,
    /// Persisted state could not be decoded without weakening its invariants.
    #[error("local metadata backup staging state was corrupt")]
    Corrupt,
}

impl LocalDatabase {
    /// Loads one exact encrypted staging record.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed identifiers, counters, filenames or digests.
    pub fn metadata_backup_staging(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<LocalMetadataBackupStaging>, LocalMetadataBackupStagingError> {
        load(self.connection(), backup_id)
    }

    /// Records complete encrypted-container evidence before any provider IO may begin.
    ///
    /// # Errors
    ///
    /// Rejects malformed evidence, unsafe filenames and changed replays.
    pub fn record_metadata_backup_staging(
        &mut self,
        staging: &LocalMetadataBackupStaging,
    ) -> Result<LocalMetadataBackupStagingDisposition, LocalMetadataBackupStagingError> {
        validate(staging)?;
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = load(&transaction, staging.evidence.source.backup_id)? {
            return if existing == *staging {
                Ok(LocalMetadataBackupStagingDisposition::Replayed)
            } else {
                Err(LocalMetadataBackupStagingError::Conflict)
            };
        }
        insert(&transaction, staging)?;
        transaction.commit()?;
        Ok(LocalMetadataBackupStagingDisposition::Applied)
    }

    /// Removes an exact staging record after provider protection or explicit abandonment.
    ///
    /// # Errors
    ///
    /// Rejects changed evidence and fails closed if concurrent state differs.
    pub fn remove_metadata_backup_staging(
        &mut self,
        expected: &LocalMetadataBackupStaging,
    ) -> Result<LocalMetadataBackupStagingDisposition, LocalMetadataBackupStagingError> {
        validate(expected)?;
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(existing) = load(&transaction, expected.evidence.source.backup_id)? else {
            return Ok(LocalMetadataBackupStagingDisposition::Replayed);
        };
        if existing != *expected {
            return Err(LocalMetadataBackupStagingError::Conflict);
        }
        let changed = transaction.execute(
            "DELETE FROM local_metadata_backup_staging
             WHERE backup_id = ?1 AND revision = ?2",
            params![
                expected.evidence.source.backup_id.as_bytes().as_slice(),
                to_i64(expected.revision)?,
            ],
        )?;
        if changed != 1 {
            return Err(LocalMetadataBackupStagingError::Conflict);
        }
        transaction.commit()?;
        Ok(LocalMetadataBackupStagingDisposition::Applied)
    }
}

fn validate(staging: &LocalMetadataBackupStaging) -> Result<(), LocalMetadataBackupStagingError> {
    staging
        .evidence
        .source
        .validate()
        .map_err(|_| LocalMetadataBackupStagingError::Invalid)?;
    let name = staging.relative_file_name.as_bytes();
    if staging.evidence.byte_length == 0
        || staging.evidence.digest == [0; 32]
        || staging.prepared_at < staging.evidence.source.created_at
        || staging.revision == 0
        || name.is_empty()
        || name.len() > MAXIMUM_RELATIVE_FILE_NAME_BYTES
        || !name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_'))
    {
        Err(LocalMetadataBackupStagingError::Invalid)
    } else {
        Ok(())
    }
}

fn insert(
    connection: &rusqlite::Connection,
    staging: &LocalMetadataBackupStaging,
) -> Result<(), LocalMetadataBackupStagingError> {
    let source = staging.evidence.source;
    connection.execute(
        "INSERT INTO local_metadata_backup_staging(
            backup_id, partition_id, mesh_id, relative_file_name, last_log_index, last_log_term,
            state_revision, source_schema_version, source_byte_length, source_digest,
            encrypted_byte_length, encrypted_digest, created_at, prepared_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            source.backup_id.as_bytes().as_slice(),
            source.partition_id.as_bytes().as_slice(),
            source.mesh_id.as_bytes().as_slice(),
            staging.relative_file_name,
            to_i64(source.last_log_index)?,
            to_i64(source.last_log_term)?,
            to_i64(source.state_revision)?,
            i64::from(source.schema_version),
            to_i64(source.byte_length)?,
            source.digest.as_slice(),
            to_i64(staging.evidence.byte_length)?,
            staging.evidence.digest.as_slice(),
            source.created_at.get(),
            staging.prepared_at.get(),
            to_i64(staging.revision)?,
        ],
    )?;
    Ok(())
}

fn load(
    connection: &rusqlite::Connection,
    backup_id: BackupId,
) -> Result<Option<LocalMetadataBackupStaging>, LocalMetadataBackupStagingError> {
    connection
        .query_row(
            &format!("SELECT {COLUMNS} FROM local_metadata_backup_staging WHERE backup_id = ?1"),
            [backup_id.as_bytes().as_slice()],
            decode,
        )
        .optional()?
        .map(validate_loaded)
        .transpose()
}

fn decode(row: &Row<'_>) -> rusqlite::Result<LocalMetadataBackupStaging> {
    Ok(LocalMetadataBackupStaging {
        evidence: BackupFileEvidence {
            source: BackupSourceManifest {
                backup_id: BackupId::from_bytes(array(row.get(0)?)?).map_err(decode_error)?,
                partition_id: PartitionId::from_bytes(array(row.get(1)?)?).map_err(decode_error)?,
                mesh_id: MeshId::from_bytes(array(row.get(2)?)?).map_err(decode_error)?,
                last_log_index: non_negative(row.get(4)?)?,
                last_log_term: non_negative(row.get(5)?)?,
                state_revision: non_negative(row.get(6)?)?,
                schema_version: positive_u32(row.get(7)?)?,
                byte_length: positive(row.get(8)?)?,
                digest: array(row.get(9)?)?,
                created_at: UnixMicros::new(row.get(12)?),
            },
            byte_length: positive(row.get(10)?)?,
            digest: array(row.get(11)?)?,
        },
        relative_file_name: row.get(3)?,
        prepared_at: UnixMicros::new(row.get(13)?),
        revision: positive(row.get(14)?)?,
    })
}

fn validate_loaded(
    staging: LocalMetadataBackupStaging,
) -> Result<LocalMetadataBackupStaging, LocalMetadataBackupStagingError> {
    validate(&staging).map(|()| staging)
}

fn array<const SIZE: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; SIZE]> {
    bytes.try_into().map_err(|_| decode_error(()))
}

fn non_negative(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(decode_error)
}

fn positive(value: i64) -> rusqlite::Result<u64> {
    let value = non_negative(value)?;
    (value > 0).then_some(value).ok_or_else(|| decode_error(()))
}

fn positive_u32(value: i64) -> rusqlite::Result<u32> {
    let value = u32::try_from(value).map_err(decode_error)?;
    (value > 0).then_some(value).ok_or_else(|| decode_error(()))
}

fn to_i64(value: u64) -> Result<i64, LocalMetadataBackupStagingError> {
    i64::try_from(value).map_err(|_| LocalMetadataBackupStagingError::Invalid)
}

fn decode_error<E>(_error: E) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(LocalMetadataBackupStagingError::Corrupt),
    )
}
