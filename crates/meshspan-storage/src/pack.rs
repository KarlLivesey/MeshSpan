// SPDX-License-Identifier: GPL-2.0-only

//! Hardened packed BLOB storage beneath one registered folder.

use std::path::Path;
use std::time::Duration;

use meshspan_contracts::{BoundedBytes, ShardIdentity, ShardReceipt};
use meshspan_domain::{OperationId, UnixMicros};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use thiserror::Error;

use crate::journal::DurablePackEvidence;
use crate::shard::{decode_receipt, encode_receipt, encode_shard};
use crate::{RegisteredFolder, TargetMarker};

mod removal;
mod scrub;

pub(crate) use removal::PackTombstoneRequest;
pub(crate) use scrub::PackScrubResult;

const SCHEMA_VERSION: u32 = 1;
const SCHEMA: &str = include_str!("../schema/pack/001_initial.sql");
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_SHARD_BYTES: usize = 64 * 1024 * 1024;
const PUT_OPERATION_KIND: i64 = 1;
const SHARD_ACTIVE: i64 = 1;

pub(crate) struct PackStore {
    connection: Connection,
    marker: TargetMarker,
    sequence: u64,
    injected_fault: Option<PackFault>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackFault {
    FullBeforeWrite,
    ShortWriteAfterShardInsert,
    LostResultAfterCommit,
}

#[derive(Clone, Copy)]
pub(crate) struct PackPutRequest<'a> {
    pub operation_id: OperationId,
    pub request_digest: [u8; 32],
    pub shard: ShardIdentity,
    pub expected_digest: [u8; 32],
    pub bytes: &'a BoundedBytes,
    pub now: UnixMicros,
}

impl PackStore {
    pub fn open(
        folder: &RegisteredFolder,
        sequence: u64,
        opened_at: UnixMicros,
    ) -> Result<Self, PackStoreError> {
        let path = folder.pack_database_path(sequence)?;
        let marker = folder.marker();
        let mut connection = open_connection(&path)?;
        migrate(&mut connection, opened_at)?;
        bind_identity(&mut connection, marker, sequence, opened_at)?;
        check_integrity(&connection)?;
        Ok(Self {
            connection,
            marker,
            sequence,
            injected_fault: None,
        })
    }

    pub fn put_exact(
        &mut self,
        request: PackPutRequest<'_>,
    ) -> Result<DurablePackEvidence, PackStoreError> {
        validate_put(request)?;
        let fault = self.injected_fault.take();
        if fault == Some(PackFault::FullBeforeWrite) {
            return Err(PackStoreError::NoSpace);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) =
            load_operation(&transaction, request.operation_id, request.request_digest)?
        {
            let offset = verified_record_number(
                &transaction,
                receipt.shard,
                receipt.length,
                receipt.digest,
            )?;
            transaction.commit()?;
            return Ok(self.evidence(receipt, offset));
        }
        let offset = install_or_reuse_shard(&transaction, request)?;
        if fault == Some(PackFault::ShortWriteAfterShardInsert) {
            return Err(PackStoreError::Indeterminate);
        }
        let receipt = ShardReceipt {
            operation_id: request.operation_id,
            shard: request.shard,
            length: u64::try_from(request.bytes.len()).map_err(|_| PackStoreError::InvalidInput)?,
            digest: request.expected_digest,
            target_id: self.marker.target_id(),
            target_generation: self.marker.generation(),
        };
        store_operation(&transaction, request, receipt)?;
        transaction.commit()?;
        self.verify_receipt(receipt)?;
        if fault == Some(PackFault::LostResultAfterCommit) {
            return Err(PackStoreError::Indeterminate);
        }
        Ok(self.evidence(receipt, offset))
    }

    #[cfg(test)]
    pub fn inject_fault(&mut self, fault: PackFault) {
        self.injected_fault = Some(fault);
    }

    pub fn get_exact(&self, shard: ShardIdentity) -> Result<BoundedBytes, PackStoreError> {
        let key = encode_shard(shard);
        let stored: Option<(i64, Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT stored_length, stored_digest, stored_bytes
                 FROM shards WHERE shard_identity = ?1 AND state = ?2",
                params![key.as_slice(), SHARD_ACTIVE],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((length, digest, bytes)) = stored else {
            return Err(PackStoreError::NotFound);
        };
        verify_bytes(length, &digest, &bytes)?;
        BoundedBytes::copy_from(&bytes, MAXIMUM_SHARD_BYTES).map_err(|_| PackStoreError::Corrupt)
    }

    pub fn recover_put(
        &self,
        operation_id: OperationId,
        request_digest: [u8; 32],
    ) -> Result<Option<DurablePackEvidence>, PackStoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        let result = load_operation(&transaction, operation_id, request_digest)?
            .map(|receipt| -> Result<DurablePackEvidence, PackStoreError> {
                let offset = verified_record_number(
                    &transaction,
                    receipt.shard,
                    receipt.length,
                    receipt.digest,
                )?;
                Ok(self.evidence(receipt, offset))
            })
            .transpose()?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn check_integrity(&self) -> Result<(), PackStoreError> {
        check_integrity(&self.connection)
    }

    const fn evidence(&self, receipt: ShardReceipt, offset: u64) -> DurablePackEvidence {
        DurablePackEvidence {
            receipt,
            pack_sequence: self.sequence,
            pack_offset: offset,
        }
    }

    fn verify_receipt(&self, receipt: ShardReceipt) -> Result<(), PackStoreError> {
        let bytes = self.get_exact(receipt.shard)?;
        if bytes.len() == usize::try_from(receipt.length).map_err(|_| PackStoreError::Corrupt)?
            && blake3::hash(bytes.as_slice()).as_bytes() == &receipt.digest
        {
            Ok(())
        } else {
            Err(PackStoreError::Corrupt)
        }
    }
}

fn open_connection(path: &Path) -> Result<Connection, PackStoreError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA recursive_triggers = OFF;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA temp_store = MEMORY;",
    )?;
    Ok(connection)
}

fn migrate(connection: &mut Connection, applied_at: UnixMicros) -> Result<(), PackStoreError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(PackStoreError::UnsupportedSchema);
    }
    let expected: [u8; 32] = blake3::hash(SCHEMA.as_bytes()).into();
    if version == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, migration_digest, applied_at)
             VALUES (?1, ?2, ?3)",
            params![SCHEMA_VERSION, expected.as_slice(), applied_at.get()],
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
    let count: i64 = connection.query_row("SELECT count(*) FROM schema_migrations", [], |row| {
        row.get(0)
    })?;
    if count != 1 || stored.as_slice() != expected {
        Err(PackStoreError::MigrationMismatch)
    } else {
        Ok(())
    }
}

fn bind_identity(
    connection: &mut Connection,
    marker: TargetMarker,
    sequence: u64,
    opened_at: UnixMicros,
) -> Result<(), PackStoreError> {
    if sequence == 0 || i64::try_from(sequence).is_err() {
        return Err(PackStoreError::InvalidInput);
    }
    let mesh = marker.mesh_id().as_bytes();
    let target = marker.target_id().as_bytes();
    let fingerprint = marker.fingerprint().as_bytes();
    let generation = to_i64(marker.generation())?;
    let sequence = to_i64(sequence)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT OR IGNORE INTO pack_state(
            singleton, mesh_id, target_id, target_generation, marker_fingerprint,
            pack_sequence, created_at, last_opened_at
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![
            mesh.as_slice(),
            target.as_slice(),
            generation,
            fingerprint.as_slice(),
            sequence,
            opened_at.get(),
        ],
    )?;
    let stored: (Vec<u8>, Vec<u8>, i64, Vec<u8>, i64) = transaction.query_row(
        "SELECT mesh_id, target_id, target_generation, marker_fingerprint, pack_sequence
         FROM pack_state WHERE singleton = 1",
        [],
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
    if stored
        != (
            mesh.to_vec(),
            target.to_vec(),
            generation,
            fingerprint.to_vec(),
            sequence,
        )
    {
        return Err(PackStoreError::IdentityMismatch);
    }
    transaction.execute(
        "UPDATE pack_state SET last_opened_at = ?1 WHERE singleton = 1",
        [opened_at.get()],
    )?;
    transaction.commit()?;
    Ok(())
}

fn validate_put(request: PackPutRequest<'_>) -> Result<(), PackStoreError> {
    let length = request.bytes.len();
    if length == 0
        || length > MAXIMUM_SHARD_BYTES
        || blake3::hash(request.bytes.as_slice()).as_bytes() != &request.expected_digest
    {
        Err(PackStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn load_operation(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
    request_digest: [u8; 32],
) -> Result<Option<ShardReceipt>, PackStoreError> {
    let operation = operation_id.as_bytes();
    let stored: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT request_digest, result_receipt FROM pack_operations
             WHERE operation_id = ?1 AND operation_kind = ?2",
            params![operation.as_slice(), PUT_OPERATION_KIND],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match stored {
        Some((stored_digest, receipt)) if stored_digest.as_slice() == request_digest => Ok(Some(
            decode_receipt(&receipt).map_err(|_| PackStoreError::Corrupt)?,
        )),
        Some(_) => Err(PackStoreError::OperationConflict),
        None => Ok(None),
    }
}

fn install_or_reuse_shard(
    transaction: &Transaction<'_>,
    request: PackPutRequest<'_>,
) -> Result<u64, PackStoreError> {
    let key = encode_shard(request.shard);
    let existing: Option<(i64, i64, Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT record_number, stored_length, stored_digest, state
             FROM shards WHERE shard_identity = ?1",
            [key.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if let Some((record, length, digest, state)) = existing {
        if usize::try_from(length).ok() == Some(request.bytes.len())
            && digest.as_slice() == request.expected_digest
            && state == SHARD_ACTIVE
        {
            verified_record_number(
                transaction,
                request.shard,
                u64::try_from(request.bytes.len()).map_err(|_| PackStoreError::InvalidInput)?,
                request.expected_digest,
            )?;
            return to_u64(record);
        }
        return Err(PackStoreError::OperationConflict);
    }
    let operation = request.operation_id.as_bytes();
    transaction.execute(
        "INSERT INTO shards(
            shard_identity, manifest_digest, stripe_index, shard_index, shard_generation,
            stored_length, stored_digest, stored_bytes, state, put_operation_id, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            key.as_slice(),
            request.shard.manifest_digest.as_slice(),
            to_i64(request.shard.stripe_index)?,
            i64::from(request.shard.shard_index),
            i64::from(request.shard.generation),
            to_i64(u64::try_from(request.bytes.len()).map_err(|_| PackStoreError::InvalidInput)?)?,
            request.expected_digest.as_slice(),
            request.bytes.as_slice(),
            SHARD_ACTIVE,
            operation.as_slice(),
            request.now.get(),
        ],
    )?;
    to_u64(transaction.last_insert_rowid())
}

fn store_operation(
    transaction: &Transaction<'_>,
    request: PackPutRequest<'_>,
    receipt: ShardReceipt,
) -> Result<(), PackStoreError> {
    let operation = request.operation_id.as_bytes();
    let shard = encode_shard(request.shard);
    let receipt = encode_receipt(receipt);
    transaction.execute(
        "INSERT INTO pack_operations(
            operation_id, operation_kind, request_digest, shard_identity,
            result_receipt, completed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            operation.as_slice(),
            PUT_OPERATION_KIND,
            request.request_digest.as_slice(),
            shard.as_slice(),
            receipt.as_slice(),
            request.now.get(),
        ],
    )?;
    Ok(())
}

fn verified_record_number(
    transaction: &Transaction<'_>,
    shard: ShardIdentity,
    expected_length: u64,
    expected_digest: [u8; 32],
) -> Result<u64, PackStoreError> {
    let key = encode_shard(shard);
    let stored: Option<(i64, i64, Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT record_number, stored_length, stored_digest, stored_bytes
             FROM shards WHERE shard_identity = ?1 AND state = ?2",
            params![key.as_slice(), SHARD_ACTIVE],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((record, length, digest, bytes)) = stored else {
        return Err(PackStoreError::Corrupt);
    };
    if to_u64(length)? != expected_length || digest.as_slice() != expected_digest {
        return Err(PackStoreError::Corrupt);
    }
    verify_bytes(length, &digest, &bytes)?;
    to_u64(record)
}

fn verify_bytes(length: i64, digest: &[u8], bytes: &[u8]) -> Result<(), PackStoreError> {
    if usize::try_from(length).ok() != Some(bytes.len())
        || digest.len() != 32
        || blake3::hash(bytes).as_bytes() != digest
    {
        Err(PackStoreError::Corrupt)
    } else {
        Ok(())
    }
}

fn check_integrity(connection: &Connection) -> Result<(), PackStoreError> {
    let result: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    let foreign_key_failure = connection
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()?
        .is_some();
    if result == "ok" && !foreign_key_failure {
        Ok(())
    } else {
        Err(PackStoreError::Corrupt)
    }
}

fn to_i64(value: u64) -> Result<i64, PackStoreError> {
    i64::try_from(value).map_err(|_| PackStoreError::InvalidInput)
}

fn to_u64(value: i64) -> Result<u64, PackStoreError> {
    u64::try_from(value).map_err(|_| PackStoreError::Corrupt)
}

#[derive(Debug, Error)]
pub(crate) enum PackStoreError {
    #[error("pack input is invalid")]
    InvalidInput,
    #[error("pack operation conflicts with prior immutable state")]
    OperationConflict,
    #[error("pack shard was not found")]
    NotFound,
    #[error("pack has no space for the requested operation")]
    NoSpace,
    #[error("pack operation outcome is indeterminate")]
    Indeterminate,
    #[error("pack bytes or state are corrupt")]
    Corrupt,
    #[error("pack identity does not match the registered target")]
    IdentityMismatch,
    #[error("pack migration history differs")]
    MigrationMismatch,
    #[error("pack schema is newer than this build")]
    UnsupportedSchema,
    #[error("registered folder rejected pack access")]
    Folder(#[from] crate::StorageFolderError),
    #[error("pack database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use meshspan_contracts::{BoundedBytes, ShardIdentity};
    use meshspan_domain::{EntropyError, MeshId, OperationId, RandomSource, TargetId, UnixMicros};
    use rusqlite::params;
    use tempfile::tempdir;

    use super::{PackPutRequest, PackStore, PackStoreError};
    use crate::shard::encode_shard;
    use crate::{FolderRegistration, RegisteredFolder, UsageLimit};

    struct FixedRandom;

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(5);
            Ok(())
        }
    }

    #[test]
    fn packed_bytes_are_durable_deduplicated_replayed_and_verified()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let storage_path = directory.path().join("target");
        fs::create_dir(&storage_path)?;
        let mut random = FixedRandom;
        let folder = RegisteredFolder::register_new(
            &storage_path,
            FolderRegistration {
                mesh_id: MeshId::from_bytes([1; 16])?,
                target_id: TargetId::from_bytes([2; 16])?,
                generation: 3,
                usage_limit: UsageLimit::DEFAULT,
            },
            &mut random,
        )?;
        let shard = ShardIdentity {
            manifest_digest: [6; 32],
            stripe_index: 7,
            shard_index: 8,
            generation: 9,
        };
        let bytes = BoundedBytes::copy_from(b"opaque encrypted shard", 1_024)?;
        let digest: [u8; 32] = blake3::hash(bytes.as_slice()).into();
        let request = PackPutRequest {
            operation_id: OperationId::from_bytes([10; 16])?,
            request_digest: [11; 32],
            shard,
            expected_digest: digest,
            bytes: &bytes,
            now: UnixMicros::new(12),
        };
        let mut pack = PackStore::open(&folder, 1, UnixMicros::new(1))?;
        let first = pack.put_exact(request)?;
        assert_eq!(pack.put_exact(request)?, first);
        assert_eq!(pack.get_exact(shard)?.as_slice(), bytes.as_slice());
        assert_eq!(
            pack.recover_put(request.operation_id, request.request_digest)?,
            Some(first)
        );

        let deduplicated = PackPutRequest {
            operation_id: OperationId::from_bytes([13; 16])?,
            request_digest: [14; 32],
            ..request
        };
        let reused = pack.put_exact(deduplicated)?;
        assert_eq!(reused.pack_offset, first.pack_offset);
        assert_ne!(reused.receipt.operation_id, first.receipt.operation_id);
        assert!(matches!(
            pack.put_exact(PackPutRequest {
                request_digest: [15; 32],
                ..request
            }),
            Err(PackStoreError::OperationConflict)
        ));
        drop(pack);

        let pack = PackStore::open(&folder, 1, UnixMicros::new(20))?;
        assert_eq!(pack.get_exact(shard)?.as_slice(), bytes.as_slice());
        pack.check_integrity()?;
        Ok(())
    }

    #[test]
    fn corrupted_packed_bytes_never_replay_or_read_as_valid()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let storage_path = directory.path().join("target");
        fs::create_dir(&storage_path)?;
        let mut random = FixedRandom;
        let folder = RegisteredFolder::register_new(
            &storage_path,
            FolderRegistration {
                mesh_id: MeshId::from_bytes([21; 16])?,
                target_id: TargetId::from_bytes([22; 16])?,
                generation: 23,
                usage_limit: UsageLimit::DEFAULT,
            },
            &mut random,
        )?;
        let shard = ShardIdentity {
            manifest_digest: [24; 32],
            stripe_index: 25,
            shard_index: 26,
            generation: 27,
        };
        let bytes = BoundedBytes::copy_from(b"verified before damage", 1_024)?;
        let request = PackPutRequest {
            operation_id: OperationId::from_bytes([28; 16])?,
            request_digest: [29; 32],
            shard,
            expected_digest: blake3::hash(bytes.as_slice()).into(),
            bytes: &bytes,
            now: UnixMicros::new(30),
        };
        let mut pack = PackStore::open(&folder, 1, UnixMicros::new(1))?;
        pack.put_exact(request)?;
        pack.connection.execute(
            "UPDATE shards SET stored_bytes = ?1 WHERE shard_identity = ?2",
            params![b"corrupt".as_slice(), encode_shard(shard).as_slice()],
        )?;
        assert!(matches!(
            pack.get_exact(shard),
            Err(PackStoreError::Corrupt)
        ));
        assert!(matches!(
            pack.put_exact(request),
            Err(PackStoreError::Corrupt)
        ));
        assert!(matches!(
            pack.recover_put(request.operation_id, request.request_digest),
            Err(PackStoreError::Corrupt)
        ));
        Ok(())
    }
}
