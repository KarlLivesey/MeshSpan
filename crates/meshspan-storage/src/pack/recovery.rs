// SPDX-License-Identifier: GPL-2.0-only

//! Read-only queries against an isolated recovery copy, including crash-left WAL.

use std::path::Path;

use meshspan_contracts::BoundedBytes;
use meshspan_domain::UnixMicros;
use rusqlite::{Connection, OpenFlags, params};

use super::{PackStore, PackStoreError, SCHEMA_VERSION, migrate, verify_identity};
use crate::TargetMarker;
use crate::recovery::{RecoveryShardPage, RecoveryShardRecord, RecoveryShardRetention};
use crate::shard::decode_shard;

impl PackStore {
    pub(crate) fn open_recovery(
        file_path: &Path,
        marker: TargetMarker,
        sequence: u64,
    ) -> Result<Self, PackStoreError> {
        if sequence == 0
            || !std::fs::symlink_metadata(file_path)
                .map_err(|_| PackStoreError::NotFound)?
                .is_file()
        {
            return Err(PackStoreError::InvalidInput);
        }
        // This is a private copy, never a source pack. SQLite may rebuild the WAL
        // index here; the database itself remains read-only and is never checkpointed.
        let mut connection = Connection::open_with_flags(
            file_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA query_only = ON;")?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(PackStoreError::UnsupportedSchema);
        }
        migrate(&mut connection, UnixMicros::new(0))?;
        verify_identity(&connection, marker, sequence)?;
        Ok(Self {
            connection,
            marker,
            sequence,
            injected_fault: None,
        })
    }

    pub(crate) fn recover_bytes(
        &self,
        shard: meshspan_contracts::ShardIdentity,
    ) -> Result<BoundedBytes, PackStoreError> {
        // A tombstone is not serving authority. Recovery may salvage bytes still
        // physically present; only the independently verified backup selects content.
        self.read_retained(shard, 2)
    }

    pub(crate) fn recovery_inventory(
        &self,
        after_record: u64,
        limit: u16,
    ) -> Result<RecoveryShardPage, PackStoreError> {
        let after_record = i64::try_from(after_record).map_err(|_| PackStoreError::InvalidInput)?;
        let mut statement = self.connection.prepare(
            "SELECT record_number,
                    CASE WHEN length(shard_identity) = 46 THEN shard_identity ELSE NULL END,
                    stored_length,
                    CASE WHEN length(stored_digest) = 32 THEN stored_digest ELSE NULL END,
                    state
             FROM shards WHERE record_number > ?1 ORDER BY record_number LIMIT ?2",
        )?;
        let mut rows = statement.query(params![after_record, i64::from(limit) + 1])?;
        let mut records = Vec::with_capacity(usize::from(limit));
        while let Some(row) = rows.next()? {
            if records.len() == usize::from(limit) {
                return Ok(RecoveryShardPage {
                    next_after_record: records
                        .last()
                        .map(|record: &RecoveryShardRecord| record.record_number),
                    records,
                });
            }
            records.push(decode_inventory_record(row)?);
        }
        Ok(RecoveryShardPage {
            records,
            next_after_record: None,
        })
    }
}

fn decode_inventory_record(row: &rusqlite::Row<'_>) -> Result<RecoveryShardRecord, PackStoreError> {
    let record_number =
        u64::try_from(row.get::<_, i64>(0)?).map_err(|_| PackStoreError::Corrupt)?;
    let shard = decode_shard(&row.get::<_, Vec<u8>>(1)?).map_err(|_| PackStoreError::Corrupt)?;
    let length = u64::try_from(row.get::<_, i64>(2)?).map_err(|_| PackStoreError::Corrupt)?;
    if record_number == 0 || length == 0 || length > 64 * 1024 * 1024 {
        return Err(PackStoreError::Corrupt);
    }
    let digest = row
        .get::<_, Vec<u8>>(3)?
        .try_into()
        .map_err(|_| PackStoreError::Corrupt)?;
    let retention = match row.get::<_, i64>(4)? {
        1 => RecoveryShardRetention::Active,
        2 => RecoveryShardRetention::Tombstoned,
        3 => RecoveryShardRetention::Unlinked,
        _ => return Err(PackStoreError::Corrupt),
    };
    Ok(RecoveryShardRecord {
        record_number,
        shard,
        length,
        digest,
        retention,
    })
}
