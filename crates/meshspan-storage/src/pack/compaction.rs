// SPDX-License-Identifier: GPL-2.0-only

//! Copy-on-write reclamation: verify a compacted copy before replacing the closed original.

use meshspan_domain::UnixMicros;
use rusqlite::{Connection, OpenFlags};

use super::{
    MAXIMUM_SHARD_BYTES, PackFault, PackStore, PackStoreError, check_integrity, verify_bytes,
    verify_identity,
};
use crate::RegisteredFolder;

impl PackStore {
    /// Runs only under the provider's exclusive lock, after all borrowed reads have finished.
    /// Returns logical database extent reclaimed, not a device free-space guarantee.
    pub(crate) fn compact(
        &mut self,
        folder: &RegisteredFolder,
        now: UnixMicros,
    ) -> Result<u64, PackStoreError> {
        let before = self.observe_space()?;
        // Legacy/unbounded packs need a staged migration, not an unbounded foreground pause.
        if before.database_bytes > 512 * 1024 * 1024 {
            return Err(PackStoreError::NoSpace);
        }
        check_integrity(&self.connection)?;
        let pending = folder.prepare_compaction(self.sequence)?;
        self.connection.backup(rusqlite::MAIN_DB, &pending, None)?;
        let copy = Connection::open_with_flags(
            &pending,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        copy.execute_batch(
            "PRAGMA trusted_schema = OFF; PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = FULL; VACUUM;",
        )?;
        check_integrity(&copy)?;
        verify_identity(&copy, self.marker, self.sequence)?;
        verify_remaining_bytes(&copy)?;
        let after = super::space::observe_space(&copy)?.database_bytes;
        if after > before.database_bytes {
            return Err(PackStoreError::Corrupt);
        }
        copy.close().map_err(|(_, error)| error)?;
        let fault = self.injected_fault.take();
        if fault == Some(PackFault::BeforeCompactionPublish) {
            return Err(PackStoreError::Indeterminate);
        }
        self.publish_compacted(folder, now)?;
        if fault == Some(PackFault::AfterCompactionPublish) {
            return Err(PackStoreError::Indeterminate);
        }
        Ok(before.database_bytes - after)
    }

    /// No live or tombstoned payload may be discarded by whole-pack retirement.
    pub(crate) fn verify_reclaimed(&self) -> Result<(), PackStoreError> {
        verify_identity(&self.connection, self.marker, self.sequence)?;
        let (records, payload): (i64, bool) = self.connection.query_row(
            "SELECT count(*), COALESCE(max(state <> 3 OR payload), 0)
             FROM (SELECT state, stored_bytes IS NOT NULL AS payload FROM shards LIMIT 4097)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if records > 4096 || payload {
            return Err(PackStoreError::Corrupt);
        }
        Ok(())
    }

    fn publish_compacted(
        &mut self,
        folder: &RegisteredFolder,
        now: UnixMicros,
    ) -> Result<(), PackStoreError> {
        let checkpoint: (i64, i64, i64) =
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
        if checkpoint != (0, 0, 0) {
            return Err(PackStoreError::Indeterminate);
        }
        // Keep the object valid if close or publication fails. No consumer can observe
        // this placeholder while the target's exclusive mutation/read lock is held.
        let original = std::mem::replace(&mut self.connection, Connection::open_in_memory()?);
        if let Err((connection, error)) = original.close() {
            self.connection = connection;
            return Err(error.into());
        }
        let publication = folder.publish_compaction(self.sequence);
        let reopened = Self::open(folder, self.sequence, now)?;
        *self = reopened;
        publication?;
        Ok(())
    }
}

fn verify_remaining_bytes(connection: &Connection) -> Result<(), PackStoreError> {
    let (records, oversized): (i64, i64) = connection.query_row(
        "SELECT count(*), COALESCE(max(length(stored_bytes)), 0) FROM shards",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if records > 4_096
        || usize::try_from(oversized).map_err(|_| PackStoreError::Corrupt)? > MAXIMUM_SHARD_BYTES
    {
        return Err(PackStoreError::Corrupt);
    }
    let mut statement = connection.prepare(
        "SELECT stored_length, stored_digest, stored_bytes FROM shards WHERE state IN (1, 2) ORDER BY record_number",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let length: i64 = row.get(0)?;
        let digest: Vec<u8> = row.get(1)?;
        let bytes: Vec<u8> = row.get(2)?;
        verify_bytes(length, &digest, &bytes)?;
    }
    Ok(())
}
