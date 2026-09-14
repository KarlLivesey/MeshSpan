// SPDX-License-Identifier: GPL-2.0-only

//! Resolve the journal's exact shard route; never search unrelated packs for bytes.

use meshspan_contracts::{PackSpaceObservation, ShardIdentity};
use meshspan_domain::UnixMicros;

use super::{FolderShardStore, FolderShardStoreError, map_pack};
use crate::pack::PackStore;

impl FolderShardStore {
    /// One bounded maintenance candidate; reusable pages are its restart-persistent work source.
    pub(crate) fn compact_next_pack(
        &mut self,
        now: UnixMicros,
    ) -> Result<Option<u64>, FolderShardStoreError> {
        let sequence = match self
            .journal
            .next_pack_sequence(self.last_compaction_sequence)?
        {
            Some(value) => value,
            None => self
                .journal
                .next_pack_sequence(0)?
                .ok_or(FolderShardStoreError::Corrupt)?,
        };
        self.last_compaction_sequence = sequence;
        if self.journal.pack_retirement_pending(sequence)?
            || self.journal.prepare_pack_retirement(sequence)?
        {
            return self.retire_pack(sequence, now).map(Some);
        }
        let space = if sequence == self.pack.sequence() {
            self.pack.observe_space()
        } else {
            PackStore::open_read(&self.folder, sequence).and_then(|pack| pack.observe_space())
        }
        .map_err(|error| map_pack(&error))?;
        if space.reusable_bytes < 1024 * 1024 || space.reusable_bytes < space.database_bytes / 4 {
            return Ok(None);
        }
        if sequence != self.pack.sequence() {
            self.pack =
                PackStore::open(&self.folder, sequence, now).map_err(|error| map_pack(&error))?;
        }
        self.pack
            .compact(&self.folder, now)
            .map(Some)
            .map_err(|error| map_pack(&error))
    }

    fn retire_pack(
        &mut self,
        sequence: u64,
        now: UnixMicros,
    ) -> Result<u64, FolderShardStoreError> {
        // The shared provider's exclusive lock pins readers for this bounded slice.
        // Close any cached source handle before removing its main database and sidecars.
        if self.pack.sequence() == sequence {
            self.pack = PackStore::open(&self.folder, self.journal.active_pack_sequence()?, now)
                .map_err(|error| map_pack(&error))?;
        }
        let source_exists = self.folder.pack_file_exists(sequence)?;
        let reclaimed = if source_exists {
            let source =
                PackStore::open_read(&self.folder, sequence).map_err(|error| map_pack(&error))?;
            source
                .verify_reclaimed()
                .map_err(|error| map_pack(&error))?;
            source
                .observe_space()
                .map_err(|error| map_pack(&error))?
                .database_bytes
        } else {
            // A committed retirement may have unlinked the main file before a crash.
            0
        };
        self.folder.retire_pack_files(sequence)?;
        self.journal.complete_pack_retirement(sequence)?;
        Ok(reclaimed)
    }

    pub(super) fn select_pack(
        &mut self,
        shard: ShardIdentity,
        now: UnixMicros,
    ) -> Result<(), FolderShardStoreError> {
        let sequence = self
            .journal
            .pack_sequence(shard)?
            .ok_or(FolderShardStoreError::NotFound)?;
        if self.pack.sequence() != sequence {
            self.pack =
                PackStore::open(&self.folder, sequence, now).map_err(|error| map_pack(&error))?;
        }
        Ok(())
    }

    pub(super) fn read_pack<T>(
        &self,
        shard: ShardIdentity,
        read: impl FnOnce(&PackStore) -> Result<T, crate::pack::PackStoreError>,
    ) -> Result<T, FolderShardStoreError> {
        let sequence = self
            .journal
            .pack_sequence(shard)?
            .ok_or(FolderShardStoreError::NotFound)?;
        if self.pack.sequence() == sequence {
            return read(&self.pack).map_err(|error| map_pack(&error));
        }
        let pack =
            PackStore::open_read(&self.folder, sequence).map_err(|error| map_pack(&error))?;
        read(&pack).map_err(|error| map_pack(&error))
    }

    pub(super) fn observe_pack_space(&self) -> Result<PackSpaceObservation, FolderShardStoreError> {
        // A telemetry pass has a fixed IO budget. Larger targets report missing coverage,
        // not the active pack's extent misleadingly presented as the whole target.
        const MAXIMUM_SAMPLED_PACKS: u32 = 32;
        let sequences = self.journal.pack_sequences(MAXIMUM_SAMPLED_PACKS + 1)?;
        if sequences.len() > MAXIMUM_SAMPLED_PACKS as usize {
            return Err(FolderShardStoreError::ResourceExhausted);
        }
        let mut total = PackSpaceObservation {
            database_bytes: 0,
            reusable_bytes: 0,
        };
        for sequence in sequences {
            let observation = if self.pack.sequence() == sequence {
                self.pack.observe_space()
            } else {
                PackStore::open_read(&self.folder, sequence).and_then(|pack| pack.observe_space())
            }
            .map_err(|error| map_pack(&error))?;
            total.database_bytes = total
                .database_bytes
                .checked_add(observation.database_bytes)
                .ok_or(FolderShardStoreError::Corrupt)?;
            total.reusable_bytes = total
                .reusable_bytes
                .checked_add(observation.reusable_bytes)
                .ok_or(FolderShardStoreError::Corrupt)?;
        }
        Ok(total)
    }
}
