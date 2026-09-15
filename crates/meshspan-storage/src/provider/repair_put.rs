// SPDX-License-Identifier: GPL-2.0-only

//! Repair resumption reauthorises progress, without replacing the original physical attempt.

use meshspan_contracts::{
    PutShardRequest, RepairPutAdmission, ReservationClass, ShardPutIntent, ShardPutResolution,
    ShardReceipt, ShardWritePermit,
};
use meshspan_domain::UnixMicros;

use super::{FolderShardStore, FolderShardStoreError};
use crate::journal::JournalPutRequest;

impl FolderShardStore {
    /// Admits or recovers one exact repair intent before bytes are sent.
    /// Capacity is pinned atomically with preparation, including after a lost admission reply.
    /// # Errors
    /// Rejects stale/forged authority, foreground writes, changed intent, exhausted capacity,
    /// inconsistent journals and corrupt bytes. Original deadlines and request digests are retained.
    pub fn prepare_repair_put(
        &mut self,
        intent: ShardPutIntent,
        authority: ShardWritePermit,
        now: UnixMicros,
    ) -> Result<RepairPutAdmission, FolderShardStoreError> {
        self.authorise_put_intent(intent, authority, now)?;
        if intent.reservation_class == ReservationClass::ForegroundWrite
            || authority.maximum_bytes < intent.maximum_bytes
        {
            return Err(FolderShardStoreError::Unauthorized);
        }
        let observation = self.folder.capacity_observation()?;
        let original = self.journal.prepare_repair_put(intent, observation, now)?;
        match self.resolve_put(original, authority, now)? {
            ShardPutResolution::Prepared => Ok(RepairPutAdmission::Prepared(original)),
            ShardPutResolution::Verified(receipt) => Ok(RepairPutAdmission::Verified(receipt)),
            ShardPutResolution::Unknown => Err(FolderShardStoreError::Corrupt),
        }
    }

    /// Finishes bytes for a prepared repair using fresh authority and the original write identity.
    /// # Errors
    /// Rejects absent preparation, changed bytes/identity, foreground writes, stale or forged
    /// authority and corrupt existing data. It never creates a reservation or another operation.
    pub fn finish_repair_put(
        &mut self,
        request: &PutShardRequest,
        authority: ShardWritePermit,
        now: UnixMicros,
    ) -> Result<ShardReceipt, FolderShardStoreError> {
        if request.reservation.class == ReservationClass::ForegroundWrite
            || usize::try_from(request.expected_length).ok() != Some(request.bytes.len())
            || blake3::hash(request.bytes.as_slice()).as_bytes() != &request.expected_digest
        {
            return Err(FolderShardStoreError::InvalidInput);
        }
        match self.resolve_put(request.identity(), authority, now)? {
            ShardPutResolution::Unknown => return Err(FolderShardStoreError::InvalidInput),
            ShardPutResolution::Verified(receipt) => return Ok(receipt),
            ShardPutResolution::Prepared => {}
        }
        self.persist_prepared_put(
            JournalPutRequest {
                reservation: request.reservation,
                request_digest: request.identity().request_digest(),
                shard: request.shard,
                expected_length: request.expected_length,
                expected_digest: request.expected_digest,
                now,
            },
            &request.bytes,
        )
    }
}
