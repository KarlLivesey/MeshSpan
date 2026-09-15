// SPDX-License-Identifier: GPL-2.0-only

//! Resolve an original write under fresh authority, without admitting another physical attempt.

use meshspan_contracts::{
    ContractVersion, ShardPutIdentity, ShardPutResolution, ShardWritePermit,
    verify_write_permit_mac,
};
use meshspan_domain::UnixMicros;

use super::{FolderShardStore, FolderShardStoreError, map_pack};
use crate::journal::{JournalPutRequest, PreparePutResult};

impl FolderShardStore {
    /// Resolves an uncertain exact put after restart or expiry of its original admission.
    /// Fresh write authority permits finishing journal accounting for already durable bytes;
    /// this operation never reserves capacity, accepts bytes or selects a new destination.
    ///
    /// # Errors
    /// Rejects stale/forged fresh authority, altered original admission, inconsistent journals
    /// and missing/corrupt previously committed bytes. Unknown is never proof of rollback.
    pub fn resolve_put(
        &mut self,
        original: ShardPutIdentity,
        authority: ShardWritePermit,
        observed_at: UnixMicros,
    ) -> Result<ShardPutResolution, FolderShardStoreError> {
        self.authorise_put_resolution(original, authority, observed_at)?;
        let Some(state) = self.journal.resolve_put(original, observed_at)? else {
            return Ok(ShardPutResolution::Unknown);
        };
        self.select_pack(original.shard, observed_at)?;
        let evidence = self
            .pack
            .recover_put(original.context.operation_id, original.request_digest())
            .map_err(|error| map_pack(&error))?;
        match (state, evidence) {
            (PreparePutResult::Prepared, None) => Ok(ShardPutResolution::Prepared),
            (PreparePutResult::Committed(_), None) => Err(FolderShardStoreError::Corrupt),
            (PreparePutResult::Committed(receipt), Some(evidence)) => {
                if receipt != evidence.receipt {
                    return Err(FolderShardStoreError::Corrupt);
                }
                Ok(ShardPutResolution::Verified(receipt))
            }
            (PreparePutResult::Prepared, Some(evidence)) => {
                let receipt = self.journal.commit_put(
                    JournalPutRequest {
                        reservation: original.reservation,
                        request_digest: original.request_digest(),
                        shard: original.shard,
                        expected_length: original.expected_length,
                        expected_digest: original.expected_digest,
                        now: observed_at,
                    },
                    evidence,
                )?;
                Ok(ShardPutResolution::Verified(receipt))
            }
        }
    }

    fn authorise_put_resolution(
        &self,
        original: ShardPutIdentity,
        authority: ShardWritePermit,
        now: UnixMicros,
    ) -> Result<(), FolderShardStoreError> {
        if original.context.contract_version != ContractVersion::V1_0
            || original.context.operation_id != original.reservation.operation_id
            || original.context.deadline.get() <= 0
            || original.context.deadline > original.reservation.expires_at
            || original.shard.manifest_digest == [0; 32]
            || original.shard.generation == 0
            || original.expected_digest == [0; 32]
        {
            return Err(FolderShardStoreError::InvalidInput);
        }
        let marker = self.folder.marker();
        if now.get() < 0
            || !verify_write_permit_mac(&self.permits.key, authority)
            || authority.mesh_id != self.permits.mesh_id
            || authority.operation_id != original.context.operation_id
            || authority.target_id != marker.target_id()
            || authority.target_generation != marker.generation()
            || authority.shard != original.shard
            || authority.reservation_class != original.reservation.class
            || authority.maximum_bytes < original.expected_length
            || authority.authorization_revision.get()
                < self.permits.minimum_catalogue_revision.get()
            || authority.expires_at <= now
        {
            return Err(FolderShardStoreError::Unauthorized);
        }
        Ok(())
    }
}
