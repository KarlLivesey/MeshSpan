// SPDX-License-Identifier: GPL-2.0-only

//! Journal/pack composition for exact local shard durability.

use std::path::Path;

use meshspan_contracts::{
    BoundedBytes, BoundedItems, ContractVersion, InventoryPage, PutShardRequest, ShardReceipt,
    StorageReservation,
};
use meshspan_domain::{RandomSource, UnixMicros};
use thiserror::Error;

use crate::journal::{
    CapacityPolicy, JournalPutRequest, PendingPutPage, PreparePutResult, ReserveCapacityRequest,
    TargetJournal, TargetJournalError,
};
use crate::pack::{PackPutRequest, PackStore, PackStoreError};
use crate::{RegisteredFolder, StorageFolderError};

const ACTIVE_PACK_SEQUENCE: u64 = 1;

/// Bounded recovery outcomes plus continuation for remaining prepared work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPage {
    /// Puts strengthened from pack-durable to journal-committed during this call.
    pub committed: BoundedItems<ShardReceipt>,
    /// Prepared operations whose pack bytes are not yet durable.
    pub awaiting_bytes: usize,
    /// Opaque next-page cursor when more prepared work exists.
    pub next_cursor: Option<BoundedBytes>,
}

/// Exact local shard store composing one registered folder, journal and active pack segment.
pub struct FolderShardStore {
    folder: RegisteredFolder,
    journal: TargetJournal,
    pack: PackStore,
}

impl FolderShardStore {
    /// Opens an identity-bound local journal and packed-byte segment for one registered folder.
    ///
    /// # Errors
    ///
    /// Rejects marker/journal/pack mismatch, migration drift, corruption or unavailable entropy.
    pub fn open(
        folder: RegisteredFolder,
        daemon_state_dir: &Path,
        policy: CapacityPolicy,
        opened_at: UnixMicros,
        random: &mut impl RandomSource,
    ) -> Result<Self, FolderShardStoreError> {
        let journal =
            TargetJournal::open(daemon_state_dir, folder.marker(), policy, opened_at, random)?;
        let pack = PackStore::open(&folder, ACTIVE_PACK_SEQUENCE, opened_at)
            .map_err(|error| map_pack(&error))?;
        Ok(Self {
            folder,
            journal,
            pack,
        })
    }

    /// Persists one exact capacity reservation in the target journal.
    ///
    /// # Errors
    ///
    /// Rejects stale identity/time, conflicting replay and unsafe capacity consumption.
    pub fn reserve(
        &mut self,
        request: ReserveCapacityRequest,
    ) -> Result<StorageReservation, FolderShardStoreError> {
        self.journal.reserve(request).map_err(Into::into)
    }

    /// Makes exact immutable shard bytes durable in the pack, then commits journal inventory.
    ///
    /// # Errors
    ///
    /// Rejects invalid/expired reservations, wrong lengths or BLAKE3 digests, stale target
    /// generations and conflicting operation/shard reuse. Pack success without journal success is
    /// recovered by exact operation ID; no receipt is invented from a connection outcome.
    pub fn put_exact(
        &mut self,
        request: &PutShardRequest,
        now: UnixMicros,
    ) -> Result<ShardReceipt, FolderShardStoreError> {
        validate_put(request, self.folder.marker(), now)?;
        let request_digest = put_request_digest(request);
        let journal_request = JournalPutRequest {
            reservation: request.reservation,
            request_digest,
            shard: request.shard,
            expected_length: request.expected_length,
            expected_digest: request.expected_digest,
            now,
        };
        if let PreparePutResult::Committed(receipt) = self.journal.prepare_put(journal_request)? {
            return Ok(receipt);
        }
        let evidence = self
            .pack
            .put_exact(PackPutRequest {
                operation_id: request.context.operation_id,
                request_digest,
                shard: request.shard,
                expected_digest: request.expected_digest,
                bytes: &request.bytes,
                now,
            })
            .map_err(|error| map_pack(&error))?;
        self.journal
            .commit_put(journal_request, evidence)
            .map_err(Into::into)
    }

    /// Reconciles bounded prepared journal work with exact durable pack-operation receipts.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursors/state and pack evidence inconsistent with the prepared request.
    pub fn recover_pending(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        now: UnixMicros,
    ) -> Result<RecoveryPage, FolderShardStoreError> {
        let PendingPutPage { puts, next_cursor } = self.journal.pending_puts(cursor, limit)?;
        let mut committed = Vec::with_capacity(puts.len());
        let mut awaiting_bytes = 0_usize;
        for pending in puts.as_slice() {
            match self
                .pack
                .recover_put(pending.reservation.operation_id, pending.request_digest)
                .map_err(|error| map_pack(&error))?
            {
                Some(evidence) => {
                    committed.push(self.journal.commit_put(
                        JournalPutRequest {
                            reservation: pending.reservation,
                            request_digest: pending.request_digest,
                            shard: pending.shard,
                            expected_length: pending.expected_length,
                            expected_digest: pending.expected_digest,
                            now,
                        },
                        evidence,
                    )?);
                }
                None => awaiting_bytes = awaiting_bytes.saturating_add(1),
            }
        }
        Ok(RecoveryPage {
            committed: BoundedItems::new(committed, limit)
                .map_err(|_| FolderShardStoreError::Corrupt)?,
            awaiting_bytes,
            next_cursor,
        })
    }

    /// Returns one bounded seek page of journal-confirmed shards.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursors, limits and durable identities.
    pub fn inventory(
        &self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
    ) -> Result<InventoryPage, FolderShardStoreError> {
        self.journal.inventory(cursor, limit).map_err(Into::into)
    }

    /// Re-runs folder, journal and pack structural health checks.
    ///
    /// # Errors
    ///
    /// Isolates and reports this target when any required local capability or state fails.
    pub fn check_health(&self) -> Result<(), FolderShardStoreError> {
        self.folder.probe()?;
        self.journal.check_integrity()?;
        self.pack
            .check_integrity()
            .map_err(|error| map_pack(&error))
    }
}

fn validate_put(
    request: &PutShardRequest,
    marker: crate::TargetMarker,
    now: UnixMicros,
) -> Result<(), FolderShardStoreError> {
    if request.context.contract_version != ContractVersion::V1_0
        || request.context.operation_id != request.reservation.operation_id
        || request.context.deadline <= now
        || request.reservation.expires_at <= now
        || request.reservation.target_id != marker.target_id()
        || request.reservation.target_generation != marker.generation()
        || request.expected_length == 0
        || usize::try_from(request.expected_length).ok() != Some(request.bytes.len())
        || request.expected_length > request.reservation.maximum_bytes
        || blake3::hash(request.bytes.as_slice()).as_bytes() != &request.expected_digest
    {
        Err(FolderShardStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn put_request_digest(request: &PutShardRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.storage.put-request.v1");
    digest.update(&request.context.operation_id.as_bytes());
    digest.update(&request.context.deadline.get().to_be_bytes());
    match request.context.expected_revision {
        Some(revision) => {
            digest.update(&[1]);
            digest.update(&revision.get().to_be_bytes());
        }
        None => {
            digest.update(&[0]);
        }
    }
    digest.update(&request.reservation.reservation_digest);
    digest.update(&crate::shard::encode_shard(request.shard));
    digest.update(&request.expected_length.to_be_bytes());
    digest.update(&request.expected_digest);
    digest.finalize().into()
}

fn map_pack(error: &PackStoreError) -> FolderShardStoreError {
    match error {
        PackStoreError::InvalidInput => FolderShardStoreError::InvalidInput,
        PackStoreError::OperationConflict => FolderShardStoreError::OperationConflict,
        PackStoreError::NotFound => FolderShardStoreError::NotFound,
        PackStoreError::Corrupt
        | PackStoreError::IdentityMismatch
        | PackStoreError::MigrationMismatch
        | PackStoreError::UnsupportedSchema => FolderShardStoreError::Corrupt,
        PackStoreError::Folder(_) | PackStoreError::Sqlite(_) => FolderShardStoreError::Unavailable,
    }
}

/// Stable composed-store failures without provider paths, SQL or shard bytes.
#[derive(Debug, Error)]
pub enum FolderShardStoreError {
    /// Request shape, bounds, time, identity or digest is invalid.
    #[error("folder shard request is invalid")]
    InvalidInput,
    /// One operation/shard identity was reused with different immutable input.
    #[error("folder shard operation conflicts with prior input")]
    OperationConflict,
    /// Exact requested provider bytes do not exist.
    #[error("folder shard was not found")]
    NotFound,
    /// Durable provider state or bytes fail identity/integrity validation.
    #[error("folder shard state is corrupt")]
    Corrupt,
    /// This target is locally unavailable without affecting sibling targets.
    #[error("folder shard target is unavailable")]
    Unavailable,
    /// Registered folder capability or marker operation failed.
    #[error("registered storage folder failed")]
    Folder(#[from] StorageFolderError),
    /// Target journal rejected or could not persist the operation.
    #[error("target journal failed")]
    Journal(#[from] TargetJournalError),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use meshspan_contracts::{
        BoundedBytes, ContractVersion, PutShardRequest, RequestContext, ReservationClass,
        ShardIdentity,
    };
    use meshspan_domain::{
        EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
    };
    use tempfile::tempdir;

    use super::{FolderShardStore, put_request_digest};
    use crate::journal::{JournalPutRequest, PreparePutResult};
    use crate::pack::PackPutRequest;
    use crate::{
        CapacityObservation, CapacityPolicy, FolderRegistration, RegisteredFolder,
        ReserveCapacityRequest, UsageLimit,
    };

    struct FixedRandom;

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(9);
            Ok(())
        }
    }

    fn reserve_put(
        store: &mut FolderShardStore,
        registration: FolderRegistration,
        operation_byte: u8,
        shard_index: u16,
        payload: &[u8],
        now: UnixMicros,
    ) -> Result<PutShardRequest, Box<dyn std::error::Error>> {
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([operation_byte; 16])?,
            deadline: UnixMicros::new(1_000),
            expected_revision: Some(Revision::new(5)),
        };
        let reservation = store.reserve(ReserveCapacityRequest {
            context,
            target_id: registration.target_id,
            target_generation: registration.generation,
            class: ReservationClass::ForegroundWrite,
            bytes: u64::try_from(payload.len())?,
            observation: CapacityObservation {
                total_bytes: 10_000,
                available_bytes: 10_000,
            },
            now,
        })?;
        let bytes = BoundedBytes::copy_from(payload, 1_024)?;
        Ok(PutShardRequest {
            context,
            reservation,
            shard: ShardIdentity {
                manifest_digest: [6; 32],
                stripe_index: 7,
                shard_index,
                generation: 9,
            },
            expected_length: u64::try_from(bytes.len())?,
            expected_digest: blake3::hash(bytes.as_slice()).into(),
            bytes,
        })
    }

    #[test]
    fn composed_store_publishes_only_after_pack_and_journal_are_durable()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let storage_path = directory.path().join("target");
        let state_path = directory.path().join("state");
        fs::create_dir(&storage_path)?;
        let mut random = FixedRandom;
        let registration = FolderRegistration {
            mesh_id: MeshId::from_bytes([1; 16])?,
            target_id: TargetId::from_bytes([2; 16])?,
            generation: 3,
            usage_limit: UsageLimit::DEFAULT,
        };
        let folder = RegisteredFolder::register_new(&storage_path, registration, &mut random)?;
        let fingerprint = folder.marker().fingerprint();
        let policy = CapacityPolicy {
            usage_limit: UsageLimit::DEFAULT,
            repair_reserve_bytes: 100,
            revision: Revision::new(1),
        };
        let mut store =
            FolderShardStore::open(folder, &state_path, policy, UnixMicros::new(1), &mut random)?;
        let request = reserve_put(
            &mut store,
            registration,
            4,
            8,
            b"opaque encrypted payload",
            UnixMicros::new(10),
        )?;
        let first = store.put_exact(&request, UnixMicros::new(20))?;
        assert_eq!(store.put_exact(&request, UnixMicros::new(21))?, first);
        assert_eq!(store.inventory(None, 10)?.entries.len(), 1);
        store.check_health()?;
        drop(store);

        let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
        let mut store = FolderShardStore::open(
            folder,
            &state_path,
            policy,
            UnixMicros::new(30),
            &mut random,
        )?;
        assert_eq!(store.put_exact(&request, UnixMicros::new(31))?, first);
        assert!(
            store
                .recover_pending(None, 10, UnixMicros::new(31))?
                .committed
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn restart_commits_pack_durable_journal_prepared_put_exactly_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let storage_path = directory.path().join("target");
        let state_path = directory.path().join("state");
        fs::create_dir(&storage_path)?;
        let mut random = FixedRandom;
        let registration = FolderRegistration {
            mesh_id: MeshId::from_bytes([11; 16])?,
            target_id: TargetId::from_bytes([12; 16])?,
            generation: 13,
            usage_limit: UsageLimit::DEFAULT,
        };
        let folder = RegisteredFolder::register_new(&storage_path, registration, &mut random)?;
        let fingerprint = folder.marker().fingerprint();
        let policy = CapacityPolicy {
            usage_limit: UsageLimit::DEFAULT,
            repair_reserve_bytes: 100,
            revision: Revision::new(1),
        };
        let mut store =
            FolderShardStore::open(folder, &state_path, policy, UnixMicros::new(1), &mut random)?;
        let request = reserve_put(
            &mut store,
            registration,
            14,
            15,
            b"durable before journal commit",
            UnixMicros::new(10),
        )?;
        let request_digest = put_request_digest(&request);
        let journal_request = JournalPutRequest {
            reservation: request.reservation,
            request_digest,
            shard: request.shard,
            expected_length: request.expected_length,
            expected_digest: request.expected_digest,
            now: UnixMicros::new(20),
        };
        assert_eq!(
            store.journal.prepare_put(journal_request)?,
            PreparePutResult::Prepared
        );
        let durable_evidence = store.pack.put_exact(PackPutRequest {
            operation_id: request.context.operation_id,
            request_digest,
            shard: request.shard,
            expected_digest: request.expected_digest,
            bytes: &request.bytes,
            now: UnixMicros::new(20),
        })?;
        assert_eq!(durable_evidence.receipt.shard, request.shard);
        assert!(store.inventory(None, 10)?.entries.is_empty());
        drop(store);

        let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
        let mut store = FolderShardStore::open(
            folder,
            &state_path,
            policy,
            UnixMicros::new(30),
            &mut random,
        )?;
        let recovered = store.recover_pending(None, 10, UnixMicros::new(31))?;
        assert_eq!(recovered.committed.as_slice(), &[durable_evidence.receipt]);
        assert_eq!(recovered.awaiting_bytes, 0);
        assert!(recovered.next_cursor.is_none());
        assert_eq!(store.inventory(None, 10)?.entries.len(), 1);

        let replay = store.recover_pending(None, 10, UnixMicros::new(32))?;
        assert!(replay.committed.is_empty());
        assert_eq!(replay.awaiting_bytes, 0);
        Ok(())
    }
}
