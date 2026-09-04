// SPDX-License-Identifier: GPL-2.0-only

//! Journal/pack composition for exact local shard durability.

use std::path::Path;

use meshspan_contracts::{
    BoundedBytes, BoundedItems, ContractError, ContractKind, ContractLimits, ContractVersion,
    ImplementationDescriptor, InventoryPage, PutShardRequest, ReclamationReceipt,
    RemovalAuthorityFence, RemovalPermit, RequestContext, ReserveStorageRequest, ScrubObservation,
    ScrubOutcome, ScrubPage, ShardReadPermit, ShardReceipt, StoragePermitMacKey, StorageProvider,
    StorageReservation, TombstoneReceipt, verify_read_permit_mac, verify_removal_permit_mac,
};
use meshspan_domain::{MeshId, RandomSource, Revision, UnixMicros};
use thiserror::Error;

use crate::journal::{
    CapacityPolicy, DurableTombstoneEvidence, JournalPutRequest, JournalTombstoneRequest,
    PendingPutPage, PendingTombstonePage, PreparePutResult, PrepareTombstoneResult,
    ReserveCapacityRequest, TargetJournal, TargetJournalError,
};
use crate::pack::{
    PackPutRequest, PackScrubResult, PackStore, PackStoreError, PackTombstoneRequest,
};
use crate::{RegisteredFolder, StorageFolderError};

const ACTIVE_PACK_SEQUENCE: u64 = 1;
const PROVIDER_VERSIONS: &[ContractVersion] = &[ContractVersion::V1_0];
const MAXIMUM_CONTROL_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_PAGE_ITEMS: usize = 1_000;

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

/// Bounded tombstone recovery outcomes plus continuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TombstoneRecoveryPage {
    /// Tombstones strengthened from pack-durable to journal-committed during this call.
    pub committed: BoundedItems<TombstoneReceipt>,
    /// Prepared operations whose pack tombstone is not yet durable.
    pub awaiting_pack: usize,
    /// Opaque next-page cursor when more prepared work exists.
    pub next_cursor: Option<BoundedBytes>,
}

/// Exact local shard store composing one registered folder, journal and active pack segment.
pub struct FolderShardStore {
    folder: RegisteredFolder,
    journal: TargetJournal,
    pack: PackStore,
    permits: StoragePermitVerifier,
}

/// Current mesh authority material used to authenticate short-lived storage permits.
pub struct StoragePermitVerifier {
    mesh_id: MeshId,
    current_removal_authority_epoch: u64,
    minimum_catalogue_revision: Revision,
    key: StoragePermitMacKey,
}

impl StoragePermitVerifier {
    /// Installs the current removal epoch, applied catalogue fence and MAC key.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero authority epoch or catalogue revision. Callers must initialise
    /// this only after the node has applied that catalogue revision locally.
    pub fn new(
        mesh_id: MeshId,
        current_removal_authority_epoch: u64,
        minimum_catalogue_revision: Revision,
        key: StoragePermitMacKey,
    ) -> Result<Self, FolderShardStoreError> {
        if current_removal_authority_epoch == 0 || minimum_catalogue_revision.get() == 0 {
            Err(FolderShardStoreError::InvalidInput)
        } else {
            Ok(Self {
                mesh_id,
                current_removal_authority_epoch,
                minimum_catalogue_revision,
                key,
            })
        }
    }

    /// Advances the local catalogue fence after the corresponding metadata revision is applied.
    ///
    /// # Errors
    ///
    /// Rejects zero or backwards movement. Equal revision replay is idempotent.
    pub const fn advance_minimum_catalogue_revision(
        &mut self,
        revision: Revision,
    ) -> Result<(), FolderShardStoreError> {
        if revision.get() == 0 || revision.get() < self.minimum_catalogue_revision.get() {
            Err(FolderShardStoreError::Stale)
        } else {
            self.minimum_catalogue_revision = revision;
            Ok(())
        }
    }

    fn authenticates_read(&self, permit: ShardReadPermit) -> bool {
        permit.mesh_id == self.mesh_id && verify_read_permit_mac(&self.key, permit)
    }

    fn authenticates_removal(&self, permit: RemovalPermit) -> bool {
        permit.mesh_id == self.mesh_id
            && permit.authority_epoch == self.current_removal_authority_epoch
            && permit.catalogue_revision >= self.minimum_catalogue_revision
            && verify_removal_permit_mac(&self.key, permit)
    }

    const fn removal_authority_fence(&self) -> RemovalAuthorityFence {
        RemovalAuthorityFence {
            authority_epoch: self.current_removal_authority_epoch,
            catalogue_revision: self.minimum_catalogue_revision,
        }
    }
}

impl FolderShardStore {
    /// Returns the exact durable target marker bound to this open provider.
    #[must_use]
    pub const fn target_marker(&self) -> crate::TargetMarker {
        self.folder.marker()
    }

    /// Opens an identity-bound local journal and packed-byte segment for one registered folder.
    ///
    /// # Errors
    ///
    /// Rejects marker/journal/pack mismatch, migration drift, corruption or unavailable entropy.
    pub fn open(
        folder: RegisteredFolder,
        daemon_state_dir: &Path,
        policy: CapacityPolicy,
        permits: StoragePermitVerifier,
        opened_at: UnixMicros,
        random: &mut impl RandomSource,
    ) -> Result<Self, FolderShardStoreError> {
        if permits.mesh_id != folder.marker().mesh_id() {
            return Err(FolderShardStoreError::InvalidInput);
        }
        let journal =
            TargetJournal::open(daemon_state_dir, folder.marker(), policy, opened_at, random)?;
        let pack = PackStore::open(&folder, ACTIVE_PACK_SEQUENCE, opened_at)
            .map_err(|error| map_pack(&error))?;
        Ok(Self {
            folder,
            journal,
            pack,
            permits,
        })
    }

    /// Measures the owned filesystem and persists one exact capacity reservation.
    ///
    /// # Errors
    ///
    /// Rejects stale identity/time, conflicting replay, measurement failure and unsafe capacity.
    pub fn reserve(
        &mut self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, FolderShardStoreError> {
        let observation = self.folder.capacity_observation()?;
        self.journal
            .reserve(ReserveCapacityRequest {
                context: request.context,
                target_id: request.target_id,
                target_generation: request.target_generation,
                class: request.class,
                bytes: request.bytes,
                observation,
                now: request.observed_at,
            })
            .map_err(Into::into)
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

    /// Makes one exact shard unreadable only under a current authenticated removal permit.
    ///
    /// # Errors
    ///
    /// Rejects forged, expired, stale-epoch or target-mismatched authority and conflicting replay.
    /// The journal publishes no tombstone until the pack independently proves it durable.
    pub fn tombstone(
        &mut self,
        permit: RemovalPermit,
        now: UnixMicros,
    ) -> Result<TombstoneReceipt, FolderShardStoreError> {
        validate_removal(permit, self.folder.marker(), now)?;
        if !self.permits.authenticates_removal(permit) {
            return Err(FolderShardStoreError::Unauthorized);
        }
        let request_digest = removal_request_digest(permit);
        let journal_request = JournalTombstoneRequest {
            permit,
            request_digest,
            now,
        };
        if let PrepareTombstoneResult::Committed(receipt) =
            self.journal.prepare_tombstone(journal_request)?
        {
            return Ok(receipt);
        }
        let receipt = self
            .pack
            .tombstone_exact(PackTombstoneRequest {
                permit,
                request_digest,
                now,
            })
            .map_err(|error| map_pack(&error))?;
        self.journal
            .commit_tombstone(journal_request, DurableTombstoneEvidence { receipt })
            .map_err(Into::into)
    }

    /// Reconciles bounded prepared journal removals with durable pack tombstones.
    ///
    /// # Errors
    ///
    /// Rejects malformed bounds/cursors and conflicting or corrupt durable evidence.
    pub fn recover_pending_tombstones(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        now: UnixMicros,
    ) -> Result<TombstoneRecoveryPage, FolderShardStoreError> {
        let PendingTombstonePage {
            tombstones,
            next_cursor,
        } = self.journal.pending_tombstones(cursor, limit)?;
        let mut committed = Vec::with_capacity(tombstones.len());
        let mut awaiting_pack = 0_usize;
        for pending in tombstones.as_slice() {
            match self
                .pack
                .recover_tombstone(pending.permit.operation_id, pending.request_digest)
                .map_err(|error| map_pack(&error))?
            {
                Some(receipt) => committed.push(self.journal.commit_tombstone(
                    JournalTombstoneRequest {
                        permit: pending.permit,
                        request_digest: pending.request_digest,
                        now,
                    },
                    DurableTombstoneEvidence { receipt },
                )?),
                None => awaiting_pack = awaiting_pack.saturating_add(1),
            }
        }
        Ok(TombstoneRecoveryPage {
            committed: BoundedItems::new(committed, limit)
                .map_err(|_| FolderShardStoreError::Corrupt)?,
            awaiting_pack,
            next_cursor,
        })
    }

    /// Physically reclaims bytes only for an exact journal-committed tombstone receipt.
    ///
    /// # Errors
    ///
    /// Rejects foreign, missing, forged or conflicting receipts and unavailable durable IO.
    pub fn unlink_tombstoned(
        &mut self,
        receipt: TombstoneReceipt,
        now: UnixMicros,
    ) -> Result<ReclamationReceipt, FolderShardStoreError> {
        if receipt.target_id != self.folder.marker().target_id()
            || receipt.target_generation != self.folder.marker().generation()
        {
            return Err(FolderShardStoreError::InvalidInput);
        }
        self.journal.verify_committed_tombstone(receipt)?;
        self.pack
            .unlink_tombstoned(receipt, now)
            .map_err(|error| map_pack(&error))?;
        self.journal.commit_unlink(receipt, now).map_err(Into::into)
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

    /// Resolves one exact journal-confirmed shard without scanning other tenant namespaces.
    ///
    /// # Errors
    ///
    /// Rejects malformed identity or unavailable/corrupt journal state.
    pub fn inventory_exact(
        &self,
        shard: meshspan_contracts::ShardIdentity,
    ) -> Result<Option<meshspan_contracts::InventoryEntry>, FolderShardStoreError> {
        self.journal.inventory_entry(shard).map_err(Into::into)
    }

    /// Independently rereads one exact committed shard and returns evidence only.
    ///
    /// # Errors
    ///
    /// Rejects missing or contradictory journal inventory and target-wide IO failure.
    pub fn scrub_exact(
        &mut self,
        expected: meshspan_contracts::InventoryEntry,
        observed_at: UnixMicros,
    ) -> Result<ScrubObservation, FolderShardStoreError> {
        let committed = self
            .journal
            .inventory_entry(expected.shard)?
            .ok_or(FolderShardStoreError::NotFound)?;
        if committed.length != expected.length || committed.digest != expected.digest {
            return Err(FolderShardStoreError::Corrupt);
        }
        self.scrub_committed(committed, observed_at)
    }

    /// Independently reads and verifies one bounded page of complete shard bytes.
    ///
    /// Results are evidence only. No outcome calls or bypasses the authenticated tombstone path.
    ///
    /// # Errors
    ///
    /// Rejects malformed paging and state changes that invalidate a healthy observation.
    pub fn scrub(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        observed_at: UnixMicros,
    ) -> Result<ScrubPage, FolderShardStoreError> {
        let page = self.journal.inventory(cursor, limit)?;
        let mut observations = Vec::with_capacity(page.entries.len());
        for entry in page.entries.as_slice() {
            observations.push(self.scrub_committed(*entry, observed_at)?);
        }
        Ok(ScrubPage {
            observations: BoundedItems::new(observations, limit)
                .map_err(|_| FolderShardStoreError::Corrupt)?,
            next_cursor: page.next_cursor,
        })
    }

    fn scrub_committed(
        &mut self,
        expected: meshspan_contracts::InventoryEntry,
        observed_at: UnixMicros,
    ) -> Result<ScrubObservation, FolderShardStoreError> {
        match self
            .pack
            .scrub_exact(expected.shard, expected.length, expected.digest)
        {
            Ok(PackScrubResult::Missing) => {
                Ok(scrub_observation(expected, None, ScrubOutcome::Missing))
            }
            Ok(PackScrubResult::Present {
                observed_length,
                observed_digest,
                healthy: true,
            }) => {
                self.journal.mark_shard_verified(expected, observed_at)?;
                Ok(scrub_observation(
                    expected,
                    Some((observed_length, observed_digest)),
                    ScrubOutcome::Healthy,
                ))
            }
            Ok(PackScrubResult::Present {
                observed_length,
                observed_digest,
                healthy: false,
            }) => Ok(scrub_observation(
                expected,
                Some((observed_length, observed_digest)),
                ScrubOutcome::Corrupt,
            )),
            Err(PackStoreError::Sqlite(_) | PackStoreError::Folder(_)) => {
                Ok(scrub_observation(expected, None, ScrubOutcome::Unreadable))
            }
            Err(error) => Err(map_pack(&error)),
        }
    }

    /// Runs one bounded page from the durable continuous-scrub checkpoint and advances it.
    ///
    /// # Errors
    ///
    /// Rejects malformed bounds, invalid observations or stale concurrent checkpoint advancement.
    pub fn scrub_continuous(
        &mut self,
        limit: usize,
        observed_at: UnixMicros,
    ) -> Result<ScrubPage, FolderShardStoreError> {
        let checkpoint = self.journal.scrub_checkpoint()?;
        let page = self.scrub(checkpoint.cursor.as_ref(), limit, observed_at)?;
        self.journal.advance_scrub_checkpoint(
            &checkpoint,
            page.next_cursor.as_ref(),
            observed_at,
        )?;
        Ok(page)
    }

    /// Reads and independently verifies one exact shard under a current authenticated permit.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, expired authority, forged or target-mismatched permits, absent
    /// bytes and any persisted length/digest corruption.
    pub fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        now: UnixMicros,
    ) -> Result<BoundedBytes, FolderShardStoreError> {
        validate_read(context, permit, self.folder.marker(), now)?;
        if !self.permits.authenticates_read(permit) {
            return Err(FolderShardStoreError::Unauthorized);
        }
        self.pack
            .get_exact(permit.shard)
            .map_err(|error| map_pack(&error))
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

    /// Returns the current configured physical-byte ceiling for this target filesystem.
    ///
    /// # Errors
    ///
    /// Fails closed when the filesystem cannot be measured or its persisted policy is invalid.
    pub fn capacity_ceiling(&self) -> Result<u64, FolderShardStoreError> {
        let observation = self.folder.capacity_observation()?;
        self.journal
            .capacity_ceiling(observation.total_bytes)
            .map_err(Into::into)
    }
}

impl StorageProvider for FolderShardStore {
    fn describe(&self) -> ImplementationDescriptor {
        ImplementationDescriptor {
            implementation_id: "folder-pack",
            contract: ContractKind::StorageProvider,
            versions: PROVIDER_VERSIONS,
            limits: ContractLimits {
                maximum_control_bytes: MAXIMUM_CONTROL_BYTES,
                maximum_items: MAXIMUM_PAGE_ITEMS,
                maximum_concurrency: 1,
            },
        }
    }

    fn reserve(
        &mut self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError> {
        FolderShardStore::reserve(self, request).map_err(contract_error)
    }

    fn put_exact(
        &mut self,
        request: PutShardRequest,
        observed_at: UnixMicros,
    ) -> Result<ShardReceipt, ContractError> {
        FolderShardStore::put_exact(self, &request, observed_at).map_err(contract_error)
    }

    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: UnixMicros,
    ) -> Result<BoundedBytes, ContractError> {
        FolderShardStore::get_exact(self, context, permit, observed_at).map_err(contract_error)
    }

    fn removal_authority_fence(&self) -> RemovalAuthorityFence {
        self.permits.removal_authority_fence()
    }

    fn tombstone(
        &mut self,
        permit: RemovalPermit,
        observed_at: UnixMicros,
    ) -> Result<TombstoneReceipt, ContractError> {
        FolderShardStore::tombstone(self, permit, observed_at).map_err(contract_error)
    }

    fn unlink_tombstoned(
        &mut self,
        receipt: TombstoneReceipt,
        observed_at: UnixMicros,
    ) -> Result<ReclamationReceipt, ContractError> {
        FolderShardStore::unlink_tombstoned(self, receipt, observed_at).map_err(contract_error)
    }

    fn inventory(
        &self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
    ) -> Result<InventoryPage, ContractError> {
        FolderShardStore::inventory(self, cursor, limit).map_err(contract_error)
    }

    fn inventory_exact(
        &self,
        shard: meshspan_contracts::ShardIdentity,
    ) -> Result<Option<meshspan_contracts::InventoryEntry>, ContractError> {
        FolderShardStore::inventory_exact(self, shard).map_err(contract_error)
    }

    fn scrub_exact(
        &mut self,
        expected: meshspan_contracts::InventoryEntry,
        observed_at: UnixMicros,
    ) -> Result<ScrubObservation, ContractError> {
        FolderShardStore::scrub_exact(self, expected, observed_at).map_err(contract_error)
    }

    fn scrub(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        observed_at: UnixMicros,
    ) -> Result<ScrubPage, ContractError> {
        FolderShardStore::scrub(self, cursor, limit, observed_at).map_err(contract_error)
    }
}

fn contract_error(error: FolderShardStoreError) -> ContractError {
    match error {
        FolderShardStoreError::InvalidInput => ContractError::InvalidInput,
        FolderShardStoreError::Unauthorized => ContractError::Unauthorized,
        FolderShardStoreError::Stale => ContractError::Stale,
        FolderShardStoreError::OperationConflict => ContractError::Conflict,
        FolderShardStoreError::ResourceExhausted => ContractError::ResourceExhausted,
        FolderShardStoreError::NotFound => ContractError::NotFound,
        FolderShardStoreError::Corrupt => ContractError::Corrupt,
        FolderShardStoreError::Unavailable | FolderShardStoreError::Folder(_) => {
            ContractError::Unavailable
        }
        FolderShardStoreError::Journal(error) => journal_contract_error(&error),
    }
}

fn journal_contract_error(error: &TargetJournalError) -> ContractError {
    match error {
        TargetJournalError::InvalidInput => ContractError::InvalidInput,
        TargetJournalError::StalePolicy => ContractError::Stale,
        TargetJournalError::PolicyConflict | TargetJournalError::OperationConflict => {
            ContractError::Conflict
        }
        TargetJournalError::CapacityExhausted => ContractError::ResourceExhausted,
        TargetJournalError::IdentityMismatch
        | TargetJournalError::MigrationMismatch
        | TargetJournalError::CorruptState => ContractError::Corrupt,
        TargetJournalError::UnsupportedSchema => ContractError::UnsupportedVersion,
        TargetJournalError::Entropy(_)
        | TargetJournalError::Io(_)
        | TargetJournalError::Sqlite(_) => ContractError::Unavailable,
    }
}

fn validate_read(
    context: RequestContext,
    permit: ShardReadPermit,
    marker: crate::TargetMarker,
    now: UnixMicros,
) -> Result<(), FolderShardStoreError> {
    if context.contract_version != ContractVersion::V1_0
        || context.operation_id != permit.operation_id
        || context.expected_revision != Some(permit.authorization_revision)
        || context.deadline > permit.expires_at
    {
        return Err(FolderShardStoreError::InvalidInput);
    }
    if context.deadline <= now || permit.expires_at <= now {
        return Err(FolderShardStoreError::Stale);
    }
    if permit.mesh_id != marker.mesh_id()
        || permit.target_id != marker.target_id()
        || permit.target_generation != marker.generation()
    {
        return Err(FolderShardStoreError::Unauthorized);
    }
    Ok(())
}

fn validate_removal(
    permit: RemovalPermit,
    marker: crate::TargetMarker,
    now: UnixMicros,
) -> Result<(), FolderShardStoreError> {
    if permit.authority_epoch == 0 {
        return Err(FolderShardStoreError::InvalidInput);
    }
    if permit.expires_at <= now {
        return Err(FolderShardStoreError::Stale);
    }
    if permit.mesh_id != marker.mesh_id()
        || permit.target_id != marker.target_id()
        || permit.target_generation != marker.generation()
    {
        return Err(FolderShardStoreError::Unauthorized);
    }
    Ok(())
}

fn removal_request_digest(permit: RemovalPermit) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.storage.removal-request.v1");
    digest.update(&permit.permit_digest);
    digest.finalize().into()
}

fn scrub_observation(
    expected: meshspan_contracts::InventoryEntry,
    observed: Option<(u64, [u8; 32])>,
    outcome: ScrubOutcome,
) -> ScrubObservation {
    ScrubObservation {
        shard: expected.shard,
        expected_length: Some(expected.length),
        expected_digest: Some(expected.digest),
        observed_length: observed.map(|value| value.0),
        observed_digest: observed.map(|value| value.1),
        outcome,
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
        PackStoreError::NoSpace => FolderShardStoreError::ResourceExhausted,
        PackStoreError::Corrupt
        | PackStoreError::IdentityMismatch
        | PackStoreError::MigrationMismatch
        | PackStoreError::UnsupportedSchema => FolderShardStoreError::Corrupt,
        PackStoreError::Indeterminate | PackStoreError::Folder(_) | PackStoreError::Sqlite(_) => {
            FolderShardStoreError::Unavailable
        }
    }
}

/// Stable composed-store failures without provider paths, SQL or shard bytes.
#[derive(Debug, Error)]
pub enum FolderShardStoreError {
    /// Request shape, bounds, time, identity or digest is invalid.
    #[error("folder shard request is invalid")]
    InvalidInput,
    /// Caller identity or permit is not authorised for this target and operation.
    #[error("folder shard request is not authorised")]
    Unauthorized,
    /// A deadline or permit is stale.
    #[error("folder shard request authority is stale")]
    Stale,
    /// One operation/shard identity was reused with different immutable input.
    #[error("folder shard operation conflicts with prior input")]
    OperationConflict,
    /// Exact requested provider bytes do not exist.
    #[error("folder shard was not found")]
    NotFound,
    /// Target-local physical or configured capacity rejects this operation.
    #[error("folder shard target capacity is exhausted")]
    ResourceExhausted,
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
        ReserveStorageRequest, ScrubOutcome, ShardIdentity, ShardReadPermit, StoragePermitMacKey,
        read_permit_mac,
    };
    use meshspan_domain::{
        EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
    };
    use tempfile::tempdir;

    use super::{FolderShardStore, StoragePermitVerifier, put_request_digest};
    use crate::journal::{JournalPutRequest, PreparePutResult};
    use crate::pack::PackPutRequest;
    use crate::{CapacityPolicy, FolderRegistration, RegisteredFolder, UsageLimit};

    struct FixedRandom;

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(9);
            Ok(())
        }
    }

    fn permit_verifier(
        mesh_id: MeshId,
    ) -> Result<StoragePermitVerifier, Box<dyn std::error::Error>> {
        Ok(StoragePermitVerifier::new(
            mesh_id,
            7,
            Revision::new(1),
            StoragePermitMacKey::from_bytes([42; 32])?,
        )?)
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
        let reservation = store.reserve(ReserveStorageRequest {
            context,
            target_id: registration.target_id,
            target_generation: registration.generation,
            class: ReservationClass::ForegroundWrite,
            bytes: u64::try_from(payload.len())?,
            observed_at: now,
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
        let mut store = FolderShardStore::open(
            folder,
            &state_path,
            policy,
            permit_verifier(registration.mesh_id)?,
            UnixMicros::new(1),
            &mut random,
        )?;
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
        let scrub = store.scrub_continuous(10, UnixMicros::new(22))?;
        assert_eq!(scrub.observations.len(), 1);
        assert_eq!(
            scrub.observations.as_slice()[0].outcome,
            ScrubOutcome::Healthy
        );
        assert!(store.inventory(None, 10)?.entries.as_slice()[0].bytes_verified);
        assert_eq!(store.journal.scrub_checkpoint()?.completed_cycles, 1);
        let read_context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([21; 16])?,
            deadline: UnixMicros::new(200),
            expected_revision: Some(Revision::new(22)),
        };
        let mut permit = ShardReadPermit {
            operation_id: read_context.operation_id,
            mesh_id: registration.mesh_id,
            target_id: registration.target_id,
            target_generation: registration.generation,
            shard: request.shard,
            authorization_revision: Revision::new(22),
            expires_at: UnixMicros::new(250),
            permit_digest: [0; 32],
        };
        let signing_key = StoragePermitMacKey::from_bytes([42; 32])?;
        permit.permit_digest = read_permit_mac(&signing_key, permit);
        assert_eq!(
            store.get_exact(read_context, permit, UnixMicros::new(30))?,
            request.bytes
        );
        let mut forged = permit;
        forged.permit_digest[0] ^= 1;
        assert!(matches!(
            store.get_exact(read_context, forged, UnixMicros::new(30)),
            Err(super::FolderShardStoreError::Unauthorized)
        ));
        store.check_health()?;
        drop(store);

        let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
        let mut store = FolderShardStore::open(
            folder,
            &state_path,
            policy,
            permit_verifier(registration.mesh_id)?,
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
        let mut store = FolderShardStore::open(
            folder,
            &state_path,
            policy,
            permit_verifier(registration.mesh_id)?,
            UnixMicros::new(1),
            &mut random,
        )?;
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
            permit_verifier(registration.mesh_id)?,
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

#[cfg(test)]
mod removal_tests;

#[cfg(test)]
mod conformance_tests;

#[cfg(test)]
mod fault_tests;
