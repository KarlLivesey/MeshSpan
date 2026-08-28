// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable storage-provider capability contract.

use meshspan_domain::{MeshId, OperationId, Revision, TargetId, UnixMicros};

use crate::{BoundedBytes, BoundedItems, ComponentLifecycle, ContractError, RequestContext};

/// Immutable identity of one erasure-coded or replicated shard generation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ShardIdentity {
    /// Digest of the immutable manifest that owns the shard.
    pub manifest_digest: [u8; 32],
    /// Stripe position within the manifest.
    pub stripe_index: u64,
    /// Shard index within the recorded coding layout.
    pub shard_index: u16,
    /// Replacement generation fenced by authoritative metadata.
    pub generation: u32,
}

/// Capacity budget whose use is visible and governed independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationClass {
    /// New user-visible data; must preserve configured repair headroom.
    ForegroundWrite,
    /// Work restoring required recoverability; may consume repair headroom.
    Repair,
    /// Copy-on-write movement or drain work; may consume repair headroom.
    Relocation,
}

/// Bounded capacity held for one exact operation on one target generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageReservation {
    /// Mutation identity that owns the reservation.
    pub operation_id: OperationId,
    /// Exact storage target.
    pub target_id: TargetId,
    /// Target incarnation/generation that admitted the reservation.
    pub target_generation: u64,
    /// Capacity budget against which this reservation was admitted.
    pub class: ReservationClass,
    /// Maximum bytes that may become durable.
    pub maximum_bytes: u64,
    /// Exclusive expiry.
    pub expires_at: UnixMicros,
    /// Digest binding the complete reservation fields and authority.
    pub reservation_digest: [u8; 32],
}

/// Complete exact-write request presented to a provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PutShardRequest {
    /// Common version, operation, deadline and revision context.
    pub context: RequestContext,
    /// Authority-issued local reservation.
    pub reservation: StorageReservation,
    /// Exact immutable shard identity.
    pub shard: ShardIdentity,
    /// Declared final byte length.
    pub expected_length: u64,
    /// Declared final digest verified incrementally and after persistence.
    pub expected_digest: [u8; 32],
    /// Bounded bytes for the first non-streaming conformance profile.
    pub bytes: BoundedBytes,
}

/// Durable provider evidence for one exact shard generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardReceipt {
    /// Mutation identity whose result may be replayed.
    pub operation_id: OperationId,
    /// Exact persisted shard identity.
    pub shard: ShardIdentity,
    /// Exact persisted length.
    pub length: u64,
    /// Digest independently calculated from persisted bytes.
    pub digest: [u8; 32],
    /// Target on which bytes became durable.
    pub target_id: TargetId,
    /// Target generation that owns the bytes.
    pub target_generation: u64,
}

/// Exact short-lived authority to read one immutable shard from one target generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardReadPermit {
    /// Read operation identity whose retries share one authority decision.
    pub operation_id: OperationId,
    /// Mesh whose authority issued the permit.
    pub mesh_id: MeshId,
    /// Exact storage target on which the permit is valid.
    pub target_id: TargetId,
    /// Exact target generation on which the permit is valid.
    pub target_generation: u64,
    /// Exact immutable shard generation authorised for reading.
    pub shard: ShardIdentity,
    /// Authorisation state revision against which the read was admitted.
    pub authorization_revision: Revision,
    /// Exclusive expiry.
    pub expires_at: UnixMicros,
    /// Digest or signature binding every permit field and its issuing authority.
    pub permit_digest: [u8; 32],
}

/// Authority-derived permission to make one exact shard generation unreachable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemovalPermit {
    /// Cleanup operation identity.
    pub operation_id: OperationId,
    /// Mesh whose current metadata authority issued the cleanup decision.
    pub mesh_id: MeshId,
    /// Exact target on which removal is authorised.
    pub target_id: TargetId,
    /// Exact shard generation authorised for removal.
    pub shard: ShardIdentity,
    /// Exact target generation authorised for removal.
    pub target_generation: u64,
    /// Current authority epoch that fences prior cleanup issuers.
    pub authority_epoch: u64,
    /// Exact catalogue revision at which reachability was revalidated.
    pub catalogue_revision: Revision,
    /// Exclusive expiry.
    pub expires_at: UnixMicros,
    /// Digest binding authority, identity, generation and expiry.
    pub permit_digest: [u8; 32],
}

/// Durable proof that one exact removal permit became irreversible locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TombstoneReceipt {
    /// Cleanup operation identity whose replay returns this exact receipt.
    pub operation_id: OperationId,
    /// Exact shard generation made ineligible for reads.
    pub shard: ShardIdentity,
    /// Exact target holding the durable tombstone.
    pub target_id: TargetId,
    /// Target generation fenced by the tombstone.
    pub target_generation: u64,
    /// Digest of the exact authority permit accepted by the provider.
    pub permit_digest: [u8; 32],
    /// Digest binding the durable provider tombstone and its identity.
    pub tombstone_digest: [u8; 32],
}

/// One bounded provider inventory result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryEntry {
    /// Exact locally present shard generation.
    pub shard: ShardIdentity,
    /// Observed byte length.
    pub length: u64,
    /// Digest revalidated or read from the provider's protected catalogue.
    pub digest: [u8; 32],
    /// Whether a current scrub verified the actual bytes.
    pub bytes_verified: bool,
}

/// Stable bounded page of local inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryPage {
    /// Entries in provider-defined stable cursor order.
    pub entries: BoundedItems<InventoryEntry>,
    /// Opaque bounded continuation cursor, or `None` at the end.
    pub next_cursor: Option<BoundedBytes>,
}

/// Byte storage beneath one registered target, without namespace or ACL knowledge.
pub trait StorageProvider: ComponentLifecycle {
    /// Reserves capacity for one exact operation without publishing a shard.
    ///
    /// # Errors
    ///
    /// Returns a stable rejection without consuming unbounded claimed capacity.
    fn reserve(
        &mut self,
        context: RequestContext,
        target_id: TargetId,
        target_generation: u64,
        class: ReservationClass,
        bytes: u64,
    ) -> Result<StorageReservation, ContractError>;

    /// Persists exactly the declared bytes or publishes no shard.
    ///
    /// # Errors
    ///
    /// Rejects stale reservations, wrong lengths/digests, conflicting replay and IO failure.
    fn put_exact(&mut self, request: PutShardRequest) -> Result<ShardReceipt, ContractError>;

    /// Reads and verifies one exact shard after validating the authority capability.
    ///
    /// # Errors
    ///
    /// Rejects unauthorised, stale, missing, corrupt or excessive reads.
    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
    ) -> Result<BoundedBytes, ContractError>;

    /// Records an irreversible tombstone before physical unlink is permitted.
    ///
    /// # Errors
    ///
    /// Rejects every permit not bound to this exact target and shard generation.
    fn tombstone(&mut self, permit: RemovalPermit) -> Result<TombstoneReceipt, ContractError>;

    /// Physically unlinks only a previously durable tombstone.
    ///
    /// # Errors
    ///
    /// Rejects missing, stale or mismatched tombstone receipts.
    fn unlink_tombstoned(&mut self, receipt: TombstoneReceipt) -> Result<(), ContractError>;

    /// Returns one stable bounded inventory page.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursors, zero/excessive limits or unavailable provider state.
    fn inventory(
        &self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
    ) -> Result<InventoryPage, ContractError>;
}
