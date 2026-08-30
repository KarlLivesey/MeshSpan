// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable storage-provider capability contract.

use meshspan_domain::{MeshId, OperationId, Revision, TargetId, UnixMicros};

use crate::{BoundedBytes, BoundedItems, ContractError, ImplementationDescriptor, RequestContext};

const READ_PERMIT_DOMAIN: &[u8] = b"meshspan.storage.read-permit.v1";
const REMOVAL_PERMIT_DOMAIN: &[u8] = b"meshspan.storage.removal-permit.v1";
const RECLAMATION_RECEIPT_DOMAIN: &[u8] = b"meshspan.storage.reclamation-receipt.v1";
const TOMBSTONE_RECEIPT_DOMAIN: &[u8] = b"meshspan.storage.tombstone-receipt.v1";
const WRITE_PERMIT_DOMAIN: &[u8] = b"meshspan.storage.write-permit.v1";

/// Secret 256-bit key used to authenticate short-lived storage permits.
///
/// This type deliberately omits `Clone`, `Copy` and `Debug`. It is capability material, not a
/// serialisable contract field or a value that may be logged.
pub struct StoragePermitMacKey([u8; 32]);

impl StoragePermitMacKey {
    /// Accepts exact key bytes obtained from the mesh secret-distribution boundary.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero sentinel, which is never valid key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ContractError> {
        if bytes == [0; 32] {
            Err(ContractError::InvalidInput)
        } else {
            Ok(Self(bytes))
        }
    }
}

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

/// Exact short-lived authority to reserve and write one immutable shard generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardWritePermit {
    /// Mutation identity whose exact retries share one authority decision.
    pub operation_id: OperationId,
    /// Mesh whose authority issued the permit.
    pub mesh_id: MeshId,
    /// Exact storage target on which the permit is valid.
    pub target_id: TargetId,
    /// Exact target incarnation/generation on which the permit is valid.
    pub target_generation: u64,
    /// Exact immutable shard generation authorised for writing.
    pub shard: ShardIdentity,
    /// Capacity budget class authorised for this write.
    pub reservation_class: ReservationClass,
    /// Exact maximum bytes this operation may make durable.
    pub maximum_bytes: u64,
    /// Authoritative metadata revision that granted the write.
    pub authorization_revision: Revision,
    /// Exclusive expiry.
    pub expires_at: UnixMicros,
    /// Domain-separated keyed BLAKE3 MAC binding every permit field and issuing authority.
    pub permit_digest: [u8; 32],
}

/// Complete bounded request for target-local capacity authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReserveStorageRequest {
    /// Version, operation, deadline and optional authority revision.
    pub context: RequestContext,
    /// Exact storage target.
    pub target_id: TargetId,
    /// Exact target incarnation/generation.
    pub target_generation: u64,
    /// Independent capacity budget being requested.
    pub class: ReservationClass,
    /// Maximum bytes the operation may make durable.
    pub bytes: u64,
    /// Current authoritative instant; filesystem capacity is measured by the provider itself.
    pub observed_at: UnixMicros,
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
    /// Domain-separated keyed BLAKE3 MAC binding every permit field and issuing authority.
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
    /// Domain-separated keyed BLAKE3 MAC binding authority, identity, generation and expiry.
    pub permit_digest: [u8; 32],
}

/// Provider-local fence values required when translating an authorised cleanup decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemovalAuthorityFence {
    /// Current provider-local cleanup authority epoch.
    pub authority_epoch: u64,
    /// Minimum storage catalogue revision already applied by the provider.
    pub catalogue_revision: Revision,
}

/// Calculates the canonical keyed MAC for one exact read permit.
///
/// The existing `permit_digest` field is excluded and may contain any value; callers replace it
/// with the returned MAC before transmission.
#[must_use]
pub fn read_permit_mac(key: &StoragePermitMacKey, permit: ShardReadPermit) -> [u8; 32] {
    let mut mac = blake3::Hasher::new_keyed(&key.0);
    mac.update(READ_PERMIT_DOMAIN);
    mac.update(&permit.operation_id.as_bytes());
    mac.update(&permit.mesh_id.as_bytes());
    mac.update(&permit.target_id.as_bytes());
    mac.update(&permit.target_generation.to_be_bytes());
    encode_shard_for_mac(&mut mac, permit.shard);
    mac.update(&permit.authorization_revision.get().to_be_bytes());
    mac.update(&permit.expires_at.get().to_be_bytes());
    mac.finalize().into()
}

/// Verifies one read permit MAC in constant time.
#[must_use]
pub fn verify_read_permit_mac(key: &StoragePermitMacKey, permit: ShardReadPermit) -> bool {
    blake3::Hash::from_bytes(read_permit_mac(key, permit))
        == blake3::Hash::from_bytes(permit.permit_digest)
}

/// Calculates the canonical keyed MAC for one exact write permit.
///
/// The existing `permit_digest` field is excluded and may contain any value; callers replace it
/// with the returned MAC before transmission.
#[must_use]
pub fn write_permit_mac(key: &StoragePermitMacKey, permit: ShardWritePermit) -> [u8; 32] {
    let mut mac = blake3::Hasher::new_keyed(&key.0);
    mac.update(WRITE_PERMIT_DOMAIN);
    mac.update(&permit.operation_id.as_bytes());
    mac.update(&permit.mesh_id.as_bytes());
    mac.update(&permit.target_id.as_bytes());
    mac.update(&permit.target_generation.to_be_bytes());
    encode_shard_for_mac(&mut mac, permit.shard);
    mac.update(&[reservation_class_code(permit.reservation_class)]);
    mac.update(&permit.maximum_bytes.to_be_bytes());
    mac.update(&permit.authorization_revision.get().to_be_bytes());
    mac.update(&permit.expires_at.get().to_be_bytes());
    mac.finalize().into()
}

/// Verifies one write permit MAC in constant time.
#[must_use]
pub fn verify_write_permit_mac(key: &StoragePermitMacKey, permit: ShardWritePermit) -> bool {
    blake3::Hash::from_bytes(write_permit_mac(key, permit))
        == blake3::Hash::from_bytes(permit.permit_digest)
}

/// Calculates the canonical keyed MAC for one exact removal permit.
#[must_use]
pub fn removal_permit_mac(key: &StoragePermitMacKey, permit: RemovalPermit) -> [u8; 32] {
    let mut mac = blake3::Hasher::new_keyed(&key.0);
    mac.update(REMOVAL_PERMIT_DOMAIN);
    mac.update(&permit.operation_id.as_bytes());
    mac.update(&permit.mesh_id.as_bytes());
    mac.update(&permit.target_id.as_bytes());
    mac.update(&permit.target_generation.to_be_bytes());
    encode_shard_for_mac(&mut mac, permit.shard);
    mac.update(&permit.authority_epoch.to_be_bytes());
    mac.update(&permit.catalogue_revision.get().to_be_bytes());
    mac.update(&permit.expires_at.get().to_be_bytes());
    mac.finalize().into()
}

/// Verifies one removal permit MAC in constant time.
#[must_use]
pub fn verify_removal_permit_mac(key: &StoragePermitMacKey, permit: RemovalPermit) -> bool {
    blake3::Hash::from_bytes(removal_permit_mac(key, permit))
        == blake3::Hash::from_bytes(permit.permit_digest)
}

/// Calculates the canonical digest of the durable provider tombstone for one exact permit.
///
/// This is an integrity binding, not an authentication MAC. The provider connection and permit
/// are authenticated separately; authoritative completion must also match a committed permit.
#[must_use]
pub fn tombstone_receipt_digest(permit: RemovalPermit) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(TOMBSTONE_RECEIPT_DOMAIN);
    digest.update(&permit.operation_id.as_bytes());
    encode_shard_for_mac(&mut digest, permit.shard);
    digest.update(&permit.target_id.as_bytes());
    digest.update(&permit.target_generation.to_be_bytes());
    digest.update(&permit.permit_digest);
    digest.finalize().into()
}

/// Calculates the canonical digest of one exact physical-unlink acknowledgement.
#[must_use]
pub fn reclamation_receipt_digest(
    tombstone: TombstoneReceipt,
    bytes_unlinked_at: UnixMicros,
    reclaimed_bytes: u64,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(RECLAMATION_RECEIPT_DOMAIN);
    digest.update(&tombstone.operation_id.as_bytes());
    encode_shard_for_mac(&mut digest, tombstone.shard);
    digest.update(&tombstone.target_id.as_bytes());
    digest.update(&tombstone.target_generation.to_be_bytes());
    digest.update(&tombstone.permit_digest);
    digest.update(&tombstone.tombstone_digest);
    digest.update(&bytes_unlinked_at.get().to_be_bytes());
    digest.update(&reclaimed_bytes.to_be_bytes());
    digest.finalize().into()
}

fn encode_shard_for_mac(mac: &mut blake3::Hasher, shard: ShardIdentity) {
    mac.update(&shard.manifest_digest);
    mac.update(&shard.stripe_index.to_be_bytes());
    mac.update(&shard.shard_index.to_be_bytes());
    mac.update(&shard.generation.to_be_bytes());
}

const fn reservation_class_code(class: ReservationClass) -> u8 {
    match class {
        ReservationClass::ForegroundWrite => 1,
        ReservationClass::Repair => 2,
        ReservationClass::Relocation => 3,
    }
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

/// Durable proof that one exact tombstoned shard's physical bytes were unlinked and accounted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReclamationReceipt {
    /// Exact earlier durable tombstone.
    pub tombstone: TombstoneReceipt,
    /// Original provider-journal instant at which unlink accounting committed.
    pub bytes_unlinked_at: UnixMicros,
    /// Exact physical byte count released from committed capacity.
    pub reclaimed_bytes: u64,
    /// Canonical digest binding the tombstone, instant and released byte count.
    pub reclamation_digest: [u8; 32],
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

/// Typed result of independently checking one complete provider shard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrubOutcome {
    /// Exact bytes, length, digest and identity match committed inventory.
    Healthy,
    /// Committed inventory names bytes that are not locally present.
    Missing,
    /// Present bytes or protected framing do not match committed integrity data.
    Corrupt,
    /// Local IO could not produce a trustworthy observation.
    Unreadable,
    /// Bytes exist locally without a corresponding committed inventory entry.
    Unexpected,
    /// Verification was deliberately postponed by a bounded local-resource decision.
    Deferred,
}

/// Evidence-only result for one scrubbed shard; it never grants cleanup authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrubObservation {
    /// Exact shard identity inspected or discovered.
    pub shard: ShardIdentity,
    /// Length committed in provider inventory, when one exists.
    pub expected_length: Option<u64>,
    /// Digest committed in provider inventory, when one exists.
    pub expected_digest: Option<[u8; 32]>,
    /// Length calculated from bytes that could be read.
    pub observed_length: Option<u64>,
    /// BLAKE3 digest calculated from bytes that could be read.
    pub observed_digest: Option<[u8; 32]>,
    /// Closed evidence classification.
    pub outcome: ScrubOutcome,
}

/// Stable bounded page of scrub evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScrubPage {
    /// Evidence records in stable provider-inventory order.
    pub observations: BoundedItems<ScrubObservation>,
    /// Opaque continuation cursor, or `None` when this pass reached the end.
    pub next_cursor: Option<BoundedBytes>,
}

/// Byte storage beneath one registered target, without namespace or ACL knowledge.
pub trait StorageProvider {
    /// Describes the compiled provider implementation and explicit bounds.
    fn describe(&self) -> ImplementationDescriptor;

    /// Reserves capacity for one exact operation without publishing a shard.
    ///
    /// # Errors
    ///
    /// Returns a stable rejection without consuming unbounded claimed capacity.
    fn reserve(
        &mut self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError>;

    /// Persists exactly the declared bytes or publishes no shard.
    ///
    /// # Errors
    ///
    /// Rejects stale reservations, wrong lengths/digests, conflicting replay and IO failure.
    fn put_exact(
        &mut self,
        request: PutShardRequest,
        observed_at: UnixMicros,
    ) -> Result<ShardReceipt, ContractError>;

    /// Reads and verifies one exact shard after validating the authority capability.
    ///
    /// # Errors
    ///
    /// Rejects unauthorised, stale, missing, corrupt or excessive reads.
    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: UnixMicros,
    ) -> Result<BoundedBytes, ContractError>;

    /// Returns the provider-local fence required by a freshly translated removal permit.
    fn removal_authority_fence(&self) -> RemovalAuthorityFence;

    /// Records an irreversible tombstone before physical unlink is permitted.
    ///
    /// # Errors
    ///
    /// Rejects every permit not bound to this exact target and shard generation.
    fn tombstone(
        &mut self,
        permit: RemovalPermit,
        observed_at: UnixMicros,
    ) -> Result<TombstoneReceipt, ContractError>;

    /// Physically unlinks only a previously durable tombstone.
    ///
    /// # Errors
    ///
    /// Rejects missing, stale or mismatched tombstone receipts.
    fn unlink_tombstoned(
        &mut self,
        receipt: TombstoneReceipt,
        observed_at: UnixMicros,
    ) -> Result<ReclamationReceipt, ContractError>;

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

    /// Independently verifies one bounded page of complete shard bytes.
    ///
    /// Scrub results are observations only and can never be used as removal authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursors/bounds or target-wide failure that prevents trustworthy paging.
    fn scrub(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        observed_at: UnixMicros,
    ) -> Result<ScrubPage, ContractError>;
}

#[cfg(test)]
mod permit_tests {
    use meshspan_domain::{MeshId, OperationId, Revision, TargetId, UnixMicros};

    use super::{
        RemovalPermit, ReservationClass, ShardIdentity, ShardReadPermit, ShardWritePermit,
        StoragePermitMacKey, read_permit_mac, removal_permit_mac, verify_read_permit_mac,
        verify_removal_permit_mac, verify_write_permit_mac, write_permit_mac,
    };

    #[test]
    fn read_mac_binds_every_identity_and_rejects_forgery() -> Result<(), Box<dyn std::error::Error>>
    {
        let key = StoragePermitMacKey::from_bytes([1; 32])?;
        let mut permit = read_permit()?;
        permit.permit_digest = read_permit_mac(&key, permit);
        assert!(verify_read_permit_mac(&key, permit));

        let mut wrong_target_generation = permit;
        wrong_target_generation.target_generation += 1;
        assert!(!verify_read_permit_mac(&key, wrong_target_generation));
        let mut wrong_shard = permit;
        wrong_shard.shard.generation += 1;
        assert!(!verify_read_permit_mac(&key, wrong_shard));
        let mut forged = permit;
        forged.permit_digest[0] ^= 1;
        assert!(!verify_read_permit_mac(&key, forged));
        Ok(())
    }

    #[test]
    fn removal_mac_binds_epoch_revision_and_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let key = StoragePermitMacKey::from_bytes([2; 32])?;
        let read = read_permit()?;
        let mut permit = RemovalPermit {
            operation_id: read.operation_id,
            mesh_id: read.mesh_id,
            target_id: read.target_id,
            shard: read.shard,
            target_generation: read.target_generation,
            authority_epoch: 9,
            catalogue_revision: Revision::new(10),
            expires_at: UnixMicros::new(11),
            permit_digest: [0; 32],
        };
        permit.permit_digest = removal_permit_mac(&key, permit);
        assert!(verify_removal_permit_mac(&key, permit));

        let mut stale_epoch = permit;
        stale_epoch.authority_epoch += 1;
        assert!(!verify_removal_permit_mac(&key, stale_epoch));
        let mut changed_revision = permit;
        changed_revision.catalogue_revision = Revision::new(12);
        assert!(!verify_removal_permit_mac(&key, changed_revision));
        let mut extended = permit;
        extended.expires_at = UnixMicros::new(12);
        assert!(!verify_removal_permit_mac(&key, extended));
        assert!(StoragePermitMacKey::from_bytes([0; 32]).is_err());
        Ok(())
    }

    #[test]
    fn write_mac_binds_capacity_class_and_length() -> Result<(), Box<dyn std::error::Error>> {
        let key = StoragePermitMacKey::from_bytes([8; 32])?;
        let read = read_permit()?;
        let mut permit = ShardWritePermit {
            operation_id: read.operation_id,
            mesh_id: read.mesh_id,
            target_id: read.target_id,
            target_generation: read.target_generation,
            shard: read.shard,
            reservation_class: ReservationClass::Repair,
            maximum_bytes: 13,
            authorization_revision: read.authorization_revision,
            expires_at: read.expires_at,
            permit_digest: [0; 32],
        };
        permit.permit_digest = write_permit_mac(&key, permit);
        assert!(verify_write_permit_mac(&key, permit));
        assert!(!verify_write_permit_mac(
            &key,
            ShardWritePermit {
                reservation_class: ReservationClass::Relocation,
                ..permit
            }
        ));
        assert!(!verify_write_permit_mac(
            &key,
            ShardWritePermit {
                maximum_bytes: 14,
                ..permit
            }
        ));
        Ok(())
    }

    fn read_permit() -> Result<ShardReadPermit, Box<dyn std::error::Error>> {
        Ok(ShardReadPermit {
            operation_id: OperationId::from_bytes([3; 16])?,
            mesh_id: MeshId::from_bytes([4; 16])?,
            target_id: TargetId::from_bytes([5; 16])?,
            target_generation: 6,
            shard: ShardIdentity {
                manifest_digest: [7; 32],
                stripe_index: 8,
                shard_index: 9,
                generation: 10,
            },
            authorization_revision: Revision::new(11),
            expires_at: UnixMicros::new(12),
            permit_digest: [0; 32],
        })
    }
}
