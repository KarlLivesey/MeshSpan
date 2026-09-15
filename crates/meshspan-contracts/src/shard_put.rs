// SPDX-License-Identifier: GPL-2.0-only

//! Exact provider write identity, retained independently of byte buffers and renewed authority.

use crate::{
    ContractError, ContractVersion, PutShardRequest, RequestContext, ReservationClass,
    ShardIdentity, ShardReceipt, StorageReservation,
};
use meshspan_domain::TargetId;

/// Complete physical intent selected before requesting provider capacity or sending bytes.
/// Unlike an admission, this contains no provider reservation or durability claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardPutIntent {
    /// Original operation, deadline and revision; fresh authority is passed separately on resume.
    pub context: RequestContext,
    /// Selected destination, unchanged when another worker takes over.
    pub target_id: TargetId,
    /// Exact destination incarnation.
    pub target_generation: u64,
    /// Capacity class chosen by the authoritative plan.
    pub reservation_class: ReservationClass,
    /// Original capacity bound.
    pub maximum_bytes: u64,
    /// Exact immutable provider shard identity.
    pub shard: ShardIdentity,
    /// Exact payload length.
    pub expected_length: u64,
    /// Exact payload digest.
    pub expected_digest: [u8; 32],
}

impl ShardPutIntent {
    /// Binds the selected intent to the actual original provider reservation.
    /// # Errors
    /// Rejects substituted destinations, operations, capacity, class, expiry or empty evidence.
    pub fn admitted(
        self,
        reservation: StorageReservation,
    ) -> Result<ShardPutIdentity, ContractError> {
        self.validate()?;
        if reservation.operation_id != self.context.operation_id
            || reservation.target_id != self.target_id
            || reservation.target_generation != self.target_generation
            || reservation.class != self.reservation_class
            || reservation.maximum_bytes != self.maximum_bytes
            || reservation.expires_at < self.context.deadline
            || reservation.reservation_digest == [0; 32]
        {
            return Err(ContractError::InvalidInput);
        }
        Ok(ShardPutIdentity {
            context: self.context,
            reservation,
            shard: self.shard,
            expected_length: self.expected_length,
            expected_digest: self.expected_digest,
        })
    }
}

impl ShardPutIntent {
    /// Validates selected identity and capacity without asserting authority or durable bytes.
    /// # Errors
    /// Rejects unsupported versions, empty identities, invalid deadlines and capacity bounds.
    pub fn validate(self) -> Result<(), ContractError> {
        if self.context.contract_version != ContractVersion::V1_0
            || self.context.deadline.get() <= 0
            || self.target_generation == 0
            || self.shard.manifest_digest == [0; 32]
            || self.shard.generation == 0
            || self.expected_length == 0
            || self.expected_length > self.maximum_bytes
            || self.expected_digest == [0; 32]
        {
            Err(ContractError::InvalidInput)
        } else {
            Ok(())
        }
    }
}

/// Immutable original admission needed to resolve an uncertain provider write.
/// Renewed authority must not replace the original context or reservation in this record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardPutIdentity {
    /// Original operation, deadline and authority revision.
    pub context: RequestContext,
    /// Actual reservation returned by the destination provider.
    pub reservation: StorageReservation,
    /// Exact provider shard identity, including any federation tenant translation.
    pub shard: ShardIdentity,
    /// Exact original byte length.
    pub expected_length: u64,
    /// Exact original byte digest.
    pub expected_digest: [u8; 32],
}

impl PutShardRequest {
    /// Retains the complete canonical write identity without copying its bytes.
    #[must_use]
    pub const fn identity(&self) -> ShardPutIdentity {
        ShardPutIdentity {
            context: self.context,
            reservation: self.reservation,
            shard: self.shard,
            expected_length: self.expected_length,
            expected_digest: self.expected_digest,
        }
    }
}

impl ShardPutIdentity {
    /// Recovers the selected physical intent without the provider's reservation evidence.
    #[must_use]
    pub const fn intent(self) -> ShardPutIntent {
        ShardPutIntent {
            context: self.context,
            target_id: self.reservation.target_id,
            target_generation: self.reservation.target_generation,
            reservation_class: self.reservation.class,
            maximum_bytes: self.reservation.maximum_bytes,
            shard: self.shard,
            expected_length: self.expected_length,
            expected_digest: self.expected_digest,
        }
    }

    /// Computes the existing version-one provider request digest, unchanged on replay.
    /// This identifies a request; it does not authenticate it or prove durable bytes.
    #[must_use]
    pub fn request_digest(self) -> [u8; 32] {
        let mut digest = blake3::Hasher::new();
        digest.update(b"meshspan.storage.put-request.v1");
        digest.update(&self.context.operation_id.as_bytes());
        digest.update(&self.context.deadline.get().to_be_bytes());
        match self.context.expected_revision {
            Some(revision) => {
                digest.update(&[1]);
                digest.update(&revision.get().to_be_bytes());
            }
            None => {
                digest.update(&[0]);
            }
        }
        digest.update(&self.reservation.reservation_digest);
        digest.update(&self.shard.manifest_digest);
        digest.update(&self.shard.stripe_index.to_be_bytes());
        digest.update(&self.shard.shard_index.to_be_bytes());
        digest.update(&self.shard.generation.to_be_bytes());
        digest.update(&self.expected_length.to_be_bytes());
        digest.update(&self.expected_digest);
        digest.finalize().into()
    }
}

/// Exact current provider evidence, never permission to start a different physical attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShardPutResolution {
    /// No matching provider journal operation is retained; the outcome is unknown.
    Unknown,
    /// The exact operation is prepared but its complete bytes are not proved durable.
    Prepared,
    /// The journal is committed and the original operation's bytes were independently verified.
    Verified(ShardReceipt),
}

/// Freshly authorised repair admission, with no unknown state or implicit permission to reselect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairPutAdmission {
    /// The original identity is durably prepared; its exact bytes can be resumed.
    Prepared(ShardPutIdentity),
    /// The exact original write is already committed and its current bytes were verified.
    Verified(ShardReceipt),
}
