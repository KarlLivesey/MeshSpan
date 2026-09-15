// SPDX-License-Identifier: GPL-2.0-only

//! Exact provider write identity, retained independently of byte buffers and renewed authority.

use crate::{PutShardRequest, RequestContext, ShardIdentity, ShardReceipt, StorageReservation};

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
