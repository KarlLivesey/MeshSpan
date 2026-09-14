// SPDX-License-Identifier: GPL-2.0-only

//! Signed node restoration claims; neither membership nor live protection authority.

use crate::{PreparedRecoveryTarget, RepositoryError as Error, recovery_target::take};
use meshspan_domain::TargetId;

const MAGIC: &[u8] = b"MeshSpan recovery target restoration v1\0";

/// Complete node claim binding a source target's retained slices to its prepared destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryShardRestoration {
    /// Independently selected and node-probed replacement target.
    pub target: PreparedRecoveryTarget,
    /// Original target from authenticated archived metadata.
    pub source_target_id: TargetId,
    /// Exact original target incarnation.
    pub source_generation: u64,
    /// SHA-256 of the complete version-one framed receipt stream.
    pub receipts_digest: [u8; 32],
    /// Receipt references in retained-tree order; shared references may repeat.
    pub receipt_count: u64,
    /// Sum of encrypted lengths across receipt references, not physical capacity accounting.
    pub encrypted_bytes: u64,
}

impl RecoveryShardRestoration {
    /// Reconstructs the exact version-one signing message emitted by the node.
    /// # Errors
    /// Rejects invalid target/source identity, generation, digest or inconsistent counters.
    pub fn installation_message(&self) -> Result<Vec<u8>, Error> {
        if self.source_target_id == self.target.target_id
            || self.source_generation == 0
            || self.source_generation > i64::MAX.unsigned_abs()
            || self.receipts_digest == [0; 32]
            || self.receipt_count > i64::MAX.unsigned_abs()
            || (self.receipt_count == 0) != (self.encrypted_bytes == 0)
            || self.encrypted_bytes < self.receipt_count
        {
            return Err(Error::InvalidCommand);
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&self.target.installation_message()?);
        bytes.extend_from_slice(&self.source_target_id.as_bytes());
        bytes.extend_from_slice(&self.source_generation.to_be_bytes());
        bytes.extend_from_slice(&self.receipts_digest);
        bytes.extend_from_slice(&self.receipt_count.to_be_bytes());
        bytes.extend_from_slice(&self.encrypted_bytes.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes a closed bounded message and validates the embedded original root authorisation.
    /// A caller must still verify the selected node's signature and archive/receipt completeness.
    /// # Errors
    /// Rejects malformed, truncated, oversized, noncanonical or foreign-root input.
    pub fn decode_message(root: &[u8], bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 1024 {
            return Err(Error::InvalidCommand);
        }
        let bytes = bytes.strip_prefix(MAGIC).ok_or(Error::InvalidCommand)?;
        let (target, mut tail) = PreparedRecoveryTarget::decode_prefix(root, bytes)?;
        let result = Self {
            target,
            source_target_id: TargetId::from_bytes(take(&mut tail)?)
                .map_err(|_| Error::InvalidCommand)?,
            source_generation: u64::from_be_bytes(take(&mut tail)?),
            receipts_digest: take(&mut tail)?,
            receipt_count: u64::from_be_bytes(take(&mut tail)?),
            encrypted_bytes: u64::from_be_bytes(take(&mut tail)?),
        };
        if !tail.is_empty() {
            return Err(Error::InvalidCommand);
        }
        result.installation_message()?;
        Ok(result)
    }
}
