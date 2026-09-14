// SPDX-License-Identifier: GPL-2.0-only

//! Offline file reconstruction over archive-selected layouts and read-only surviving media.

use std::io::Write;

use meshspan_contracts::{
    BoundedBytes, BoundedItems, CodingScheme, ContractVersion, ReconstructionRequest,
    RequestContext, ShardIdentity,
};
use zeroize::Zeroizing;

use crate::{
    CommittedContentLayoutTransfer, ContentChunkCipher, ContentChunkLimits, ContentEncryptionKey,
    ContentReadError, EncryptedContentChunk, PreparedProtectedStripe,
};

/// Read-only physical salvage supplied by the recovery orchestrator, never a live access adapter.
/// Implementations own location lookup and may try multiple copies. A locator alone grants no
/// authority: the orchestrator must already hold explicit offline recovery authorisation.
pub trait RecoveryShardSource {
    /// Returns a candidate for the exact encrypted identity or `None` when none survives.
    /// The filesystem independently checks length and digest, even after source verification.
    ///
    /// # Errors
    /// Propagates source IO, cancellation and identity failures rather than inventing absence.
    fn read_candidate(
        &mut self,
        shard: ShardIdentity,
        expected_length: u64,
        expected_digest: [u8; 32],
    ) -> Result<Option<BoundedBytes>, ContentReadError>;
}

/// Complete verified plaintext evidence, not storage protection or service admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentRecoverySummary {
    /// Exact streamed and authenticated logical bytes.
    pub logical_length: u64,
    /// Independently recalculated whole-file BLAKE3 digest.
    pub content_digest: [u8; 32],
    /// Number of successfully reconstructed and decrypted chunks.
    pub chunks: u64,
}

impl CommittedContentLayoutTransfer<'_> {
    /// Reconstructs one complete archived file into a caller-owned isolated destination.
    ///
    /// The caller selects this layout from authenticated recovery metadata and unwraps its key.
    /// This uses no live read permit, target reservation, repair write or consensus mutation.
    /// Memory is bounded by one coding stripe and one plaintext chunk, not file size. Catalogue
    /// verification happens once when opening this borrowed layout, not again for every chunk.
    /// The destination may contain a partial file on error; publish it only after success and
    /// the caller's required durable flush. Success does not readmit any node or start service.
    ///
    /// # Errors
    /// Rejects unsupported layouts, insufficient valid slices, key/ciphertext/plaintext mismatch,
    /// invalid component context and output/source IO. All emitted chunks authenticate first.
    pub fn recover_to(
        &self,
        context: RequestContext,
        key: ContentEncryptionKey,
        coding: &impl CodingScheme,
        source: &mut impl RecoveryShardSource,
        destination: &mut dyn Write,
    ) -> Result<ContentRecoverySummary, ContentReadError> {
        let header = self.header();
        if header.manifest.format_version != 2
            || context.contract_version != ContractVersion::V1_0
            || context.deadline.get() <= 0
        {
            return Err(ContentReadError::InvalidInput);
        }
        let limits = ContentChunkLimits::new(
            usize::try_from(header.chunk_bytes).map_err(|_| ContentReadError::Corrupt)?,
        )
        .map_err(|_| ContentReadError::Corrupt)?;
        let cipher = ContentChunkCipher::new(key, limits);
        let mut digest = blake3::Hasher::new();
        let mut length = 0_u64;
        for index in 0..header.chunk_count {
            let stripe = self
                .recovery_stripe(index)
                .map_err(|_| ContentReadError::Corrupt)?;
            let encrypted = reconstruct_chunk(
                context,
                header.manifest.root_digest,
                &stripe.stripe,
                coding,
                source,
            )?;
            let plaintext = Zeroizing::new(
                cipher
                    .decrypt(
                        header.manifest.manifest_id,
                        header.manifest.format_version,
                        index,
                        &encrypted,
                    )
                    .map_err(|_| ContentReadError::Corrupt)?
                    .into_vec(),
            );
            length = length
                .checked_add(u64::try_from(plaintext.len()).map_err(|_| ContentReadError::Corrupt)?)
                .filter(|total| *total <= header.manifest.logical_length)
                .ok_or(ContentReadError::Corrupt)?;
            digest.update(&plaintext);
            destination.write_all(&plaintext)?;
        }
        let digest = *digest.finalize().as_bytes();
        if length != header.manifest.logical_length || digest != header.manifest.content_digest {
            return Err(ContentReadError::Corrupt);
        }
        Ok(ContentRecoverySummary {
            logical_length: length,
            content_digest: digest,
            chunks: header.chunk_count,
        })
    }
}

pub(crate) fn reconstruct_chunk(
    context: RequestContext,
    manifest_digest: [u8; 32],
    stripe: &PreparedProtectedStripe,
    coding: &impl CodingScheme,
    source: &mut impl RecoveryShardSource,
) -> Result<EncryptedContentChunk, ContentReadError> {
    let mut slices = vec![None; stripe.shards().len()];
    let mut valid = 0;
    for (slot, planned) in slices.iter_mut().zip(stripe.shards()) {
        let shard = ShardIdentity {
            manifest_digest,
            stripe_index: stripe.chunk().chunk_index,
            shard_index: planned.shard_index,
            generation: planned.shard_generation,
        };
        if let Some(bytes) =
            source.read_candidate(shard, planned.expected_length, planned.expected_digest)?
            && u64::try_from(bytes.len()).ok() == Some(planned.expected_length)
            && blake3::hash(bytes.as_slice()).as_bytes() == &planned.expected_digest
        {
            *slot = Some(bytes);
            valid += 1;
        }
        if valid == usize::from(stripe.coding_layout().data_slices()) {
            break;
        }
    }
    if valid < usize::from(stripe.coding_layout().data_slices()) {
        return Err(ContentReadError::Unavailable);
    }
    let chunk = stripe.chunk();
    let ciphertext = coding
        .reconstruct(&ReconstructionRequest {
            context,
            layout: stripe.coding_layout(),
            available_slices: BoundedItems::new(slices, 24)
                .map_err(|_| ContentReadError::Corrupt)?,
            slice_digests: BoundedItems::new(
                stripe
                    .shards()
                    .iter()
                    .map(|shard| shard.expected_digest)
                    .collect(),
                24,
            )
            .map_err(|_| ContentReadError::Corrupt)?,
            logical_length: chunk.ciphertext_length,
            logical_digest: chunk.ciphertext_digest,
        })
        .map_err(|_| ContentReadError::Corrupt)?;
    if u64::try_from(ciphertext.len()).ok() != Some(chunk.ciphertext_length)
        || blake3::hash(ciphertext.as_slice()).as_bytes() != &chunk.ciphertext_digest
    {
        return Err(ContentReadError::Corrupt);
    }
    Ok(EncryptedContentChunk {
        plaintext_length: chunk.plaintext_length,
        plaintext_digest: chunk.plaintext_digest,
        ciphertext_digest: chunk.ciphertext_digest,
        ciphertext,
    })
}
