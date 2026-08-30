// SPDX-License-Identifier: GPL-2.0-only

//! Bounded provider-neutral transfer of immutable encrypted-content layouts.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{ContentManifestId, OperationId};
use thiserror::Error;

use crate::{ManifestPublication, PreparedContentChunk, WrappedContentKey};

/// Maximum number of immutable chunk identities carried by one layout page.
pub const MAXIMUM_CONTENT_LAYOUT_PAGE_ITEMS: usize = 1_000;

const MANIFEST_DOMAIN: &[u8] = b"meshspan.content.unprotected-manifest.v1\0";
const HEADER_DOMAIN: &[u8] = b"meshspan.content.layout-transfer-header.v1\0";

/// Provider-independent identity of one encrypted chunk.
///
/// Provider operation IDs and receipts are deliberately absent: a receiving target must create
/// its own operation authority and collect its own durable receipt for the transferred bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentLayoutChunk {
    /// Zero-based position in the logical file layout.
    pub chunk_index: u64,
    /// Exact plaintext bytes represented by the chunk.
    pub plaintext_length: u64,
    /// BLAKE3 identity of the plaintext chunk.
    pub plaintext_digest: [u8; 32],
    /// Exact encrypted bytes including the authentication tag.
    pub ciphertext_length: u64,
    /// BLAKE3 identity of the complete encrypted bytes.
    pub ciphertext_digest: [u8; 32],
}

impl From<PreparedContentChunk> for ContentLayoutChunk {
    fn from(value: PreparedContentChunk) -> Self {
        Self {
            chunk_index: value.chunk_index,
            plaintext_length: value.plaintext_length,
            plaintext_digest: value.plaintext_digest,
            ciphertext_length: value.ciphertext_length,
            ciphertext_digest: value.ciphertext_digest,
        }
    }
}

impl ContentLayoutChunk {
    pub(crate) fn with_provider_operation(self, operation_id: OperationId) -> PreparedContentChunk {
        PreparedContentChunk {
            chunk_index: self.chunk_index,
            plaintext_length: self.plaintext_length,
            plaintext_digest: self.plaintext_digest,
            ciphertext_length: self.ciphertext_length,
            ciphertext_digest: self.ciphertext_digest,
            provider_operation_id: operation_id,
        }
    }
}

pub(crate) fn provider_operation_id(
    operation_id: OperationId,
    chunk_index: u64,
) -> Result<OperationId, ContentLayoutTransferError> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.content.provider-operation.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&chunk_index.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    if bytes == [0; 16] {
        bytes[15] = 1;
    }
    OperationId::from_bytes(bytes).map_err(|_| ContentLayoutTransferError::Invalid)
}

/// Complete layout header transferred before bounded chunk-identity pages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentLayoutTransferHeader {
    /// Exact immutable manifest that all received pages must reconstruct.
    pub manifest: ManifestPublication,
    /// Maximum plaintext bytes represented by an ordinary full chunk.
    pub chunk_bytes: u64,
    /// Exact number of contiguous chunk identities required before sealing.
    pub chunk_count: u64,
    /// Content key already wrapped for the receiving volume-key generation.
    ///
    /// This envelope is authenticated separately and is intentionally excluded from the immutable
    /// manifest root so routine key rotation does not rewrite content identity.
    pub wrapped_key: WrappedContentKey,
}

impl ContentLayoutTransferHeader {
    /// Revalidates one untrusted portable layout header before persistence or key use.
    ///
    /// # Errors
    ///
    /// Rejects malformed geometry, missing versions and a receiver envelope not bound to the
    /// advertised manifest.
    pub fn from_untrusted(
        manifest: ManifestPublication,
        chunk_bytes: u64,
        chunk_count: u64,
        wrapped_key: WrappedContentKey,
    ) -> Result<Self, ContentLayoutTransferError> {
        let header = Self {
            manifest,
            chunk_bytes,
            chunk_count,
            wrapped_key,
        };
        header.validate()?;
        Ok(header)
    }

    pub(crate) const fn valid_shape(self) -> bool {
        self.manifest.format_version != 0
            && self.chunk_bytes != 0
            && self.wrapped_key.key_generation != 0
            && ((self.manifest.logical_length == 0 && self.chunk_count == 0)
                || (self.manifest.logical_length != 0 && self.chunk_count != 0))
    }

    pub(crate) fn validate(self) -> Result<(), ContentLayoutTransferError> {
        if self.valid_shape() && self.wrapped_key.valid_for(self.manifest.manifest_id) {
            Ok(())
        } else {
            Err(ContentLayoutTransferError::Invalid)
        }
    }

    /// Canonical identity of the exact expected manifest, geometry and receiver-wrapped key.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut digest = blake3::Hasher::new();
        digest.update(HEADER_DOMAIN);
        digest.update(&self.manifest.manifest_id.as_bytes());
        digest.update(&self.manifest.format_version.to_be_bytes());
        digest.update(&self.manifest.logical_length.to_be_bytes());
        digest.update(&self.manifest.content_digest);
        digest.update(&self.manifest.root_digest);
        digest.update(&self.chunk_bytes.to_be_bytes());
        digest.update(&self.chunk_count.to_be_bytes());
        digest.update(&self.wrapped_key.key_generation.to_be_bytes());
        digest.update(&self.wrapped_key.nonce);
        digest.update(&self.wrapped_key.ciphertext);
        digest.update(&self.wrapped_key.envelope_digest);
        digest.finalize().into()
    }
}

/// One bounded, contiguous page of provider-neutral chunk identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentLayoutTransferPage {
    chunks: BoundedItems<ContentLayoutChunk>,
    next_index: Option<u64>,
}

impl ContentLayoutTransferPage {
    /// Revalidates one untrusted bounded page before it enters durable recovery state.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive, discontinuous, malformed or contradictory page fields.
    pub fn from_untrusted(
        chunks: Vec<ContentLayoutChunk>,
        next_index: Option<u64>,
    ) -> Result<Self, ContentLayoutTransferError> {
        let bounded = BoundedItems::new(chunks, MAXIMUM_CONTENT_LAYOUT_PAGE_ITEMS)
            .map_err(|_| ContentLayoutTransferError::BoundsExceeded)?;
        validate_page(bounded.as_slice(), next_index)?;
        Ok(Self {
            chunks: bounded,
            next_index,
        })
    }

    /// Contiguous immutable identities in ascending chunk order.
    #[must_use]
    pub fn chunks(&self) -> &[ContentLayoutChunk] {
        self.chunks.as_slice()
    }

    /// Last returned index when another page exists.
    #[must_use]
    pub const fn next_index(&self) -> Option<u64> {
        self.next_index
    }
}

/// Incremental verifier for one complete immutable content layout.
pub(crate) struct ContentManifestAccumulator {
    manifest_id: ContentManifestId,
    format_version: u16,
    logical_length: u64,
    content_digest: [u8; 32],
    chunk_bytes: u64,
    digest: blake3::Hasher,
    chunk_count: u64,
    plaintext_total: u64,
}

impl ContentManifestAccumulator {
    pub(crate) fn new(
        manifest_id: ContentManifestId,
        format_version: u16,
        logical_length: u64,
        content_digest: [u8; 32],
        chunk_bytes: u64,
    ) -> Result<Self, ContentLayoutTransferError> {
        if format_version == 0 || chunk_bytes == 0 {
            return Err(ContentLayoutTransferError::Invalid);
        }
        let mut digest = blake3::Hasher::new();
        digest.update(MANIFEST_DOMAIN);
        digest.update(&manifest_id.as_bytes());
        digest.update(&format_version.to_be_bytes());
        digest.update(&logical_length.to_be_bytes());
        digest.update(&content_digest);
        digest.update(&chunk_bytes.to_be_bytes());
        Ok(Self {
            manifest_id,
            format_version,
            logical_length,
            content_digest,
            chunk_bytes,
            digest,
            chunk_count: 0,
            plaintext_total: 0,
        })
    }

    pub(crate) fn push(
        &mut self,
        chunk: ContentLayoutChunk,
    ) -> Result<(), ContentLayoutTransferError> {
        if chunk.chunk_index != self.chunk_count
            || chunk.plaintext_length == 0
            || chunk.plaintext_length > self.chunk_bytes
            || chunk.ciphertext_length != chunk.plaintext_length.saturating_add(16)
        {
            return Err(ContentLayoutTransferError::Invalid);
        }
        self.plaintext_total = self
            .plaintext_total
            .checked_add(chunk.plaintext_length)
            .ok_or(ContentLayoutTransferError::BoundsExceeded)?;
        self.digest.update(&chunk.chunk_index.to_be_bytes());
        self.digest.update(&chunk.plaintext_length.to_be_bytes());
        self.digest.update(&chunk.plaintext_digest);
        self.digest.update(&chunk.ciphertext_length.to_be_bytes());
        self.digest.update(&chunk.ciphertext_digest);
        self.chunk_count = self
            .chunk_count
            .checked_add(1)
            .ok_or(ContentLayoutTransferError::BoundsExceeded)?;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(ManifestPublication, u64), ContentLayoutTransferError> {
        if self.plaintext_total != self.logical_length {
            return Err(ContentLayoutTransferError::Invalid);
        }
        Ok((
            ManifestPublication {
                manifest_id: self.manifest_id,
                format_version: self.format_version,
                logical_length: self.logical_length,
                content_digest: self.content_digest,
                root_digest: self.digest.finalize().into(),
            },
            self.chunk_count,
        ))
    }
}

fn validate_page(
    chunks: &[ContentLayoutChunk],
    next_index: Option<u64>,
) -> Result<(), ContentLayoutTransferError> {
    let Some(first) = chunks.first() else {
        return Err(ContentLayoutTransferError::Invalid);
    };
    for (offset, chunk) in chunks.iter().enumerate() {
        let expected = first
            .chunk_index
            .checked_add(
                u64::try_from(offset).map_err(|_| ContentLayoutTransferError::BoundsExceeded)?,
            )
            .ok_or(ContentLayoutTransferError::BoundsExceeded)?;
        if chunk.chunk_index != expected
            || chunk.plaintext_length == 0
            || chunk.ciphertext_length != chunk.plaintext_length.saturating_add(16)
        {
            return Err(ContentLayoutTransferError::Invalid);
        }
    }
    if next_index.is_some_and(|value| Some(value) != chunks.last().map(|chunk| chunk.chunk_index)) {
        return Err(ContentLayoutTransferError::Invalid);
    }
    Ok(())
}

/// Closed failures while validating a portable encrypted-content layout.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContentLayoutTransferError {
    /// A collection, index or accumulated length exceeded its fixed bound.
    #[error("content layout transfer exceeds its bounds")]
    BoundsExceeded,
    /// The layout is empty, discontinuous, malformed or internally contradictory.
    #[error("content layout transfer is invalid")]
    Invalid,
}
