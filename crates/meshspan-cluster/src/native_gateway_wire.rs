// SPDX-License-Identifier: GPL-2.0-only

//! Canonical same-swarm content-layout and durability-route records.

use meshspan_contracts::{ShardIdentity, ShardReceipt};
use meshspan_domain::{ContentManifestId, OperationId, TargetId};
use meshspan_filesystem::{
    ContentLayoutChunk, ContentLayoutTransferHeader, ContentLayoutTransferPage,
    ManifestPublication, WrappedContentKey,
};
use meshspan_protocol::v1::VersionedPayload;
use thiserror::Error;

const FORMAT_VERSION: u32 = 1;
const HEADER_DOMAIN: &[u8] = b"meshspan.native.content-layout-header\0";
const CHUNK_DOMAIN: &[u8] = b"meshspan.native.content-layout-chunk\0";
const RECEIPT_DOMAIN: &[u8] = b"meshspan.native.content-shard-receipt\0";
const HEADER_FIELDS_LENGTH: usize = 16 + 2 + 8 + 32 + 32 + 8 + 8 + 8 + 24 + 48 + 32;
const CHUNK_FIELDS_LENGTH: usize = 8 + 8 + 32 + 8 + 32;
const RECEIPT_FIELDS_LENGTH: usize = 16 + 32 + 8 + 2 + 4 + 8 + 32 + 16 + 8;

/// Encodes immutable geometry and its already volume-wrapped same-swarm content key.
#[must_use]
pub fn version_native_content_layout_header(
    header: ContentLayoutTransferHeader,
) -> VersionedPayload {
    let mut bytes = Vec::with_capacity(HEADER_DOMAIN.len() + HEADER_FIELDS_LENGTH);
    bytes.extend_from_slice(HEADER_DOMAIN);
    bytes.extend_from_slice(&header.manifest.manifest_id.as_bytes());
    bytes.extend_from_slice(&header.manifest.format_version.to_be_bytes());
    bytes.extend_from_slice(&header.manifest.logical_length.to_be_bytes());
    bytes.extend_from_slice(&header.manifest.content_digest);
    bytes.extend_from_slice(&header.manifest.root_digest);
    bytes.extend_from_slice(&header.chunk_bytes.to_be_bytes());
    bytes.extend_from_slice(&header.chunk_count.to_be_bytes());
    bytes.extend_from_slice(&header.wrapped_key.key_generation.to_be_bytes());
    bytes.extend_from_slice(&header.wrapped_key.nonce);
    bytes.extend_from_slice(&header.wrapped_key.ciphertext);
    bytes.extend_from_slice(&header.wrapped_key.envelope_digest);
    VersionedPayload {
        format_version: FORMAT_VERSION,
        canonical_bytes: bytes,
    }
}

/// Decodes and revalidates one same-swarm content layout header.
///
/// # Errors
///
/// Rejects a wrong version, domain, length or invalid content-layout field.
pub fn decode_native_content_layout_header(
    payload: &VersionedPayload,
) -> Result<ContentLayoutTransferHeader, NativeGatewayWireError> {
    let mut reader = Reader::payload(payload, HEADER_DOMAIN, HEADER_FIELDS_LENGTH)?;
    let manifest_id = ContentManifestId::from_bytes(reader.array()?)
        .map_err(|_| NativeGatewayWireError::Invalid)?;
    let manifest = ManifestPublication {
        manifest_id,
        format_version: reader.u16()?,
        logical_length: reader.u64()?,
        content_digest: reader.array()?,
        root_digest: reader.array()?,
    };
    let chunk_bytes = reader.u64()?;
    let chunk_count = reader.u64()?;
    let wrapped_key = WrappedContentKey {
        key_generation: reader.u64()?,
        nonce: reader.array()?,
        ciphertext: reader.array()?,
        envelope_digest: reader.array()?,
    };
    reader.finish()?;
    ContentLayoutTransferHeader::from_untrusted(manifest, chunk_bytes, chunk_count, wrapped_key)
        .map_err(|_| NativeGatewayWireError::Invalid)
}

/// Encodes one independently verifiable encrypted-chunk identity.
///
/// # Errors
///
/// Rejects a chunk whose lengths, index or digests violate the layout contract.
pub fn version_native_content_layout_chunk(
    chunk: ContentLayoutChunk,
) -> Result<VersionedPayload, NativeGatewayWireError> {
    ContentLayoutTransferPage::from_untrusted(vec![chunk], None)
        .map_err(|_| NativeGatewayWireError::Invalid)?;
    let mut bytes = Vec::with_capacity(CHUNK_DOMAIN.len() + CHUNK_FIELDS_LENGTH);
    bytes.extend_from_slice(CHUNK_DOMAIN);
    bytes.extend_from_slice(&chunk.chunk_index.to_be_bytes());
    bytes.extend_from_slice(&chunk.plaintext_length.to_be_bytes());
    bytes.extend_from_slice(&chunk.plaintext_digest);
    bytes.extend_from_slice(&chunk.ciphertext_length.to_be_bytes());
    bytes.extend_from_slice(&chunk.ciphertext_digest);
    Ok(VersionedPayload {
        format_version: FORMAT_VERSION,
        canonical_bytes: bytes,
    })
}

/// Decodes and revalidates one encrypted-chunk identity.
///
/// # Errors
///
/// Rejects a wrong version, domain, length or invalid chunk field.
pub fn decode_native_content_layout_chunk(
    payload: &VersionedPayload,
) -> Result<ContentLayoutChunk, NativeGatewayWireError> {
    let mut reader = Reader::payload(payload, CHUNK_DOMAIN, CHUNK_FIELDS_LENGTH)?;
    let chunk = ContentLayoutChunk {
        chunk_index: reader.u64()?,
        plaintext_length: reader.u64()?,
        plaintext_digest: reader.array()?,
        ciphertext_length: reader.u64()?,
        ciphertext_digest: reader.array()?,
    };
    reader.finish()?;
    ContentLayoutTransferPage::from_untrusted(vec![chunk], None)
        .map_err(|_| NativeGatewayWireError::Invalid)?;
    Ok(chunk)
}

/// Encodes the exact source-provider receipt authorising one remote read route.
#[must_use]
pub fn version_native_shard_receipt(receipt: ShardReceipt) -> VersionedPayload {
    let mut bytes = Vec::with_capacity(RECEIPT_DOMAIN.len() + RECEIPT_FIELDS_LENGTH);
    bytes.extend_from_slice(RECEIPT_DOMAIN);
    bytes.extend_from_slice(&receipt.operation_id.as_bytes());
    bytes.extend_from_slice(&receipt.shard.manifest_digest);
    bytes.extend_from_slice(&receipt.shard.stripe_index.to_be_bytes());
    bytes.extend_from_slice(&receipt.shard.shard_index.to_be_bytes());
    bytes.extend_from_slice(&receipt.shard.generation.to_be_bytes());
    bytes.extend_from_slice(&receipt.length.to_be_bytes());
    bytes.extend_from_slice(&receipt.digest);
    bytes.extend_from_slice(&receipt.target_id.as_bytes());
    bytes.extend_from_slice(&receipt.target_generation.to_be_bytes());
    VersionedPayload {
        format_version: FORMAT_VERSION,
        canonical_bytes: bytes,
    }
}

/// Decodes one exact source-provider receipt without trusting any field.
///
/// # Errors
///
/// Rejects a wrong version, domain, length, identity or zero-valued fence.
pub fn decode_native_shard_receipt(
    payload: &VersionedPayload,
) -> Result<ShardReceipt, NativeGatewayWireError> {
    let mut reader = Reader::payload(payload, RECEIPT_DOMAIN, RECEIPT_FIELDS_LENGTH)?;
    let operation_id =
        OperationId::from_bytes(reader.array()?).map_err(|_| NativeGatewayWireError::Invalid)?;
    let shard = ShardIdentity {
        manifest_digest: reader.array()?,
        stripe_index: reader.u64()?,
        shard_index: reader.u16()?,
        generation: reader.u32()?,
    };
    let length = reader.u64()?;
    let digest = reader.array()?;
    let target_id =
        TargetId::from_bytes(reader.array()?).map_err(|_| NativeGatewayWireError::Invalid)?;
    let target_generation = reader.u64()?;
    reader.finish()?;
    if length == 0 || target_generation == 0 || shard.generation == 0 {
        return Err(NativeGatewayWireError::Invalid);
    }
    Ok(ShardReceipt {
        operation_id,
        shard,
        length,
        digest,
        target_id,
        target_generation,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn payload(
        payload: &'a VersionedPayload,
        domain: &[u8],
        fields_length: usize,
    ) -> Result<Self, NativeGatewayWireError> {
        if payload.format_version != FORMAT_VERSION
            || payload.canonical_bytes.len() != domain.len() + fields_length
            || !payload.canonical_bytes.starts_with(domain)
        {
            return Err(NativeGatewayWireError::Invalid);
        }
        Ok(Self {
            bytes: &payload.canonical_bytes[domain.len()..],
            offset: 0,
        })
    }

    fn array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], NativeGatewayWireError> {
        let end = self
            .offset
            .checked_add(LENGTH)
            .ok_or(NativeGatewayWireError::Invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(NativeGatewayWireError::Invalid)?
            .try_into()
            .map_err(|_| NativeGatewayWireError::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, NativeGatewayWireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, NativeGatewayWireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, NativeGatewayWireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), NativeGatewayWireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(NativeGatewayWireError::Invalid)
        }
    }
}

/// Stable failure for non-canonical or contradictory native gateway records.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NativeGatewayWireError {
    /// Version, domain, length, identity or semantic shape is invalid.
    #[error("native gateway record is invalid")]
    Invalid,
}
