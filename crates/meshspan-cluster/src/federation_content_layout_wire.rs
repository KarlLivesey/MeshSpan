// SPDX-License-Identifier: GPL-2.0-only

//! Canonical provider-neutral wire encoding for encrypted content layouts.

use meshspan_domain::{ContentManifestId, RandomSource};
use meshspan_filesystem::{
    ContentKeyEnvelopeCipher, ContentKeyTransitCipher, ContentLayoutChunk,
    ContentLayoutTransferHeader, ContentLayoutTransferPage, ManifestPublication,
    TransitWrappedContentKey,
};
use meshspan_protocol::v1::VersionedPayload;
use thiserror::Error;

const FORMAT_VERSION: u32 = 1;
const HEADER_DOMAIN: &[u8] = b"meshspan.federation.content-layout-header\0";
const CHUNK_DOMAIN: &[u8] = b"meshspan.federation.content-layout-chunk\0";
const CURSOR_DOMAIN: &[u8] = b"meshspan.federation.content-layout-cursor\0";
const HEADER_FIELDS_LENGTH: usize = 16 + 2 + 8 + 32 + 32 + 8 + 8 + 24 + 48 + 32;
const CHUNK_FIELDS_LENGTH: usize = 8 + 8 + 32 + 8 + 32;
const CURSOR_FIELDS_LENGTH: usize = 8;

/// Encodes immutable geometry plus the connection-bound content-key envelope.
///
/// Source-local provider identities, receipts and the volume-wrapped key are never encoded.
#[must_use]
pub fn version_federated_content_layout_header(
    header: ContentLayoutTransferHeader,
    transit: TransitWrappedContentKey,
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
    bytes.extend_from_slice(&transit.nonce);
    bytes.extend_from_slice(&transit.ciphertext);
    bytes.extend_from_slice(&transit.transit_digest);
    VersionedPayload {
        format_version: FORMAT_VERSION,
        canonical_bytes: bytes,
    }
}

/// Decodes immutable geometry, opens its connection-bound key and immediately rewraps locally.
///
/// # Errors
///
/// Rejects unknown versions, wrong domains/lengths, malformed geometry, key substitution,
/// unavailable entropy and trailing bytes.
pub fn decode_federated_content_layout_header(
    payload: &VersionedPayload,
    transit_cipher: &ContentKeyTransitCipher,
    target_cipher: &ContentKeyEnvelopeCipher,
    random: &mut impl RandomSource,
) -> Result<ContentLayoutTransferHeader, FederationContentLayoutWireError> {
    if payload.format_version != FORMAT_VERSION
        || payload.canonical_bytes.len() != HEADER_DOMAIN.len() + HEADER_FIELDS_LENGTH
        || !payload.canonical_bytes.starts_with(HEADER_DOMAIN)
    {
        return Err(FederationContentLayoutWireError::Invalid);
    }
    let mut reader = Reader::new(&payload.canonical_bytes[HEADER_DOMAIN.len()..]);
    let manifest_id = ContentManifestId::from_bytes(reader.array()?)
        .map_err(|_| FederationContentLayoutWireError::Invalid)?;
    let manifest = ManifestPublication {
        manifest_id,
        format_version: reader.u16()?,
        logical_length: reader.u64()?,
        content_digest: reader.array()?,
        root_digest: reader.array()?,
    };
    let chunk_bytes = reader.u64()?;
    let chunk_count = reader.u64()?;
    let transit = TransitWrappedContentKey {
        nonce: reader.array()?,
        ciphertext: reader.array()?,
        transit_digest: reader.array()?,
    };
    reader.finish()?;
    let wrapped_key = transit_cipher
        .rewrap_for_volume(manifest_id, target_cipher, transit, random)
        .map_err(map_transit)?;
    ContentLayoutTransferHeader::from_untrusted(manifest, chunk_bytes, chunk_count, wrapped_key)
        .map_err(|_| FederationContentLayoutWireError::Invalid)
}

/// Encodes one provider-neutral encrypted-chunk identity.
///
/// # Errors
///
/// Rejects malformed length or index relationships.
pub fn version_federated_content_layout_chunk(
    chunk: ContentLayoutChunk,
) -> Result<VersionedPayload, FederationContentLayoutWireError> {
    ContentLayoutTransferPage::from_untrusted(vec![chunk], None)
        .map_err(|_| FederationContentLayoutWireError::Invalid)?;
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

/// Decodes one exact provider-neutral encrypted-chunk identity.
///
/// # Errors
///
/// Rejects unknown versions, wrong domains/lengths, malformed fields and trailing bytes.
pub fn decode_federated_content_layout_chunk(
    payload: &VersionedPayload,
) -> Result<ContentLayoutChunk, FederationContentLayoutWireError> {
    if payload.format_version != FORMAT_VERSION
        || payload.canonical_bytes.len() != CHUNK_DOMAIN.len() + CHUNK_FIELDS_LENGTH
        || !payload.canonical_bytes.starts_with(CHUNK_DOMAIN)
    {
        return Err(FederationContentLayoutWireError::Invalid);
    }
    let mut reader = Reader::new(&payload.canonical_bytes[CHUNK_DOMAIN.len()..]);
    let chunk = ContentLayoutChunk {
        chunk_index: reader.u64()?,
        plaintext_length: reader.u64()?,
        plaintext_digest: reader.array()?,
        ciphertext_length: reader.u64()?,
        ciphertext_digest: reader.array()?,
    };
    reader.finish()?;
    ContentLayoutTransferPage::from_untrusted(vec![chunk], None)
        .map_err(|_| FederationContentLayoutWireError::Invalid)?;
    Ok(chunk)
}

pub(crate) fn encode_content_layout_cursor(index: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CURSOR_DOMAIN.len() + CURSOR_FIELDS_LENGTH);
    bytes.extend_from_slice(CURSOR_DOMAIN);
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes
}

pub(crate) fn decode_content_layout_cursor(
    bytes: &[u8],
) -> Result<Option<u64>, FederationContentLayoutWireError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != CURSOR_DOMAIN.len() + CURSOR_FIELDS_LENGTH
        || !bytes.starts_with(CURSOR_DOMAIN)
    {
        return Err(FederationContentLayoutWireError::Invalid);
    }
    Ok(Some(u64::from_be_bytes(
        bytes[CURSOR_DOMAIN.len()..]
            .try_into()
            .map_err(|_| FederationContentLayoutWireError::Invalid)?,
    )))
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; LENGTH], FederationContentLayoutWireError> {
        let end = self
            .offset
            .checked_add(LENGTH)
            .ok_or(FederationContentLayoutWireError::Invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FederationContentLayoutWireError::Invalid)?
            .try_into()
            .map_err(|_| FederationContentLayoutWireError::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, FederationContentLayoutWireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, FederationContentLayoutWireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), FederationContentLayoutWireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(FederationContentLayoutWireError::Invalid)
        }
    }
}

fn map_transit(
    error: meshspan_filesystem::ContentKeyTransitError,
) -> FederationContentLayoutWireError {
    match error {
        meshspan_filesystem::ContentKeyTransitError::InvalidInput => {
            FederationContentLayoutWireError::Invalid
        }
        meshspan_filesystem::ContentKeyTransitError::Corrupt => {
            FederationContentLayoutWireError::Corrupt
        }
        meshspan_filesystem::ContentKeyTransitError::Unavailable => {
            FederationContentLayoutWireError::Unavailable
        }
    }
}

/// Stable failures while decoding or locally rewrapping one federated layout.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationContentLayoutWireError {
    /// Version, domain, length, identifier or semantic shape is invalid.
    #[error("federated content layout encoding is invalid")]
    Invalid,
    /// Connection-bound key or encrypted layout evidence is corrupt.
    #[error("federated content layout evidence is corrupt")]
    Corrupt,
    /// Required cryptography or secure entropy is unavailable.
    #[error("federated content layout cryptography is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{ContentManifestId, EntropyError, RandomSource};
    use meshspan_filesystem::{
        ContentEncryptionKey, ContentKeyEnvelopeCipher, ContentKeyTransitCipher,
        ContentLayoutChunk, ContentLayoutTransferHeader, ManifestPublication,
        VolumeKeyEncryptionKey,
    };

    use super::{
        decode_content_layout_cursor, decode_federated_content_layout_chunk,
        decode_federated_content_layout_header, encode_content_layout_cursor,
        version_federated_content_layout_chunk, version_federated_content_layout_header,
    };

    #[test]
    fn header_rewraps_locally_and_rejects_connection_or_byte_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest_id = ContentManifestId::from_bytes([1; 16])?;
        let source = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(1, [2; 32])?);
        let target = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(2, [3; 32])?);
        let key = ContentEncryptionKey::from_bytes([4; 32])?;
        let source_envelope = source.wrap(manifest_id, &key, &mut FixedRandom(5))?;
        let header = ContentLayoutTransferHeader::from_untrusted(
            ManifestPublication {
                manifest_id,
                format_version: 1,
                logical_length: 8,
                content_digest: [6; 32],
                root_digest: [7; 32],
            },
            8,
            1,
            source_envelope,
        )?;
        let transit = ContentKeyTransitCipher::new([8; 32], [9; 32])?;
        let transit_key = transit.wrap_from_volume(
            manifest_id,
            &source,
            source_envelope,
            &mut FixedRandom(10),
        )?;
        let encoded = version_federated_content_layout_header(header, transit_key);
        let decoded = decode_federated_content_layout_header(
            &encoded,
            &transit,
            &target,
            &mut FixedRandom(11),
        )?;
        assert_eq!(decoded.manifest, header.manifest);
        assert_eq!(decoded.chunk_bytes, header.chunk_bytes);
        assert_eq!(decoded.chunk_count, header.chunk_count);
        target.unwrap(manifest_id, decoded.wrapped_key)?;

        let wrong = ContentKeyTransitCipher::new([12; 32], [9; 32])?;
        assert!(
            decode_federated_content_layout_header(&encoded, &wrong, &target, &mut FixedRandom(11))
                .is_err()
        );
        let mut corrupt = encoded;
        let last = corrupt.canonical_bytes.len() - 1;
        corrupt.canonical_bytes[last] ^= 1;
        assert!(
            decode_federated_content_layout_header(
                &corrupt,
                &transit,
                &target,
                &mut FixedRandom(11)
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn chunk_and_cursor_are_canonical_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let chunk = ContentLayoutChunk {
            chunk_index: 3,
            plaintext_length: 4,
            plaintext_digest: [5; 32],
            ciphertext_length: 20,
            ciphertext_digest: [6; 32],
        };
        let encoded = version_federated_content_layout_chunk(chunk)?;
        assert_eq!(decode_federated_content_layout_chunk(&encoded)?, chunk);
        let mut trailing = encoded;
        trailing.canonical_bytes.push(0);
        assert!(decode_federated_content_layout_chunk(&trailing).is_err());
        let cursor = encode_content_layout_cursor(7);
        assert_eq!(decode_content_layout_cursor(&cursor)?, Some(7));
        assert_eq!(decode_content_layout_cursor(&[])?, None);
        assert!(decode_content_layout_cursor(&cursor[..cursor.len() - 1]).is_err());
        Ok(())
    }

    struct FixedRandom(u8);

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(self.0);
            Ok(())
        }
    }
}
