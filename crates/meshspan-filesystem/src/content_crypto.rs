// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic, domain-separated authenticated encryption for immutable content chunks.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshspan_contracts::BoundedBytes;
use meshspan_domain::ContentManifestId;
use thiserror::Error;
use zeroize::Zeroizing;

const AUTHENTICATION_TAG_BYTES: usize = 16;
const HARD_MAXIMUM_PLAINTEXT_BYTES: usize = 64 * 1_024 * 1_024 - AUTHENTICATION_TAG_BYTES;
const KEY_DOMAIN: &[u8] = b"meshspan.content.chunk-key.v1\0";
const NONCE_DOMAIN: &[u8] = b"meshspan.content.chunk-nonce.v1\0";
const AAD_DOMAIN: &[u8] = b"meshspan.content.chunk-aad.v1\0";

/// Non-exportable per-layout material used to derive independent chunk encryption keys.
///
/// The owner must generate this key cryptographically and persist it only inside a wrapped key
/// envelope. Rewrapping that envelope rotates the protecting key without rewriting content. This
/// type does not implement `Clone`, `Copy` or `Debug`, and clears its owned bytes on drop.
pub struct ContentEncryptionKey(pub(crate) Zeroizing<[u8; 32]>);

impl ContentEncryptionKey {
    /// Takes ownership of one temporarily unwrapped content key.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero value.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ContentCryptoError> {
        if bytes == [0; 32] {
            Err(ContentCryptoError::InvalidInput)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }

    /// Generates a fresh key using the caller's cryptographic random source.
    ///
    /// # Errors
    ///
    /// Rejects unavailable entropy and the all-zero sentinel.
    pub fn generate(
        random: &mut impl meshspan_domain::RandomSource,
    ) -> Result<Self, ContentCryptoError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        random
            .fill_bytes(&mut bytes[..])
            .map_err(|_| ContentCryptoError::Unavailable)?;
        Self::from_bytes(*bytes)
    }
}

/// Explicit per-operation chunk allocation ceiling beneath the provider contract maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentChunkLimits {
    maximum_plaintext_bytes: usize,
}

impl ContentChunkLimits {
    /// Validates a selected chunk ceiling without choosing a product sizing profile.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above the compiled provider-message ceiling.
    pub const fn new(maximum_plaintext_bytes: usize) -> Result<Self, ContentCryptoError> {
        if maximum_plaintext_bytes == 0 || maximum_plaintext_bytes > HARD_MAXIMUM_PLAINTEXT_BYTES {
            Err(ContentCryptoError::InvalidInput)
        } else {
            Ok(Self {
                maximum_plaintext_bytes,
            })
        }
    }

    /// Maximum plaintext bytes accepted for one independently encrypted chunk.
    #[must_use]
    pub const fn maximum_plaintext_bytes(self) -> usize {
        self.maximum_plaintext_bytes
    }
}

/// Immutable encrypted chunk bytes and independent plaintext/ciphertext integrity identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedContentChunk {
    /// Exact plaintext length before authenticated encryption.
    pub plaintext_length: u64,
    /// BLAKE3 identity of the plaintext chunk.
    pub plaintext_digest: [u8; 32],
    /// BLAKE3 identity of the complete ciphertext including its authentication tag.
    pub ciphertext_digest: [u8; 32],
    /// Ciphertext and appended Poly1305 authentication tag.
    pub ciphertext: BoundedBytes,
}

/// Bounded authenticated chunk codec using XChaCha20-Poly1305.
pub struct ContentChunkCipher {
    key: ContentEncryptionKey,
    limits: ContentChunkLimits,
}

impl ContentChunkCipher {
    /// Installs one root-key capability and explicit per-chunk bound.
    #[must_use]
    pub const fn new(key: ContentEncryptionKey, limits: ContentChunkLimits) -> Self {
        Self { key, limits }
    }

    /// Encrypts one non-empty immutable chunk under manifest/index/domain-bound material.
    ///
    /// The per-chunk key and nonce also bind the plaintext digest. Reusing a manifest identity
    /// with conflicting content therefore cannot repeat a key/nonce pair, while the publication
    /// layer must still reject that immutable-identity conflict.
    ///
    /// # Errors
    ///
    /// Rejects zero format versions, empty/excessive input, allocation overflow and AEAD failure.
    pub fn encrypt(
        &self,
        manifest_id: ContentManifestId,
        format_version: u16,
        chunk_index: u64,
        plaintext: &BoundedBytes,
    ) -> Result<EncryptedContentChunk, ContentCryptoError> {
        validate_plaintext(format_version, plaintext.len(), self.limits)?;
        let plaintext_length =
            u64::try_from(plaintext.len()).map_err(|_| ContentCryptoError::InvalidInput)?;
        let plaintext_digest: [u8; 32] = blake3::hash(plaintext.as_slice()).into();
        let material = derive_material(
            &self.key,
            manifest_id,
            format_version,
            chunk_index,
            plaintext_length,
            plaintext_digest,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(material.key.as_ref())
            .map_err(|_| ContentCryptoError::InvalidInput)?;
        let nonce = XNonce::try_from(material.nonce.as_slice())
            .map_err(|_| ContentCryptoError::InvalidInput)?;
        let associated_data = associated_data(
            manifest_id,
            format_version,
            chunk_index,
            plaintext_length,
            plaintext_digest,
        );
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &associated_data,
                },
            )
            .map_err(|_| ContentCryptoError::Unavailable)?;
        let maximum_ciphertext = self
            .limits
            .maximum_plaintext_bytes
            .checked_add(AUTHENTICATION_TAG_BYTES)
            .ok_or(ContentCryptoError::InvalidInput)?;
        let ciphertext = BoundedBytes::copy_from(&ciphertext, maximum_ciphertext)
            .map_err(|_| ContentCryptoError::InvalidInput)?;
        Ok(EncryptedContentChunk {
            plaintext_length,
            plaintext_digest,
            ciphertext_digest: blake3::hash(ciphertext.as_slice()).into(),
            ciphertext,
        })
    }

    /// Authenticates and decrypts one exact immutable chunk.
    ///
    /// Ciphertext digest/length are checked before AEAD, and plaintext length/digest are checked
    /// again afterwards. Callers cannot substitute a chunk across a manifest, format or index.
    ///
    /// # Errors
    ///
    /// Rejects malformed bounds, ciphertext corruption, authentication failure and plaintext
    /// identity mismatch.
    pub fn decrypt(
        &self,
        manifest_id: ContentManifestId,
        format_version: u16,
        chunk_index: u64,
        encrypted: &EncryptedContentChunk,
    ) -> Result<BoundedBytes, ContentCryptoError> {
        validate_encrypted(format_version, encrypted, self.limits)?;
        let material = derive_material(
            &self.key,
            manifest_id,
            format_version,
            chunk_index,
            encrypted.plaintext_length,
            encrypted.plaintext_digest,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(material.key.as_ref())
            .map_err(|_| ContentCryptoError::InvalidInput)?;
        let nonce = XNonce::try_from(material.nonce.as_slice())
            .map_err(|_| ContentCryptoError::InvalidInput)?;
        let associated_data = associated_data(
            manifest_id,
            format_version,
            chunk_index,
            encrypted.plaintext_length,
            encrypted.plaintext_digest,
        );
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: encrypted.ciphertext.as_slice(),
                    aad: &associated_data,
                },
            )
            .map_err(|_| ContentCryptoError::Corrupt)?;
        if u64::try_from(plaintext.len()).map_err(|_| ContentCryptoError::Corrupt)?
            != encrypted.plaintext_length
            || blake3::hash(&plaintext).as_bytes() != &encrypted.plaintext_digest
        {
            return Err(ContentCryptoError::Corrupt);
        }
        BoundedBytes::copy_from(&plaintext, self.limits.maximum_plaintext_bytes)
            .map_err(|_| ContentCryptoError::Corrupt)
    }
}

/// Stable failures from content encryption and verification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContentCryptoError {
    /// Format, bounds, length or secret material is invalid.
    #[error("content crypto input is invalid")]
    InvalidInput,
    /// Ciphertext or recovered plaintext violates its authenticated identity.
    #[error("content crypto material is corrupt")]
    Corrupt,
    /// The authenticated-encryption implementation rejected local encryption.
    #[error("content crypto operation is unavailable")]
    Unavailable,
}

struct ChunkMaterial {
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 24],
}

fn validate_plaintext(
    format_version: u16,
    plaintext_bytes: usize,
    limits: ContentChunkLimits,
) -> Result<(), ContentCryptoError> {
    if format_version == 0
        || plaintext_bytes == 0
        || plaintext_bytes > limits.maximum_plaintext_bytes
    {
        Err(ContentCryptoError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_encrypted(
    format_version: u16,
    encrypted: &EncryptedContentChunk,
    limits: ContentChunkLimits,
) -> Result<(), ContentCryptoError> {
    let plaintext_length = usize::try_from(encrypted.plaintext_length)
        .map_err(|_| ContentCryptoError::InvalidInput)?;
    validate_plaintext(format_version, plaintext_length, limits)?;
    let expected_ciphertext = plaintext_length
        .checked_add(AUTHENTICATION_TAG_BYTES)
        .ok_or(ContentCryptoError::InvalidInput)?;
    if encrypted.ciphertext.len() != expected_ciphertext
        || blake3::hash(encrypted.ciphertext.as_slice()).as_bytes() != &encrypted.ciphertext_digest
    {
        Err(ContentCryptoError::Corrupt)
    } else {
        Ok(())
    }
}

fn derive_material(
    content_key: &ContentEncryptionKey,
    manifest_id: ContentManifestId,
    format_version: u16,
    chunk_index: u64,
    plaintext_length: u64,
    plaintext_digest: [u8; 32],
) -> ChunkMaterial {
    let mut key = blake3::Hasher::new_keyed(&content_key.0);
    key.update(KEY_DOMAIN);
    update_identity(
        &mut key,
        manifest_id,
        format_version,
        chunk_index,
        plaintext_length,
        plaintext_digest,
    );
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(key.finalize().into());
    let mut nonce = [0_u8; 24];
    let mut nonce_hasher = blake3::Hasher::new_keyed(&key);
    nonce_hasher.update(NONCE_DOMAIN);
    update_identity(
        &mut nonce_hasher,
        manifest_id,
        format_version,
        chunk_index,
        plaintext_length,
        plaintext_digest,
    );
    nonce_hasher.finalize_xof().fill(&mut nonce);
    ChunkMaterial { key, nonce }
}

fn associated_data(
    manifest_id: ContentManifestId,
    format_version: u16,
    chunk_index: u64,
    plaintext_length: u64,
    plaintext_digest: [u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(
        AAD_DOMAIN.len()
            + manifest_id.as_bytes().len()
            + size_of::<u16>()
            + size_of::<u64>() * 2
            + plaintext_digest.len(),
    );
    data.extend_from_slice(AAD_DOMAIN);
    data.extend_from_slice(&manifest_id.as_bytes());
    data.extend_from_slice(&format_version.to_be_bytes());
    data.extend_from_slice(&chunk_index.to_be_bytes());
    data.extend_from_slice(&plaintext_length.to_be_bytes());
    data.extend_from_slice(&plaintext_digest);
    data
}

fn update_identity(
    digest: &mut blake3::Hasher,
    manifest_id: ContentManifestId,
    format_version: u16,
    chunk_index: u64,
    plaintext_length: u64,
    plaintext_digest: [u8; 32],
) {
    digest.update(&manifest_id.as_bytes());
    digest.update(&format_version.to_be_bytes());
    digest.update(&chunk_index.to_be_bytes());
    digest.update(&plaintext_length.to_be_bytes());
    digest.update(&plaintext_digest);
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::BoundedBytes;
    use meshspan_domain::ContentManifestId;

    use super::{ContentChunkCipher, ContentChunkLimits, ContentCryptoError, ContentEncryptionKey};

    #[test]
    fn deterministic_vector_round_trips_and_changes_across_chunk_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let cipher = cipher()?;
        let manifest = ContentManifestId::from_bytes([2; 16])?;
        let plaintext = BoundedBytes::copy_from(b"MeshSpan encrypted chunk vector", 64)?;
        let encrypted = cipher.encrypt(manifest, 1, 7, &plaintext)?;
        assert_eq!(
            encrypted.plaintext_digest,
            *blake3::hash(plaintext.as_slice()).as_bytes()
        );
        assert_eq!(encrypted.ciphertext.len(), plaintext.len() + 16);
        assert_eq!(
            cipher.decrypt(manifest, 1, 7, &encrypted)?.as_slice(),
            plaintext.as_slice()
        );
        let other_index = cipher.encrypt(manifest, 1, 8, &plaintext)?;
        assert_ne!(encrypted.ciphertext, other_index.ciphertext);
        assert_eq!(
            encrypted.ciphertext_digest,
            [
                110, 120, 87, 151, 1, 200, 114, 173, 55, 155, 211, 217, 24, 167, 47, 235, 135, 48,
                17, 228, 117, 231, 205, 40, 236, 94, 28, 64, 247, 104, 97, 52,
            ]
        );
        Ok(())
    }

    #[test]
    fn every_substitution_and_corruption_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let cipher = cipher()?;
        let manifest = ContentManifestId::from_bytes([3; 16])?;
        let plaintext = BoundedBytes::copy_from(b"never plaintext on storage", 64)?;
        let encrypted = cipher.encrypt(manifest, 1, 4, &plaintext)?;
        assert_eq!(
            cipher.decrypt(ContentManifestId::from_bytes([4; 16])?, 1, 4, &encrypted),
            Err(ContentCryptoError::Corrupt)
        );
        assert_eq!(
            cipher.decrypt(manifest, 2, 4, &encrypted),
            Err(ContentCryptoError::Corrupt)
        );
        assert_eq!(
            cipher.decrypt(manifest, 1, 5, &encrypted),
            Err(ContentCryptoError::Corrupt)
        );
        let mut corrupted_bytes = encrypted.ciphertext.as_slice().to_vec();
        corrupted_bytes[0] ^= 1;
        let mut corrupted = encrypted.clone();
        corrupted.ciphertext = BoundedBytes::copy_from(&corrupted_bytes, 64)?;
        assert_eq!(
            cipher.decrypt(manifest, 1, 4, &corrupted),
            Err(ContentCryptoError::Corrupt)
        );
        corrupted.ciphertext_digest = blake3::hash(&corrupted_bytes).into();
        assert_eq!(
            cipher.decrypt(manifest, 1, 4, &corrupted),
            Err(ContentCryptoError::Corrupt)
        );
        Ok(())
    }

    #[test]
    fn invalid_keys_limits_and_chunks_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            ContentEncryptionKey::from_bytes([0; 32]),
            Err(ContentCryptoError::InvalidInput)
        ));
        assert_eq!(
            ContentChunkLimits::new(0),
            Err(ContentCryptoError::InvalidInput)
        );
        let cipher = cipher()?;
        let manifest = ContentManifestId::from_bytes([5; 16])?;
        assert_eq!(
            cipher.encrypt(manifest, 0, 0, &BoundedBytes::copy_from(b"x", 1)?),
            Err(ContentCryptoError::InvalidInput)
        );
        assert_eq!(
            cipher.encrypt(manifest, 1, 0, &BoundedBytes::copy_from(&[], 0)?),
            Err(ContentCryptoError::InvalidInput)
        );
        Ok(())
    }

    fn cipher() -> Result<ContentChunkCipher, ContentCryptoError> {
        Ok(ContentChunkCipher::new(
            ContentEncryptionKey::from_bytes([1; 32])?,
            ContentChunkLimits::new(64)?,
        ))
    }
}
