// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated wrapping and rewrapping of per-layout content-encryption keys.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshspan_domain::{ContentManifestId, RandomSource};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{ContentCryptoError, ContentEncryptionKey};

const ENVELOPE_DOMAIN: &[u8] = b"meshspan.content.key-envelope.v1\0";
const ENVELOPE_NONCE_DOMAIN: &[u8] = b"meshspan.content.key-envelope-nonce.v1\0";
const CONTENT_KEY_BYTES: usize = 32;
const ENVELOPE_BYTES: usize = 48;

/// Volume-scoped key-encryption capability and its authoritative generation.
///
/// The bytes are never cloneable or printable and are cleared on drop. Rotation installs a new
/// generation and rewraps content-key envelopes without decrypting or rewriting user chunks.
pub struct VolumeKeyEncryptionKey {
    generation: u64,
    bytes: Zeroizing<[u8; 32]>,
}

impl VolumeKeyEncryptionKey {
    /// Installs one temporarily unwrapped volume key-encryption key.
    ///
    /// # Errors
    ///
    /// Rejects generation zero and all-zero key material.
    pub fn from_bytes(generation: u64, bytes: [u8; 32]) -> Result<Self, ContentKeyError> {
        if generation == 0 || bytes == [0; 32] {
            Err(ContentKeyError::InvalidInput)
        } else {
            Ok(Self {
                generation,
                bytes: Zeroizing::new(bytes),
            })
        }
    }

    /// Authoritative wrapping-key generation recorded by new envelopes.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Fixed-width authenticated envelope containing one per-layout content key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrappedContentKey {
    /// Wrapping-key generation required to open the envelope.
    pub key_generation: u64,
    /// Unique XChaCha20-Poly1305 nonce generated for this envelope.
    pub nonce: [u8; 24],
    /// Encrypted 32-byte content key plus 16-byte authentication tag.
    pub ciphertext: [u8; ENVELOPE_BYTES],
    /// Independent BLAKE3 digest of the complete stored envelope fields.
    pub envelope_digest: [u8; 32],
}

/// Authenticated volume-key envelope codec.
pub struct ContentKeyEnvelopeCipher {
    key: VolumeKeyEncryptionKey,
}

impl ContentKeyEnvelopeCipher {
    /// Installs one volume wrapping-key capability.
    #[must_use]
    pub const fn new(key: VolumeKeyEncryptionKey) -> Self {
        Self { key }
    }

    /// Wraps a content key under a fresh random nonce and manifest-bound associated data.
    ///
    /// # Errors
    ///
    /// Rejects unavailable entropy and local authenticated-encryption failure.
    pub fn wrap(
        &self,
        manifest_id: ContentManifestId,
        content_key: &ContentEncryptionKey,
        random: &mut impl RandomSource,
    ) -> Result<WrappedContentKey, ContentKeyError> {
        let nonce = self.derive_nonce(manifest_id, content_key, random)?;
        let cipher = self.cipher()?;
        let nonce_value =
            XNonce::try_from(nonce.as_slice()).map_err(|_| ContentKeyError::InvalidInput)?;
        let associated_data = associated_data(manifest_id, self.key.generation);
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: content_key.0.as_ref(),
                    aad: &associated_data,
                },
            )
            .map_err(|_| ContentKeyError::Unavailable)?;
        let ciphertext: [u8; ENVELOPE_BYTES] = ciphertext
            .try_into()
            .map_err(|_| ContentKeyError::Unavailable)?;
        Ok(WrappedContentKey {
            key_generation: self.key.generation,
            nonce,
            ciphertext,
            envelope_digest: envelope_digest(manifest_id, self.key.generation, nonce, ciphertext),
        })
    }

    /// Authenticates and unwraps a content key for the exact manifest and key generation.
    ///
    /// # Errors
    ///
    /// Rejects wrong generations, corrupt envelope digests/tags and invalid recovered key bytes.
    pub fn unwrap(
        &self,
        manifest_id: ContentManifestId,
        envelope: WrappedContentKey,
    ) -> Result<ContentEncryptionKey, ContentKeyError> {
        if envelope.key_generation != self.key.generation
            || envelope.envelope_digest
                != envelope_digest(
                    manifest_id,
                    envelope.key_generation,
                    envelope.nonce,
                    envelope.ciphertext,
                )
        {
            return Err(ContentKeyError::Corrupt);
        }
        let cipher = self.cipher()?;
        let nonce =
            XNonce::try_from(envelope.nonce.as_slice()).map_err(|_| ContentKeyError::Corrupt)?;
        let associated_data = associated_data(manifest_id, envelope.key_generation);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &associated_data,
                    },
                )
                .map_err(|_| ContentKeyError::Corrupt)?,
        );
        let mut key_bytes = Zeroizing::new([0_u8; CONTENT_KEY_BYTES]);
        if plaintext.len() != CONTENT_KEY_BYTES {
            return Err(ContentKeyError::Corrupt);
        }
        key_bytes.copy_from_slice(&plaintext);
        ContentEncryptionKey::from_bytes(*key_bytes).map_err(map_content_crypto)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, ContentKeyError> {
        XChaCha20Poly1305::new_from_slice(self.key.bytes.as_ref())
            .map_err(|_| ContentKeyError::InvalidInput)
    }

    fn derive_nonce(
        &self,
        manifest_id: ContentManifestId,
        content_key: &ContentEncryptionKey,
        random: &mut impl RandomSource,
    ) -> Result<[u8; 24], ContentKeyError> {
        let mut entropy = Zeroizing::new([0_u8; 32]);
        random
            .fill_bytes(&mut entropy[..])
            .map_err(|_| ContentKeyError::Unavailable)?;
        let mut digest = blake3::Hasher::new_keyed(&self.key.bytes);
        digest.update(ENVELOPE_NONCE_DOMAIN);
        digest.update(&manifest_id.as_bytes());
        digest.update(&self.key.generation.to_be_bytes());
        digest.update(content_key.0.as_ref());
        digest.update(entropy.as_ref());
        let mut nonce = [0_u8; 24];
        digest.finalize_xof().fill(&mut nonce);
        Ok(nonce)
    }
}

impl WrappedContentKey {
    pub(crate) fn valid_for(self, manifest_id: ContentManifestId) -> bool {
        self.key_generation != 0
            && self.envelope_digest
                == envelope_digest(
                    manifest_id,
                    self.key_generation,
                    self.nonce,
                    self.ciphertext,
                )
    }
}

/// Unwraps under the prior generation and wraps under the replacement generation.
///
/// # Errors
///
/// Rejects every old-envelope authentication failure and new entropy/encryption failure.
pub fn rewrap_content_key(
    manifest_id: ContentManifestId,
    old: &ContentKeyEnvelopeCipher,
    new: &ContentKeyEnvelopeCipher,
    envelope: WrappedContentKey,
    random: &mut impl RandomSource,
) -> Result<WrappedContentKey, ContentKeyError> {
    let content_key = old.unwrap(manifest_id, envelope)?;
    new.wrap(manifest_id, &content_key, random)
}

/// Stable failures from content-key envelope handling.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContentKeyError {
    /// Key generation, key material or a fixed-width field is invalid.
    #[error("content key input is invalid")]
    InvalidInput,
    /// Envelope digest, generation, authentication tag or recovered key is corrupt.
    #[error("content key envelope is corrupt")]
    Corrupt,
    /// Cryptographic entropy or local encryption is unavailable.
    #[error("content key operation is unavailable")]
    Unavailable,
}

fn associated_data(manifest_id: ContentManifestId, key_generation: u64) -> Vec<u8> {
    let mut data =
        Vec::with_capacity(ENVELOPE_DOMAIN.len() + manifest_id.as_bytes().len() + size_of::<u64>());
    data.extend_from_slice(ENVELOPE_DOMAIN);
    data.extend_from_slice(&manifest_id.as_bytes());
    data.extend_from_slice(&key_generation.to_be_bytes());
    data
}

fn envelope_digest(
    manifest_id: ContentManifestId,
    key_generation: u64,
    nonce: [u8; 24],
    ciphertext: [u8; ENVELOPE_BYTES],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(ENVELOPE_DOMAIN);
    digest.update(&manifest_id.as_bytes());
    digest.update(&key_generation.to_be_bytes());
    digest.update(&nonce);
    digest.update(&ciphertext);
    digest.finalize().into()
}

fn map_content_crypto(error: ContentCryptoError) -> ContentKeyError {
    match error {
        ContentCryptoError::InvalidInput | ContentCryptoError::Corrupt => ContentKeyError::Corrupt,
        ContentCryptoError::Unavailable => ContentKeyError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::BoundedBytes;
    use meshspan_domain::{ContentManifestId, EntropyError, RandomSource};

    use super::{
        ContentKeyEnvelopeCipher, ContentKeyError, VolumeKeyEncryptionKey, rewrap_content_key,
    };
    use crate::{ContentChunkCipher, ContentChunkLimits, ContentEncryptionKey};

    #[test]
    fn deterministic_envelope_vector_round_trips_and_binds_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest = ContentManifestId::from_bytes([2; 16])?;
        let cipher = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(3, [1; 32])?);
        let content_key = ContentEncryptionKey::from_bytes([4; 32])?;
        let mut random = FixedRandom(5);
        let envelope = cipher.wrap(manifest, &content_key, &mut random)?;
        assert_eq!(envelope.key_generation, 3);
        assert_eq!(
            envelope.nonce,
            [
                42, 3, 78, 222, 31, 88, 255, 215, 141, 70, 181, 223, 141, 88, 21, 193, 160, 87, 55,
                152, 25, 253, 74, 128,
            ]
        );
        assert_eq!(
            envelope.envelope_digest,
            [
                18, 124, 122, 179, 214, 205, 178, 57, 158, 201, 107, 3, 124, 75, 20, 15, 207, 52,
                226, 214, 248, 87, 85, 234, 159, 114, 15, 74, 131, 195, 75, 216,
            ]
        );
        let unwrapped = cipher.unwrap(manifest, envelope)?;
        assert_same_chunk_ciphertext(content_key, unwrapped, manifest)?;
        assert!(matches!(
            cipher.unwrap(ContentManifestId::from_bytes([6; 16])?, envelope),
            Err(ContentKeyError::Corrupt)
        ));
        Ok(())
    }

    #[test]
    fn rewrap_changes_only_the_envelope_and_rejects_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest = ContentManifestId::from_bytes([7; 16])?;
        let old = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(8, [8; 32])?);
        let new = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(9, [9; 32])?);
        let content_key = ContentEncryptionKey::from_bytes([10; 32])?;
        let mut random = FixedRandom(11);
        let envelope = old.wrap(manifest, &content_key, &mut random)?;
        random.0 = 12;
        let rewrapped = rewrap_content_key(manifest, &old, &new, envelope, &mut random)?;
        assert_eq!(rewrapped.key_generation, 9);
        assert_ne!(rewrapped.ciphertext, envelope.ciphertext);
        let unwrapped = new.unwrap(manifest, rewrapped)?;
        assert_same_chunk_ciphertext(content_key, unwrapped, manifest)?;

        let mut corrupt = envelope;
        corrupt.ciphertext[0] ^= 1;
        assert!(matches!(
            old.unwrap(manifest, corrupt),
            Err(ContentKeyError::Corrupt)
        ));
        corrupt.envelope_digest = super::envelope_digest(
            manifest,
            corrupt.key_generation,
            corrupt.nonce,
            corrupt.ciphertext,
        );
        assert!(matches!(
            old.unwrap(manifest, corrupt),
            Err(ContentKeyError::Corrupt)
        ));
        Ok(())
    }

    #[test]
    fn invalid_generations_keys_and_entropy_fail_before_an_envelope_exists()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            VolumeKeyEncryptionKey::from_bytes(0, [1; 32]),
            Err(ContentKeyError::InvalidInput)
        ));
        assert!(matches!(
            VolumeKeyEncryptionKey::from_bytes(1, [0; 32]),
            Err(ContentKeyError::InvalidInput)
        ));
        assert!(matches!(
            ContentEncryptionKey::generate(&mut FixedRandom(0)),
            Err(crate::ContentCryptoError::InvalidInput)
        ));
        let cipher = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(1, [1; 32])?);
        let manifest = ContentManifestId::from_bytes([13; 16])?;
        let content_key = ContentEncryptionKey::from_bytes([14; 32])?;
        assert!(matches!(
            cipher.wrap(manifest, &content_key, &mut FailingRandom),
            Err(ContentKeyError::Unavailable)
        ));
        Ok(())
    }

    fn assert_same_chunk_ciphertext(
        left: ContentEncryptionKey,
        right: ContentEncryptionKey,
        manifest: ContentManifestId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let limits = ContentChunkLimits::new(64)?;
        let plaintext = BoundedBytes::copy_from(b"key rewrap does not rewrite content", 64)?;
        let left = ContentChunkCipher::new(left, limits).encrypt(manifest, 1, 0, &plaintext)?;
        let right = ContentChunkCipher::new(right, limits).encrypt(manifest, 1, 0, &plaintext)?;
        assert_eq!(left, right);
        Ok(())
    }

    struct FixedRandom(u8);

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(self.0);
            Ok(())
        }
    }

    struct FailingRandom;

    impl RandomSource for FailingRandom {
        fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError)
        }
    }
}
