// SPDX-License-Identifier: GPL-2.0-only

//! Connection-bound transfer and receiver-local rewrapping of one content key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshspan_domain::{ContentManifestId, RandomSource};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{ContentEncryptionKey, ContentKeyEnvelopeCipher, ContentKeyError, WrappedContentKey};

const TRANSIT_DOMAIN: &[u8] = b"meshspan.content.key-transit.v1\0";
const CONTENT_KEY_BYTES: usize = 32;
const TRANSIT_CIPHERTEXT_BYTES: usize = 48;

/// One per-content key encrypted under a connection-exporter key and exact request binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitWrappedContentKey {
    /// Fresh XChaCha20-Poly1305 nonce for this response.
    pub nonce: [u8; 24],
    /// Encrypted 32-byte content key plus authentication tag.
    pub ciphertext: [u8; TRANSIT_CIPHERTEXT_BYTES],
    /// Independent digest binding manifest, request, nonce and ciphertext.
    pub transit_digest: [u8; 32],
}

/// Non-exportable TLS-exporter material bound to one exact content-key request.
pub struct ContentKeyTransitCipher {
    key: Zeroizing<[u8; 32]>,
    binding: [u8; 32],
}

impl ContentKeyTransitCipher {
    /// Installs connection-exporter material and the digest of the exact authorised request.
    ///
    /// # Errors
    ///
    /// Rejects zero exporter material or an empty request binding.
    pub fn new(key: [u8; 32], binding: [u8; 32]) -> Result<Self, ContentKeyTransitError> {
        if key == [0; 32] || binding == [0; 32] {
            Err(ContentKeyTransitError::InvalidInput)
        } else {
            Ok(Self {
                key: Zeroizing::new(key),
                binding,
            })
        }
    }

    /// Opens one source volume envelope and emits only a connection-bound transit envelope.
    ///
    /// # Errors
    ///
    /// Rejects the wrong source key, corrupt envelopes, unavailable entropy and AEAD failure.
    pub fn wrap_from_volume(
        &self,
        manifest_id: ContentManifestId,
        source: &ContentKeyEnvelopeCipher,
        envelope: WrappedContentKey,
        random: &mut impl RandomSource,
    ) -> Result<TransitWrappedContentKey, ContentKeyTransitError> {
        let content_key = source
            .unwrap(manifest_id, envelope)
            .map_err(map_key_error)?;
        let mut nonce = [0_u8; 24];
        random
            .fill_bytes(&mut nonce)
            .map_err(|_| ContentKeyTransitError::Unavailable)?;
        let cipher = self.cipher()?;
        let nonce_value =
            XNonce::try_from(nonce.as_slice()).map_err(|_| ContentKeyTransitError::InvalidInput)?;
        let associated_data = associated_data(manifest_id, self.binding);
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: content_key.0.as_ref(),
                    aad: &associated_data,
                },
            )
            .map_err(|_| ContentKeyTransitError::Unavailable)?;
        let ciphertext: [u8; TRANSIT_CIPHERTEXT_BYTES] = ciphertext
            .try_into()
            .map_err(|_| ContentKeyTransitError::Unavailable)?;
        Ok(TransitWrappedContentKey {
            nonce,
            ciphertext,
            transit_digest: transit_digest(manifest_id, self.binding, nonce, ciphertext),
        })
    }

    /// Opens a connection-bound envelope and immediately wraps the key for the receiver volume.
    ///
    /// # Errors
    ///
    /// Rejects request/manifest substitution, corruption, wrong exporter material, entropy failure
    /// and receiver key errors.
    pub fn rewrap_for_volume(
        &self,
        manifest_id: ContentManifestId,
        target: &ContentKeyEnvelopeCipher,
        transit: TransitWrappedContentKey,
        random: &mut impl RandomSource,
    ) -> Result<WrappedContentKey, ContentKeyTransitError> {
        if transit.transit_digest
            != transit_digest(manifest_id, self.binding, transit.nonce, transit.ciphertext)
        {
            return Err(ContentKeyTransitError::Corrupt);
        }
        let cipher = self.cipher()?;
        let nonce = XNonce::try_from(transit.nonce.as_slice())
            .map_err(|_| ContentKeyTransitError::Corrupt)?;
        let associated_data = associated_data(manifest_id, self.binding);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &transit.ciphertext,
                        aad: &associated_data,
                    },
                )
                .map_err(|_| ContentKeyTransitError::Corrupt)?,
        );
        let key_bytes: [u8; CONTENT_KEY_BYTES] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| ContentKeyTransitError::Corrupt)?;
        let content_key = ContentEncryptionKey::from_bytes(key_bytes)
            .map_err(|_| ContentKeyTransitError::Corrupt)?;
        target
            .wrap(manifest_id, &content_key, random)
            .map_err(map_key_error)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, ContentKeyTransitError> {
        XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| ContentKeyTransitError::InvalidInput)
    }
}

/// Stable failures from connection-bound content-key transfer.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContentKeyTransitError {
    /// Exporter key or exact request binding is invalid.
    #[error("content key transit input is invalid")]
    InvalidInput,
    /// Source, transit or receiver envelope authentication failed.
    #[error("content key transit material is corrupt")]
    Corrupt,
    /// Entropy or authenticated encryption is unavailable.
    #[error("content key transit operation is unavailable")]
    Unavailable,
}

fn associated_data(manifest_id: ContentManifestId, binding: [u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(
        TRANSIT_DOMAIN
            .len()
            .saturating_add(manifest_id.as_bytes().len())
            .saturating_add(binding.len()),
    );
    data.extend_from_slice(TRANSIT_DOMAIN);
    data.extend_from_slice(&manifest_id.as_bytes());
    data.extend_from_slice(&binding);
    data
}

fn transit_digest(
    manifest_id: ContentManifestId,
    binding: [u8; 32],
    nonce: [u8; 24],
    ciphertext: [u8; TRANSIT_CIPHERTEXT_BYTES],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(TRANSIT_DOMAIN);
    digest.update(&manifest_id.as_bytes());
    digest.update(&binding);
    digest.update(&nonce);
    digest.update(&ciphertext);
    digest.finalize().into()
}

const fn map_key_error(error: ContentKeyError) -> ContentKeyTransitError {
    match error {
        ContentKeyError::InvalidInput | ContentKeyError::Corrupt => ContentKeyTransitError::Corrupt,
        ContentKeyError::Unavailable => ContentKeyTransitError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{ContentManifestId, EntropyError, RandomSource};

    use super::{ContentKeyTransitCipher, ContentKeyTransitError};
    use crate::{
        ContentChunkCipher, ContentChunkLimits, ContentEncryptionKey, ContentKeyEnvelopeCipher,
        VolumeKeyEncryptionKey,
    };

    #[test]
    fn content_key_moves_between_volume_keys_without_changing_ciphertext()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest = ContentManifestId::from_bytes([1; 16])?;
        let source = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(1, [2; 32])?);
        let target = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(2, [3; 32])?);
        let content_key = ContentEncryptionKey::from_bytes([4; 32])?;
        let source_envelope = source.wrap(manifest, &content_key, &mut FixedRandom(5))?;
        let transit = ContentKeyTransitCipher::new([6; 32], [7; 32])?;
        let envelope =
            transit.wrap_from_volume(manifest, &source, source_envelope, &mut FixedRandom(8))?;
        let target_envelope =
            transit.rewrap_for_volume(manifest, &target, envelope, &mut FixedRandom(9))?;
        let plaintext = meshspan_contracts::BoundedBytes::copy_from(b"federated", 16)?;
        let source_cipher = ContentChunkCipher::new(content_key, ContentChunkLimits::new(16)?);
        let encrypted = source_cipher.encrypt(manifest, 1, 0, &plaintext)?;
        let target_key = target.unwrap(manifest, target_envelope)?;
        let recovered = ContentChunkCipher::new(target_key, ContentChunkLimits::new(16)?)
            .decrypt(manifest, 1, 0, &encrypted)?;
        assert_eq!(recovered, plaintext);
        Ok(())
    }

    #[test]
    fn wrong_connection_request_manifest_and_corruption_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest = ContentManifestId::from_bytes([10; 16])?;
        let source =
            ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(1, [11; 32])?);
        let target =
            ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(2, [12; 32])?);
        let source_envelope = source.wrap(
            manifest,
            &ContentEncryptionKey::from_bytes([13; 32])?,
            &mut FixedRandom(14),
        )?;
        let transit = ContentKeyTransitCipher::new([15; 32], [16; 32])?;
        let envelope =
            transit.wrap_from_volume(manifest, &source, source_envelope, &mut FixedRandom(17))?;
        for wrong in [
            ContentKeyTransitCipher::new([18; 32], [16; 32])?,
            ContentKeyTransitCipher::new([15; 32], [19; 32])?,
        ] {
            assert!(matches!(
                wrong.rewrap_for_volume(manifest, &target, envelope, &mut FixedRandom(20)),
                Err(ContentKeyTransitError::Corrupt)
            ));
        }
        assert!(matches!(
            transit.rewrap_for_volume(
                ContentManifestId::from_bytes([21; 16])?,
                &target,
                envelope,
                &mut FixedRandom(20)
            ),
            Err(ContentKeyTransitError::Corrupt)
        ));
        let mut corrupt = envelope;
        corrupt.ciphertext[0] ^= 1;
        assert!(matches!(
            transit.rewrap_for_volume(manifest, &target, corrupt, &mut FixedRandom(20)),
            Err(ContentKeyTransitError::Corrupt)
        ));
        assert!(ContentKeyTransitCipher::new([0; 32], [1; 32]).is_err());
        assert!(ContentKeyTransitCipher::new([1; 32], [0; 32]).is_err());
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
