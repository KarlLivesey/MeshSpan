// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated secret ciphertext bound to one immutable generation.

use std::collections::BTreeSet;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshspan_domain::RandomSource;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::key::SecretDataKey;
use crate::{
    MAXIMUM_SECRET_BYTES, MAXIMUM_SECRET_RECIPIENTS, RecipientKeyEnvelope, SecretEnvelopeError,
    WrappingPublicKey,
};

const FORMAT_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const AUTHENTICATION_TAG_BYTES: usize = 16;
const SECRET_AAD_DOMAIN: &[u8] = b"meshspan.secret-envelope.secret-aad.v1\0";
const SECRET_DIGEST_DOMAIN: &[u8] = b"meshspan.secret-envelope.secret-digest.v1\0";

/// Immutable authority and generation binding for one encrypted secret.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SecretContext {
    kind: u16,
    id: [u8; 16],
    generation: u64,
}

impl SecretContext {
    /// Creates a non-empty, positive-generation secret identity.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero kind, identifier or generation.
    pub fn new(kind: u16, id: [u8; 16], generation: u64) -> Result<Self, SecretEnvelopeError> {
        if kind == 0 || id == [0; 16] || generation == 0 {
            Err(SecretEnvelopeError::InvalidInput)
        } else {
            Ok(Self {
                kind,
                id,
                generation,
            })
        }
    }

    /// Returns the application-defined secret-kind code.
    #[must_use]
    pub const fn kind(self) -> u16 {
        self.kind
    }

    /// Returns the stable secret identity.
    #[must_use]
    pub const fn id(self) -> [u8; 16] {
        self.id
    }

    /// Returns the immutable secret generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) fn append_to(self, destination: &mut Vec<u8>) {
        destination.extend_from_slice(&self.kind.to_be_bytes());
        destination.extend_from_slice(&self.id);
        destination.extend_from_slice(&self.generation.to_be_bytes());
    }
}

/// Validated plaintext secret bytes which clear themselves on drop.
///
/// The type deliberately implements neither `Clone`, `Debug` nor `Display`.
pub struct SecretPlaintext(Zeroizing<Vec<u8>>);

impl SecretPlaintext {
    /// Takes ownership of bounded non-empty secret bytes.
    ///
    /// # Errors
    ///
    /// Rejects empty secrets and secrets larger than [`MAXIMUM_SECRET_BYTES`].
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SecretEnvelopeError> {
        validate_plaintext_length(bytes.len())?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Borrows the plaintext for its immediate protected consumer.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Persisted fields for one authenticated encrypted secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedSecretParts {
    /// Wire and storage format version.
    pub format_version: u8,
    /// Immutable authority and generation binding.
    pub context: SecretContext,
    /// Fresh XChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_BYTES],
    /// Authenticated ciphertext including its tag.
    pub ciphertext: Vec<u8>,
    /// Domain-separated digest covering every persisted field.
    pub digest: [u8; 32],
}

/// Validated authenticated ciphertext for one secret generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedSecret(EncryptedSecretParts);

impl EncryptedSecret {
    /// Restores and validates persisted secret fields before any decryption attempt.
    ///
    /// # Errors
    ///
    /// Rejects unknown formats, invalid bounds, reserved nonces and digest mismatch.
    pub fn from_parts(parts: EncryptedSecretParts) -> Result<Self, SecretEnvelopeError> {
        validate_encrypted_parts(&parts)?;
        Ok(Self(parts))
    }

    /// Returns the immutable secret identity and generation.
    #[must_use]
    pub const fn context(&self) -> SecretContext {
        self.0.context
    }

    /// Copies the persisted representation for metadata storage or transport.
    #[must_use]
    pub fn parts(&self) -> EncryptedSecretParts {
        self.0.clone()
    }

    /// Authenticates and decrypts this secret with a recovered data key.
    ///
    /// # Errors
    ///
    /// Rejects a wrong key, changed context, malformed ciphertext or failed authentication tag.
    pub fn decrypt(&self, key: &SecretDataKey) -> Result<SecretPlaintext, SecretEnvelopeError> {
        let cipher = secret_cipher(key)?;
        let aad = secret_associated_data(self.0.context);
        let plaintext = cipher
            .decrypt(
                &XNonce::from(self.0.nonce),
                Payload {
                    msg: &self.0.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| SecretEnvelopeError::Corrupt)?;
        SecretPlaintext::from_bytes(plaintext).map_err(|_| SecretEnvelopeError::Corrupt)
    }
}

/// Encrypts one secret generation and wraps its random data key for every exact recipient.
///
/// # Errors
///
/// Rejects invalid plaintext, empty, duplicate or excessive recipients, unavailable entropy and
/// any cryptographic failure. No partial result is returned.
pub fn encrypt_secret(
    context: SecretContext,
    plaintext: &[u8],
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<(EncryptedSecret, Vec<RecipientKeyEnvelope>), SecretEnvelopeError> {
    validate_plaintext_length(plaintext.len())?;
    validate_recipients(recipients)?;
    let key = SecretDataKey::generate(random)?;
    let encrypted = encrypt_plaintext(context, plaintext, &key, random)?;
    let mut ordered_recipients = recipients.to_vec();
    ordered_recipients.sort_by_key(|recipient| recipient.fingerprint());
    let envelopes = ordered_recipients
        .iter()
        .map(|recipient| RecipientKeyEnvelope::wrap(context, *recipient, &key, random))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((encrypted, envelopes))
}

fn encrypt_plaintext(
    context: SecretContext,
    plaintext: &[u8],
    key: &SecretDataKey,
    random: &mut impl RandomSource,
) -> Result<EncryptedSecret, SecretEnvelopeError> {
    let nonce = random_nonce(random)?;
    let aad = secret_associated_data(context);
    let ciphertext = secret_cipher(key)?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SecretEnvelopeError::Unavailable)?;
    let mut parts = EncryptedSecretParts {
        format_version: FORMAT_VERSION,
        context,
        nonce,
        ciphertext,
        digest: [0; 32],
    };
    parts.digest = encrypted_digest(&parts);
    EncryptedSecret::from_parts(parts)
}

fn validate_recipients(recipients: &[WrappingPublicKey]) -> Result<(), SecretEnvelopeError> {
    if recipients.is_empty() || recipients.len() > MAXIMUM_SECRET_RECIPIENTS {
        return Err(SecretEnvelopeError::InvalidInput);
    }
    let unique = recipients
        .iter()
        .map(|recipient| recipient.fingerprint())
        .collect::<BTreeSet<_>>();
    if unique.len() == recipients.len() {
        Ok(())
    } else {
        Err(SecretEnvelopeError::InvalidInput)
    }
}

fn validate_encrypted_parts(parts: &EncryptedSecretParts) -> Result<(), SecretEnvelopeError> {
    let valid_length = (1 + AUTHENTICATION_TAG_BYTES
        ..=MAXIMUM_SECRET_BYTES + AUTHENTICATION_TAG_BYTES)
        .contains(&parts.ciphertext.len());
    if parts.format_version != FORMAT_VERSION
        || parts.nonce == [0; NONCE_BYTES]
        || !valid_length
        || parts.digest != encrypted_digest(parts)
    {
        Err(SecretEnvelopeError::Corrupt)
    } else {
        Ok(())
    }
}

fn validate_plaintext_length(length: usize) -> Result<(), SecretEnvelopeError> {
    if (1..=MAXIMUM_SECRET_BYTES).contains(&length) {
        Ok(())
    } else {
        Err(SecretEnvelopeError::InvalidInput)
    }
}

fn secret_cipher(key: &SecretDataKey) -> Result<XChaCha20Poly1305, SecretEnvelopeError> {
    XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| SecretEnvelopeError::Unavailable)
}

fn secret_associated_data(context: SecretContext) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SECRET_AAD_DOMAIN.len() + 26);
    aad.extend_from_slice(SECRET_AAD_DOMAIN);
    context.append_to(&mut aad);
    aad
}

fn encrypted_digest(parts: &EncryptedSecretParts) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SECRET_DIGEST_DOMAIN);
    digest.update([parts.format_version]);
    let mut context = Vec::with_capacity(26);
    parts.context.append_to(&mut context);
    digest.update(context);
    digest.update(parts.nonce);
    digest.update((parts.ciphertext.len() as u64).to_be_bytes());
    digest.update(&parts.ciphertext);
    digest.finalize().into()
}

fn random_nonce(random: &mut impl RandomSource) -> Result<[u8; NONCE_BYTES], SecretEnvelopeError> {
    let mut nonce = [0_u8; NONCE_BYTES];
    random
        .fill_bytes(&mut nonce)
        .map_err(|_| SecretEnvelopeError::Entropy)?;
    if nonce == [0; NONCE_BYTES] {
        Err(SecretEnvelopeError::Entropy)
    } else {
        Ok(nonce)
    }
}
