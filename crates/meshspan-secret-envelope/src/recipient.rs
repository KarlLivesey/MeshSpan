// SPDX-License-Identifier: GPL-2.0-only

//! Per-recipient X25519 wrapping of one secret-generation data key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use meshspan_domain::RandomSource;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::key::{SecretDataKey, ephemeral_agreement};
use crate::{SecretContext, SecretEnvelopeError, WrappingPrivateKey, WrappingPublicKey};

const FORMAT_VERSION: u8 = 1;
const SALT_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const WRAPPED_KEY_BYTES: usize = 32;
const AUTHENTICATION_TAG_BYTES: usize = 16;
const ENVELOPE_AAD_DOMAIN: &[u8] = b"meshspan.secret-envelope.recipient-aad.v1\0";
const ENVELOPE_KDF_DOMAIN: &[u8] = b"meshspan.secret-envelope.recipient-kdf.v1\0";
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"meshspan.secret-envelope.recipient-digest.v1\0";

/// Persisted fields for one exact recipient's wrapped data key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientEnvelopeParts {
    /// Wire and storage format version.
    pub format_version: u8,
    /// Immutable secret authority and generation binding.
    pub context: SecretContext,
    /// Authorised recipient public wrapping key.
    pub recipient_public_key: [u8; 32],
    /// One-use sender public key for this envelope.
    pub ephemeral_public_key: [u8; 32],
    /// Fresh HKDF salt.
    pub salt: [u8; SALT_BYTES],
    /// Fresh XChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_BYTES],
    /// Authenticated wrapped data key including its tag.
    pub ciphertext: Vec<u8>,
    /// Domain-separated digest covering every persisted field.
    pub digest: [u8; 32],
}

/// Validated per-recipient envelope for one secret-generation data key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientKeyEnvelope(RecipientEnvelopeParts);

impl RecipientKeyEnvelope {
    pub(crate) fn wrap(
        context: SecretContext,
        recipient: WrappingPublicKey,
        key: &SecretDataKey,
        random: &mut impl RandomSource,
    ) -> Result<Self, SecretEnvelopeError> {
        let (ephemeral, shared) = ephemeral_agreement(recipient, random)?;
        let salt = random_array(random)?;
        let nonce = random_nonce(random)?;
        let wrapping_key = derive_wrapping_key(&shared, context, recipient, ephemeral, &salt)?;
        let aad = envelope_associated_data(context, recipient, ephemeral, &salt, &nonce);
        let ciphertext = envelope_cipher(&wrapping_key)?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: key.0.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| SecretEnvelopeError::Unavailable)?;
        let mut parts = RecipientEnvelopeParts {
            format_version: FORMAT_VERSION,
            context,
            recipient_public_key: recipient.as_bytes(),
            ephemeral_public_key: ephemeral.as_bytes(),
            salt,
            nonce,
            ciphertext,
            digest: [0; 32],
        };
        parts.digest = envelope_digest(&parts);
        Self::from_parts(parts)
    }

    /// Restores and validates persisted recipient-envelope fields.
    ///
    /// # Errors
    ///
    /// Rejects unknown formats, invalid keys, reserved entropy, field bounds or digest mismatch.
    pub fn from_parts(parts: RecipientEnvelopeParts) -> Result<Self, SecretEnvelopeError> {
        validate_parts(&parts)?;
        Ok(Self(parts))
    }

    /// Returns the immutable secret identity and generation.
    #[must_use]
    pub const fn context(&self) -> SecretContext {
        self.0.context
    }

    /// Returns the exact validated public key authorised to open this envelope.
    ///
    /// # Errors
    ///
    /// Rejects invalid persisted recipient public material.
    pub fn recipient_public_key(&self) -> Result<WrappingPublicKey, SecretEnvelopeError> {
        WrappingPublicKey::from_bytes(self.0.recipient_public_key)
    }

    /// Returns the exact recipient-key fingerprint.
    ///
    /// # Errors
    ///
    /// Rejects invalid persisted recipient public material.
    pub fn recipient_fingerprint(&self) -> Result<[u8; 32], SecretEnvelopeError> {
        Ok(self.recipient_public_key()?.fingerprint())
    }

    /// Copies the persisted representation for metadata storage or transport.
    #[must_use]
    pub fn parts(&self) -> RecipientEnvelopeParts {
        self.0.clone()
    }

    /// Authenticates and opens this data key with the exact recipient private key.
    ///
    /// # Errors
    ///
    /// Rejects recipient substitution, changed context, invalid agreement or failed authentication.
    pub fn open(
        &self,
        recipient_private_key: &WrappingPrivateKey,
    ) -> Result<SecretDataKey, SecretEnvelopeError> {
        let recipient = WrappingPublicKey::from_bytes(self.0.recipient_public_key)?;
        if recipient_private_key.public_key() != recipient {
            return Err(SecretEnvelopeError::Corrupt);
        }
        let ephemeral = WrappingPublicKey::from_bytes(self.0.ephemeral_public_key)?;
        let shared = Zeroizing::new(recipient_private_key.agree(ephemeral)?);
        let wrapping_key =
            derive_wrapping_key(&shared, self.0.context, recipient, ephemeral, &self.0.salt)?;
        let aad = envelope_associated_data(
            self.0.context,
            recipient,
            ephemeral,
            &self.0.salt,
            &self.0.nonce,
        );
        let plaintext = envelope_cipher(&wrapping_key)?
            .decrypt(
                &XNonce::from(self.0.nonce),
                Payload {
                    msg: &self.0.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| SecretEnvelopeError::Corrupt)?;
        let recovered: [u8; WRAPPED_KEY_BYTES] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| SecretEnvelopeError::Corrupt)?;
        SecretDataKey::from_recovered(recovered)
    }
}

fn validate_parts(parts: &RecipientEnvelopeParts) -> Result<(), SecretEnvelopeError> {
    let recipient = WrappingPublicKey::from_bytes(parts.recipient_public_key)
        .map_err(|_| SecretEnvelopeError::Corrupt)?;
    let ephemeral = WrappingPublicKey::from_bytes(parts.ephemeral_public_key)
        .map_err(|_| SecretEnvelopeError::Corrupt)?;
    let invalid = parts.format_version != FORMAT_VERSION
        || parts.salt == [0; SALT_BYTES]
        || parts.nonce == [0; NONCE_BYTES]
        || parts.ciphertext.len() != WRAPPED_KEY_BYTES + AUTHENTICATION_TAG_BYTES
        || recipient == ephemeral
        || parts.digest != envelope_digest(parts);
    if invalid {
        Err(SecretEnvelopeError::Corrupt)
    } else {
        Ok(())
    }
}

fn derive_wrapping_key(
    shared: &[u8; 32],
    context: SecretContext,
    recipient: WrappingPublicKey,
    ephemeral: WrappingPublicKey,
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; 32]>, SecretEnvelopeError> {
    let mut info = Vec::with_capacity(ENVELOPE_KDF_DOMAIN.len() + 90);
    info.extend_from_slice(ENVELOPE_KDF_DOMAIN);
    context.append_to(&mut info);
    info.extend_from_slice(&recipient.as_bytes());
    info.extend_from_slice(&ephemeral.as_bytes());
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), shared)
        .expand(&info, key.as_mut())
        .map_err(|_| SecretEnvelopeError::Unavailable)?;
    Ok(key)
}

fn envelope_cipher(key: &[u8; 32]) -> Result<XChaCha20Poly1305, SecretEnvelopeError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| SecretEnvelopeError::Unavailable)
}

fn envelope_associated_data(
    context: SecretContext,
    recipient: WrappingPublicKey,
    ephemeral: WrappingPublicKey,
    salt: &[u8; SALT_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENVELOPE_AAD_DOMAIN.len() + 114);
    aad.extend_from_slice(ENVELOPE_AAD_DOMAIN);
    context.append_to(&mut aad);
    aad.extend_from_slice(&recipient.as_bytes());
    aad.extend_from_slice(&ephemeral.as_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

fn envelope_digest(parts: &RecipientEnvelopeParts) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ENVELOPE_DIGEST_DOMAIN);
    digest.update([parts.format_version]);
    let mut context = Vec::with_capacity(26);
    parts.context.append_to(&mut context);
    digest.update(context);
    digest.update(parts.recipient_public_key);
    digest.update(parts.ephemeral_public_key);
    digest.update(parts.salt);
    digest.update(parts.nonce);
    digest.update((parts.ciphertext.len() as u64).to_be_bytes());
    digest.update(&parts.ciphertext);
    digest.finalize().into()
}

fn random_array(random: &mut impl RandomSource) -> Result<[u8; SALT_BYTES], SecretEnvelopeError> {
    let mut bytes = [0_u8; SALT_BYTES];
    random
        .fill_bytes(&mut bytes)
        .map_err(|_| SecretEnvelopeError::Entropy)?;
    if bytes == [0; SALT_BYTES] {
        Err(SecretEnvelopeError::Entropy)
    } else {
        Ok(bytes)
    }
}

fn random_nonce(random: &mut impl RandomSource) -> Result<[u8; NONCE_BYTES], SecretEnvelopeError> {
    let mut bytes = [0_u8; NONCE_BYTES];
    random
        .fill_bytes(&mut bytes)
        .map_err(|_| SecretEnvelopeError::Entropy)?;
    if bytes == [0; NONCE_BYTES] {
        Err(SecretEnvelopeError::Entropy)
    } else {
        Ok(bytes)
    }
}
