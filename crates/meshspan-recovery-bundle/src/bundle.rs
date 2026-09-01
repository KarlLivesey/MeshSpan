// SPDX-License-Identifier: GPL-2.0-only

//! Canonical authenticated recovery-bundle file encoding.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use meshspan_domain::{MeshId, RandomSource};
use meshspan_secret_envelope::{WrappingPrivateKey, WrappingPublicKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{RecoveryBundleCode, RecoveryBundleError, RecoveryChallenge};

const MAGIC: &[u8] = b"MESHSPAN-RECOVERY\0";
const FORMAT_VERSION: u8 = 1;
const SALT_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const DIGEST_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const MAXIMUM_ROOT_CERTIFICATE_BYTES: usize = 8 * 1_024;
const MAXIMUM_ROOT_PRIVATE_KEY_BYTES: usize = 2 * 1_024;
const BUNDLE_KDF_DOMAIN: &[u8] = b"meshspan.recovery-bundle.kdf.v1\0";
const BUNDLE_AAD_DOMAIN: &[u8] = b"meshspan.recovery-bundle.aad.v1\0";
const BUNDLE_DIGEST_DOMAIN: &[u8] = b"meshspan.recovery-bundle.digest.v1\0";
const PRIVATE_PAYLOAD_DOMAIN: &[u8] = b"meshspan.recovery-bundle.private.v1\0";

/// Maximum accepted encoded recovery-bundle file size.
pub const MAXIMUM_RECOVERY_BUNDLE_BYTES: usize = 16 * 1_024;

/// Validated public and encrypted fields of one recovery bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryBundleParts {
    /// Stable format version.
    pub format_version: u8,
    /// Exact owning mesh.
    pub mesh_id: MeshId,
    /// Offline public key admitted as a recovery secret recipient.
    pub recovery_public_key: [u8; 32],
    /// Offline root certificate committed as mesh identity.
    pub root_certificate_der: Vec<u8>,
    /// Fresh HKDF salt.
    pub salt: [u8; SALT_BYTES],
    /// Fresh XChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_BYTES],
    /// Authenticated encrypted private payload including its tag.
    pub ciphertext: Vec<u8>,
    /// Domain-separated digest of every encoded field.
    pub digest: [u8; DIGEST_BYTES],
}

/// Portable encrypted recovery-bundle file for one exact mesh.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryBundle(RecoveryBundleParts);

impl RecoveryBundle {
    pub(crate) fn encrypt(
        mesh_id: MeshId,
        recovery_key: &WrappingPrivateKey,
        root_certificate_der: &[u8],
        root_private_key: &[u8],
        code: &RecoveryBundleCode,
        random: &mut impl RandomSource,
    ) -> Result<Self, RecoveryBundleError> {
        validate_public_fields(mesh_id, recovery_key.public_key(), root_certificate_der)?;
        if !(1..=MAXIMUM_ROOT_PRIVATE_KEY_BYTES).contains(&root_private_key.len()) {
            return Err(RecoveryBundleError::InvalidInput);
        }
        let salt = random_nonzero(random)?;
        let nonce = random_nonce(random)?;
        let public_key = recovery_key.public_key();
        let aad = associated_data(mesh_id, public_key, root_certificate_der, &salt, &nonce)?;
        let key = derive_key(code, &aad, &salt)?;
        let plaintext = private_payload(
            recovery_key,
            root_private_key,
            certificate_digest(root_certificate_der),
        )?;
        let ciphertext = cipher(&key)?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| RecoveryBundleError::Unavailable)?;
        let mut parts = RecoveryBundleParts {
            format_version: FORMAT_VERSION,
            mesh_id,
            recovery_public_key: public_key.as_bytes(),
            root_certificate_der: root_certificate_der.to_vec(),
            salt,
            nonce,
            ciphertext,
            digest: [0; DIGEST_BYTES],
        };
        parts.digest = bundle_digest(&parts)?;
        Self::from_parts(parts)
    }

    /// Validates already separated persisted fields.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, invalid public keys, reserved values, bounds or digest mismatch.
    pub fn from_parts(parts: RecoveryBundleParts) -> Result<Self, RecoveryBundleError> {
        let public_key = WrappingPublicKey::from_bytes(parts.recovery_public_key)
            .map_err(|_| RecoveryBundleError::Corrupt)?;
        validate_public_fields(parts.mesh_id, public_key, &parts.root_certificate_der)
            .map_err(|_| RecoveryBundleError::Corrupt)?;
        let valid_ciphertext = (TAG_BYTES + 1
            ..=TAG_BYTES + 32 + 2 + MAXIMUM_ROOT_PRIVATE_KEY_BYTES + DIGEST_BYTES)
            .contains(&parts.ciphertext.len());
        if parts.format_version != FORMAT_VERSION
            || parts.salt == [0; SALT_BYTES]
            || parts.nonce == [0; NONCE_BYTES]
            || !valid_ciphertext
            || parts.digest != bundle_digest(&parts)?
        {
            return Err(RecoveryBundleError::Corrupt);
        }
        Ok(Self(parts))
    }

    /// Decodes and validates one complete opaque recovery file.
    ///
    /// # Errors
    ///
    /// Rejects truncation, excess bytes, unknown versions, malformed lengths or changed fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecoveryBundleError> {
        if bytes.len() > MAXIMUM_RECOVERY_BUNDLE_BYTES {
            return Err(RecoveryBundleError::InvalidInput);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(MAGIC.len())? != MAGIC {
            return Err(RecoveryBundleError::Corrupt);
        }
        let format_version = decoder.byte()?;
        let mesh_id =
            MeshId::from_bytes(decoder.array()?).map_err(|_| RecoveryBundleError::Corrupt)?;
        let recovery_public_key = decoder.array()?;
        let root_certificate_der = decoder.bounded_bytes(MAXIMUM_ROOT_CERTIFICATE_BYTES)?;
        let salt = decoder.array()?;
        let nonce = decoder.array()?;
        let ciphertext = decoder
            .bounded_bytes(TAG_BYTES + 32 + 2 + MAXIMUM_ROOT_PRIVATE_KEY_BYTES + DIGEST_BYTES)?;
        let digest = decoder.array()?;
        decoder.finish()?;
        Self::from_parts(RecoveryBundleParts {
            format_version,
            mesh_id,
            recovery_public_key,
            root_certificate_der,
            salt,
            nonce,
            ciphertext,
            digest,
        })
    }

    /// Encodes the canonical opaque file bytes.
    ///
    /// # Errors
    ///
    /// Fails closed if any platform length cannot enter the fixed portable encoding.
    pub fn encode(&self) -> Result<Vec<u8>, RecoveryBundleError> {
        let mut output =
            Vec::with_capacity(MAXIMUM_RECOVERY_BUNDLE_BYTES.min(
                MAGIC.len() + 138 + self.0.root_certificate_der.len() + self.0.ciphertext.len(),
            ));
        output.extend_from_slice(MAGIC);
        output.push(self.0.format_version);
        output.extend_from_slice(&self.0.mesh_id.as_bytes());
        output.extend_from_slice(&self.0.recovery_public_key);
        append_bytes(&mut output, &self.0.root_certificate_der)?;
        output.extend_from_slice(&self.0.salt);
        output.extend_from_slice(&self.0.nonce);
        append_bytes(&mut output, &self.0.ciphertext)?;
        output.extend_from_slice(&self.0.digest);
        if output.len() > MAXIMUM_RECOVERY_BUNDLE_BYTES {
            Err(RecoveryBundleError::InvalidInput)
        } else {
            Ok(output)
        }
    }

    /// Returns a copy of validated public/encrypted fields for persistence or transport.
    #[must_use]
    pub fn parts(&self) -> RecoveryBundleParts {
        self.0.clone()
    }

    /// Returns the immutable owning mesh.
    #[must_use]
    pub const fn mesh_id(&self) -> MeshId {
        self.0.mesh_id
    }

    /// Returns the committed offline recovery recipient.
    ///
    /// # Errors
    ///
    /// Fails only if in-memory validated evidence has been corrupted.
    pub fn recovery_public_key(&self) -> Result<WrappingPublicKey, RecoveryBundleError> {
        WrappingPublicKey::from_bytes(self.0.recovery_public_key)
            .map_err(|_| RecoveryBundleError::Corrupt)
    }

    /// Borrows the root certificate safe for committed mesh identity.
    #[must_use]
    pub fn root_certificate_der(&self) -> &[u8] {
        &self.0.root_certificate_der
    }

    /// Returns the digest binding the exact downloaded bundle file.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.0.digest
    }

    /// Derives the short save-verification proof from this exact file and its separate code.
    #[must_use]
    pub fn challenge(&self, code: &RecoveryBundleCode) -> RecoveryChallenge {
        code.challenge(self.0.digest)
    }

    pub(crate) fn decrypt_private_payload(
        &self,
        code: &RecoveryBundleCode,
    ) -> Result<DecryptedPrivatePayload, RecoveryBundleError> {
        let public_key = self.recovery_public_key()?;
        let aad = associated_data(
            self.0.mesh_id,
            public_key,
            &self.0.root_certificate_der,
            &self.0.salt,
            &self.0.nonce,
        )?;
        let key = derive_key(code, &aad, &self.0.salt)?;
        let plaintext = Zeroizing::new(
            cipher(&key)?
                .decrypt(
                    &XNonce::from(self.0.nonce),
                    Payload {
                        msg: &self.0.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| RecoveryBundleError::Corrupt)?,
        );
        decode_private_payload(&plaintext)
    }
}

pub(crate) struct DecryptedPrivatePayload {
    pub recovery_private_key: [u8; 32],
    pub root_private_key: Zeroizing<Vec<u8>>,
    pub root_certificate_digest: [u8; 32],
}

fn private_payload(
    recovery_key: &WrappingPrivateKey,
    root_private_key: &[u8],
    root_certificate_digest: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, RecoveryBundleError> {
    let key = recovery_key.expose_for_protected_persistence();
    let mut output = Zeroizing::new(Vec::with_capacity(
        PRIVATE_PAYLOAD_DOMAIN.len() + 66 + root_private_key.len(),
    ));
    output.extend_from_slice(PRIVATE_PAYLOAD_DOMAIN);
    output.extend_from_slice(key.as_ref());
    let length =
        u16::try_from(root_private_key.len()).map_err(|_| RecoveryBundleError::InvalidInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(root_private_key);
    output.extend_from_slice(&root_certificate_digest);
    Ok(output)
}

fn decode_private_payload(bytes: &[u8]) -> Result<DecryptedPrivatePayload, RecoveryBundleError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take(PRIVATE_PAYLOAD_DOMAIN.len())? != PRIVATE_PAYLOAD_DOMAIN {
        return Err(RecoveryBundleError::Corrupt);
    }
    let recovery_private_key = decoder.array()?;
    let root_key_length = usize::from(u16::from_be_bytes(decoder.array()?));
    if !(1..=MAXIMUM_ROOT_PRIVATE_KEY_BYTES).contains(&root_key_length) {
        return Err(RecoveryBundleError::Corrupt);
    }
    let root_private_key = Zeroizing::new(decoder.take(root_key_length)?.to_vec());
    let root_certificate_digest = decoder.array()?;
    decoder.finish()?;
    Ok(DecryptedPrivatePayload {
        recovery_private_key,
        root_private_key,
        root_certificate_digest,
    })
}

fn validate_public_fields(
    mesh_id: MeshId,
    public_key: WrappingPublicKey,
    root_certificate_der: &[u8],
) -> Result<(), RecoveryBundleError> {
    if mesh_id.as_bytes() == [0; 16]
        || public_key.as_bytes() == [0; 32]
        || !(1..=MAXIMUM_ROOT_CERTIFICATE_BYTES).contains(&root_certificate_der.len())
    {
        Err(RecoveryBundleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn associated_data(
    mesh_id: MeshId,
    public_key: WrappingPublicKey,
    root_certificate_der: &[u8],
    salt: &[u8; SALT_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>, RecoveryBundleError> {
    let mut aad = Vec::with_capacity(BUNDLE_AAD_DOMAIN.len() + 108 + root_certificate_der.len());
    aad.extend_from_slice(BUNDLE_AAD_DOMAIN);
    aad.extend_from_slice(&mesh_id.as_bytes());
    aad.extend_from_slice(&public_key.as_bytes());
    append_bytes(&mut aad, root_certificate_der)?;
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    Ok(aad)
}

fn derive_key(
    code: &RecoveryBundleCode,
    aad: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; 32]>, RecoveryBundleError> {
    let mut info = Vec::with_capacity(BUNDLE_KDF_DOMAIN.len() + aad.len());
    info.extend_from_slice(BUNDLE_KDF_DOMAIN);
    info.extend_from_slice(aad);
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), code.key_bytes())
        .expand(&info, key.as_mut())
        .map_err(|_| RecoveryBundleError::Unavailable)?;
    Ok(key)
}

fn cipher(key: &[u8; 32]) -> Result<XChaCha20Poly1305, RecoveryBundleError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| RecoveryBundleError::Unavailable)
}

fn bundle_digest(parts: &RecoveryBundleParts) -> Result<[u8; 32], RecoveryBundleError> {
    let mut digest = Sha256::new();
    digest.update(BUNDLE_DIGEST_DOMAIN);
    digest.update([parts.format_version]);
    digest.update(parts.mesh_id.as_bytes());
    digest.update(parts.recovery_public_key);
    update_bytes(&mut digest, &parts.root_certificate_der)?;
    digest.update(parts.salt);
    digest.update(parts.nonce);
    update_bytes(&mut digest, &parts.ciphertext)?;
    Ok(digest.finalize().into())
}

pub(crate) fn certificate_digest(certificate: &[u8]) -> [u8; 32] {
    Sha256::digest(certificate).into()
}

fn update_bytes(digest: &mut Sha256, bytes: &[u8]) -> Result<(), RecoveryBundleError> {
    let length = u32::try_from(bytes.len()).map_err(|_| RecoveryBundleError::InvalidInput)?;
    digest.update(length.to_be_bytes());
    digest.update(bytes);
    Ok(())
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RecoveryBundleError> {
    let length = u32::try_from(bytes.len()).map_err(|_| RecoveryBundleError::InvalidInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn random_nonzero(random: &mut impl RandomSource) -> Result<[u8; SALT_BYTES], RecoveryBundleError> {
    let mut bytes = [0; SALT_BYTES];
    random
        .fill_bytes(&mut bytes)
        .map_err(|_| RecoveryBundleError::Entropy)?;
    if bytes == [0; SALT_BYTES] {
        Err(RecoveryBundleError::Entropy)
    } else {
        Ok(bytes)
    }
}

fn random_nonce(random: &mut impl RandomSource) -> Result<[u8; NONCE_BYTES], RecoveryBundleError> {
    let mut bytes = [0; NONCE_BYTES];
    random
        .fill_bytes(&mut bytes)
        .map_err(|_| RecoveryBundleError::Entropy)?;
    if bytes == [0; NONCE_BYTES] {
        Err(RecoveryBundleError::Entropy)
    } else {
        Ok(bytes)
    }
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RecoveryBundleError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(RecoveryBundleError::Corrupt)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, RecoveryBundleError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(RecoveryBundleError::Corrupt)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RecoveryBundleError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RecoveryBundleError::Corrupt)
    }

    fn bounded_bytes(&mut self, maximum: usize) -> Result<Vec<u8>, RecoveryBundleError> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| RecoveryBundleError::Corrupt)?;
        if length == 0 || length > maximum {
            return Err(RecoveryBundleError::Corrupt);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn finish(self) -> Result<(), RecoveryBundleError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(RecoveryBundleError::Corrupt)
        }
    }
}
