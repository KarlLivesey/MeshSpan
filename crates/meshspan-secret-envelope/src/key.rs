// SPDX-License-Identifier: GPL-2.0-only

//! Non-exportable-by-default data keys and node-local X25519 wrapping keys.

use meshspan_domain::RandomSource;
use sha2::{Digest, Sha256};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

use crate::SecretEnvelopeError;

const PUBLIC_KEY_FINGERPRINT_DOMAIN: &[u8] = b"meshspan.secret-envelope.recipient-key.v1\0";

/// One random secret-generation data-encryption key.
///
/// The type deliberately implements neither `Clone`, `Debug` nor byte export. It can only encrypt
/// a secret or enter an authenticated recipient envelope.
pub struct SecretDataKey(pub(crate) Zeroizing<[u8; 32]>);

impl SecretDataKey {
    pub(crate) fn generate(random: &mut impl RandomSource) -> Result<Self, SecretEnvelopeError> {
        let bytes = random_bytes(random)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn from_recovered(bytes: [u8; 32]) -> Result<Self, SecretEnvelopeError> {
        if bytes == [0; 32] {
            Err(SecretEnvelopeError::Corrupt)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }
}

/// Node-local or offline-recovery X25519 private wrapping key.
///
/// Private bytes are accepted only at the protected persistence boundary and zeroized on drop.
/// The type deliberately implements neither `Clone` nor `Debug`.
pub struct WrappingPrivateKey(Zeroizing<[u8; 32]>);

impl WrappingPrivateKey {
    /// Generates a new wrapping key from caller-supplied cryptographic entropy.
    ///
    /// # Errors
    ///
    /// Rejects unavailable or all-zero entropy.
    pub fn generate(random: &mut impl RandomSource) -> Result<Self, SecretEnvelopeError> {
        Ok(Self(Zeroizing::new(random_bytes(random)?)))
    }

    /// Loads exact private bytes from an already protected node-local or recovery boundary.
    ///
    /// # Errors
    ///
    /// Rejects all-zero key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SecretEnvelopeError> {
        if bytes == [0; 32] {
            Err(SecretEnvelopeError::InvalidInput)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }

    /// Returns the public recipient key safe for committed metadata.
    #[must_use]
    pub fn public_key(&self) -> WrappingPublicKey {
        WrappingPublicKey(x25519(*self.0, X25519_BASEPOINT_BYTES))
    }

    pub(crate) fn agree(&self, peer: WrappingPublicKey) -> Result<[u8; 32], SecretEnvelopeError> {
        contributory_shared_secret(x25519(*self.0, peer.0))
    }

    /// Copies private bytes only for the protected persistence adapter.
    #[must_use]
    pub fn expose_for_protected_persistence(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0)
    }
}

/// Public X25519 recipient key committed for one exact node or offline recovery identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WrappingPublicKey(pub(crate) [u8; 32]);

impl WrappingPublicKey {
    /// Validates public key bytes received from persistence or transport.
    ///
    /// Full low-order rejection occurs during contributory agreement because not every invalid
    /// Montgomery input is the all-zero encoding.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero public-key encoding.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SecretEnvelopeError> {
        if bytes == [0; 32] {
            Err(SecretEnvelopeError::InvalidRecipient)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns canonical public bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the domain-separated committed recipient-key fingerprint.
    #[must_use]
    pub fn fingerprint(self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(PUBLIC_KEY_FINGERPRINT_DOMAIN);
        digest.update(self.0);
        digest.finalize().into()
    }
}

pub(crate) fn ephemeral_agreement(
    recipient: WrappingPublicKey,
    random: &mut impl RandomSource,
) -> Result<(WrappingPublicKey, Zeroizing<[u8; 32]>), SecretEnvelopeError> {
    let private = Zeroizing::new(random_bytes(random)?);
    let public = WrappingPublicKey(x25519(*private, X25519_BASEPOINT_BYTES));
    let shared = contributory_shared_secret(x25519(*private, recipient.0))?;
    Ok((public, Zeroizing::new(shared)))
}

fn contributory_shared_secret(shared: [u8; 32]) -> Result<[u8; 32], SecretEnvelopeError> {
    if shared == [0; 32] {
        Err(SecretEnvelopeError::InvalidRecipient)
    } else {
        Ok(shared)
    }
}

fn random_bytes(random: &mut impl RandomSource) -> Result<[u8; 32], SecretEnvelopeError> {
    let mut bytes = [0_u8; 32];
    random
        .fill_bytes(&mut bytes)
        .map_err(|_| SecretEnvelopeError::Entropy)?;
    if bytes == [0; 32] {
        Err(SecretEnvelopeError::Entropy)
    } else {
        Ok(bytes)
    }
}
