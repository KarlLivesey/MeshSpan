// SPDX-License-Identifier: GPL-2.0-only

//! Protected restart-stable node wrapping key for replicated secret envelopes.

use std::path::Path;

use meshspan_secret_envelope::{
    EncryptedSecret, RecipientKeyEnvelope, SecretPlaintext, WrappingPrivateKey, WrappingPublicKey,
};
use thiserror::Error;

use crate::OperatingSystemRandom;
use crate::protected_file::{self, ProtectedFileError, PublishMode};

const PRIVATE_KEY_BYTES: usize = 32;

/// One node-local X25519 wrapping key loaded from owner-only daemon state.
///
/// The type implements neither `Clone`, `Debug` nor `Display`; its private key never enters
/// replicated metadata. Only [`Self::public_key`] crosses the local-state boundary.
pub struct LocalWrappingKey {
    key: WrappingPrivateKey,
}

impl LocalWrappingKey {
    /// Opens an existing key or atomically creates one when the destination is exactly absent.
    ///
    /// # Errors
    ///
    /// Rejects unsafe, malformed or replaced files and unavailable cryptographic entropy.
    pub fn open_or_create(path: &Path) -> Result<Self, LocalWrappingKeyError> {
        match protected_file::read_bounded(path, PRIVATE_KEY_BYTES, PRIVATE_KEY_BYTES) {
            Ok(bytes) => Self::from_protected_bytes(&bytes),
            Err(ProtectedFileError::Missing) => Self::create(path),
            Err(error) => Err(error.into()),
        }
    }

    /// Opens an existing owner-only key without creating missing material.
    ///
    /// # Errors
    ///
    /// Rejects missing, unsafe, malformed, replaced or incorrectly sized files.
    pub fn open(path: &Path) -> Result<Self, LocalWrappingKeyError> {
        let bytes = protected_file::read_bounded(path, PRIVATE_KEY_BYTES, PRIVATE_KEY_BYTES)?;
        Self::from_protected_bytes(&bytes)
    }

    /// Returns the public wrapping identity safe for authoritative metadata.
    #[must_use]
    pub fn public_key(&self) -> WrappingPublicKey {
        self.key.public_key()
    }

    /// Opens one exact recipient envelope and decrypts its bound secret generation.
    ///
    /// The private wrapping key and intermediate secret data key remain inside this boundary.
    ///
    /// # Errors
    ///
    /// Rejects a different recipient, changed context or failed authenticated decryption.
    pub fn decrypt_secret(
        &self,
        secret: &EncryptedSecret,
        recipient: &RecipientKeyEnvelope,
    ) -> Result<SecretPlaintext, LocalWrappingKeyError> {
        if recipient.context() != secret.context() {
            return Err(LocalWrappingKeyError::Secret);
        }
        let key = recipient
            .open(&self.key)
            .map_err(|_| LocalWrappingKeyError::Secret)?;
        secret
            .decrypt(&key)
            .map_err(|_| LocalWrappingKeyError::Secret)
    }

    fn create(path: &Path) -> Result<Self, LocalWrappingKeyError> {
        let key = WrappingPrivateKey::generate(&mut OperatingSystemRandom)?;
        let bytes = key.expose_for_protected_persistence();
        protected_file::publish(path, bytes.as_ref(), PublishMode::Create)?;
        Ok(Self { key })
    }

    fn from_protected_bytes(bytes: &[u8]) -> Result<Self, LocalWrappingKeyError> {
        let private_bytes: [u8; PRIVATE_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| LocalWrappingKeyError::Invalid)?;
        let key = WrappingPrivateKey::from_bytes(private_bytes)
            .map_err(|_| LocalWrappingKeyError::Invalid)?;
        Ok(Self { key })
    }
}

/// Stable node-wrapping-key failure without path or key contents.
#[derive(Debug, Error)]
pub enum LocalWrappingKeyError {
    /// Owner-only atomic local-file handling failed.
    #[error("protected node wrapping key file failed")]
    File,
    /// Key generation failed because cryptographic entropy was unavailable.
    #[error("node wrapping key entropy is unavailable")]
    Entropy,
    /// Protected bytes do not contain one valid X25519 private key.
    #[error("node wrapping key is invalid")]
    Invalid,
    /// Replicated encrypted secret evidence could not be authenticated for this node.
    #[error("encrypted secret generation is invalid for this node")]
    Secret,
}

impl From<ProtectedFileError> for LocalWrappingKeyError {
    fn from(_: ProtectedFileError) -> Self {
        Self::File
    }
}

impl From<meshspan_secret_envelope::SecretEnvelopeError> for LocalWrappingKeyError {
    fn from(error: meshspan_secret_envelope::SecretEnvelopeError) -> Self {
        match error {
            meshspan_secret_envelope::SecretEnvelopeError::Entropy => Self::Entropy,
            _ => Self::Invalid,
        }
    }
}
