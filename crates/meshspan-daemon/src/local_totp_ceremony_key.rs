// SPDX-License-Identifier: GPL-2.0-only

//! Protected restart-stable key for unfinished node-local TOTP enrolment ceremonies.

use std::path::Path;

use meshspan_domain::RandomSource;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::protected_file::{self, ProtectedFileError, PublishMode};
use crate::{OperatingSystemRandom, TotpCeremonyKey};

const KEY_BYTES: usize = 32;

/// Owner-only persisted TOTP ceremony key, distinct from every replicated mesh secret.
pub struct LocalTotpCeremonyKey {
    key: TotpCeremonyKey,
}

impl LocalTotpCeremonyKey {
    /// Opens an existing key or atomically creates one when the destination is exactly absent.
    ///
    /// # Errors
    ///
    /// Rejects unsafe, malformed or replaced files and unavailable cryptographic entropy.
    pub fn open_or_create(path: &Path) -> Result<Self, LocalTotpCeremonyKeyError> {
        match protected_file::read_bounded(path, KEY_BYTES, KEY_BYTES) {
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
    pub fn open(path: &Path) -> Result<Self, LocalTotpCeremonyKeyError> {
        let bytes = protected_file::read_bounded(path, KEY_BYTES, KEY_BYTES)?;
        Self::from_protected_bytes(&bytes)
    }

    /// Transfers the key into one registration service without exposing its bytes.
    #[must_use]
    pub fn into_key(self) -> TotpCeremonyKey {
        self.key
    }

    fn create(path: &Path) -> Result<Self, LocalTotpCeremonyKeyError> {
        let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
        OperatingSystemRandom
            .fill_bytes(bytes.as_mut())
            .map_err(|_| LocalTotpCeremonyKeyError::Entropy)?;
        let key =
            TotpCeremonyKey::from_bytes(*bytes).map_err(|_| LocalTotpCeremonyKeyError::Invalid)?;
        protected_file::publish(path, bytes.as_ref(), PublishMode::Create)?;
        Ok(Self { key })
    }

    fn from_protected_bytes(bytes: &[u8]) -> Result<Self, LocalTotpCeremonyKeyError> {
        let key_bytes: [u8; KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| LocalTotpCeremonyKeyError::Invalid)?;
        let key = TotpCeremonyKey::from_bytes(key_bytes)
            .map_err(|_| LocalTotpCeremonyKeyError::Invalid)?;
        Ok(Self { key })
    }
}

/// Stable local TOTP-ceremony-key failure without path or key contents.
#[derive(Debug, Error)]
pub enum LocalTotpCeremonyKeyError {
    /// Owner-only atomic local-file handling failed.
    #[error("protected TOTP ceremony key file failed")]
    File,
    /// Key generation failed because cryptographic entropy was unavailable.
    #[error("TOTP ceremony key entropy is unavailable")]
    Entropy,
    /// Protected bytes do not contain one valid key.
    #[error("TOTP ceremony key is invalid")]
    Invalid,
}

impl From<ProtectedFileError> for LocalTotpCeremonyKeyError {
    fn from(_: ProtectedFileError) -> Self {
        Self::File
    }
}
