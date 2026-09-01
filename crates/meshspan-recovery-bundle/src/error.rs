// SPDX-License-Identifier: GPL-2.0-only

//! Secret-safe recovery-bundle failure categories.

use thiserror::Error;

/// Closed recovery-bundle failure categories without key, code or plaintext detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryBundleError {
    /// A supplied code, identifier, field or public certificate is malformed or out of bounds.
    #[error("recovery bundle input is invalid")]
    InvalidInput,
    /// Cryptographic entropy was unavailable or reserved entropy was produced.
    #[error("recovery bundle entropy is unavailable")]
    Entropy,
    /// The encoded file, authenticated fields or decrypted authority do not agree.
    #[error("recovery bundle is corrupt or the code is incorrect")]
    Corrupt,
    /// Certificate authority material could not be generated or reconstructed.
    #[error("recovery certificate authority is invalid or unavailable")]
    Certificate,
    /// Authenticated encryption or key derivation could not complete.
    #[error("recovery bundle cryptography is unavailable")]
    Unavailable,
}
