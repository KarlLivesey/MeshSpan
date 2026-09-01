// SPDX-License-Identifier: GPL-2.0-only

//! Stable secret-envelope failure categories without key or plaintext detail.

use thiserror::Error;

/// Closed failure categories for secret encryption and recipient envelopes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretEnvelopeError {
    /// Context, bounds, key material or stored field shape is invalid.
    #[error("secret envelope input is invalid")]
    InvalidInput,
    /// Recipient public material cannot produce a contributory X25519 agreement.
    #[error("secret envelope recipient is invalid")]
    InvalidRecipient,
    /// Cryptographic entropy was unavailable or failed its basic health boundary.
    #[error("secret envelope entropy is unavailable")]
    Entropy,
    /// Digest, context, recipient or authenticated ciphertext does not verify.
    #[error("secret envelope evidence is corrupt")]
    Corrupt,
    /// Authenticated encryption or key derivation could not complete.
    #[error("secret envelope cryptography is unavailable")]
    Unavailable,
}
