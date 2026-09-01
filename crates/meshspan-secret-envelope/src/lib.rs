// SPDX-License-Identifier: GPL-2.0-only

//! Bounded generation-fenced secret encryption with per-recipient X25519 envelopes.
//!
//! Mesh metadata stores encrypted secret bytes and one envelope per exact authorised node or
//! recovery key. Private wrapping keys remain node-local; plaintext and data-encryption keys are
//! non-debuggable and zeroized on drop.

mod error;
mod key;
mod recipient;
mod secret;

pub use error::SecretEnvelopeError;
pub use key::{SecretDataKey, WrappingPrivateKey, WrappingPublicKey};
pub use recipient::{RecipientEnvelopeParts, RecipientKeyEnvelope};
pub use secret::{
    EncryptedSecret, EncryptedSecretParts, SecretContext, SecretPlaintext, encrypt_secret,
};

/// Maximum plaintext accepted by one encrypted secret generation.
pub const MAXIMUM_SECRET_BYTES: usize = 64 * 1_024;

/// Maximum exact recipients admitted for one secret generation.
pub const MAXIMUM_SECRET_RECIPIENTS: usize = 1_024;

#[cfg(test)]
mod tests;
