// SPDX-License-Identifier: GPL-2.0-only

//! Closed encrypted-backup failures.

use thiserror::Error;

/// Failure while creating or restoring an authenticated metadata backup.
#[derive(Debug, Error)]
pub enum BackupError {
    /// Caller-supplied identities, positions, sizes or recipients are invalid.
    #[error("backup input is invalid")]
    InvalidInput,
    /// A parsed backup violates its bounded format or authentication contract.
    #[error("backup is corrupt or does not match its manifest")]
    Corrupt,
    /// A destination already exists and therefore cannot be replaced safely.
    #[error("backup destination already exists")]
    DestinationExists,
    /// No envelope grants the supplied recovery key access to this backup.
    #[error("recovery key is not a recipient of this backup")]
    RecipientUnavailable,
    /// Cryptographic entropy or an authenticated operation failed.
    #[error("backup cryptography is unavailable")]
    Cryptography,
    /// A local filesystem operation failed.
    #[error("backup filesystem operation failed")]
    Io(#[from] std::io::Error),
}

impl From<meshspan_secret_envelope::SecretEnvelopeError> for BackupError {
    fn from(error: meshspan_secret_envelope::SecretEnvelopeError) -> Self {
        match error {
            meshspan_secret_envelope::SecretEnvelopeError::Corrupt => Self::Corrupt,
            meshspan_secret_envelope::SecretEnvelopeError::InvalidRecipient
            | meshspan_secret_envelope::SecretEnvelopeError::InvalidInput => Self::InvalidInput,
            meshspan_secret_envelope::SecretEnvelopeError::Entropy
            | meshspan_secret_envelope::SecretEnvelopeError::Unavailable => Self::Cryptography,
        }
    }
}
