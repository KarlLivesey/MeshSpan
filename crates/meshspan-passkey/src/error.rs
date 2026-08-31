// SPDX-License-Identifier: GPL-2.0-only

//! Stable, non-disclosing passkey verification failures.

use core::fmt;

/// Stable failure category suitable for metrics without credential details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasskeyErrorKind {
    /// One input exceeded a documented bound.
    LimitExceeded,
    /// Encoded input was malformed or non-canonical.
    Malformed,
    /// The ceremony type, challenge, origin or relying party did not match.
    BindingMismatch,
    /// Required user presence or verification evidence was absent.
    UserInteractionRequired,
    /// Credential/public-key material is not in the supported profile.
    UnsupportedCredential,
    /// The assertion signature was not valid for the stored credential.
    InvalidSignature,
    /// A non-zero signature counter did not advance.
    CounterRegression,
}

/// Non-disclosing passkey verification error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasskeyError {
    kind: PasskeyErrorKind,
}

impl PasskeyError {
    pub(crate) const fn new(kind: PasskeyErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category without attacker-controlled details.
    #[must_use]
    pub const fn kind(self) -> PasskeyErrorKind {
        self.kind
    }
}

impl fmt::Display for PasskeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("passkey assertion was rejected")
    }
}

impl std::error::Error for PasskeyError {}
