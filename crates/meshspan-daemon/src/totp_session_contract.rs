// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable boundary for verifying TOTP session factors.

use meshspan_domain::{AuthenticationMethodId, PrincipalId, Revision, UnixMicros};
use meshspan_metadata::TotpVerificationMaterial;
use thiserror::Error;

/// Exact accepted TOTP evidence passed to authoritative session issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedTotpFactor {
    /// User account authenticated by the already-established primary factor.
    pub principal_id: PrincipalId,
    /// Independently revocable TOTP method whose code matched.
    pub method_id: AuthenticationMethodId,
    /// Exact credential generation observed by the verifier.
    pub credential_generation: u64,
    /// Exact method revision observed by the verifier.
    pub method_revision: Revision,
    /// Exact current step whose code matched.
    pub accepted_step: u64,
}

/// Replaceable verifier consumed by authoritative session issuance.
pub trait TotpFactorVerifier {
    /// Verifies one fresh code against all bounded active methods for the authenticated user.
    ///
    /// # Errors
    ///
    /// Rejects malformed, incorrect, unavailable, substituted or corrupt evidence.
    fn verify_current(
        &self,
        principal_id: PrincipalId,
        materials: &[TotpVerificationMaterial],
        code: &str,
        now: UnixMicros,
    ) -> Result<VerifiedTotpFactor, TotpSessionError>;

    /// Verifies an exact code against an already-authoritatively consumed method and step.
    ///
    /// This is exclusively for exact operation replay and does not admit a new authentication.
    ///
    /// # Errors
    ///
    /// Rejects changed input, missing current authority, or invalid protected evidence.
    fn verify_replay(
        &self,
        principal_id: PrincipalId,
        materials: &[TotpVerificationMaterial],
        method_id: AuthenticationMethodId,
        code: &str,
        accepted_step: u64,
    ) -> Result<(), TotpSessionError>;
}

/// Default adapter which keeps TOTP login closed until a mesh envelope key is composed.
pub struct DisabledTotpFactors;

impl TotpFactorVerifier for DisabledTotpFactors {
    fn verify_current(
        &self,
        _: PrincipalId,
        _: &[TotpVerificationMaterial],
        _: &str,
        _: UnixMicros,
    ) -> Result<VerifiedTotpFactor, TotpSessionError> {
        Err(TotpSessionError::Unsupported)
    }

    fn verify_replay(
        &self,
        _: PrincipalId,
        _: &[TotpVerificationMaterial],
        _: AuthenticationMethodId,
        _: &str,
        _: u64,
    ) -> Result<(), TotpSessionError> {
        Err(TotpSessionError::Unsupported)
    }
}

/// Stable TOTP verification failure containing no code or seed material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TotpSessionError {
    /// No TOTP adapter was explicitly composed.
    #[error("TOTP session factors are not configured")]
    Unsupported,
    /// Current encrypted mesh key authority cannot serve verification.
    #[error("TOTP authentication is temporarily unavailable")]
    Unavailable,
    /// The code did not match current authoritative evidence.
    #[error("TOTP authentication was rejected")]
    Rejected,
    /// Encrypted material, parameters or authority bindings failed closed.
    #[error("TOTP authentication evidence is invalid")]
    InvalidEvidence,
    /// Authoritative time cannot be represented safely.
    #[error("TOTP authentication time is invalid")]
    InvalidTime,
}
