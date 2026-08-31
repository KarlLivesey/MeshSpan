// SPDX-License-Identifier: GPL-2.0-only

//! Persistence, replicated-authority and failure contracts for TOTP registration.

use meshspan_domain::{AuthenticationMethodId, OperationId, UnixMicros};
use meshspan_metadata::{AuthenticationRegistrationProfile, AuthoritativeCommand, CommandContext};
use thiserror::Error;

use crate::totp_registration_state::TotpRegistrationStateError;
use crate::{
    AuthenticationRegistrationStoreError, BrowserAuthenticationError, BrowserSessionAuthority,
};

/// Replicated reads and mutation required by current-user TOTP registration.
pub trait TotpRegistrationAuthority: BrowserSessionAuthority {
    /// Loads one current active user's canonical registration identity.
    ///
    /// # Errors
    ///
    /// Fails closed when replicated identity evidence is unavailable or malformed.
    fn registration_profile(
        &self,
        principal_id: meshspan_domain::PrincipalId,
    ) -> Result<Option<AuthenticationRegistrationProfile>, TotpRegistrationAuthorityError>;

    /// Resolves an already committed TOTP method creation.
    ///
    /// # Errors
    ///
    /// Rejects an operation naming another command family and fails closed for malformed
    /// authoritative evidence.
    fn resolve_registration(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<TotpRegistrationCommit>, TotpRegistrationAuthorityError>;

    /// Commits or exactly resolves one TOTP method creation through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never claims success without a durable result.
    fn commit_or_resolve_registration(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<TotpRegistrationCommit, TotpRegistrationAuthorityError>;
}

/// Exact durable facts returned by authoritative TOTP method creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotpRegistrationCommit {
    /// Semantic request digest stored by authority.
    pub request_digest: [u8; 32],
    /// Digest of the durable command result.
    pub result_digest: [u8; 32],
    /// Exact created method.
    pub method_id: AuthenticationMethodId,
    /// Exact owning user.
    pub principal_id: meshspan_domain::PrincipalId,
    /// Original authoritative creation instant.
    pub created_at: UnixMicros,
}

/// Closed replicated-authority TOTP registration failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TotpRegistrationAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("TOTP registration authority is unavailable")]
    Unavailable,
    /// Operation identity is already bound to different input.
    #[error("TOTP registration authority conflicts with durable state")]
    Conflict,
    /// Persisted authority or its receipt failed validation.
    #[error("TOTP registration authority failed closed")]
    Failed,
}

/// Stable TOTP registration failure containing no seed, code or session material.
#[derive(Debug, Error)]
pub enum TotpRegistrationError {
    /// Public identifiers or bounded fields are invalid.
    #[error("TOTP registration request is invalid")]
    InvalidRequest,
    /// The current browser session or confirmation code was rejected.
    #[error("TOTP registration was rejected")]
    Rejected,
    /// The challenge or operation conflicts with durable state.
    #[error("TOTP registration conflicts with durable state")]
    Conflict,
    /// The challenge lifetime cannot be represented safely.
    #[error("TOTP registration time window is invalid")]
    InvalidTime,
    /// Cryptographic entropy was unavailable.
    #[error("TOTP registration is unavailable")]
    Unavailable,
    /// Current browser authentication failed.
    #[error("TOTP registration authentication failed")]
    Authentication(#[source] BrowserAuthenticationError),
    /// Node-local journal failure.
    #[error("TOTP registration local state failed")]
    Store(#[from] AuthenticationRegistrationStoreError),
    /// Protected registration state or seed-envelope failure.
    #[error("TOTP registration protected state failed")]
    State,
    /// Replicated authority failure.
    #[error("TOTP registration authority failed")]
    Authority(#[from] TotpRegistrationAuthorityError),
    /// Durable result evidence is invalid.
    #[error("TOTP registration receipt is invalid")]
    InvalidReceipt,
}

impl From<crate::TotpRegistrationConfigurationError> for TotpRegistrationError {
    fn from(_: crate::TotpRegistrationConfigurationError) -> Self {
        Self::InvalidRequest
    }
}

impl From<TotpRegistrationStateError> for TotpRegistrationError {
    fn from(_: TotpRegistrationStateError) -> Self {
        Self::State
    }
}

impl From<crate::TotpSecretError> for TotpRegistrationError {
    fn from(error: crate::TotpSecretError) -> Self {
        match error {
            crate::TotpSecretError::EntropyUnavailable => Self::Unavailable,
            crate::TotpSecretError::InvalidKey
            | crate::TotpSecretError::InvalidBinding
            | crate::TotpSecretError::InvalidSecret
            | crate::TotpSecretError::InvalidEnvelope
            | crate::TotpSecretError::Cryptographic => Self::State,
        }
    }
}
