// SPDX-License-Identifier: GPL-2.0-only

//! Replicated-authority and failure contracts for authentication-method revocation.

use meshspan_domain::{AuthenticationMethodId, OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{AuthoritativeCommand, CommandContext};
use thiserror::Error;

use crate::{BrowserAuthenticationError, BrowserSessionAuthority};

/// Replicated mutation boundary required by current-user method revocation.
pub trait AuthenticationMethodRevocationAuthority: BrowserSessionAuthority {
    /// Resolves one already committed authentication-method revocation.
    ///
    /// # Errors
    ///
    /// Rejects another command family or malformed authoritative evidence.
    fn resolve_authentication_method_revocation(
        &self,
        operation_id: OperationId,
    ) -> Result<
        Option<AuthenticationMethodRevocationCommit>,
        AuthenticationMethodRevocationAuthorityError,
    >;

    /// Commits or exactly resolves one authentication-method revocation through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never claims success without durable evidence.
    fn commit_or_resolve_authentication_method_revocation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<AuthenticationMethodRevocationCommit, AuthenticationMethodRevocationAuthorityError>;
}

/// Exact durable facts returned by authentication-method revocation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationMethodRevocationCommit {
    /// Original semantic request digest.
    pub request_digest: [u8; 32],
    /// Durable result digest.
    pub result_digest: [u8; 32],
    /// Revoked authentication method.
    pub method_id: AuthenticationMethodId,
    /// User who owned the method.
    pub principal_id: PrincipalId,
    /// Principal which performed the revocation.
    pub actor_principal_id: PrincipalId,
    /// Original authoritative revocation instant.
    pub revoked_at: UnixMicros,
}

/// Closed replicated-authority authentication-method revocation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationMethodRevocationAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("authentication-method revocation authority is unavailable")]
    Unavailable,
    /// Operation identity is already bound to different input.
    #[error("authentication-method revocation conflicts with durable state")]
    Conflict,
    /// Persisted authority or its receipt failed validation.
    #[error("authentication-method revocation authority failed closed")]
    Failed,
}

/// Stable authentication-method revocation failure containing no credential material.
#[derive(Debug, Error)]
pub enum AuthenticationMethodRevocationError {
    /// Public identifiers or reason are invalid.
    #[error("authentication-method revocation request is invalid")]
    InvalidRequest,
    /// Current browser session or method ownership was rejected.
    #[error("authentication-method revocation was rejected")]
    Rejected,
    /// Operation reuse conflicts with durable state.
    #[error("authentication-method revocation conflicts with durable state")]
    Conflict,
    /// Current browser authentication failed.
    #[error("authentication-method revocation authentication failed")]
    Authentication(#[from] BrowserAuthenticationError),
    /// Replicated authority failed.
    #[error("authentication-method revocation authority failed")]
    Authority(#[from] AuthenticationMethodRevocationAuthorityError),
    /// Durable authority returned substituted or malformed evidence.
    #[error("authentication-method revocation receipt is invalid")]
    InvalidReceipt,
}
