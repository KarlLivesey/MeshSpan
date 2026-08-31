// SPDX-License-Identifier: GPL-2.0-only

//! Replicated-authority and failure contracts for current-user API-key issuance.

use meshspan_domain::{AuthenticationMethodId, OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{AuthoritativeCommand, CommandContext};
use thiserror::Error;

use crate::{BrowserAuthenticationError, BrowserSessionAuthority};

/// Replicated mutation boundary required by API-key issuance.
pub trait ApiKeyIssuanceAuthority: BrowserSessionAuthority {
    /// Resolves one already committed API-key creation.
    ///
    /// # Errors
    ///
    /// Rejects another command family or malformed authoritative evidence.
    fn resolve_api_key_issuance(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ApiKeyIssuanceCommit>, ApiKeyIssuanceAuthorityError>;

    /// Commits or exactly resolves one API-key method creation through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never claims success without durable evidence.
    fn commit_or_resolve_api_key_issuance(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<ApiKeyIssuanceCommit, ApiKeyIssuanceAuthorityError>;
}

/// Exact durable facts returned by API-key creation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyIssuanceCommit {
    /// Original semantic request digest.
    pub request_digest: [u8; 32],
    /// Durable result digest.
    pub result_digest: [u8; 32],
    /// Created authentication method.
    pub method_id: AuthenticationMethodId,
    /// Owning current user.
    pub principal_id: PrincipalId,
    /// Original authoritative creation instant.
    pub created_at: UnixMicros,
}

/// Closed replicated-authority API-key issuance failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ApiKeyIssuanceAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("API-key issuance authority is unavailable")]
    Unavailable,
    /// Operation identity is already bound to different input.
    #[error("API-key issuance conflicts with durable state")]
    Conflict,
    /// Persisted authority or its receipt failed validation.
    #[error("API-key issuance authority failed closed")]
    Failed,
}

/// Stable API-key issuance failure containing no key or session material.
#[derive(Debug, Error)]
pub enum ApiKeyIssuanceError {
    /// Public identifiers, scopes or expiry are invalid.
    #[error("API-key issuance request is invalid")]
    InvalidRequest,
    /// Current browser session was rejected.
    #[error("API-key issuance was rejected")]
    Rejected,
    /// Operation reuse conflicts with durable state.
    #[error("API-key issuance conflicts with durable state")]
    Conflict,
    /// The issuance key or derived material failed closed.
    #[error("API-key issuance material is invalid")]
    Material,
    /// Current browser authentication failed.
    #[error("API-key issuance authentication failed")]
    Authentication(#[from] BrowserAuthenticationError),
    /// Replicated authority failed.
    #[error("API-key issuance authority failed")]
    Authority(#[from] ApiKeyIssuanceAuthorityError),
    /// Durable authority returned substituted or malformed evidence.
    #[error("API-key issuance receipt is invalid")]
    InvalidReceipt,
}
