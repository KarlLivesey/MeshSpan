// SPDX-License-Identifier: GPL-2.0-only

//! Replicated-authority and failure contracts for current-user recovery-code issuance.

use meshspan_domain::{AuthenticationMethodId, OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{AuthoritativeCommand, CommandContext};
use thiserror::Error;

use crate::{BrowserAuthenticationError, BrowserSessionAuthority};

/// Replicated mutation boundary required by recovery-code issuance.
pub trait RecoveryCodeIssuanceAuthority: BrowserSessionAuthority {
    /// Resolves one already committed recovery-code set creation.
    ///
    /// # Errors
    ///
    /// Rejects another command family or malformed authoritative evidence.
    fn resolve_recovery_code_issuance(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<RecoveryCodeIssuanceCommit>, RecoveryCodeIssuanceAuthorityError>;

    /// Commits or exactly resolves one recovery-code method creation through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never claims success without durable evidence.
    fn commit_or_resolve_recovery_code_issuance(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<RecoveryCodeIssuanceCommit, RecoveryCodeIssuanceAuthorityError>;
}

/// Exact durable facts returned by recovery-code creation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCodeIssuanceCommit {
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

/// Closed replicated-authority recovery-code issuance failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryCodeIssuanceAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("recovery-code issuance authority is unavailable")]
    Unavailable,
    /// Operation identity is already bound to different input.
    #[error("recovery-code issuance conflicts with durable state")]
    Conflict,
    /// Persisted authority or its receipt failed validation.
    #[error("recovery-code issuance authority failed closed")]
    Failed,
}

/// Stable recovery-code issuance failure containing no code or session material.
#[derive(Debug, Error)]
pub enum RecoveryCodeIssuanceError {
    /// Public identifiers or label are invalid.
    #[error("recovery-code issuance request is invalid")]
    InvalidRequest,
    /// Current browser authentication failed.
    #[error("recovery-code issuance authentication failed")]
    Authentication(#[from] BrowserAuthenticationError),
    /// Operation reuse conflicts with durable state.
    #[error("recovery-code issuance conflicts with durable state")]
    Conflict,
    /// The issuance key or derived material failed closed.
    #[error("recovery-code issuance material is invalid")]
    Material,
    /// Replicated authority failed.
    #[error("recovery-code issuance authority failed")]
    Authority(#[from] RecoveryCodeIssuanceAuthorityError),
    /// Durable authority returned substituted or malformed evidence.
    #[error("recovery-code issuance receipt is invalid")]
    InvalidReceipt,
}
