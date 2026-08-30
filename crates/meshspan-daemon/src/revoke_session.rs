// SPDX-License-Identifier: GPL-2.0-only

//! Replay-safe current browser-session revocation composed with replicated authority.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    OperationId as ApiOperationId, RevokeCurrentSessionRequest, RevokeCurrentSessionResponse,
    SessionId as ApiSessionId,
};
use meshspan_domain::{AssuranceLevel, AuditEventId, OperationId, SessionId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, RevokeAuthenticationSession, SessionRevocationReplay,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::create_mesh_setup::parse_uuid;
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    BrowserSessionAuthority, GatewaySessionIdentity, parse_browser_session,
};

/// Minimal replicated authority required for exact current-session revocation.
pub trait SessionRevocationAuthority: BrowserSessionAuthority {
    /// Resolves a prior self-revocation against the exact presented browser evidence.
    ///
    /// # Errors
    ///
    /// Fails closed for conflicting operation reuse or untrustworthy persisted state.
    fn resolve_revocation(
        &self,
        operation_id: OperationId,
        session_id: SessionId,
        token_digest: [u8; 32],
        csrf_digest: [u8; 32],
    ) -> Result<Option<SessionRevocationReplay>, SessionRevocationAuthorityError>;

    /// Commits or exactly resolves one revocation through consensus.
    ///
    /// # Errors
    ///
    /// Never claims success without a durable authoritative result.
    fn commit_or_resolve_revocation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<SessionRevocationCommit, SessionRevocationAuthorityError>;
}

/// Minimal evidence returned by the authoritative mutation path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionRevocationCommit {
    /// Digest of the durable command result.
    pub result_digest: [u8; 32],
}

/// Closed mutation-authority failures safe to map at the public boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionRevocationAuthorityError {
    /// Current authority cannot be reached.
    #[error("session revocation authority is unavailable")]
    Unavailable,
    /// The operation identity is already bound to different semantic input.
    #[error("session revocation conflicts with durable state")]
    Conflict,
    /// Persisted authority or its receipt failed validation.
    #[error("session revocation authority failed closed")]
    Failed,
}

/// Revokes the exact browser session presented by the caller.
pub struct RevokeCurrentSessionService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> RevokeCurrentSessionService<A>
where
    A: SessionRevocationAuthority,
{
    /// Creates one revocation service bound to a live gateway incarnation.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }

    /// Revokes or exactly resolves the current browser session.
    ///
    /// # Errors
    ///
    /// Rejects malformed credentials, missing CSRF, stale authority, conflicting retries and
    /// invalid committed receipts without exposing which check failed.
    pub fn revoke(
        &mut self,
        request: &RevokeCurrentSessionRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<RevokeCurrentSessionResponse, RevokeCurrentSessionError> {
        let operation_bytes = parse_uuid(request.operation_id.as_str())
            .map_err(|_| RevokeCurrentSessionError::InvalidOperation)?;
        let operation_id = OperationId::from_bytes(operation_bytes)
            .map_err(|_| RevokeCurrentSessionError::InvalidOperation)?;
        let evidence = parse_browser_session(headers, BrowserRequestProtection::Mutation)
            .map_err(|_| RevokeCurrentSessionError::Rejected)?;
        let csrf_digest = evidence
            .csrf_digest
            .ok_or(RevokeCurrentSessionError::Rejected)?;
        if let Some(replay) = self.authority.resolve_revocation(
            operation_id,
            evidence.session_id,
            evidence.token_digest,
            csrf_digest,
        )? {
            return replay_response(request.operation_id.clone(), replay);
        }
        let authenticator = BrowserSessionAuthenticator::new(&self.authority, self.gateway);
        let capability = authenticator.authenticate_evidence(
            evidence,
            BrowserRequestProtection::Mutation,
            AssuranceLevel::SingleFactor,
            now,
        )?;
        let command =
            AuthoritativeCommand::RevokeAuthenticationSession(RevokeAuthenticationSession {
                session_id: capability.session_id,
                principal_id: capability.principal_id,
            });
        let context = CommandContext {
            operation_id,
            actor_principal_id: capability.principal_id,
            audit_event_id: revocation_audit_event_id(operation_id, capability.session_id)?,
            occurred_at: now,
            expected_revision: None,
        };
        let commit = self
            .authority
            .commit_or_resolve_revocation(context, &command)?;
        if commit.result_digest == [0; 32] {
            return Err(RevokeCurrentSessionError::InvalidReceipt);
        }
        response(request.operation_id.clone(), capability.session_id, now)
    }
}

fn replay_response(
    operation_id: ApiOperationId,
    replay: SessionRevocationReplay,
) -> Result<RevokeCurrentSessionResponse, RevokeCurrentSessionError> {
    if replay.result_digest == [0; 32] {
        return Err(RevokeCurrentSessionError::InvalidReceipt);
    }
    response(operation_id, replay.session_id, replay.revoked_at)
}

fn response(
    operation_id: ApiOperationId,
    session_id: SessionId,
    revoked_at: UnixMicros,
) -> Result<RevokeCurrentSessionResponse, RevokeCurrentSessionError> {
    let session_id = ApiSessionId::from_uuid_bytes(session_id.as_bytes())
        .ok_or(RevokeCurrentSessionError::InvalidReceipt)?;
    Ok(RevokeCurrentSessionResponse {
        operation_id,
        session_id,
        revoked_at_epoch_micros: revoked_at.get(),
    })
}

fn revocation_audit_event_id(
    operation_id: OperationId,
    session_id: SessionId,
) -> Result<AuditEventId, RevokeCurrentSessionError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.session-revocation-audit-id.v1");
    digest.update(operation_id.as_bytes());
    digest.update(session_id.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| RevokeCurrentSessionError::InvalidReceipt)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    AuditEventId::from_bytes(bytes).map_err(|_| RevokeCurrentSessionError::InvalidReceipt)
}

/// Stable current-session revocation failure.
#[derive(Debug, Error)]
pub enum RevokeCurrentSessionError {
    /// The operation identity is not canonical.
    #[error("session revocation operation identity is invalid")]
    InvalidOperation,
    /// Browser credential presentation or current authority was rejected.
    #[error("session revocation was rejected")]
    Rejected,
    /// Current browser authentication failed.
    #[error("session revocation authentication failed")]
    Authentication(#[from] BrowserAuthenticationError),
    /// Committed result evidence is invalid.
    #[error("session revocation receipt is invalid")]
    InvalidReceipt,
    /// Replicated mutation authority failed.
    #[error("session revocation authority failed")]
    Authority(#[from] SessionRevocationAuthorityError),
}
