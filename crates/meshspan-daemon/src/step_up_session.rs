// SPDX-License-Identifier: GPL-2.0-only

//! Replay-safe browser-session rotation after one fresh additional factor.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    AssuranceLevel as ApiAssuranceLevel, CreateSessionResponse, SessionAdditionalFactor,
    StepUpCurrentSessionRequest,
};
use meshspan_domain::{
    AssuranceLevel, AuditEventId, AuthenticationMethodKind, AuthenticationOperationClass,
    AuthenticationService, OperationId, RecoveryCodeBundle, SessionCsrfBundle, SessionTokenBundle,
    SessionTokenBundleError, UnixMicros,
};
use meshspan_metadata::{
    AuthenticationSessionReplay, AuthenticationSessionReplayCredential, AuthoritativeCommand,
    CommandContext, SessionAuthenticationFactor, StepUpAuthenticationSession,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::browser_session::parse_browser_session_material;
use crate::create_mesh_setup::parse_uuid;
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    BrowserSessionAuthority, CreateSessionResult, GatewaySessionIdentity, SessionAuthority,
    SessionAuthorityError, TotpFactorVerifier, TotpSessionError,
};

/// Authority needed to rotate a current browser session exactly once.
pub trait StepUpSessionAuthority: SessionAuthority + BrowserSessionAuthority {
    /// Resolves a committed rotation using the presentation of its now-revoked source session.
    ///
    /// # Errors
    ///
    /// Fails closed for conflicting operation reuse or untrustworthy durable evidence.
    fn resolve_step_up_session(
        &self,
        operation_id: OperationId,
        source_session_id: meshspan_domain::SessionId,
        source_token_digest: [u8; 32],
        source_csrf_digest: [u8; 32],
    ) -> Result<Option<AuthenticationSessionReplay>, SessionAuthorityError>;
}

/// Current-session step-up service with a replaceable TOTP verifier.
pub struct StepUpCurrentSessionService<A, T> {
    authority: A,
    gateway: GatewaySessionIdentity,
    totp: T,
}

impl<A, T> StepUpCurrentSessionService<A, T>
where
    A: StepUpSessionAuthority,
    T: TotpFactorVerifier,
{
    /// Binds step-up to current replicated authority, a live gateway and protected TOTP material.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity, totp: T) -> Self {
        Self {
            authority,
            gateway,
            totp,
        }
    }

    /// Returns the authority after service composition, primarily for staged daemon assembly.
    #[must_use]
    pub fn into_authority(self) -> A {
        self.authority
    }

    /// Atomically replaces the current session after a fresh TOTP or recovery-code proof.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale, substituted, reused or conflicting proof without disclosure.
    pub fn step_up(
        &mut self,
        request: &StepUpCurrentSessionRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, StepUpCurrentSessionError> {
        let operation_id = operation_id(request)?;
        let (evidence, source) =
            parse_browser_session_material(headers, BrowserRequestProtection::Mutation)
                .map_err(|_| StepUpCurrentSessionError::Rejected)?;
        let source_csrf_digest = evidence
            .csrf_digest
            .ok_or(StepUpCurrentSessionError::Rejected)?;
        let bearer = SessionTokenBundle::derive_rotation(&source, operation_id)?;
        let csrf = SessionCsrfBundle::derive_rotation(&source, operation_id)?;

        if let Some(replay) = self.authority.resolve_step_up_session(
            operation_id,
            evidence.session_id,
            evidence.token_digest,
            source_csrf_digest,
        )? {
            validate_common_replay(&replay, evidence.session_id, &bearer, &csrf)?;
            self.validate_factor_replay(request, &replay, now)?;
            return result(request, bearer, csrf, &replay);
        }

        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate_evidence(
                evidence,
                BrowserRequestProtection::Mutation,
                AssuranceLevel::SingleFactor,
                now,
            )?;
        let additional_factor =
            self.verify_current_factor(&request.additional_factor, capability.principal_id, now)?;
        let expires_at = replacement_expiry(
            self.authority.session_policy()?,
            additional_factor_kind(&additional_factor),
            now,
        )?;
        let command =
            AuthoritativeCommand::StepUpAuthenticationSession(StepUpAuthenticationSession {
                source_session_id: capability.session_id,
                replacement_session_id: bearer.session_id(),
                principal_id: capability.principal_id,
                token_digest: bearer.token_digest(),
                csrf_digest: csrf.token_digest(),
                additional_factor,
                expires_at,
            });
        let context = CommandContext {
            operation_id,
            actor_principal_id: capability.principal_id,
            audit_event_id: step_up_audit_event_id(operation_id, capability.session_id)?,
            occurred_at: now,
            expected_revision: None,
        };
        let commit = self.authority.commit_or_resolve(context, &command)?;
        if commit.result_digest == [0; 32] {
            return Err(StepUpCurrentSessionError::InvalidReceipt);
        }
        create_result(
            request,
            bearer,
            csrf,
            expires_at,
            capability.persistent_cookie,
        )
    }

    fn verify_current_factor(
        &self,
        factor: &SessionAdditionalFactor,
        principal_id: meshspan_domain::PrincipalId,
        now: UnixMicros,
    ) -> Result<SessionAuthenticationFactor, StepUpCurrentSessionError> {
        match factor {
            SessionAdditionalFactor::Totp { code } => {
                let materials = self
                    .authority
                    .totp_verification_materials(principal_id, now)?;
                let factor = self
                    .totp
                    .verify_current(principal_id, &materials, code, now)?;
                Ok(SessionAuthenticationFactor::Totp {
                    method_id: factor.method_id,
                    credential_generation: factor.credential_generation,
                    method_revision: factor.method_revision,
                    accepted_step: factor.accepted_step,
                })
            }
            SessionAdditionalFactor::RecoveryCode { code } => {
                let code = RecoveryCodeBundle::parse(code)
                    .map_err(|_| StepUpCurrentSessionError::Rejected)?;
                let material = self
                    .authority
                    .recovery_code_verification_material(
                        principal_id,
                        code.code_id(),
                        code.secret_digest(),
                        now,
                    )?
                    .filter(|material| material.used_at.is_none())
                    .ok_or(StepUpCurrentSessionError::Rejected)?;
                Ok(SessionAuthenticationFactor::RecoveryCode {
                    method_id: material.method_id,
                    credential_generation: material.credential_generation,
                    method_revision: material.revision,
                    code_id: material.code_id,
                })
            }
        }
    }

    fn validate_factor_replay(
        &self,
        request: &StepUpCurrentSessionRequest,
        replay: &AuthenticationSessionReplay,
        now: UnixMicros,
    ) -> Result<(), StepUpCurrentSessionError> {
        let primary_count = replay
            .factors
            .iter()
            .filter(|factor| factor.kind.is_primary())
            .count();
        if replay.factors.len() != 2 || primary_count != 1 {
            return Err(SessionAuthorityError::Conflict.into());
        }
        match &request.additional_factor {
            SessionAdditionalFactor::Totp { code } => {
                let retained = replay
                    .factors
                    .iter()
                    .find_map(|factor| match factor.credential {
                        AuthenticationSessionReplayCredential::Totp { accepted_step } => {
                            Some((factor.method_id, accepted_step))
                        }
                        _ => None,
                    })
                    .ok_or(SessionAuthorityError::Conflict)?;
                let materials = self
                    .authority
                    .totp_verification_materials(replay.principal_id, now)?;
                self.totp.verify_replay(
                    replay.principal_id,
                    &materials,
                    retained.0,
                    code,
                    retained.1,
                )?;
            }
            SessionAdditionalFactor::RecoveryCode { code } => {
                let code = RecoveryCodeBundle::parse(code)
                    .map_err(|_| StepUpCurrentSessionError::Rejected)?;
                let material = self
                    .authority
                    .recovery_code_verification_material(
                        replay.principal_id,
                        code.code_id(),
                        code.secret_digest(),
                        now,
                    )?
                    .ok_or(SessionAuthorityError::Conflict)?;
                let retained = replay.factors.iter().any(|factor| {
                    factor.method_id == material.method_id
                        && factor.credential_generation == material.credential_generation
                        && factor.method_revision <= material.revision
                        && factor.credential
                            == AuthenticationSessionReplayCredential::RecoveryCode(material.code_id)
                });
                if !retained || material.used_at != Some(replay.issued_at) {
                    return Err(SessionAuthorityError::Conflict.into());
                }
            }
        }
        Ok(())
    }
}

fn operation_id(
    request: &StepUpCurrentSessionRequest,
) -> Result<OperationId, StepUpCurrentSessionError> {
    let bytes = parse_uuid(request.operation_id.as_str())
        .map_err(|_| StepUpCurrentSessionError::InvalidOperation)?;
    OperationId::from_bytes(bytes).map_err(|_| StepUpCurrentSessionError::InvalidOperation)
}

fn replacement_expiry(
    policy: meshspan_metadata::AuthenticationPolicy,
    additional: AuthenticationMethodKind,
    now: UnixMicros,
) -> Result<UnixMicros, StepUpCurrentSessionError> {
    let permits_primary = policy
        .allowed_factor_classes
        .contains(AuthenticationMethodKind::ApiKey)
        || policy
            .allowed_factor_classes
            .contains(AuthenticationMethodKind::Passkey);
    if policy.service != AuthenticationService::Https
        || policy.operation_class != AuthenticationOperationClass::SessionEstablishment
        || policy.minimum_factor_count > 2
        || !permits_primary
        || !policy.allowed_factor_classes.contains(additional)
    {
        return Err(StepUpCurrentSessionError::InvalidPolicy);
    }
    now.checked_add(policy.maximum_session_duration)
        .ok_or(StepUpCurrentSessionError::InvalidPolicy)
}

const fn additional_factor_kind(factor: &SessionAuthenticationFactor) -> AuthenticationMethodKind {
    match factor {
        SessionAuthenticationFactor::Totp { .. } => AuthenticationMethodKind::Totp,
        SessionAuthenticationFactor::RecoveryCode { .. } => AuthenticationMethodKind::RecoveryCode,
        SessionAuthenticationFactor::Passkey { .. } => AuthenticationMethodKind::Passkey,
        SessionAuthenticationFactor::ApiKey { .. } => AuthenticationMethodKind::ApiKey,
    }
}

fn validate_common_replay(
    replay: &AuthenticationSessionReplay,
    source_session_id: meshspan_domain::SessionId,
    bearer: &SessionTokenBundle,
    csrf: &SessionCsrfBundle,
) -> Result<(), StepUpCurrentSessionError> {
    if replay.result_digest == [0; 32]
        || replay.source_session_id != Some(source_session_id)
        || replay.session_id != bearer.session_id()
        || replay.token_digest != bearer.token_digest()
        || replay.csrf_digest != csrf.token_digest()
        || replay.service != AuthenticationService::Https
        || replay.assurance != AssuranceLevel::MultiFactor
        || replay.revoked_at.is_some()
    {
        Err(SessionAuthorityError::Conflict.into())
    } else {
        Ok(())
    }
}

fn result(
    request: &StepUpCurrentSessionRequest,
    bearer: SessionTokenBundle,
    csrf: SessionCsrfBundle,
    replay: &AuthenticationSessionReplay,
) -> Result<CreateSessionResult, StepUpCurrentSessionError> {
    create_result(
        request,
        bearer,
        csrf,
        replay.expires_at,
        replay.persistent_cookie,
    )
}

fn create_result(
    request: &StepUpCurrentSessionRequest,
    bearer: SessionTokenBundle,
    csrf: SessionCsrfBundle,
    expires_at: UnixMicros,
    persistent_cookie: bool,
) -> Result<CreateSessionResult, StepUpCurrentSessionError> {
    let session_id =
        meshspan_api_contract::SessionId::from_uuid_bytes(bearer.session_id().as_bytes())
            .ok_or(StepUpCurrentSessionError::InvalidReceipt)?;
    Ok(CreateSessionResult {
        response: CreateSessionResponse {
            operation_id: request.operation_id.clone(),
            session_id,
            expires_at_epoch_micros: expires_at.get(),
            assurance: ApiAssuranceLevel::RecentStepUp,
        },
        bearer,
        csrf,
        persistent_cookie,
    })
}

fn step_up_audit_event_id(
    operation_id: OperationId,
    source_session_id: meshspan_domain::SessionId,
) -> Result<AuditEventId, StepUpCurrentSessionError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.session-step-up-audit-id.v1");
    digest.update(operation_id.as_bytes());
    digest.update(source_session_id.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| StepUpCurrentSessionError::InvalidReceipt)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    AuditEventId::from_bytes(bytes).map_err(|_| StepUpCurrentSessionError::InvalidReceipt)
}

/// Stable current-session step-up failure containing no submitted secrets.
#[derive(Debug, Error)]
pub enum StepUpCurrentSessionError {
    /// Operation identity is not canonical.
    #[error("session step-up operation identity is invalid")]
    InvalidOperation,
    /// Current browser or additional-factor proof was rejected.
    #[error("session step-up was rejected")]
    Rejected,
    /// Current browser authentication failed.
    #[error("session step-up authentication failed")]
    Authentication(#[from] BrowserAuthenticationError),
    /// TOTP proof could not be verified.
    #[error("session step-up TOTP verification failed")]
    Totp(#[from] TotpSessionError),
    /// Replacement token derivation failed closed.
    #[error("session step-up token derivation failed")]
    Token(#[from] SessionTokenBundleError),
    /// Current authentication policy is unusable.
    #[error("session step-up policy is invalid")]
    InvalidPolicy,
    /// Committed result evidence is invalid.
    #[error("session step-up receipt is invalid")]
    InvalidReceipt,
    /// Replicated authority rejected or could not resolve the operation.
    #[error("session step-up authority failed")]
    Authority(#[from] SessionAuthorityError),
}
