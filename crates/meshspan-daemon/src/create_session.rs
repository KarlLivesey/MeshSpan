// SPDX-License-Identifier: GPL-2.0-only

//! API-key authentication composed into one replicated browser session.

use meshspan_api_contract::{
    AssuranceLevel as ApiAssuranceLevel, CreateSessionRequest, CreateSessionResponse,
    NullableField, SessionAuthentication,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ApiKeyBundle, ApiKeyBundleError, AuditEventId, AuthenticationOperationClass,
    AuthenticationService, OperationId, SessionCsrfBundle, SessionTokenBundle,
    SessionTokenBundleError, UnixMicros,
};
use meshspan_metadata::{
    ApiKeyAuthentication, ApiKeySessionReplay, AuthenticationPolicy, AuthoritativeCommand,
    CommandContext, IssueAuthenticationSession, SessionAuthenticationFactor, SessionClientLabel,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::create_mesh_setup::parse_uuid;

/// Result of one committed browser-session exchange.
pub struct CreateSessionResult {
    /// Public non-secret response body.
    pub response: CreateSessionResponse,
    /// Opaque bearer value installed only in a secure HTTP-only cookie.
    pub bearer: SessionTokenBundle,
    /// Independently presented CSRF value readable by the browser application.
    pub csrf: SessionCsrfBundle,
    /// Whether the cookie may carry a bounded persistence lifetime.
    pub persistent_cookie: bool,
}

/// Minimal root-partition boundary required by session establishment.
pub trait SessionAuthority {
    /// Resolves one API-key verifier without disclosing rejection details.
    ///
    /// # Errors
    ///
    /// Fails closed when current authority cannot provide trustworthy evidence.
    fn authenticate_api_key(
        &self,
        digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, SessionAuthorityError>;

    /// Loads the current HTTPS session-establishment policy.
    ///
    /// # Errors
    ///
    /// Fails closed when current policy cannot be read and validated.
    fn session_policy(&self) -> Result<AuthenticationPolicy, SessionAuthorityError>;

    /// Resolves one already-committed API-key session before mutable factor evidence is captured
    /// again.
    ///
    /// # Errors
    ///
    /// Fails closed when durable replay evidence cannot be read or validated.
    fn resolve_api_key_session(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ApiKeySessionReplay>, SessionAuthorityError>;

    /// Commits or exactly resolves the session command through consensus.
    ///
    /// # Errors
    ///
    /// Fails without claiming success when consensus or exact replay resolution fails.
    fn commit_or_resolve(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<SessionCommit, SessionAuthorityError>;
}

/// Minimal receipt proving the exact authoritative session result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionCommit {
    /// Digest of the committed command result.
    pub result_digest: [u8; 32],
}

/// Closed authority failures safe to map at the public boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionAuthorityError {
    /// Current authority cannot be reached.
    #[error("session authority is unavailable")]
    Unavailable,
    /// The operation identity is bound to different input.
    #[error("session operation conflicts with durable state")]
    Conflict,
    /// Persisted authority failed validation.
    #[error("session authority failed closed")]
    Failed,
}

/// Creates HTTPS browser sessions without retaining plaintext credential material.
pub struct CreateSessionService<A> {
    authority: A,
}

impl<A> CreateSessionService<A>
where
    A: SessionAuthority,
{
    /// Creates a session service over the live root authority.
    #[must_use]
    pub const fn new(authority: A) -> Self {
        Self { authority }
    }

    /// Returns the authority so adjacent authentication lifecycle services can be composed.
    #[must_use]
    pub fn into_authority(self) -> A {
        self.authority
    }

    /// Authenticates and commits one exact API-key browser session.
    ///
    /// # Errors
    ///
    /// Rejects unsupported ceremonies, invalid credentials, insufficient factors,
    /// changed retries, unavailable authority and invalid durable policy.
    pub fn create(
        &mut self,
        request: &CreateSessionRequest,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, CreateSessionError> {
        if request.additional_factor.is_some() {
            return Err(CreateSessionError::UnsupportedCeremony);
        }
        let secret = match &request.authentication {
            SessionAuthentication::ApiKey { secret } => secret,
            SessionAuthentication::Passkey { .. } => {
                return Err(CreateSessionError::UnsupportedCeremony);
            }
        };
        let api_key = ApiKeyBundle::parse(secret)?;
        let operation_id = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str())
                .map_err(|_| CreateSessionError::InvalidOperation)?,
        )
        .map_err(|_| CreateSessionError::InvalidOperation)?;
        let authenticated = self
            .authority
            .authenticate_api_key(api_key.secret_digest(), now)?
            .ok_or(CreateSessionError::Rejected)?;
        let bearer = SessionTokenBundle::derive(&api_key, operation_id)?;
        let csrf = SessionCsrfBundle::derive(&api_key, operation_id)?;
        if let Some(replay) = self.authority.resolve_api_key_session(operation_id)? {
            return replay_result(request, &authenticated, bearer, csrf, &replay);
        }
        let policy = self.authority.session_policy()?;
        if policy.service != AuthenticationService::Https
            || policy.operation_class != AuthenticationOperationClass::SessionEstablishment
            || policy.minimum_factor_count != 1
        {
            return Err(CreateSessionError::AdditionalFactorRequired);
        }
        let expires_at = now
            .checked_add(policy.maximum_session_duration)
            .ok_or(CreateSessionError::InvalidPolicy)?;
        let factors = BoundedItems::new(
            vec![SessionAuthenticationFactor::ApiKey {
                method_id: authenticated.method_id,
                credential_generation: authenticated.credential_generation,
                method_revision: authenticated.revision,
                key_id: authenticated.key_id,
            }],
            8,
        )
        .map_err(|_| CreateSessionError::InvalidPolicy)?;
        let command =
            AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
                session_id: bearer.session_id(),
                principal_id: authenticated.principal_id,
                token_digest: bearer.token_digest(),
                csrf_digest: csrf.token_digest(),
                client_label: client_label(request),
                persistent_cookie: request.remember,
                service: AuthenticationService::Https,
                factors,
                expires_at,
            });
        let context = CommandContext {
            operation_id,
            actor_principal_id: authenticated.principal_id,
            audit_event_id: audit_event_id(operation_id, authenticated.key_id.as_bytes())?,
            occurred_at: now,
            expected_revision: None,
        };
        let commit = self.authority.commit_or_resolve(context, &command)?;
        if commit.result_digest == [0; 32] {
            return Err(CreateSessionError::InvalidReceipt);
        }
        let session_id =
            meshspan_api_contract::SessionId::from_uuid_bytes(bearer.session_id().as_bytes())
                .ok_or(CreateSessionError::InvalidReceipt)?;
        Ok(CreateSessionResult {
            response: CreateSessionResponse {
                operation_id: request.operation_id.clone(),
                session_id,
                expires_at_epoch_micros: expires_at.get(),
                assurance: ApiAssuranceLevel::SingleFactor,
            },
            bearer,
            csrf,
            persistent_cookie: request.remember,
        })
    }
}

fn replay_result(
    request: &CreateSessionRequest,
    authenticated: &ApiKeyAuthentication,
    bearer: SessionTokenBundle,
    csrf: SessionCsrfBundle,
    replay: &ApiKeySessionReplay,
) -> Result<CreateSessionResult, CreateSessionError> {
    if replay.result_digest == [0; 32]
        || replay.session_id != bearer.session_id()
        || replay.principal_id != authenticated.principal_id
        || replay.token_digest != bearer.token_digest()
        || replay.csrf_digest != csrf.token_digest()
        || replay.client_label != client_label(request)
        || replay.persistent_cookie != request.remember
        || replay.service != AuthenticationService::Https
        || replay.revoked_at.is_some()
        || replay.method_id != authenticated.method_id
        || replay.credential_generation != authenticated.credential_generation
        || replay.key_id != authenticated.key_id
    {
        return Err(CreateSessionError::Authority(
            SessionAuthorityError::Conflict,
        ));
    }
    let session_id =
        meshspan_api_contract::SessionId::from_uuid_bytes(replay.session_id.as_bytes())
            .ok_or(CreateSessionError::InvalidReceipt)?;
    Ok(CreateSessionResult {
        response: CreateSessionResponse {
            operation_id: request.operation_id.clone(),
            session_id,
            expires_at_epoch_micros: replay.expires_at.get(),
            assurance: ApiAssuranceLevel::SingleFactor,
        },
        bearer,
        csrf,
        persistent_cookie: replay.persistent_cookie,
    })
}

fn client_label(request: &CreateSessionRequest) -> SessionClientLabel {
    match &request.client_label {
        NullableField::Missing => SessionClientLabel::Missing,
        NullableField::Null => SessionClientLabel::Null,
        NullableField::Value(label) => SessionClientLabel::Value(label.as_str().to_owned()),
    }
}

fn audit_event_id(
    operation_id: OperationId,
    key_id: [u8; 16],
) -> Result<AuditEventId, CreateSessionError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.session-audit-id.v1");
    digest.update(operation_id.as_bytes());
    digest.update(key_id);
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| CreateSessionError::InvalidPolicy)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    AuditEventId::from_bytes(bytes).map_err(|_| CreateSessionError::InvalidPolicy)
}

/// Stable session-creation failure which contains no submitted secrets.
#[derive(Debug, Error)]
pub enum CreateSessionError {
    /// The operation UUID is not canonical.
    #[error("session operation identifier is invalid")]
    InvalidOperation,
    /// The API key is not canonical.
    #[error("authentication was rejected")]
    ApiKey(#[from] ApiKeyBundleError),
    /// The current credential was not accepted.
    #[error("authentication was rejected")]
    Rejected,
    /// This authentication ceremony is not implemented by the current slice.
    #[error("authentication ceremony is not currently supported")]
    UnsupportedCeremony,
    /// Current policy requires another independent factor.
    #[error("an additional authentication factor is required")]
    AdditionalFactorRequired,
    /// Session material could not be derived safely.
    #[error("session material is invalid")]
    Material(#[from] SessionTokenBundleError),
    /// Current policy could not produce a safe session.
    #[error("authentication policy is invalid")]
    InvalidPolicy,
    /// Authority returned an invalid committed receipt.
    #[error("session authority returned an invalid receipt")]
    InvalidReceipt,
    /// Root authority rejected or could not resolve the session.
    #[error("session authority failed")]
    Authority(#[from] SessionAuthorityError),
}
