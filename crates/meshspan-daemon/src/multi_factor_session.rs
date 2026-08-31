// SPDX-License-Identifier: GPL-2.0-only

//! Shared construction and replay invariants for two-factor browser sessions.

use meshspan_api_contract::{
    AssuranceLevel as ApiAssuranceLevel, CreateSessionRequest, CreateSessionResponse,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{AuthenticationService, SessionCsrfBundle, SessionTokenBundle, UnixMicros};
use meshspan_metadata::{
    ApiKeyAuthentication, AuthenticationSessionReplay, AuthoritativeCommand,
    IssueAuthenticationSession, SessionAuthenticationFactor,
};

use crate::create_session::client_label;
use crate::{
    CreateSessionError, CreateSessionResult, SessionAuthorityError, VerifiedPasskeyFactor,
};

pub(crate) fn api_key_factor(primary: &ApiKeyAuthentication) -> SessionAuthenticationFactor {
    SessionAuthenticationFactor::ApiKey {
        method_id: primary.method_id,
        credential_generation: primary.credential_generation,
        method_revision: primary.revision,
        key_id: primary.key_id,
    }
}

pub(crate) fn passkey_factor(primary: &VerifiedPasskeyFactor) -> SessionAuthenticationFactor {
    SessionAuthenticationFactor::Passkey {
        method_id: primary.method_id,
        credential_generation: primary.credential_generation,
        method_revision: primary.method_revision,
        credential_id: primary.credential_id.clone(),
        signature_counter: primary.signature_counter,
        backup_state: primary.backup_state,
    }
}

pub(crate) fn ordered_factors(
    first: SessionAuthenticationFactor,
    second: SessionAuthenticationFactor,
) -> Result<BoundedItems<SessionAuthenticationFactor>, CreateSessionError> {
    let mut factors = vec![first, second];
    factors.sort_by_key(SessionAuthenticationFactor::method_id);
    if factors[0].method_id() == factors[1].method_id() {
        return Err(CreateSessionError::InvalidPolicy);
    }
    BoundedItems::new(factors, 8).map_err(|_| CreateSessionError::InvalidPolicy)
}

pub(crate) fn session_command(
    request: &CreateSessionRequest,
    bearer: &SessionTokenBundle,
    csrf: &SessionCsrfBundle,
    principal_id: meshspan_domain::PrincipalId,
    factors: BoundedItems<SessionAuthenticationFactor>,
    expires_at: UnixMicros,
) -> AuthoritativeCommand {
    AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
        session_id: bearer.session_id(),
        principal_id,
        token_digest: bearer.token_digest(),
        csrf_digest: csrf.token_digest(),
        client_label: client_label(request),
        persistent_cookie: request.remember,
        service: AuthenticationService::Https,
        factors,
        expires_at,
    })
}

pub(crate) fn validate_common_replay(
    request: &CreateSessionRequest,
    replay: &AuthenticationSessionReplay,
    bearer: &SessionTokenBundle,
    csrf: &SessionCsrfBundle,
) -> Result<(), CreateSessionError> {
    if replay.result_digest == [0; 32]
        || replay.session_id != bearer.session_id()
        || replay.token_digest != bearer.token_digest()
        || replay.csrf_digest != csrf.token_digest()
        || replay.client_label != client_label(request)
        || replay.persistent_cookie != request.remember
        || replay.service != AuthenticationService::Https
        || replay.assurance != meshspan_domain::AssuranceLevel::MultiFactor
        || replay.revoked_at.is_some()
        || replay.factors.len() != 2
    {
        Err(SessionAuthorityError::Conflict.into())
    } else {
        Ok(())
    }
}

pub(crate) fn replay_result(
    request: &CreateSessionRequest,
    bearer: SessionTokenBundle,
    csrf: SessionCsrfBundle,
    replay: &AuthenticationSessionReplay,
) -> Result<CreateSessionResult, CreateSessionError> {
    create_result(
        request,
        bearer,
        csrf,
        replay.expires_at,
        replay.persistent_cookie,
    )
}

pub(crate) fn create_result(
    request: &CreateSessionRequest,
    bearer: SessionTokenBundle,
    csrf: SessionCsrfBundle,
    expires_at: UnixMicros,
    persistent_cookie: bool,
) -> Result<CreateSessionResult, CreateSessionError> {
    let session_id =
        meshspan_api_contract::SessionId::from_uuid_bytes(bearer.session_id().as_bytes())
            .ok_or(CreateSessionError::InvalidReceipt)?;
    Ok(CreateSessionResult {
        response: CreateSessionResponse {
            operation_id: request.operation_id.clone(),
            session_id,
            expires_at_epoch_micros: expires_at.get(),
            assurance: ApiAssuranceLevel::MultiFactor,
        },
        bearer,
        csrf,
        persistent_cookie,
    })
}

pub(crate) fn require_receipt(digest: [u8; 32]) -> Result<(), CreateSessionError> {
    if digest == [0; 32] {
        Err(CreateSessionError::InvalidReceipt)
    } else {
        Ok(())
    }
}
