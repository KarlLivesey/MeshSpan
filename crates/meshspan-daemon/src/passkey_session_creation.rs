// SPDX-License-Identifier: GPL-2.0-only

//! Passkey assertion composition into one authoritative browser session.

use meshspan_api_contract::{
    AssuranceLevel as ApiAssuranceLevel, CreateSessionRequest, CreateSessionResponse,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuthenticationMethodKind, AuthenticationService, OperationId, SessionCsrfBundle,
    SessionTokenBundle, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, IssueAuthenticationSession, PasskeySessionReplay,
    PasskeyVerificationMaterial, SessionAuthenticationFactor,
};

use crate::create_session::{client_label, session_audit_event_id, session_expiry};
use crate::{
    CreateSessionError, CreateSessionResult, CreateSessionService, PasskeySessionCeremony,
    PreparedPasskeyProof, SessionAuthority, SessionAuthorityError,
};

impl<A, P, T> CreateSessionService<A, P, T>
where
    A: SessionAuthority,
    P: PasskeySessionCeremony,
{
    pub(crate) fn create_passkey(
        &mut self,
        request: &CreateSessionRequest,
        operation_id: OperationId,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, CreateSessionError> {
        let prepared = self
            .passkeys
            .prepare(&request.authentication, operation_id, now)?;
        let bearer =
            SessionTokenBundle::derive_from_passkey_seed(prepared.session_seed(), operation_id)?;
        let csrf =
            SessionCsrfBundle::derive_from_passkey_seed(prepared.session_seed(), operation_id)?;
        let material = self
            .authority
            .passkey_verification_material(prepared.credential_id(), now)?
            .ok_or(CreateSessionError::Rejected)?;
        if let Some(replay) = self.authority.resolve_passkey_session(operation_id)? {
            let result = replay_result(request, &prepared, &material, bearer, csrf, &replay)?;
            self.passkeys
                .complete(&prepared, replay.result_digest, now)?;
            return Ok(result);
        }
        if prepared.recorded_result_digest().is_some() {
            return Err(SessionAuthorityError::Conflict.into());
        }
        let verified = prepared.verify(&material)?;
        let expires_at = session_expiry(
            self.authority.session_policy()?,
            AuthenticationMethodKind::Passkey,
            now,
        )?;
        let factors = BoundedItems::new(
            vec![SessionAuthenticationFactor::Passkey {
                method_id: verified.method_id,
                credential_generation: verified.credential_generation,
                method_revision: verified.method_revision,
                credential_id: verified.credential_id.clone(),
                signature_counter: verified.signature_counter,
                backup_state: verified.backup_state,
            }],
            8,
        )
        .map_err(|_| CreateSessionError::InvalidPolicy)?;
        let command =
            AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
                session_id: bearer.session_id(),
                principal_id: verified.principal_id,
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
            actor_principal_id: verified.principal_id,
            audit_event_id: session_audit_event_id(operation_id, &verified.credential_id)?,
            occurred_at: now,
            expected_revision: None,
        };
        let commit = self.authority.commit_or_resolve(context, &command)?;
        if commit.result_digest == [0; 32] {
            return Err(CreateSessionError::InvalidReceipt);
        }
        self.passkeys
            .complete(&prepared, commit.result_digest, now)?;
        create_result(request, bearer, csrf, expires_at, request.remember)
    }
}

fn replay_result(
    request: &CreateSessionRequest,
    prepared: &impl PreparedPasskeyProof,
    material: &PasskeyVerificationMaterial,
    bearer: SessionTokenBundle,
    csrf: SessionCsrfBundle,
    replay: &PasskeySessionReplay,
) -> Result<CreateSessionResult, CreateSessionError> {
    if replay.result_digest == [0; 32]
        || prepared
            .recorded_result_digest()
            .is_some_and(|digest| digest != replay.result_digest)
        || replay.session_id != bearer.session_id()
        || replay.principal_id != material.principal_id
        || replay.token_digest != bearer.token_digest()
        || replay.csrf_digest != csrf.token_digest()
        || replay.client_label != client_label(request)
        || replay.persistent_cookie != request.remember
        || replay.service != AuthenticationService::Https
        || replay.revoked_at.is_some()
        || replay.method_id != material.method_id
        || replay.credential_generation != material.credential_generation
        || replay.credential_id != material.credential_id
        || replay.credential_id != prepared.credential_id()
    {
        return Err(SessionAuthorityError::Conflict.into());
    }
    create_result(
        request,
        bearer,
        csrf,
        replay.expires_at,
        replay.persistent_cookie,
    )
}

fn create_result(
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
            assurance: ApiAssuranceLevel::SingleFactor,
        },
        bearer,
        csrf,
        persistent_cookie,
    })
}
