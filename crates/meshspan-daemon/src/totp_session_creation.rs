// SPDX-License-Identifier: GPL-2.0-only

//! TOTP additional-factor composition for API-key and passkey session creation.

use meshspan_api_contract::CreateSessionRequest;
use meshspan_domain::{
    ApiKeyBundle, AuthenticationMethodId, AuthenticationMethodKind, OperationId, SessionCsrfBundle,
    SessionTokenBundle, UnixMicros,
};
use meshspan_metadata::{
    ApiKeyAuthentication, AuthenticationSessionReplayCredential, AuthenticationSessionReplayFactor,
    CommandContext, PasskeyVerificationMaterial, SessionAuthenticationFactor,
};

use crate::create_session::{session_audit_event_id, session_expiry_for_factors};
use crate::multi_factor_session::{
    api_key_factor, create_result, ordered_factors, passkey_factor, replay_result, require_receipt,
    session_command, validate_common_replay,
};
use crate::{
    CreateSessionError, CreateSessionResult, CreateSessionService, PasskeySessionCeremony,
    PreparedPasskeyProof, SessionAuthority, SessionAuthorityError, TotpFactorVerifier,
    VerifiedTotpFactor,
};

impl<A, P, T> CreateSessionService<A, P, T>
where
    A: SessionAuthority,
    P: PasskeySessionCeremony,
    T: TotpFactorVerifier,
{
    pub(crate) fn create_api_key_totp(
        &mut self,
        request: &CreateSessionRequest,
        secret: &str,
        code: &str,
        operation_id: OperationId,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, CreateSessionError> {
        let api_key = ApiKeyBundle::parse(secret)?;
        let primary = self
            .authority
            .authenticate_api_key(api_key.secret_digest(), now)?
            .ok_or(CreateSessionError::Rejected)?;
        let bearer = SessionTokenBundle::derive(&api_key, operation_id)?;
        let csrf = SessionCsrfBundle::derive(&api_key, operation_id)?;
        let materials = self
            .authority
            .totp_verification_materials(primary.principal_id, now)?;
        if let Some(replay) = self
            .authority
            .resolve_authentication_session(operation_id)?
        {
            validate_common_replay(request, &replay, &bearer, &csrf)?;
            if replay.principal_id != primary.principal_id {
                return Err(SessionAuthorityError::Conflict.into());
            }
            let retained = validate_api_key_replay(&replay.factors, &primary)?;
            self.totp.verify_replay(
                primary.principal_id,
                &materials,
                retained.method_id,
                code,
                retained.accepted_step,
            )?;
            return replay_result(request, bearer, csrf, &replay);
        }
        let additional = self
            .totp
            .verify_current(primary.principal_id, &materials, code, now)?;
        let expires_at = session_expiry_for_factors(
            self.authority.session_policy()?,
            &[
                AuthenticationMethodKind::ApiKey,
                AuthenticationMethodKind::Totp,
            ],
            now,
        )?;
        let factors = ordered_factors(api_key_factor(&primary), totp_factor(additional))?;
        let command = session_command(
            request,
            &bearer,
            &csrf,
            primary.principal_id,
            factors,
            expires_at,
        );
        let context = CommandContext {
            operation_id,
            actor_principal_id: primary.principal_id,
            audit_event_id: session_audit_event_id(operation_id, &primary.key_id.as_bytes())?,
            occurred_at: now,
            expected_revision: None,
        };
        let commit = self.authority.commit_or_resolve(context, &command)?;
        require_receipt(commit.result_digest)?;
        create_result(request, bearer, csrf, expires_at, request.remember)
    }

    pub(crate) fn create_passkey_totp(
        &mut self,
        request: &CreateSessionRequest,
        code: &str,
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
        let materials = self
            .authority
            .totp_verification_materials(material.principal_id, now)?;
        if let Some(replay) = self
            .authority
            .resolve_authentication_session(operation_id)?
        {
            validate_common_replay(request, &replay, &bearer, &csrf)?;
            if replay.principal_id != material.principal_id {
                return Err(SessionAuthorityError::Conflict.into());
            }
            if prepared
                .recorded_result_digest()
                .is_some_and(|digest| digest != replay.result_digest)
            {
                return Err(SessionAuthorityError::Conflict.into());
            }
            let retained = validate_passkey_replay(&replay.factors, &material, &prepared)?;
            self.totp.verify_replay(
                material.principal_id,
                &materials,
                retained.method_id,
                code,
                retained.accepted_step,
            )?;
            self.passkeys
                .complete(&prepared, replay.result_digest, now)?;
            return replay_result(request, bearer, csrf, &replay);
        }
        if prepared.recorded_result_digest().is_some() {
            return Err(SessionAuthorityError::Conflict.into());
        }
        let primary = prepared.verify(&material)?;
        let additional = self
            .totp
            .verify_current(primary.principal_id, &materials, code, now)?;
        let expires_at = session_expiry_for_factors(
            self.authority.session_policy()?,
            &[
                AuthenticationMethodKind::Passkey,
                AuthenticationMethodKind::Totp,
            ],
            now,
        )?;
        let factors = ordered_factors(passkey_factor(&primary), totp_factor(additional))?;
        let command = session_command(
            request,
            &bearer,
            &csrf,
            primary.principal_id,
            factors,
            expires_at,
        );
        let context = CommandContext {
            operation_id,
            actor_principal_id: primary.principal_id,
            audit_event_id: session_audit_event_id(operation_id, &primary.credential_id)?,
            occurred_at: now,
            expected_revision: None,
        };
        let commit = self.authority.commit_or_resolve(context, &command)?;
        require_receipt(commit.result_digest)?;
        self.passkeys
            .complete(&prepared, commit.result_digest, now)?;
        create_result(request, bearer, csrf, expires_at, request.remember)
    }
}

fn totp_factor(additional: VerifiedTotpFactor) -> SessionAuthenticationFactor {
    SessionAuthenticationFactor::Totp {
        method_id: additional.method_id,
        credential_generation: additional.credential_generation,
        method_revision: additional.method_revision,
        accepted_step: additional.accepted_step,
    }
}

fn validate_api_key_replay(
    factors: &[AuthenticationSessionReplayFactor],
    primary: &ApiKeyAuthentication,
) -> Result<RetainedTotp, CreateSessionError> {
    let mut retained = None;
    let mut primary_found = false;
    for factor in factors {
        match &factor.credential {
            AuthenticationSessionReplayCredential::ApiKey(key_id)
                if factor.method_id == primary.method_id
                    && factor.credential_generation == primary.credential_generation
                    && factor.method_revision <= primary.revision
                    && *key_id == primary.key_id =>
            {
                primary_found = true;
            }
            AuthenticationSessionReplayCredential::Totp { accepted_step } => {
                retained = Some(RetainedTotp {
                    method_id: factor.method_id,
                    accepted_step: *accepted_step,
                });
            }
            _ => return Err(SessionAuthorityError::Conflict.into()),
        }
    }
    retained
        .filter(|_| primary_found)
        .ok_or_else(|| SessionAuthorityError::Conflict.into())
}

fn validate_passkey_replay(
    factors: &[AuthenticationSessionReplayFactor],
    material: &PasskeyVerificationMaterial,
    prepared: &impl PreparedPasskeyProof,
) -> Result<RetainedTotp, CreateSessionError> {
    let mut retained = None;
    let mut primary_found = false;
    for factor in factors {
        match &factor.credential {
            AuthenticationSessionReplayCredential::Passkey(credential_id)
                if factor.method_id == material.method_id
                    && factor.credential_generation == material.credential_generation
                    && factor.method_revision <= material.revision
                    && credential_id == &material.credential_id
                    && credential_id.as_slice() == prepared.credential_id() =>
            {
                primary_found = true;
            }
            AuthenticationSessionReplayCredential::Totp { accepted_step } => {
                retained = Some(RetainedTotp {
                    method_id: factor.method_id,
                    accepted_step: *accepted_step,
                });
            }
            _ => return Err(SessionAuthorityError::Conflict.into()),
        }
    }
    retained
        .filter(|_| primary_found)
        .ok_or_else(|| SessionAuthorityError::Conflict.into())
}

#[derive(Clone, Copy)]
struct RetainedTotp {
    method_id: AuthenticationMethodId,
    accepted_step: u64,
}
