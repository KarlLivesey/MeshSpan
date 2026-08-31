// SPDX-License-Identifier: GPL-2.0-only

//! Atomic recovery-code consumption beside API-key and passkey session proofs.

use meshspan_api_contract::CreateSessionRequest;
use meshspan_domain::{
    ApiKeyBundle, AuthenticationMethodKind, OperationId, RecoveryCodeBundle, UnixMicros,
};
use meshspan_metadata::{
    ApiKeyAuthentication, AuthenticationSessionReplay, AuthenticationSessionReplayCredential,
    AuthenticationSessionReplayFactor, PasskeyVerificationMaterial,
    RecoveryCodeVerificationMaterial, SessionAuthenticationFactor,
};

use crate::create_session::{session_audit_event_id, session_expiry_for_factors};
use crate::multi_factor_session::{
    api_key_factor, ordered_factors, passkey_factor, replay_result, require_receipt,
    session_command, validate_common_replay,
};
use crate::{
    CreateSessionError, CreateSessionResult, CreateSessionService, PasskeySessionCeremony,
    PreparedPasskeyProof, SessionAuthority, SessionAuthorityError,
};

impl<A, P, T> CreateSessionService<A, P, T>
where
    A: SessionAuthority,
    P: PasskeySessionCeremony,
{
    pub(crate) fn create_api_key_recovery(
        &mut self,
        request: &CreateSessionRequest,
        secret: &str,
        recovery_code: &str,
        operation_id: OperationId,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, CreateSessionError> {
        let api_key = ApiKeyBundle::parse(secret)?;
        let primary = self
            .authority
            .authenticate_api_key(api_key.key_id(), api_key.secret_digest(), now)?
            .ok_or(CreateSessionError::Rejected)?;
        let recovery = parse_recovery_code(recovery_code)?;
        let material = self.recovery_material(primary.principal_id, &recovery, now)?;
        let bearer = meshspan_domain::SessionTokenBundle::derive(&api_key, operation_id)?;
        let csrf = meshspan_domain::SessionCsrfBundle::derive(&api_key, operation_id)?;
        if let Some(replay) = self
            .authority
            .resolve_authentication_session(operation_id)?
        {
            validate_common_replay(request, &replay, &bearer, &csrf)?;
            validate_replay(&replay, &material, |factors| {
                validate_api_key_primary(factors, &primary)
            })?;
            return replay_result(request, bearer, csrf, &replay);
        }
        require_unused(material)?;
        let expires_at =
            recovery_session_expiry(&self.authority, AuthenticationMethodKind::ApiKey, now)?;
        let factors = ordered_factors(api_key_factor(&primary), recovery_factor(material))?;
        let command = session_command(
            request,
            &bearer,
            &csrf,
            primary.principal_id,
            factors,
            expires_at,
        );
        let context = meshspan_metadata::CommandContext {
            operation_id,
            actor_principal_id: primary.principal_id,
            audit_event_id: session_audit_event_id(operation_id, &primary.key_id.as_bytes())?,
            occurred_at: now,
            expected_revision: None,
        };
        let commit = self.authority.commit_or_resolve(context, &command)?;
        require_receipt(commit.result_digest)?;
        crate::multi_factor_session::create_result(
            request,
            bearer,
            csrf,
            expires_at,
            request.remember,
        )
    }

    pub(crate) fn create_passkey_recovery(
        &mut self,
        request: &CreateSessionRequest,
        recovery_code: &str,
        operation_id: OperationId,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, CreateSessionError> {
        let prepared = self
            .passkeys
            .prepare(&request.authentication, operation_id, now)?;
        let bearer = meshspan_domain::SessionTokenBundle::derive_from_passkey_seed(
            prepared.session_seed(),
            operation_id,
        )?;
        let csrf = meshspan_domain::SessionCsrfBundle::derive_from_passkey_seed(
            prepared.session_seed(),
            operation_id,
        )?;
        let primary = self
            .authority
            .passkey_verification_material(prepared.credential_id(), now)?
            .ok_or(CreateSessionError::Rejected)?;
        let recovery = parse_recovery_code(recovery_code)?;
        let material = self.recovery_material(primary.principal_id, &recovery, now)?;
        if let Some(replay) = self
            .authority
            .resolve_authentication_session(operation_id)?
        {
            validate_common_replay(request, &replay, &bearer, &csrf)?;
            if prepared
                .recorded_result_digest()
                .is_some_and(|digest| digest != replay.result_digest)
            {
                return Err(SessionAuthorityError::Conflict.into());
            }
            validate_replay(&replay, &material, |factors| {
                validate_passkey_primary(factors, &primary, &prepared)
            })?;
            self.passkeys
                .complete(&prepared, replay.result_digest, now)?;
            return replay_result(request, bearer, csrf, &replay);
        }
        if prepared.recorded_result_digest().is_some() {
            return Err(SessionAuthorityError::Conflict.into());
        }
        require_unused(material)?;
        let verified = prepared.verify(&primary)?;
        let expires_at =
            recovery_session_expiry(&self.authority, AuthenticationMethodKind::Passkey, now)?;
        let factors = ordered_factors(passkey_factor(&verified), recovery_factor(material))?;
        let command = session_command(
            request,
            &bearer,
            &csrf,
            verified.principal_id,
            factors,
            expires_at,
        );
        let context = meshspan_metadata::CommandContext {
            operation_id,
            actor_principal_id: verified.principal_id,
            audit_event_id: session_audit_event_id(operation_id, &verified.credential_id)?,
            occurred_at: now,
            expected_revision: None,
        };
        let commit = self.authority.commit_or_resolve(context, &command)?;
        require_receipt(commit.result_digest)?;
        self.passkeys
            .complete(&prepared, commit.result_digest, now)?;
        crate::multi_factor_session::create_result(
            request,
            bearer,
            csrf,
            expires_at,
            request.remember,
        )
    }

    fn recovery_material(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        code: &RecoveryCodeBundle,
        now: UnixMicros,
    ) -> Result<RecoveryCodeVerificationMaterial, CreateSessionError> {
        self.authority
            .recovery_code_verification_material(
                principal_id,
                code.code_id(),
                code.secret_digest(),
                now,
            )?
            .ok_or(CreateSessionError::Rejected)
    }
}

fn parse_recovery_code(value: &str) -> Result<RecoveryCodeBundle, CreateSessionError> {
    RecoveryCodeBundle::parse(value).map_err(|_| CreateSessionError::Rejected)
}

fn recovery_session_expiry(
    authority: &impl SessionAuthority,
    primary: AuthenticationMethodKind,
    now: UnixMicros,
) -> Result<UnixMicros, CreateSessionError> {
    session_expiry_for_factors(
        authority.session_policy()?,
        &[primary, AuthenticationMethodKind::RecoveryCode],
        now,
    )
}

fn require_unused(material: RecoveryCodeVerificationMaterial) -> Result<(), CreateSessionError> {
    if material.used_at.is_none() {
        Ok(())
    } else {
        Err(CreateSessionError::Rejected)
    }
}

fn recovery_factor(material: RecoveryCodeVerificationMaterial) -> SessionAuthenticationFactor {
    SessionAuthenticationFactor::RecoveryCode {
        method_id: material.method_id,
        credential_generation: material.credential_generation,
        method_revision: material.revision,
        code_id: material.code_id,
    }
}

fn validate_replay<F>(
    replay: &AuthenticationSessionReplay,
    material: &RecoveryCodeVerificationMaterial,
    validate_primary: F,
) -> Result<(), CreateSessionError>
where
    F: FnOnce(&[AuthenticationSessionReplayFactor]) -> Result<(), CreateSessionError>,
{
    if replay.principal_id != material.principal_id
        || material.used_at != Some(replay.issued_at)
        || !replay.factors.iter().any(|factor| {
            factor.method_id == material.method_id
                && factor.credential_generation == material.credential_generation
                && factor.method_revision <= material.revision
                && factor.credential
                    == AuthenticationSessionReplayCredential::RecoveryCode(material.code_id)
        })
    {
        return Err(SessionAuthorityError::Conflict.into());
    }
    validate_primary(&replay.factors)
}

fn validate_api_key_primary(
    factors: &[AuthenticationSessionReplayFactor],
    primary: &ApiKeyAuthentication,
) -> Result<(), CreateSessionError> {
    let found = factors.iter().any(|factor| {
        factor.method_id == primary.method_id
            && factor.credential_generation == primary.credential_generation
            && factor.method_revision <= primary.revision
            && factor.credential == AuthenticationSessionReplayCredential::ApiKey(primary.key_id)
    });
    exact_primary(found, factors)
}

fn validate_passkey_primary(
    factors: &[AuthenticationSessionReplayFactor],
    primary: &PasskeyVerificationMaterial,
    prepared: &impl PreparedPasskeyProof,
) -> Result<(), CreateSessionError> {
    let found = factors.iter().any(|factor| {
        factor.method_id == primary.method_id
            && factor.credential_generation == primary.credential_generation
            && factor.method_revision <= primary.revision
            && factor.credential
                == AuthenticationSessionReplayCredential::Passkey(primary.credential_id.clone())
            && primary.credential_id.as_slice() == prepared.credential_id()
    });
    exact_primary(found, factors)
}

fn exact_primary(
    found: bool,
    factors: &[AuthenticationSessionReplayFactor],
) -> Result<(), CreateSessionError> {
    if found && factors.len() == 2 {
        Ok(())
    } else {
        Err(SessionAuthorityError::Conflict.into())
    }
}
