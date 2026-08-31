// SPDX-License-Identifier: GPL-2.0-only

//! Current-user TOTP registration composed with session and metadata authority.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    CreateTotpRegistrationChallengeRequest, CreateTotpRegistrationChallengeResponse,
    CreateTotpRegistrationRequest, CreateTotpRegistrationResponse,
};
use meshspan_domain::{
    AssuranceLevel, AuthenticationChallengeId, AuthenticationMethodId, RandomSource, UnixMicros,
};
use meshspan_metadata::{
    AuthenticationCeremonyKind, AuthenticationCeremonyRecord, AuthenticationRegistrationProfile,
    NewAuthenticationCeremony,
};
use meshspan_otp::{TotpAlgorithm, TotpProfile};
use zeroize::Zeroizing;

use crate::totp_registration_model::{
    ACCEPTED_STEP_WINDOW, ALGORITHM_CODE, DIGITS, PERIOD_SECONDS, SECRET_BYTES, binding,
    challenge_expiry, challenge_request_digest, challenge_response, parse_challenge,
    parse_operation, random_nonzero, random_uuid, registration_command, registration_context,
    registration_response, registration_response_digest, require_capability, validate_commit,
};
use crate::totp_registration_state::{
    FrozenTotpRegistrationState, TotpRegistrationBinding, TotpRegistrationProtector,
};
use crate::{
    AuthenticationRegistrationStore, BrowserRequestProtection, BrowserSessionAuthenticator,
    GatewaySessionIdentity, TotpCeremonyKey, TotpEnvelopeKey, TotpRegistrationAuthority,
    TotpRegistrationConfiguration, TotpRegistrationError, TotpSecretBinding, TotpSecretCipher,
};

/// Complete current-user TOTP registration application service.
pub struct TotpRegistrationService<S, A, R> {
    store: S,
    authority: A,
    random: R,
    protector: TotpRegistrationProtector,
    envelope: TotpSecretCipher,
    configuration: TotpRegistrationConfiguration,
    gateway: GatewaySessionIdentity,
}

impl<S, A, R> TotpRegistrationService<S, A, R>
where
    S: AuthenticationRegistrationStore,
    A: TotpRegistrationAuthority,
    R: RandomSource,
{
    /// Composes registration from local journal, replicated authority and distinct local/mesh
    /// seed-protection keys.
    #[must_use]
    pub const fn new(
        store: S,
        authority: A,
        random: R,
        ceremony_key: TotpCeremonyKey,
        envelope_key: TotpEnvelopeKey,
        configuration: TotpRegistrationConfiguration,
        gateway: GatewaySessionIdentity,
    ) -> Self {
        Self {
            store,
            authority,
            random,
            protector: TotpRegistrationProtector::new(ceremony_key),
            envelope: TotpSecretCipher::new(envelope_key),
            configuration,
            gateway,
        }
    }

    /// Decomposes the service so process composition can persist and reopen owned adapters.
    #[must_use]
    pub fn into_parts(self) -> (S, A, R) {
        (self.store, self.authority, self.random)
    }

    /// Creates or exactly replays TOTP registration material for the current user.
    ///
    /// # Errors
    ///
    /// Rejects invalid or stale session evidence, changed retries, unsafe time windows,
    /// unavailable entropy, malformed authority and corrupt protected state.
    pub fn create_challenge(
        &mut self,
        request: &CreateTotpRegistrationChallengeRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateTotpRegistrationChallengeResponse, TotpRegistrationError> {
        let operation_id = parse_operation(request.operation_id.as_str())?;
        let capability = self.authenticate(headers, now)?;
        if let Some(record) = self.store.ceremony_by_creation(operation_id)? {
            let state = self.registration_state(&record)?;
            require_capability(&state, capability)?;
            if state.label != request.label.as_str() {
                return Err(TotpRegistrationError::Conflict);
            }
            return challenge_response(request, record.challenge_id, record.expires_at, &state);
        }
        let profile = self
            .authority
            .registration_profile(capability.principal_id)?
            .ok_or(TotpRegistrationError::Rejected)?;
        if profile.principal_id != capability.principal_id
            || profile.identity_revision != capability.identity_revision
        {
            return Err(TotpRegistrationError::Rejected);
        }
        self.create_new_challenge(request, operation_id, capability, profile, now)
    }

    /// Verifies possession and authoritatively creates one independently revocable TOTP method.
    ///
    /// # Errors
    ///
    /// Rejects invalid session/challenge bindings, incorrect codes, changed operation input and
    /// untrustworthy local or replicated results.
    pub fn register(
        &mut self,
        request: &CreateTotpRegistrationRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateTotpRegistrationResponse, TotpRegistrationError> {
        let operation_id = parse_operation(request.operation_id.as_str())?;
        let challenge_id = parse_challenge(request.challenge_id.as_str())?;
        let capability = self.authenticate(headers, now)?;
        let record = self
            .store
            .ceremony(challenge_id)?
            .ok_or(TotpRegistrationError::Conflict)?;
        let state = self.registration_state(&record)?;
        require_capability(&state, capability)?;
        let existing = self.authority.resolve_registration(operation_id)?;
        if existing.is_none() {
            verify_code(&state, &request.code, now)?;
        }
        self.store.begin_verification(
            challenge_id,
            operation_id,
            registration_response_digest(request)?,
            now,
        )?;
        let command = registration_command(&state);
        let occurred_at = existing.map_or(now, |commit| commit.created_at);
        let context = registration_context(operation_id, &state, occurred_at)?;
        let expected_request_digest = command.request_digest(context);
        let commit = match existing {
            Some(commit) => commit,
            None => self
                .authority
                .commit_or_resolve_registration(context, &command)?,
        };
        validate_commit(&state, &record, commit, expected_request_digest)?;
        self.store.record_authority_commit(
            challenge_id,
            operation_id,
            commit.result_digest,
            now,
        )?;
        self.store
            .complete_ceremony(challenge_id, operation_id, now)?;
        registration_response(request, commit)
    }

    fn create_new_challenge(
        &mut self,
        request: &CreateTotpRegistrationChallengeRequest,
        operation_id: meshspan_domain::OperationId,
        capability: meshspan_metadata::SessionAccessCapability,
        profile: AuthenticationRegistrationProfile,
        now: UnixMicros,
    ) -> Result<CreateTotpRegistrationChallengeResponse, TotpRegistrationError> {
        let expires_at = challenge_expiry(now, capability.expires_at, &self.configuration)?;
        let challenge_id = AuthenticationChallengeId::from_bytes(random_uuid(&mut self.random)?)
            .map_err(|_| TotpRegistrationError::Unavailable)?;
        let method_id = AuthenticationMethodId::from_bytes(random_uuid(&mut self.random)?)
            .map_err(|_| TotpRegistrationError::Unavailable)?;
        let secret = Zeroizing::new(random_nonzero::<SECRET_BYTES>(&mut self.random)?);
        let secret_ciphertext = self.envelope.encrypt(
            TotpSecretBinding {
                method_id,
                principal_id: capability.principal_id,
                algorithm: ALGORITHM_CODE,
                digits: DIGITS,
                period_seconds: PERIOD_SECONDS,
                accepted_step_window: ACCEPTED_STEP_WINDOW,
            },
            secret.as_ref(),
            &mut self.random,
        )?;
        let state = FrozenTotpRegistrationState {
            secret,
            secret_ciphertext,
            method_id,
            principal_id: capability.principal_id,
            session_id: capability.session_id,
            identity_revision: capability.identity_revision,
            capability_digest: capability.capability_digest,
            label: request.label.as_str().to_owned(),
            account_name: profile.user_name,
            issuer: self.configuration.issuer().to_owned(),
            algorithm: ALGORITHM_CODE,
            digits: DIGITS,
            period_seconds: PERIOD_SECONDS,
            accepted_step_window: ACCEPTED_STEP_WINDOW,
        };
        state.validate()?;
        let request_digest = challenge_request_digest(&state, &self.configuration)?;
        let protected_state = self.protector.protect(
            TotpRegistrationBinding {
                challenge_id,
                creation_operation_id: operation_id,
                request_digest,
                created_at: now,
                expires_at,
            },
            &state,
            &mut self.random,
        )?;
        self.store.create_ceremony(&NewAuthenticationCeremony {
            challenge_id,
            creation_operation_id: operation_id,
            kind: AuthenticationCeremonyKind::TotpRegistration,
            request_digest,
            protected_state,
            created_at: now,
            expires_at,
        })?;
        challenge_response(request, challenge_id, expires_at, &state)
    }

    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<meshspan_metadata::SessionAccessCapability, TotpRegistrationError> {
        BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(
                headers,
                BrowserRequestProtection::Mutation,
                AssuranceLevel::SingleFactor,
                now,
            )
            .map_err(TotpRegistrationError::Authentication)
    }

    fn registration_state(
        &self,
        record: &AuthenticationCeremonyRecord,
    ) -> Result<FrozenTotpRegistrationState, TotpRegistrationError> {
        if record.kind != AuthenticationCeremonyKind::TotpRegistration {
            return Err(TotpRegistrationError::Conflict);
        }
        self.protector
            .unprotect(binding(record), &record.protected_state)
            .map_err(TotpRegistrationError::from)
    }
}

fn verify_code(
    state: &FrozenTotpRegistrationState,
    code: &str,
    now: UnixMicros,
) -> Result<(), TotpRegistrationError> {
    let seconds =
        u64::try_from(now.get()).map_err(|_| TotpRegistrationError::InvalidTime)? / 1_000_000;
    let profile = TotpProfile::new(
        TotpAlgorithm::Sha1,
        state.digits,
        state.period_seconds,
        state.accepted_step_window,
    )
    .map_err(|_| TotpRegistrationError::State)?;
    match profile
        .verify(state.secret.as_ref(), code, seconds)
        .map_err(|_| TotpRegistrationError::Rejected)?
    {
        Some(_) => Ok(()),
        None => Err(TotpRegistrationError::Rejected),
    }
}
