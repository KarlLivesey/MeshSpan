// SPDX-License-Identifier: GPL-2.0-only

//! Current-user passkey registration composed with session and metadata authority.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    CreatePasskeyRegistrationChallengeRequest, CreatePasskeyRegistrationChallengeResponse,
    CreatePasskeyRegistrationRequest, CreatePasskeyRegistrationResponse,
};
use meshspan_domain::{
    AssuranceLevel, AuthenticationChallengeId, AuthenticationMethodId, RandomSource, UnixMicros,
};
use meshspan_metadata::{
    AuthenticationCeremonyKind, AuthenticationCeremonyRecord, NewAuthenticationCeremony,
    PasskeyRegistrationProfile,
};
use meshspan_passkey::{
    OwnedRegistration, PasskeyChallenge, RegistrationExpectation, UserVerification,
    verify_registration,
};

use crate::passkey_registration_model::{
    binding, bounded_exclusions, challenge_expiry, challenge_request_digest, challenge_response,
    parse_challenge, parse_operation, random_nonzero, random_uuid, registration_command,
    registration_context, registration_response, registration_response_digest, require_capability,
    validate_commit,
};
use crate::passkey_registration_state::{
    FrozenPasskeyRegistrationState, PasskeyRegistrationBinding, PasskeyRegistrationProtector,
};
use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, GatewaySessionIdentity,
    PasskeyCeremonyKey, PasskeyRegistrationAuthority, PasskeyRegistrationConfiguration,
    PasskeyRegistrationError, PasskeyRegistrationStore,
};

/// Complete current-user passkey registration application service.
pub struct PasskeyRegistrationService<S, A, R> {
    store: S,
    authority: A,
    random: R,
    protector: PasskeyRegistrationProtector,
    configuration: PasskeyRegistrationConfiguration,
    gateway: GatewaySessionIdentity,
}

impl<S, A, R> PasskeyRegistrationService<S, A, R>
where
    S: PasskeyRegistrationStore,
    A: PasskeyRegistrationAuthority,
    R: RandomSource,
{
    /// Composes registration from local journal, current authority, entropy and RP policy.
    #[must_use]
    pub const fn new(
        store: S,
        authority: A,
        random: R,
        key: PasskeyCeremonyKey,
        configuration: PasskeyRegistrationConfiguration,
        gateway: GatewaySessionIdentity,
    ) -> Self {
        Self {
            store,
            authority,
            random,
            protector: PasskeyRegistrationProtector::new(key),
            configuration,
            gateway,
        }
    }

    /// Decomposes the service so process composition can persist and reopen owned adapters.
    #[must_use]
    pub fn into_parts(self) -> (S, A, R) {
        (self.store, self.authority, self.random)
    }

    /// Creates or exactly replays browser-ready registration options for the current user.
    ///
    /// # Errors
    ///
    /// Rejects invalid or stale session evidence, changed retries, unsafe time windows,
    /// unavailable entropy, malformed authority and corrupt local state.
    pub fn create_challenge(
        &mut self,
        request: &CreatePasskeyRegistrationChallengeRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreatePasskeyRegistrationChallengeResponse, PasskeyRegistrationError> {
        let operation_id = parse_operation(request.operation_id.as_str())?;
        let capability = self.authenticate(headers, now)?;
        if let Some(record) = self.store.ceremony_by_creation(operation_id)? {
            let state = self.registration_state(&record)?;
            require_capability(&state, capability)?;
            return challenge_response(
                request,
                record.challenge_id,
                record.created_at,
                record.expires_at,
                &state,
            );
        }
        let profile = self
            .authority
            .registration_profile(capability.principal_id)?
            .ok_or(PasskeyRegistrationError::Rejected)?;
        if profile.principal_id != capability.principal_id
            || profile.identity_revision != capability.identity_revision
        {
            return Err(PasskeyRegistrationError::Rejected);
        }
        self.create_new_challenge(request, operation_id, capability, profile, now)
    }

    /// Verifies and authoritatively creates one independently revocable passkey method.
    ///
    /// # Errors
    ///
    /// Rejects invalid session/challenge bindings, malformed or substituted authenticator
    /// evidence, duplicate operation input and untrustworthy local or replicated results.
    pub fn register(
        &mut self,
        request: &CreatePasskeyRegistrationRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreatePasskeyRegistrationResponse, PasskeyRegistrationError> {
        let operation_id = parse_operation(request.operation_id.as_str())?;
        let challenge_id = parse_challenge(request.challenge_id.as_str())?;
        let capability = self.authenticate(headers, now)?;
        let record = self
            .store
            .ceremony(challenge_id)?
            .ok_or(PasskeyRegistrationError::Conflict)?;
        let state = self.registration_state(&record)?;
        require_capability(&state, capability)?;
        let registration = OwnedRegistration::decode(
            &request.credential_id,
            &request.client_data_json,
            &request.attestation_object,
        )
        .map_err(|_| PasskeyRegistrationError::Rejected)?;
        self.store.begin_verification(
            challenge_id,
            operation_id,
            registration_response_digest(request)?,
            now,
        )?;
        let origins: Vec<&str> = state.allowed_origins.iter().map(String::as_str).collect();
        let outcome = verify_registration(
            &registration.as_registration(),
            &RegistrationExpectation {
                challenge: state.challenge.as_bytes(),
                relying_party_id: &state.relying_party_id,
                allowed_origins: &origins,
                user_verification: UserVerification::Required,
            },
        )
        .map_err(|_| PasskeyRegistrationError::Rejected)?;
        let command = registration_command(request, &state, outcome)?;
        let existing = self.authority.resolve_registration(operation_id)?;
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
        request: &CreatePasskeyRegistrationChallengeRequest,
        operation_id: meshspan_domain::OperationId,
        capability: meshspan_metadata::SessionAccessCapability,
        profile: PasskeyRegistrationProfile,
        now: UnixMicros,
    ) -> Result<CreatePasskeyRegistrationChallengeResponse, PasskeyRegistrationError> {
        let expires_at = challenge_expiry(now, capability.expires_at, &self.configuration)?;
        let challenge_id = random_uuid(&mut self.random)
            .and_then(|bytes| AuthenticationChallengeId::from_bytes(bytes).map_err(|_| ()))
            .map_err(|()| PasskeyRegistrationError::Unavailable)?;
        let method_id = random_uuid(&mut self.random)
            .and_then(|bytes| AuthenticationMethodId::from_bytes(bytes).map_err(|_| ()))
            .map_err(|()| PasskeyRegistrationError::Unavailable)?;
        let challenge = PasskeyChallenge::from_bytes(random_nonzero(&mut self.random)?)
            .map_err(|_| PasskeyRegistrationError::Unavailable)?;
        let state = self.new_state(challenge, method_id, capability, profile)?;
        let request_digest = challenge_request_digest(&state, &self.configuration)?;
        let protected_state = self.protector.protect(
            PasskeyRegistrationBinding {
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
            kind: AuthenticationCeremonyKind::PasskeyRegistration,
            request_digest,
            protected_state,
            created_at: now,
            expires_at,
        })?;
        challenge_response(request, challenge_id, now, expires_at, &state)
    }

    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<meshspan_metadata::SessionAccessCapability, PasskeyRegistrationError> {
        BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(
                headers,
                BrowserRequestProtection::Mutation,
                AssuranceLevel::SingleFactor,
                now,
            )
            .map_err(PasskeyRegistrationError::Authentication)
    }

    fn registration_state(
        &self,
        record: &AuthenticationCeremonyRecord,
    ) -> Result<FrozenPasskeyRegistrationState, PasskeyRegistrationError> {
        if record.kind != AuthenticationCeremonyKind::PasskeyRegistration {
            return Err(PasskeyRegistrationError::Conflict);
        }
        self.protector
            .unprotect(binding(record), &record.protected_state)
            .map_err(PasskeyRegistrationError::from)
    }

    fn new_state(
        &self,
        challenge: PasskeyChallenge,
        method_id: AuthenticationMethodId,
        capability: meshspan_metadata::SessionAccessCapability,
        profile: PasskeyRegistrationProfile,
    ) -> Result<FrozenPasskeyRegistrationState, PasskeyRegistrationError> {
        let state = FrozenPasskeyRegistrationState {
            challenge,
            method_id,
            principal_id: capability.principal_id,
            session_id: capability.session_id,
            identity_revision: capability.identity_revision,
            capability_digest: capability.capability_digest,
            relying_party_id: self.configuration.relying_party_id().to_owned(),
            relying_party_name: self.configuration.relying_party_name().to_owned(),
            allowed_origins: self.configuration.allowed_origins().to_vec(),
            user_name: profile.user_name,
            user_display_name: profile.display_name,
            exclude_credential_ids: bounded_exclusions(profile.exclude_credential_ids),
        };
        state.validate()?;
        Ok(state)
    }
}
