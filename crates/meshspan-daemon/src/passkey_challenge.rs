// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe, non-enumerating passkey authentication challenge creation.

use meshspan_api_contract::{
    CreatePasskeyChallengeRequest, CreatePasskeyChallengeResponse, PasskeyChallengeId,
    PasskeyUserVerification,
};
use meshspan_domain::{
    AuthenticationChallengeId, DurationMicros, OperationId, RandomSource, UnixMicros,
};
use meshspan_metadata::{
    AuthenticationCeremonyDisposition, AuthenticationCeremonyError, AuthenticationCeremonyKind,
    AuthenticationCeremonyRecord, LocalDatabase, NewAuthenticationCeremony,
};
use meshspan_passkey::{PASSKEY_CHALLENGE_BYTES, PasskeyChallenge};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::PasskeyCeremonyKey;
use crate::create_mesh_setup::parse_uuid;
use crate::passkey_challenge_configuration::{
    MAXIMUM_LIFETIME_MICROS, MICROS_PER_MILLISECOND, MINIMUM_LIFETIME_MICROS,
    PasskeyChallengeConfiguration,
};
use crate::passkey_challenge_state::{
    FrozenPasskeyChallengeState, PasskeyChallengeBinding, PasskeyChallengeProtector,
    PasskeyChallengeStateError,
};

const SESSION_SEED_BYTES: usize = 32;

/// Minimal node-local persistence boundary required by passkey challenge creation.
pub trait PasskeyCeremonyStore {
    /// Resolves an earlier creation operation for exact response replay.
    ///
    /// # Errors
    ///
    /// Fails closed when node-local evidence cannot be loaded and verified.
    fn ceremony_by_creation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthenticationCeremonyRecord>, PasskeyCeremonyStoreError>;

    /// Durably inserts one challenge or confirms its exact existing record.
    ///
    /// # Errors
    ///
    /// Rejects changed retries and unavailable or corrupt local persistence.
    fn create_ceremony(
        &mut self,
        ceremony: &NewAuthenticationCeremony,
    ) -> Result<AuthenticationCeremonyDisposition, PasskeyCeremonyStoreError>;
}

impl PasskeyCeremonyStore for LocalDatabase {
    fn ceremony_by_creation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthenticationCeremonyRecord>, PasskeyCeremonyStoreError> {
        self.authentication_ceremony_by_creation(operation_id)
            .map_err(map_ceremony_error)
    }

    fn create_ceremony(
        &mut self,
        ceremony: &NewAuthenticationCeremony,
    ) -> Result<AuthenticationCeremonyDisposition, PasskeyCeremonyStoreError> {
        self.create_authentication_ceremony(ceremony)
            .map_err(map_ceremony_error)
    }
}

/// Closed persistence failure visible to the challenge application service.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasskeyCeremonyStoreError {
    /// The creation identity already names different semantic input.
    #[error("passkey ceremony operation conflicts with local state")]
    Conflict,
    /// The node-local store is unavailable or its evidence is invalid.
    #[error("passkey ceremony store failed closed")]
    Failed,
}

/// Creates exact-retry-stable passkey challenges over one node-local store.
pub struct PasskeyChallengeService<S, R> {
    store: S,
    random: R,
    protector: PasskeyChallengeProtector,
    configuration: PasskeyChallengeConfiguration,
}

impl<S, R> PasskeyChallengeService<S, R>
where
    S: PasskeyCeremonyStore,
    R: RandomSource,
{
    /// Composes a challenge service from local persistence, entropy, protection and RP policy.
    #[must_use]
    pub const fn new(
        store: S,
        random: R,
        key: PasskeyCeremonyKey,
        configuration: PasskeyChallengeConfiguration,
    ) -> Self {
        Self {
            store,
            random,
            protector: PasskeyChallengeProtector::new(key),
            configuration,
        }
    }

    /// Creates or exactly replays one non-enumerating passkey challenge.
    ///
    /// # Errors
    ///
    /// Rejects invalid operation identities, changed retries, unavailable entropy, corrupt
    /// protected state, time overflow and unavailable node-local persistence.
    pub fn create(
        &mut self,
        request: &CreatePasskeyChallengeRequest,
        now: UnixMicros,
    ) -> Result<CreatePasskeyChallengeResponse, PasskeyChallengeError> {
        let operation_id = parse_operation(&request.operation_id)?;
        let request_digest = configuration_digest(&self.configuration)?;
        if let Some(existing) = self.store.ceremony_by_creation(operation_id)? {
            return self.replay_response(request, request_digest, &existing);
        }
        let expires_at = now
            .checked_add(self.configuration.lifetime())
            .ok_or(PasskeyChallengeError::InvalidTime)?;
        let challenge_id = random_challenge_id(&mut self.random)?;
        let challenge = random_challenge(&mut self.random)?;
        let session_seed = random_nonzero::<SESSION_SEED_BYTES>(&mut self.random)?;
        let state = FrozenPasskeyChallengeState::new(
            challenge,
            session_seed,
            self.configuration.relying_party_id().to_owned(),
            self.configuration.allowed_origins().to_vec(),
        )?;
        let binding = PasskeyChallengeBinding {
            challenge_id,
            operation_id,
            request_digest,
            created_at: now,
            expires_at,
        };
        let protected_state = self.protector.protect(binding, &state, &mut self.random)?;
        let ceremony = NewAuthenticationCeremony {
            challenge_id,
            creation_operation_id: operation_id,
            kind: AuthenticationCeremonyKind::PasskeyAuthentication,
            request_digest,
            protected_state,
            created_at: now,
            expires_at,
        };
        self.store.create_ceremony(&ceremony)?;
        response(request, challenge_id, &state, self.configuration.lifetime())
    }

    fn replay_response(
        &self,
        request: &CreatePasskeyChallengeRequest,
        request_digest: [u8; 32],
        existing: &AuthenticationCeremonyRecord,
    ) -> Result<CreatePasskeyChallengeResponse, PasskeyChallengeError> {
        if existing.kind != AuthenticationCeremonyKind::PasskeyAuthentication
            || existing.request_digest != request_digest
        {
            return Err(PasskeyChallengeError::Conflict);
        }
        let binding = PasskeyChallengeBinding {
            challenge_id: existing.challenge_id,
            operation_id: existing.creation_operation_id,
            request_digest: existing.request_digest,
            created_at: existing.created_at,
            expires_at: existing.expires_at,
        };
        let state = self
            .protector
            .unprotect(binding, &existing.protected_state)?;
        if state.relying_party_id() != self.configuration.relying_party_id()
            || state.allowed_origins() != self.configuration.allowed_origins()
        {
            return Err(PasskeyChallengeError::Conflict);
        }
        response(
            request,
            existing.challenge_id,
            &state,
            duration_between(existing.created_at, existing.expires_at)?,
        )
    }
}

/// Stable passkey challenge failure without challenge, key or account detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasskeyChallengeError {
    /// The public operation identity was not canonical.
    #[error("passkey challenge operation is invalid")]
    InvalidOperation,
    /// The operation identity names different durable input.
    #[error("passkey challenge operation conflicts with local state")]
    Conflict,
    /// Authoritative time could not represent the configured challenge window.
    #[error("passkey challenge time window is invalid")]
    InvalidTime,
    /// Cryptographic challenge material was unavailable or invalid.
    #[error("passkey challenge generation is unavailable")]
    Unavailable,
    /// Node-local persistence or protected state failed closed.
    #[error("passkey challenge state failed closed")]
    Failed,
}

impl From<PasskeyCeremonyStoreError> for PasskeyChallengeError {
    fn from(error: PasskeyCeremonyStoreError) -> Self {
        match error {
            PasskeyCeremonyStoreError::Conflict => Self::Conflict,
            PasskeyCeremonyStoreError::Failed => Self::Failed,
        }
    }
}

impl From<PasskeyChallengeStateError> for PasskeyChallengeError {
    fn from(error: PasskeyChallengeStateError) -> Self {
        match error {
            PasskeyChallengeStateError::Invalid => Self::Failed,
            PasskeyChallengeStateError::Unavailable => Self::Unavailable,
        }
    }
}

fn response(
    request: &CreatePasskeyChallengeRequest,
    challenge_id: AuthenticationChallengeId,
    state: &FrozenPasskeyChallengeState,
    lifetime: DurationMicros,
) -> Result<CreatePasskeyChallengeResponse, PasskeyChallengeError> {
    let challenge_id = PasskeyChallengeId::from_uuid_bytes(challenge_id.as_bytes())
        .ok_or(PasskeyChallengeError::Failed)?;
    let timeout_milliseconds = u32::try_from(lifetime.get() / MICROS_PER_MILLISECOND)
        .map_err(|_| PasskeyChallengeError::InvalidTime)?;
    Ok(CreatePasskeyChallengeResponse {
        operation_id: request.operation_id.clone(),
        challenge_id,
        challenge: state.challenge().to_base64url(),
        relying_party_id: state.relying_party_id().to_owned(),
        timeout_milliseconds,
        user_verification: PasskeyUserVerification::Required,
    })
}

fn parse_operation(
    operation_id: &meshspan_api_contract::OperationId,
) -> Result<OperationId, PasskeyChallengeError> {
    OperationId::from_bytes(
        parse_uuid(operation_id.as_str()).map_err(|_| PasskeyChallengeError::InvalidOperation)?,
    )
    .map_err(|_| PasskeyChallengeError::InvalidOperation)
}

fn random_challenge_id(
    random: &mut impl RandomSource,
) -> Result<AuthenticationChallengeId, PasskeyChallengeError> {
    let mut bytes = random_nonzero::<16>(random)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    AuthenticationChallengeId::from_bytes(bytes).map_err(|_| PasskeyChallengeError::Unavailable)
}

fn random_challenge(
    random: &mut impl RandomSource,
) -> Result<PasskeyChallenge, PasskeyChallengeError> {
    PasskeyChallenge::from_bytes(random_nonzero::<PASSKEY_CHALLENGE_BYTES>(random)?)
        .map_err(|_| PasskeyChallengeError::Unavailable)
}

fn random_nonzero<const N: usize>(
    random: &mut impl RandomSource,
) -> Result<[u8; N], PasskeyChallengeError> {
    let mut bytes = [0_u8; N];
    random
        .fill_bytes(&mut bytes)
        .map_err(|_| PasskeyChallengeError::Unavailable)?;
    if bytes == [0; N] {
        Err(PasskeyChallengeError::Unavailable)
    } else {
        Ok(bytes)
    }
}

fn duration_between(
    created_at: UnixMicros,
    expires_at: UnixMicros,
) -> Result<DurationMicros, PasskeyChallengeError> {
    let lifetime = expires_at
        .get()
        .checked_sub(created_at.get())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(PasskeyChallengeError::Failed)?;
    if !(MINIMUM_LIFETIME_MICROS..=MAXIMUM_LIFETIME_MICROS).contains(&lifetime)
        || !lifetime.is_multiple_of(MICROS_PER_MILLISECOND)
    {
        return Err(PasskeyChallengeError::Failed);
    }
    Ok(DurationMicros::new(lifetime))
}

fn configuration_digest(
    configuration: &PasskeyChallengeConfiguration,
) -> Result<[u8; 32], PasskeyChallengeError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.passkey-challenge-request.v1\0");
    digest_text(&mut digest, configuration.relying_party_id())?;
    digest.update(configuration.lifetime().get().to_be_bytes());
    digest.update(
        u16::try_from(configuration.allowed_origins().len())
            .map_err(|_| PasskeyChallengeError::Failed)?
            .to_be_bytes(),
    );
    for origin in configuration.allowed_origins() {
        digest_text(&mut digest, origin)?;
    }
    digest.update(b"required");
    Ok(digest.finalize().into())
}

fn digest_text(digest: &mut Sha256, value: &str) -> Result<(), PasskeyChallengeError> {
    digest.update(
        u16::try_from(value.len())
            .map_err(|_| PasskeyChallengeError::Failed)?
            .to_be_bytes(),
    );
    digest.update(value.as_bytes());
    Ok(())
}

const fn map_ceremony_error(error: AuthenticationCeremonyError) -> PasskeyCeremonyStoreError {
    match error {
        AuthenticationCeremonyError::Conflict | AuthenticationCeremonyError::Expired => {
            PasskeyCeremonyStoreError::Conflict
        }
        AuthenticationCeremonyError::Store | AuthenticationCeremonyError::Invalid => {
            PasskeyCeremonyStoreError::Failed
        }
    }
}
