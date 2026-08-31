// SPDX-License-Identifier: GPL-2.0-only

//! Single-use passkey assertion reservation and cryptographic verification.

use meshspan_api_contract::SessionAuthentication;
use meshspan_domain::{
    AuthenticationChallengeId, AuthenticationMethodId, OperationId, PrincipalId, Revision,
    UnixMicros,
};
use meshspan_metadata::{
    AuthenticationCeremonyDisposition, AuthenticationCeremonyError, AuthenticationCeremonyKind,
    AuthenticationCeremonyRecord, LocalDatabase, PasskeyVerificationMaterial,
};
use meshspan_passkey::{
    AssertionExpectation, CounterState, Es256PublicKey, OwnedAssertion, UserVerification,
    verify_assertion,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::PasskeyCeremonyKey;
use crate::create_mesh_setup::parse_uuid;
use crate::passkey_challenge_state::{
    FrozenPasskeyChallengeState, PasskeyChallengeBinding, PasskeyChallengeProtector,
};

/// Minimal local-journal boundary required by passkey session completion.
pub trait PasskeySessionStore {
    /// Permanently reserves one challenge for one exact completion operation and assertion.
    ///
    /// # Errors
    ///
    /// Rejects expiry, reuse, substitution and unavailable or invalid local persistence.
    fn begin_verification(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        assertion_digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, PasskeySessionStoreError>;

    /// Loads complete protected ceremony evidence by challenge identity.
    ///
    /// # Errors
    ///
    /// Fails closed when the row is absent, malformed or substituted.
    fn ceremony(
        &self,
        challenge_id: AuthenticationChallengeId,
    ) -> Result<Option<AuthenticationCeremonyRecord>, PasskeySessionStoreError>;

    /// Records the exact authoritative session receipt after consensus commits it.
    ///
    /// # Errors
    ///
    /// Rejects a missing reservation, changed receipt or invalid time ordering.
    fn record_authority_commit(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        result_digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, PasskeySessionStoreError>;

    /// Marks the local challenge terminal only after its authoritative receipt is durable.
    ///
    /// # Errors
    ///
    /// Rejects premature, substituted or unavailable completion.
    fn complete_ceremony(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, PasskeySessionStoreError>;
}

impl PasskeySessionStore for LocalDatabase {
    fn begin_verification(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        assertion_digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, PasskeySessionStoreError> {
        self.begin_authentication_verification(challenge_id, operation_id, assertion_digest, now)
            .map_err(map_store_error)
    }

    fn ceremony(
        &self,
        challenge_id: AuthenticationChallengeId,
    ) -> Result<Option<AuthenticationCeremonyRecord>, PasskeySessionStoreError> {
        self.authentication_ceremony(challenge_id)
            .map_err(map_store_error)
    }

    fn record_authority_commit(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        result_digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, PasskeySessionStoreError> {
        self.record_authentication_authority_commit(challenge_id, operation_id, result_digest, now)
            .map_err(map_store_error)
    }

    fn complete_ceremony(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, PasskeySessionStoreError> {
        self.complete_authentication_ceremony(challenge_id, operation_id, now)
            .map_err(map_store_error)
    }
}

/// Closed local passkey-session journal failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasskeySessionStoreError {
    /// The challenge is expired or no longer usable.
    #[error("passkey challenge was rejected")]
    Rejected,
    /// The challenge or operation is already bound to different evidence.
    #[error("passkey challenge conflicts with local state")]
    Conflict,
    /// Local persistence is unavailable or invalid.
    #[error("passkey challenge store failed closed")]
    Failed,
}

/// Node-local service which reserves, verifies and completes passkey session ceremonies.
pub struct PasskeySessionService<S> {
    store: S,
    protector: PasskeyChallengeProtector,
}

impl<S> PasskeySessionService<S>
where
    S: PasskeySessionStore,
{
    /// Composes passkey completion from the local journal and its persisted protection key.
    #[must_use]
    pub const fn new(store: S, key: PasskeyCeremonyKey) -> Self {
        Self {
            store,
            protector: PasskeyChallengeProtector::new(key),
        }
    }

    /// Reserves and opens one exact hostile assertion without yet claiming authentication.
    ///
    /// # Errors
    ///
    /// Rejects malformed transport, expired/reused challenges, changed retries, wrong keys and
    /// malformed or substituted local evidence.
    pub fn prepare(
        &mut self,
        authentication: &SessionAuthentication,
        operation_id: OperationId,
        now: UnixMicros,
    ) -> Result<PreparedPasskeySession, PasskeySessionError> {
        let SessionAuthentication::Passkey {
            challenge_id,
            credential_id,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
        } = authentication
        else {
            return Err(PasskeySessionError::Rejected);
        };
        let challenge_id = parse_challenge_id(challenge_id)?;
        let assertion = OwnedAssertion::decode(
            credential_id,
            client_data_json,
            authenticator_data,
            signature,
            user_handle.as_deref(),
        )
        .map_err(|_| PasskeySessionError::Rejected)?;
        let assertion_digest = assertion_digest(&assertion)?;
        self.store
            .begin_verification(challenge_id, operation_id, assertion_digest, now)?;
        let record = self
            .store
            .ceremony(challenge_id)?
            .ok_or(PasskeySessionError::Rejected)?;
        if record.kind != AuthenticationCeremonyKind::PasskeyAuthentication
            || record.completion_operation_id != Some(operation_id)
            || record.assertion_digest != Some(assertion_digest)
        {
            return Err(PasskeySessionError::Conflict);
        }
        let binding = PasskeyChallengeBinding {
            challenge_id,
            operation_id: record.creation_operation_id,
            request_digest: record.request_digest,
            created_at: record.created_at,
            expires_at: record.expires_at,
        };
        let state = self
            .protector
            .unprotect(binding, &record.protected_state)
            .map_err(|_| PasskeySessionError::Failed)?;
        Ok(PreparedPasskeySession {
            challenge_id,
            operation_id,
            assertion,
            state,
            recorded_result_digest: record.authority_result_digest,
        })
    }

    /// Records and locally completes the exact authoritative result.
    ///
    /// # Errors
    ///
    /// Fails closed until both restart-safe local transitions are durable.
    pub fn complete(
        &mut self,
        prepared: &PreparedPasskeySession,
        result_digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<(), PasskeySessionError> {
        self.store.record_authority_commit(
            prepared.challenge_id,
            prepared.operation_id,
            result_digest,
            now,
        )?;
        self.store
            .complete_ceremony(prepared.challenge_id, prepared.operation_id, now)?;
        Ok(())
    }
}

/// Reserved assertion plus its authenticated challenge state.
pub struct PreparedPasskeySession {
    challenge_id: AuthenticationChallengeId,
    operation_id: OperationId,
    assertion: OwnedAssertion,
    state: FrozenPasskeyChallengeState,
    recorded_result_digest: Option<[u8; 32]>,
}

impl PreparedPasskeySession {
    /// Borrows the opaque credential identity for current authoritative lookup.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        self.assertion.credential_id()
    }

    /// Borrows the secret seed used only to reconstruct exact session delivery material.
    #[must_use]
    pub fn session_seed(&self) -> &[u8; 32] {
        self.state.session_seed()
    }

    /// Returns a locally recorded authoritative receipt after an interrupted completion.
    #[must_use]
    pub const fn recorded_result_digest(&self) -> Option<[u8; 32]> {
        self.recorded_result_digest
    }

    /// Cryptographically verifies the reserved assertion against current authoritative material.
    ///
    /// # Errors
    ///
    /// Rejects wrong credential/key shape, challenge/RP/origin/user binding, interaction flags,
    /// invalid signature, counter regression and backup-eligibility substitution.
    pub fn verify(
        &self,
        material: &PasskeyVerificationMaterial,
    ) -> Result<VerifiedPasskeyFactor, PasskeySessionError> {
        if material.public_key_algorithm != -7
            || material.credential_id != self.assertion.credential_id()
        {
            return Err(PasskeySessionError::Rejected);
        }
        let public_key = Es256PublicKey::from_sec1_bytes(&material.public_key)
            .map_err(|_| PasskeySessionError::Rejected)?;
        let origins: Vec<&str> = self
            .state
            .allowed_origins()
            .iter()
            .map(String::as_str)
            .collect();
        let principal_handle = material.principal_id.as_bytes();
        let previous_sign_count =
            u32::try_from(material.signature_counter).map_err(|_| PasskeySessionError::Failed)?;
        let outcome = verify_assertion(
            &self.assertion.as_assertion(),
            &AssertionExpectation {
                credential_id: &material.credential_id,
                public_key: &public_key,
                challenge: self.state.challenge().as_bytes(),
                relying_party_id: self.state.relying_party_id(),
                allowed_origins: &origins,
                user_verification: UserVerification::Required,
                previous_sign_count,
                user_handle: Some(&principal_handle),
            },
        )
        .map_err(|_| PasskeySessionError::Rejected)?;
        if outcome.backup_eligible != material.backup_eligible {
            return Err(PasskeySessionError::Rejected);
        }
        let signature_counter = match outcome.counter {
            CounterState::Unsupported => 0,
            CounterState::Advanced(counter) => u64::from(counter),
        };
        Ok(VerifiedPasskeyFactor {
            principal_id: material.principal_id,
            method_id: material.method_id,
            credential_generation: material.credential_generation,
            method_revision: material.revision,
            credential_id: material.credential_id.clone(),
            signature_counter,
            backup_state: outcome.backup_state,
        })
    }
}

/// Verified passkey evidence safe to submit to authoritative session issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPasskeyFactor {
    /// Authenticated principal.
    pub principal_id: PrincipalId,
    /// Authoritative method identity.
    pub method_id: AuthenticationMethodId,
    /// Credential generation fencing older evidence.
    pub credential_generation: u64,
    /// Exact method revision verified before the command.
    pub method_revision: Revision,
    /// Opaque credential identity.
    pub credential_id: Vec<u8>,
    /// Verified new authenticator signature counter, or zero when unsupported.
    pub signature_counter: u64,
    /// Verified current credential backup state.
    pub backup_state: bool,
}

/// Stable passkey session failure without assertion, credential or key detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasskeySessionError {
    /// Assertion transport, challenge or cryptographic evidence was rejected.
    #[error("passkey authentication was rejected")]
    Rejected,
    /// The operation or challenge is already bound to different evidence.
    #[error("passkey authentication conflicts with local state")]
    Conflict,
    /// Local protected state or persistence failed closed.
    #[error("passkey authentication failed closed")]
    Failed,
}

impl From<PasskeySessionStoreError> for PasskeySessionError {
    fn from(error: PasskeySessionStoreError) -> Self {
        match error {
            PasskeySessionStoreError::Rejected => Self::Rejected,
            PasskeySessionStoreError::Conflict => Self::Conflict,
            PasskeySessionStoreError::Failed => Self::Failed,
        }
    }
}

fn parse_challenge_id(value: &str) -> Result<AuthenticationChallengeId, PasskeySessionError> {
    AuthenticationChallengeId::from_bytes(
        parse_uuid(value).map_err(|_| PasskeySessionError::Rejected)?,
    )
    .map_err(|_| PasskeySessionError::Rejected)
}

fn assertion_digest(assertion: &OwnedAssertion) -> Result<[u8; 32], PasskeySessionError> {
    let assertion = assertion.as_assertion();
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.passkey-assertion.v1\0");
    digest_field(&mut digest, assertion.credential_id)?;
    digest_field(&mut digest, assertion.client_data_json)?;
    digest_field(&mut digest, assertion.authenticator_data)?;
    digest_field(&mut digest, assertion.signature)?;
    match assertion.user_handle {
        Some(user_handle) => {
            digest.update([1]);
            digest_field(&mut digest, user_handle)?;
        }
        None => digest.update([0]),
    }
    Ok(digest.finalize().into())
}

fn digest_field(digest: &mut Sha256, value: &[u8]) -> Result<(), PasskeySessionError> {
    digest.update(
        u64::try_from(value.len())
            .map_err(|_| PasskeySessionError::Failed)?
            .to_be_bytes(),
    );
    digest.update(value);
    Ok(())
}

const fn map_store_error(error: AuthenticationCeremonyError) -> PasskeySessionStoreError {
    match error {
        AuthenticationCeremonyError::Expired => PasskeySessionStoreError::Rejected,
        AuthenticationCeremonyError::Conflict => PasskeySessionStoreError::Conflict,
        AuthenticationCeremonyError::Store | AuthenticationCeremonyError::Invalid => {
            PasskeySessionStoreError::Failed
        }
    }
}
