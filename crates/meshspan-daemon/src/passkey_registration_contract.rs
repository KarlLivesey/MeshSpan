// SPDX-License-Identifier: GPL-2.0-only

//! Persistence, replicated-authority and failure contracts for passkey registration.

use meshspan_domain::{AuthenticationChallengeId, AuthenticationMethodId, OperationId, UnixMicros};
use meshspan_metadata::{
    AuthenticationCeremonyDisposition, AuthenticationCeremonyError, AuthenticationCeremonyRecord,
    AuthoritativeCommand, CommandContext, LocalDatabase, NewAuthenticationCeremony,
    PasskeyRegistrationProfile,
};
use thiserror::Error;

use crate::passkey_registration_state::PasskeyRegistrationStateError;
use crate::{BrowserAuthenticationError, BrowserSessionAuthority};

/// Node-local crash-safe persistence shared by authentication-method registration ceremonies.
pub trait AuthenticationRegistrationStore {
    /// Resolves an earlier challenge-creation operation.
    ///
    /// # Errors
    ///
    /// Fails closed when local ceremony evidence cannot be read and validated.
    fn ceremony_by_creation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthenticationCeremonyRecord>, AuthenticationRegistrationStoreError>;

    /// Resolves one exact registration challenge.
    ///
    /// # Errors
    ///
    /// Fails closed when local ceremony evidence cannot be read and validated.
    fn ceremony(
        &self,
        challenge_id: AuthenticationChallengeId,
    ) -> Result<Option<AuthenticationCeremonyRecord>, AuthenticationRegistrationStoreError>;

    /// Durably creates or exactly replays one challenge.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and unavailable or corrupt persistence.
    fn create_ceremony(
        &mut self,
        ceremony: &NewAuthenticationCeremony,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationRegistrationStoreError>;

    /// Reserves one exact browser response before verification.
    ///
    /// # Errors
    ///
    /// Rejects expiry, changed completion input and unavailable or corrupt persistence.
    fn begin_verification(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        response_digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationRegistrationStoreError>;

    /// Records the exact durable metadata result.
    ///
    /// # Errors
    ///
    /// Rejects missing verification, changed receipts and invalid lifecycle ordering.
    fn record_authority_commit(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        result_digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationRegistrationStoreError>;

    /// Marks the registration terminal only after authority is durable.
    ///
    /// # Errors
    ///
    /// Rejects early or substituted completion and unavailable persistence.
    fn complete_ceremony(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationRegistrationStoreError>;
}

impl AuthenticationRegistrationStore for LocalDatabase {
    fn ceremony_by_creation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthenticationCeremonyRecord>, AuthenticationRegistrationStoreError> {
        self.authentication_ceremony_by_creation(operation_id)
            .map_err(map_store_error)
    }

    fn ceremony(
        &self,
        challenge_id: AuthenticationChallengeId,
    ) -> Result<Option<AuthenticationCeremonyRecord>, AuthenticationRegistrationStoreError> {
        self.authentication_ceremony(challenge_id)
            .map_err(map_store_error)
    }

    fn create_ceremony(
        &mut self,
        ceremony: &NewAuthenticationCeremony,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationRegistrationStoreError> {
        self.create_authentication_ceremony(ceremony)
            .map_err(map_store_error)
    }

    fn begin_verification(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        response_digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationRegistrationStoreError> {
        self.begin_authentication_verification(challenge_id, operation_id, response_digest, now)
            .map_err(map_store_error)
    }

    fn record_authority_commit(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        result_digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationRegistrationStoreError> {
        self.record_authentication_authority_commit(challenge_id, operation_id, result_digest, now)
            .map_err(map_store_error)
    }

    fn complete_ceremony(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        operation_id: OperationId,
        now: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationRegistrationStoreError> {
        self.complete_authentication_ceremony(challenge_id, operation_id, now)
            .map_err(map_store_error)
    }
}

/// Compatibility-facing passkey name over the common registration journal contract.
pub trait PasskeyRegistrationStore: AuthenticationRegistrationStore {}

impl<T> PasskeyRegistrationStore for T where T: AuthenticationRegistrationStore + ?Sized {}

/// Replicated reads and mutation required by current-user passkey registration.
pub trait PasskeyRegistrationAuthority: BrowserSessionAuthority {
    /// Loads one current active user's authenticator profile.
    ///
    /// # Errors
    ///
    /// Fails closed when replicated identity evidence is unavailable or malformed.
    fn registration_profile(
        &self,
        principal_id: meshspan_domain::PrincipalId,
    ) -> Result<Option<PasskeyRegistrationProfile>, PasskeyRegistrationAuthorityError>;

    /// Resolves an already committed registration before reconstructing its original time-bound
    /// command digest.
    ///
    /// # Errors
    ///
    /// Rejects an operation naming another command family and fails closed for malformed
    /// authoritative evidence.
    fn resolve_registration(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<PasskeyRegistrationCommit>, PasskeyRegistrationAuthorityError>;

    /// Commits or exactly resolves one passkey method creation through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never claims success without a durable result.
    fn commit_or_resolve_registration(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<PasskeyRegistrationCommit, PasskeyRegistrationAuthorityError>;
}

/// Exact result facts returned by the authoritative mutation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasskeyRegistrationCommit {
    /// Semantic request digest stored by authority.
    pub request_digest: [u8; 32],
    /// Durable result digest.
    pub result_digest: [u8; 32],
    /// Exact created method.
    pub method_id: AuthenticationMethodId,
    /// Exact owning user.
    pub principal_id: meshspan_domain::PrincipalId,
    /// Original authoritative creation instant.
    pub created_at: UnixMicros,
}

/// Closed local registration-journal failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationRegistrationStoreError {
    /// Challenge expiry won the verification reservation race.
    #[error("passkey registration challenge expired")]
    Expired,
    /// An identifier names different local semantic input.
    #[error("passkey registration conflicts with local state")]
    Conflict,
    /// Local persistence or its protected evidence failed closed.
    #[error("passkey registration store failed closed")]
    Failed,
}

/// Passkey-facing name retained for its public error surface.
pub type PasskeyRegistrationStoreError = AuthenticationRegistrationStoreError;

/// Closed replicated-authority registration failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasskeyRegistrationAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("passkey registration authority is unavailable")]
    Unavailable,
    /// Operation identity is already bound to different input.
    #[error("passkey registration authority conflicts with durable state")]
    Conflict,
    /// Persisted authority or its receipt failed validation.
    #[error("passkey registration authority failed closed")]
    Failed,
}

/// Stable registration failure containing no credential, challenge or session material.
#[derive(Debug, Error)]
pub enum PasskeyRegistrationError {
    /// Public identifiers or bounded fields are invalid.
    #[error("passkey registration request is invalid")]
    InvalidRequest,
    /// The current browser session or registration response was rejected.
    #[error("passkey registration was rejected")]
    Rejected,
    /// The challenge or operation conflicts with durable state.
    #[error("passkey registration conflicts with durable state")]
    Conflict,
    /// The challenge lifetime cannot be represented safely.
    #[error("passkey registration time window is invalid")]
    InvalidTime,
    /// Cryptographic entropy was unavailable.
    #[error("passkey registration is unavailable")]
    Unavailable,
    /// Current browser authentication failed.
    #[error("passkey registration authentication failed")]
    Authentication(#[source] BrowserAuthenticationError),
    /// Node-local journal failure.
    #[error("passkey registration local state failed")]
    Store(#[from] PasskeyRegistrationStoreError),
    /// Protected registration state failure.
    #[error("passkey registration protected state failed")]
    State,
    /// Replicated authority failure.
    #[error("passkey registration authority failed")]
    Authority(#[from] PasskeyRegistrationAuthorityError),
    /// Durable result evidence is invalid.
    #[error("passkey registration receipt is invalid")]
    InvalidReceipt,
}

impl From<crate::PasskeyRegistrationConfigurationError> for PasskeyRegistrationError {
    fn from(_: crate::PasskeyRegistrationConfigurationError) -> Self {
        Self::InvalidRequest
    }
}

impl From<PasskeyRegistrationStateError> for PasskeyRegistrationError {
    fn from(_: PasskeyRegistrationStateError) -> Self {
        Self::State
    }
}

const fn map_store_error(
    error: AuthenticationCeremonyError,
) -> AuthenticationRegistrationStoreError {
    match error {
        AuthenticationCeremonyError::Expired => AuthenticationRegistrationStoreError::Expired,
        AuthenticationCeremonyError::Conflict => AuthenticationRegistrationStoreError::Conflict,
        AuthenticationCeremonyError::Store | AuthenticationCeremonyError::Invalid => {
            AuthenticationRegistrationStoreError::Failed
        }
    }
}
