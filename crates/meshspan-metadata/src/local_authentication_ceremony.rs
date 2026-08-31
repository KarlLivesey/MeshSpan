// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe node-local journal for short-lived authentication ceremonies.

use std::fmt;

use meshspan_domain::{AuthenticationChallengeId, OperationId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::LocalDatabase;

/// Maximum lifetime of one gateway-bound challenge: ten minutes.
pub const MAXIMUM_AUTHENTICATION_CEREMONY_LIFETIME_MICROS: i64 = 600_000_000;
const MAXIMUM_PROTECTED_STATE_BYTES: usize = 65_536;

/// Closed ceremony families sharing the same crash-safe lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationCeremonyKind {
    /// Authentication with an existing passkey.
    PasskeyAuthentication,
    /// Additional TOTP or recovery proof for login or recent step-up.
    AdditionalFactor,
    /// Registration of a new passkey after current authority is established.
    PasskeyRegistration,
    /// Registration of a new TOTP seed after current authority is established.
    TotpRegistration,
}

/// Authenticated ciphertext owned by the selected authentication adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedAuthenticationState(Vec<u8>);

impl ProtectedAuthenticationState {
    /// Wraps one bounded non-empty authenticated ciphertext.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized adapter state before persistence.
    pub fn new(bytes: Vec<u8>) -> Result<Self, AuthenticationCeremonyError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_PROTECTED_STATE_BYTES {
            Err(AuthenticationCeremonyError::Invalid)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Borrows the ciphertext for the authentication adapter.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.0).into()
    }
}

impl fmt::Debug for ProtectedAuthenticationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedAuthenticationState")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// First durable record for one exact challenge-generation operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewAuthenticationCeremony {
    /// Random stable challenge identity returned to the client.
    pub challenge_id: AuthenticationChallengeId,
    /// Idempotency identity of challenge creation.
    pub creation_operation_id: OperationId,
    /// Authentication adapter family.
    pub kind: AuthenticationCeremonyKind,
    /// Digest of all canonical non-random request fields.
    pub request_digest: [u8; 32],
    /// Authenticated ciphertext required to verify the response.
    pub protected_state: ProtectedAuthenticationState,
    /// Local creation instant.
    pub created_at: UnixMicros,
    /// Exclusive bounded challenge expiry.
    pub expires_at: UnixMicros,
}

/// Durable ceremony lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationCeremonyState {
    /// Challenge is available for one completion operation.
    Active,
    /// One exact assertion and completion operation own verification.
    Verifying,
    /// The mesh-wide authoritative result is durable.
    AuthorityCommitted,
    /// Local completion is durable and the challenge is terminal.
    Consumed,
}

/// Complete bounded node-local ceremony evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationCeremonyRecord {
    /// Stable challenge identity.
    pub challenge_id: AuthenticationChallengeId,
    /// Challenge-generation operation.
    pub creation_operation_id: OperationId,
    /// Authentication adapter family.
    pub kind: AuthenticationCeremonyKind,
    /// Canonical challenge request digest.
    pub request_digest: [u8; 32],
    /// Authenticated verifier state ciphertext.
    pub protected_state: ProtectedAuthenticationState,
    /// Digest detecting ciphertext substitution before adapter use.
    pub protected_state_digest: [u8; 32],
    /// Current lifecycle state.
    pub state: AuthenticationCeremonyState,
    /// Completion operation permanently bound on first verification attempt.
    pub completion_operation_id: Option<OperationId>,
    /// Digest of the exact untrusted assertion bound to that operation.
    pub assertion_digest: Option<[u8; 32]>,
    /// Mesh-wide result receipt once committed.
    pub authority_result_digest: Option<[u8; 32]>,
    /// Creation and expiry window.
    pub created_at: UnixMicros,
    /// Exclusive expiry.
    pub expires_at: UnixMicros,
    /// First verification reservation instant.
    pub verification_started_at: Option<UnixMicros>,
    /// Local observation of the authoritative result.
    pub authority_committed_at: Option<UnixMicros>,
    /// Terminal local completion instant.
    pub consumed_at: Option<UnixMicros>,
    /// Monotonic local journal revision.
    pub revision: Revision,
}

/// Idempotent result of one ceremony transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationCeremonyDisposition {
    /// This invocation durably advanced the lifecycle.
    Applied,
    /// The exact requested state was already durable.
    Replayed,
}

/// Stable node-local ceremony failure without assertion or credential details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationCeremonyError {
    /// SQLite could not durably complete the transition.
    #[error("authentication ceremony persistence failed")]
    Store,
    /// Proposed or stored evidence violates the closed lifecycle.
    #[error("authentication ceremony evidence is invalid")]
    Invalid,
    /// An identifier is already bound to different semantic input.
    #[error("authentication ceremony state conflicts with the request")]
    Conflict,
    /// The challenge expired before verification ownership was established.
    #[error("authentication ceremony has expired")]
    Expired,
}

impl From<rusqlite::Error> for AuthenticationCeremonyError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Store
    }
}

impl LocalDatabase {
    /// Creates or exactly resolves one bounded authentication challenge.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds, digest substitution and changed operation retries.
    pub fn create_authentication_ceremony(
        &mut self,
        ceremony: &NewAuthenticationCeremony,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationCeremonyError> {
        validate_new(ceremony)?;
        let state_digest = ceremony.protected_state.digest();
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = load_by_creation(&transaction, ceremony.creation_operation_id)? {
            return if matches_new(&existing, ceremony, state_digest) {
                Ok(AuthenticationCeremonyDisposition::Replayed)
            } else {
                Err(AuthenticationCeremonyError::Conflict)
            };
        }
        transaction.execute(
            "INSERT INTO local_authentication_ceremonies(
                challenge_id, creation_operation_id, ceremony_kind, request_digest,
                protected_state, protected_state_digest, state, completion_operation_id,
                assertion_digest, authority_result_digest, created_at, expires_at,
                verification_started_at, authority_committed_at, consumed_at, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, NULL, NULL, NULL, ?7, ?8,
                       NULL, NULL, NULL, 1)",
            params![
                ceremony.challenge_id.as_bytes().as_slice(),
                ceremony.creation_operation_id.as_bytes().as_slice(),
                kind_code(ceremony.kind),
                ceremony.request_digest.as_slice(),
                ceremony.protected_state.as_bytes(),
                state_digest.as_slice(),
                ceremony.created_at.get(),
                ceremony.expires_at.get(),
            ],
        )?;
        transaction.commit()?;
        Ok(AuthenticationCeremonyDisposition::Applied)
    }

    /// Permanently binds one challenge to one assertion and completion operation.
    ///
    /// # Errors
    ///
    /// Rejects expiry, zero digests, changed retries and terminal or corrupt state.
    pub fn begin_authentication_verification(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        completion_operation_id: OperationId,
        assertion_digest: [u8; 32],
        started_at: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationCeremonyError> {
        if assertion_digest == [0; 32] {
            return Err(AuthenticationCeremonyError::Invalid);
        }
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = load_by_challenge(&transaction, challenge_id)?
            .ok_or(AuthenticationCeremonyError::Conflict)?;
        if record.state != AuthenticationCeremonyState::Active {
            return replay_verification(&record, completion_operation_id, assertion_digest);
        }
        if started_at < record.created_at {
            return Err(AuthenticationCeremonyError::Invalid);
        }
        if started_at >= record.expires_at {
            return Err(AuthenticationCeremonyError::Expired);
        }
        let changed = transaction.execute(
            "UPDATE local_authentication_ceremonies
             SET state = 2, completion_operation_id = ?1, assertion_digest = ?2,
                 verification_started_at = ?3, revision = revision + 1
             WHERE challenge_id = ?4 AND state = 1 AND revision = ?5",
            params![
                completion_operation_id.as_bytes().as_slice(),
                assertion_digest.as_slice(),
                started_at.get(),
                challenge_id.as_bytes().as_slice(),
                revision_i64(record.revision)?,
            ],
        )?;
        if changed != 1 {
            return Err(AuthenticationCeremonyError::Conflict);
        }
        transaction.commit()?;
        Ok(AuthenticationCeremonyDisposition::Applied)
    }

    /// Records the mesh-wide result for the exact bound completion operation.
    ///
    /// # Errors
    ///
    /// Rejects missing verification, zero or changed receipts and invalid time ordering.
    pub fn record_authentication_authority_commit(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        completion_operation_id: OperationId,
        result_digest: [u8; 32],
        committed_at: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationCeremonyError> {
        if result_digest == [0; 32] {
            return Err(AuthenticationCeremonyError::Invalid);
        }
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = load_by_challenge(&transaction, challenge_id)?
            .ok_or(AuthenticationCeremonyError::Conflict)?;
        require_completion(&record, completion_operation_id)?;
        match record.state {
            AuthenticationCeremonyState::Verifying => {
                let started = record
                    .verification_started_at
                    .ok_or(AuthenticationCeremonyError::Invalid)?;
                if committed_at < started {
                    return Err(AuthenticationCeremonyError::Invalid);
                }
                let changed = transaction.execute(
                    "UPDATE local_authentication_ceremonies
                     SET state = 3, authority_result_digest = ?1,
                         authority_committed_at = ?2, revision = revision + 1
                     WHERE challenge_id = ?3 AND state = 2 AND revision = ?4",
                    params![
                        result_digest.as_slice(),
                        committed_at.get(),
                        challenge_id.as_bytes().as_slice(),
                        revision_i64(record.revision)?,
                    ],
                )?;
                if changed != 1 {
                    return Err(AuthenticationCeremonyError::Conflict);
                }
                transaction.commit()?;
                Ok(AuthenticationCeremonyDisposition::Applied)
            }
            AuthenticationCeremonyState::AuthorityCommitted
            | AuthenticationCeremonyState::Consumed
                if record.authority_result_digest == Some(result_digest) =>
            {
                Ok(AuthenticationCeremonyDisposition::Replayed)
            }
            AuthenticationCeremonyState::Active
            | AuthenticationCeremonyState::AuthorityCommitted
            | AuthenticationCeremonyState::Consumed => Err(AuthenticationCeremonyError::Conflict),
        }
    }

    /// Completes one ceremony only after its exact authoritative result is durable.
    ///
    /// # Errors
    ///
    /// Rejects early, substituted, stale-time or changed completion attempts.
    pub fn complete_authentication_ceremony(
        &mut self,
        challenge_id: AuthenticationChallengeId,
        completion_operation_id: OperationId,
        consumed_at: UnixMicros,
    ) -> Result<AuthenticationCeremonyDisposition, AuthenticationCeremonyError> {
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = load_by_challenge(&transaction, challenge_id)?
            .ok_or(AuthenticationCeremonyError::Conflict)?;
        require_completion(&record, completion_operation_id)?;
        match record.state {
            AuthenticationCeremonyState::AuthorityCommitted => {
                let committed = record
                    .authority_committed_at
                    .ok_or(AuthenticationCeremonyError::Invalid)?;
                if consumed_at < committed {
                    return Err(AuthenticationCeremonyError::Invalid);
                }
                let changed = transaction.execute(
                    "UPDATE local_authentication_ceremonies
                     SET state = 4, consumed_at = ?1, revision = revision + 1
                     WHERE challenge_id = ?2 AND state = 3 AND revision = ?3",
                    params![
                        consumed_at.get(),
                        challenge_id.as_bytes().as_slice(),
                        revision_i64(record.revision)?,
                    ],
                )?;
                if changed != 1 {
                    return Err(AuthenticationCeremonyError::Conflict);
                }
                transaction.commit()?;
                Ok(AuthenticationCeremonyDisposition::Applied)
            }
            AuthenticationCeremonyState::Consumed => {
                Ok(AuthenticationCeremonyDisposition::Replayed)
            }
            AuthenticationCeremonyState::Active | AuthenticationCeremonyState::Verifying => {
                Err(AuthenticationCeremonyError::Conflict)
            }
        }
    }

    /// Loads one challenge while verifying its protected-state digest and lifecycle shape.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed or substituted persisted evidence.
    pub fn authentication_ceremony(
        &self,
        challenge_id: AuthenticationChallengeId,
    ) -> Result<Option<AuthenticationCeremonyRecord>, AuthenticationCeremonyError> {
        load_by_challenge(self.connection(), challenge_id)
    }

    /// Loads one challenge by its creation operation while verifying all persisted evidence.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed or substituted persisted evidence.
    pub fn authentication_ceremony_by_creation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthenticationCeremonyRecord>, AuthenticationCeremonyError> {
        load_by_creation(self.connection(), operation_id)
    }
}

fn validate_new(ceremony: &NewAuthenticationCeremony) -> Result<(), AuthenticationCeremonyError> {
    let lifetime = ceremony
        .expires_at
        .get()
        .checked_sub(ceremony.created_at.get())
        .ok_or(AuthenticationCeremonyError::Invalid)?;
    if ceremony.request_digest == [0; 32]
        || lifetime <= 0
        || lifetime > MAXIMUM_AUTHENTICATION_CEREMONY_LIFETIME_MICROS
    {
        Err(AuthenticationCeremonyError::Invalid)
    } else {
        Ok(())
    }
}

fn matches_new(
    existing: &AuthenticationCeremonyRecord,
    candidate: &NewAuthenticationCeremony,
    state_digest: [u8; 32],
) -> bool {
    existing.challenge_id == candidate.challenge_id
        && existing.kind == candidate.kind
        && existing.request_digest == candidate.request_digest
        && existing.protected_state_digest == state_digest
        && existing.protected_state == candidate.protected_state
        && existing.created_at == candidate.created_at
        && existing.expires_at == candidate.expires_at
}

fn replay_verification(
    record: &AuthenticationCeremonyRecord,
    operation_id: OperationId,
    assertion_digest: [u8; 32],
) -> Result<AuthenticationCeremonyDisposition, AuthenticationCeremonyError> {
    if record.completion_operation_id == Some(operation_id)
        && record.assertion_digest == Some(assertion_digest)
    {
        Ok(AuthenticationCeremonyDisposition::Replayed)
    } else {
        Err(AuthenticationCeremonyError::Conflict)
    }
}

fn require_completion(
    record: &AuthenticationCeremonyRecord,
    operation_id: OperationId,
) -> Result<(), AuthenticationCeremonyError> {
    if record.completion_operation_id == Some(operation_id) {
        Ok(())
    } else {
        Err(AuthenticationCeremonyError::Conflict)
    }
}

fn load_by_creation(
    connection: &rusqlite::Connection,
    operation_id: OperationId,
) -> Result<Option<AuthenticationCeremonyRecord>, AuthenticationCeremonyError> {
    load(connection, "creation_operation_id", operation_id.as_bytes())
}

fn load_by_challenge(
    connection: &rusqlite::Connection,
    challenge_id: AuthenticationChallengeId,
) -> Result<Option<AuthenticationCeremonyRecord>, AuthenticationCeremonyError> {
    load(connection, "challenge_id", challenge_id.as_bytes())
}

fn load(
    connection: &rusqlite::Connection,
    column: &str,
    identifier: [u8; 16],
) -> Result<Option<AuthenticationCeremonyRecord>, AuthenticationCeremonyError> {
    let sql = format!(
        "SELECT challenge_id, creation_operation_id, ceremony_kind, request_digest,
                protected_state, protected_state_digest, state, completion_operation_id,
                assertion_digest, authority_result_digest, created_at, expires_at,
                verification_started_at, authority_committed_at, consumed_at, revision
         FROM local_authentication_ceremonies WHERE {column} = ?1"
    );
    connection
        .query_row(&sql, [identifier.as_slice()], parse_record)
        .optional()
        .map_err(AuthenticationCeremonyError::from)
}

fn parse_record(row: &Row<'_>) -> Result<AuthenticationCeremonyRecord, rusqlite::Error> {
    parse_record_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn parse_record_inner(
    row: &Row<'_>,
) -> Result<AuthenticationCeremonyRecord, AuthenticationCeremonyError> {
    let protected_state = ProtectedAuthenticationState::new(row.get(4)?)?;
    let protected_state_digest = fixed(row.get(5)?)?;
    if protected_state.digest() != protected_state_digest {
        return Err(AuthenticationCeremonyError::Invalid);
    }
    Ok(AuthenticationCeremonyRecord {
        challenge_id: AuthenticationChallengeId::from_bytes(fixed(row.get(0)?)?)
            .map_err(|_| AuthenticationCeremonyError::Invalid)?,
        creation_operation_id: OperationId::from_bytes(fixed(row.get(1)?)?)
            .map_err(|_| AuthenticationCeremonyError::Invalid)?,
        kind: parse_kind(row.get(2)?)?,
        request_digest: fixed(row.get(3)?)?,
        protected_state,
        protected_state_digest,
        state: parse_state(row.get(6)?)?,
        completion_operation_id: optional_identifier(row.get(7)?)?,
        assertion_digest: optional_fixed(row.get(8)?)?,
        authority_result_digest: optional_fixed(row.get(9)?)?,
        created_at: UnixMicros::new(row.get(10)?),
        expires_at: UnixMicros::new(row.get(11)?),
        verification_started_at: row.get::<_, Option<i64>>(12)?.map(UnixMicros::new),
        authority_committed_at: row.get::<_, Option<i64>>(13)?.map(UnixMicros::new),
        consumed_at: row.get::<_, Option<i64>>(14)?.map(UnixMicros::new),
        revision: Revision::new(
            u64::try_from(row.get::<_, i64>(15)?)
                .map_err(|_| AuthenticationCeremonyError::Invalid)?,
        ),
    })
}

const fn kind_code(kind: AuthenticationCeremonyKind) -> i64 {
    match kind {
        AuthenticationCeremonyKind::PasskeyAuthentication => 1,
        AuthenticationCeremonyKind::AdditionalFactor => 2,
        AuthenticationCeremonyKind::PasskeyRegistration => 3,
        AuthenticationCeremonyKind::TotpRegistration => 4,
    }
}

const fn parse_kind(value: i64) -> Result<AuthenticationCeremonyKind, AuthenticationCeremonyError> {
    match value {
        1 => Ok(AuthenticationCeremonyKind::PasskeyAuthentication),
        2 => Ok(AuthenticationCeremonyKind::AdditionalFactor),
        3 => Ok(AuthenticationCeremonyKind::PasskeyRegistration),
        4 => Ok(AuthenticationCeremonyKind::TotpRegistration),
        _ => Err(AuthenticationCeremonyError::Invalid),
    }
}

const fn parse_state(
    value: i64,
) -> Result<AuthenticationCeremonyState, AuthenticationCeremonyError> {
    match value {
        1 => Ok(AuthenticationCeremonyState::Active),
        2 => Ok(AuthenticationCeremonyState::Verifying),
        3 => Ok(AuthenticationCeremonyState::AuthorityCommitted),
        4 => Ok(AuthenticationCeremonyState::Consumed),
        _ => Err(AuthenticationCeremonyError::Invalid),
    }
}

fn optional_identifier(
    value: Option<Vec<u8>>,
) -> Result<Option<OperationId>, AuthenticationCeremonyError> {
    value
        .map(|value| {
            OperationId::from_bytes(fixed(value)?).map_err(|_| AuthenticationCeremonyError::Invalid)
        })
        .transpose()
}

fn optional_fixed<const N: usize>(
    value: Option<Vec<u8>>,
) -> Result<Option<[u8; N]>, AuthenticationCeremonyError> {
    value.map(fixed).transpose()
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], AuthenticationCeremonyError> {
    value
        .try_into()
        .map_err(|_| AuthenticationCeremonyError::Invalid)
}

fn revision_i64(revision: Revision) -> Result<i64, AuthenticationCeremonyError> {
    i64::try_from(revision.get()).map_err(|_| AuthenticationCeremonyError::Invalid)
}
