// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe node-local journal around cross-database setup transitions.

use meshspan_domain::{ClaimId, OperationId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;

use crate::local_claim::{consume_in_transaction, digests_match, load_by_id};
use crate::{LocalClaimError, LocalClaimMutationDisposition, LocalClaimState, LocalDatabase};

const CREATE_MESH: i64 = 1;
const JOIN_MESH: i64 = 2;
const PREPARED: i64 = 1;
const AUTHORITY_COMMITTED: i64 = 2;
const CONFIGURED: i64 = 3;

/// Closed first-start operation families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalSetupKind {
    /// Creates the first authoritative mesh partition on this node.
    CreateMesh,
    /// Enrols this node into an existing mesh.
    JoinMesh,
}

/// Durable progress through a restartable first-start operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalSetupState {
    /// Exact input is journalled; authoritative work may need to run or resolve.
    Prepared,
    /// The authoritative result is durable; local claim completion remains.
    AuthorityCommitted,
    /// Authoritative setup and atomic local claim consumption both completed.
    Configured,
}

/// Input needed to durably bind one first-start request before remote work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewLocalSetup {
    /// Idempotency identity also used for authoritative result resolution.
    pub operation_id: OperationId,
    /// Exact active first-boot claim being presented.
    pub claim_id: ClaimId,
    /// Digest of the presented claim secret; plaintext is never persisted.
    pub claim_secret_digest: [u8; 32],
    /// Create or join family.
    pub kind: LocalSetupKind,
    /// Canonical digest of every semantic request field.
    pub request_digest: [u8; 32],
    /// Local authoritative instant when preparation began.
    pub created_at: UnixMicros,
}

/// Complete non-secret setup journal evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalSetupRecord {
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// First-boot claim bound to this operation.
    pub claim_id: ClaimId,
    /// Create or join family.
    pub kind: LocalSetupKind,
    /// Canonical semantic input digest.
    pub request_digest: [u8; 32],
    /// Current restart state.
    pub state: LocalSetupState,
    /// Digest of the authoritative receipt, once resolved.
    pub authority_result_digest: Option<[u8; 32]>,
    /// Preparation instant.
    pub created_at: UnixMicros,
    /// Local observation time of the authoritative commit.
    pub authority_committed_at: Option<UnixMicros>,
    /// Local completion and claim-consumption instant.
    pub completed_at: Option<UnixMicros>,
    /// Monotonic journal revision.
    pub revision: Revision,
}

/// Idempotent outcome of one setup-journal transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalSetupDisposition {
    /// This call made the requested transition durable.
    Applied,
    /// The exact requested transition was already durable.
    Replayed,
}

/// Stable setup-journal failure without claim or request details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocalSetupError {
    /// SQLite rejected or could not durably commit the operation.
    #[error("local setup persistence failed")]
    Store,
    /// Proposed or persisted setup evidence violates the closed contract.
    #[error("local setup evidence is invalid")]
    Invalid,
    /// Another operation or changed retry conflicts with this transition.
    #[error("local setup state conflicts with the requested transition")]
    Conflict,
    /// The presented first-boot claim was not accepted.
    #[error("first-boot claim was not accepted")]
    ClaimRejected,
}

impl From<rusqlite::Error> for LocalSetupError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Store
    }
}

impl From<LocalClaimError> for LocalSetupError {
    fn from(error: LocalClaimError) -> Self {
        match error {
            LocalClaimError::Store => Self::Store,
            LocalClaimError::Invalid => Self::Invalid,
            LocalClaimError::Conflict => Self::Conflict,
            LocalClaimError::Rejected => Self::ClaimRejected,
        }
    }
}

impl LocalDatabase {
    /// Verifies the active claim and journals one exact setup request before authority work.
    ///
    /// # Errors
    ///
    /// Rejects a changed retry, another setup, an invalid claim or corrupt/store state.
    pub fn prepare_local_setup(
        &mut self,
        setup: NewLocalSetup,
    ) -> Result<LocalSetupDisposition, LocalSetupError> {
        validate_new(setup)?;
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = load_by_operation(&transaction, setup.operation_id)? {
            if !matches_new(existing, setup) {
                return Err(LocalSetupError::Conflict);
            }
            let claim =
                load_by_id(&transaction, setup.claim_id)?.ok_or(LocalSetupError::ClaimRejected)?;
            let expected_claim_state = match existing.state {
                LocalSetupState::Prepared | LocalSetupState::AuthorityCommitted => {
                    LocalClaimState::Active
                }
                LocalSetupState::Configured => LocalClaimState::Consumed,
            };
            return if claim.state == expected_claim_state
                && digests_match(claim.secret_digest, setup.claim_secret_digest)
            {
                Ok(LocalSetupDisposition::Replayed)
            } else {
                Err(LocalSetupError::ClaimRejected)
            };
        }
        let claim =
            load_by_id(&transaction, setup.claim_id)?.ok_or(LocalSetupError::ClaimRejected)?;
        if claim.state != LocalClaimState::Active
            || !digests_match(claim.secret_digest, setup.claim_secret_digest)
        {
            return Err(LocalSetupError::ClaimRejected);
        }
        let count: i64 = transaction.query_row(
            "SELECT count(*) FROM local_setup_operations LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        if count != 0 {
            return Err(LocalSetupError::Conflict);
        }
        transaction.execute(
            "INSERT INTO local_setup_operations(
                operation_id, claim_id, operation_kind, request_digest, state,
                authority_result_digest, created_at, authority_committed_at,
                completed_at, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, NULL, NULL, 1)",
            params![
                setup.operation_id.as_bytes().as_slice(),
                setup.claim_id.as_bytes().as_slice(),
                kind_code(setup.kind),
                setup.request_digest.as_slice(),
                PREPARED,
                setup.created_at.get(),
            ],
        )?;
        transaction.commit()?;
        Ok(LocalSetupDisposition::Applied)
    }

    /// Records resolution of the exact authoritative create/join operation.
    ///
    /// # Errors
    ///
    /// Rejects zero/changed receipts, invalid time ordering, stale state or store failure.
    pub fn record_local_setup_authority_commit(
        &mut self,
        operation_id: OperationId,
        result_digest: [u8; 32],
        committed_at: UnixMicros,
    ) -> Result<LocalSetupDisposition, LocalSetupError> {
        if result_digest == [0; 32] {
            return Err(LocalSetupError::Invalid);
        }
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record =
            load_by_operation(&transaction, operation_id)?.ok_or(LocalSetupError::Conflict)?;
        match record.state {
            LocalSetupState::Prepared => {
                if committed_at < record.created_at {
                    return Err(LocalSetupError::Invalid);
                }
                let changed = transaction.execute(
                    "UPDATE local_setup_operations
                     SET state = ?1, authority_result_digest = ?2,
                         authority_committed_at = ?3, revision = revision + 1
                     WHERE operation_id = ?4 AND state = ?5 AND revision = ?6",
                    params![
                        AUTHORITY_COMMITTED,
                        result_digest.as_slice(),
                        committed_at.get(),
                        operation_id.as_bytes().as_slice(),
                        PREPARED,
                        revision_i64(record.revision)?,
                    ],
                )?;
                if changed != 1 {
                    return Err(LocalSetupError::Conflict);
                }
                transaction.commit()?;
                Ok(LocalSetupDisposition::Applied)
            }
            LocalSetupState::AuthorityCommitted | LocalSetupState::Configured
                if record.authority_result_digest == Some(result_digest) =>
            {
                Ok(LocalSetupDisposition::Replayed)
            }
            LocalSetupState::AuthorityCommitted | LocalSetupState::Configured => {
                Err(LocalSetupError::Conflict)
            }
        }
    }

    /// Atomically completes local setup and consumes the exact claim verifier.
    ///
    /// # Errors
    ///
    /// Rejects completion before authority, substituted claims, invalid time or store failure.
    pub fn complete_local_setup(
        &mut self,
        operation_id: OperationId,
        claim_id: ClaimId,
        presented_secret_digest: [u8; 32],
        completed_at: UnixMicros,
    ) -> Result<LocalSetupDisposition, LocalSetupError> {
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record =
            load_by_operation(&transaction, operation_id)?.ok_or(LocalSetupError::Conflict)?;
        if record.claim_id != claim_id {
            return Err(LocalSetupError::ClaimRejected);
        }
        match record.state {
            LocalSetupState::Prepared => Err(LocalSetupError::Conflict),
            LocalSetupState::Configured => {
                let claim =
                    load_by_id(&transaction, claim_id)?.ok_or(LocalSetupError::ClaimRejected)?;
                if claim.state == LocalClaimState::Consumed
                    && digests_match(claim.secret_digest, presented_secret_digest)
                {
                    Ok(LocalSetupDisposition::Replayed)
                } else {
                    Err(LocalSetupError::ClaimRejected)
                }
            }
            LocalSetupState::AuthorityCommitted => {
                let authority_time = record
                    .authority_committed_at
                    .ok_or(LocalSetupError::Invalid)?;
                if completed_at < authority_time {
                    return Err(LocalSetupError::Invalid);
                }
                let claim_disposition = consume_in_transaction(
                    &transaction,
                    claim_id,
                    presented_secret_digest,
                    completed_at,
                )?;
                if claim_disposition != LocalClaimMutationDisposition::Applied {
                    return Err(LocalSetupError::Conflict);
                }
                let changed = transaction.execute(
                    "UPDATE local_setup_operations
                     SET state = ?1, completed_at = ?2, revision = revision + 1
                     WHERE operation_id = ?3 AND state = ?4 AND revision = ?5",
                    params![
                        CONFIGURED,
                        completed_at.get(),
                        operation_id.as_bytes().as_slice(),
                        AUTHORITY_COMMITTED,
                        revision_i64(record.revision)?,
                    ],
                )?;
                if changed != 1 {
                    return Err(LocalSetupError::Conflict);
                }
                transaction.commit()?;
                Ok(LocalSetupDisposition::Applied)
            }
        }
    }

    /// Loads and validates the sole first-start operation, if one exists.
    ///
    /// # Errors
    ///
    /// Rejects corrupt persisted evidence or a store failure.
    pub fn local_setup(&self) -> Result<Option<LocalSetupRecord>, LocalSetupError> {
        let record = self
            .connection()
            .query_row(
                "SELECT operation_id, claim_id, operation_kind, request_digest, state,
                        authority_result_digest, created_at, authority_committed_at,
                        completed_at, revision
                 FROM local_setup_operations LIMIT 2",
                [],
                read_record,
            )
            .optional()?;
        record.map(validate_record).transpose()
    }
}

fn load_by_operation(
    connection: &rusqlite::Connection,
    operation_id: OperationId,
) -> Result<Option<LocalSetupRecord>, LocalSetupError> {
    let record = connection
        .query_row(
            "SELECT operation_id, claim_id, operation_kind, request_digest, state,
                    authority_result_digest, created_at, authority_committed_at,
                    completed_at, revision
             FROM local_setup_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            read_record,
        )
        .optional()?;
    record.map(validate_record).transpose()
}

fn read_record(row: &Row<'_>) -> rusqlite::Result<StoredSetup> {
    Ok(StoredSetup {
        operation_id: row.get(0)?,
        claim_id: row.get(1)?,
        kind: row.get(2)?,
        request_digest: row.get(3)?,
        state: row.get(4)?,
        authority_result_digest: row.get(5)?,
        created_at: row.get(6)?,
        authority_committed_at: row.get(7)?,
        completed_at: row.get(8)?,
        revision: row.get(9)?,
    })
}

struct StoredSetup {
    operation_id: Vec<u8>,
    claim_id: Vec<u8>,
    kind: i64,
    request_digest: Vec<u8>,
    state: i64,
    authority_result_digest: Option<Vec<u8>>,
    created_at: i64,
    authority_committed_at: Option<i64>,
    completed_at: Option<i64>,
    revision: i64,
}

fn validate_record(stored: StoredSetup) -> Result<LocalSetupRecord, LocalSetupError> {
    let record = LocalSetupRecord {
        operation_id: OperationId::from_bytes(fixed(stored.operation_id)?)
            .map_err(|_| LocalSetupError::Invalid)?,
        claim_id: ClaimId::from_bytes(fixed(stored.claim_id)?)
            .map_err(|_| LocalSetupError::Invalid)?,
        kind: decode_kind(stored.kind)?,
        request_digest: fixed(stored.request_digest)?,
        state: decode_state(stored.state)?,
        authority_result_digest: stored.authority_result_digest.map(fixed).transpose()?,
        created_at: UnixMicros::new(stored.created_at),
        authority_committed_at: stored.authority_committed_at.map(UnixMicros::new),
        completed_at: stored.completed_at.map(UnixMicros::new),
        revision: Revision::new(
            u64::try_from(stored.revision).map_err(|_| LocalSetupError::Invalid)?,
        ),
    };
    validate_shape(record)?;
    Ok(record)
}

fn validate_shape(record: LocalSetupRecord) -> Result<(), LocalSetupError> {
    if record.request_digest == [0; 32]
        || record.authority_result_digest == Some([0; 32])
        || record.revision == Revision::ZERO
    {
        return Err(LocalSetupError::Invalid);
    }
    match record.state {
        LocalSetupState::Prepared
            if record.authority_result_digest.is_none()
                && record.authority_committed_at.is_none()
                && record.completed_at.is_none()
                && record.revision == Revision::new(1) =>
        {
            Ok(())
        }
        LocalSetupState::AuthorityCommitted
            if record.authority_result_digest.is_some()
                && record
                    .authority_committed_at
                    .is_some_and(|value| value >= record.created_at)
                && record.completed_at.is_none()
                && record.revision == Revision::new(2) =>
        {
            Ok(())
        }
        LocalSetupState::Configured
            if record.authority_result_digest.is_some()
                && record
                    .authority_committed_at
                    .is_some_and(|value| value >= record.created_at)
                && record.completed_at.is_some_and(|value| {
                    record
                        .authority_committed_at
                        .is_some_and(|authority| value >= authority)
                })
                && record.revision == Revision::new(3) =>
        {
            Ok(())
        }
        LocalSetupState::Prepared
        | LocalSetupState::AuthorityCommitted
        | LocalSetupState::Configured => Err(LocalSetupError::Invalid),
    }
}

fn validate_new(setup: NewLocalSetup) -> Result<(), LocalSetupError> {
    if setup.claim_secret_digest == [0; 32] || setup.request_digest == [0; 32] {
        Err(LocalSetupError::Invalid)
    } else {
        Ok(())
    }
}

fn matches_new(record: LocalSetupRecord, setup: NewLocalSetup) -> bool {
    record.operation_id == setup.operation_id
        && record.claim_id == setup.claim_id
        && record.kind == setup.kind
        && record.request_digest == setup.request_digest
}

const fn kind_code(kind: LocalSetupKind) -> i64 {
    match kind {
        LocalSetupKind::CreateMesh => CREATE_MESH,
        LocalSetupKind::JoinMesh => JOIN_MESH,
    }
}

const fn decode_kind(value: i64) -> Result<LocalSetupKind, LocalSetupError> {
    match value {
        CREATE_MESH => Ok(LocalSetupKind::CreateMesh),
        JOIN_MESH => Ok(LocalSetupKind::JoinMesh),
        _ => Err(LocalSetupError::Invalid),
    }
}

const fn decode_state(value: i64) -> Result<LocalSetupState, LocalSetupError> {
    match value {
        PREPARED => Ok(LocalSetupState::Prepared),
        AUTHORITY_COMMITTED => Ok(LocalSetupState::AuthorityCommitted),
        CONFIGURED => Ok(LocalSetupState::Configured),
        _ => Err(LocalSetupError::Invalid),
    }
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], LocalSetupError> {
    value.try_into().map_err(|_| LocalSetupError::Invalid)
}

fn revision_i64(revision: Revision) -> Result<i64, LocalSetupError> {
    i64::try_from(revision.get()).map_err(|_| LocalSetupError::Invalid)
}
