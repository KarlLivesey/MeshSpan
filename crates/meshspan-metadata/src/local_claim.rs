// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe state transitions for one node-local first-boot claim.

use meshspan_domain::{ClaimId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::LocalDatabase;

const ACTIVE: i64 = 1;
const CONSUMED: i64 = 2;
const ROTATED: i64 = 3;

/// Input for one newly generated claim whose plaintext remains outside metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewLocalClaim {
    /// Stable claim identity included in the printable claim bundle.
    pub claim_id: ClaimId,
    /// Fingerprint of the node public key this claim is allowed to enrol.
    pub node_public_key_fingerprint: [u8; 32],
    /// Digest of the secret verifier; never the printable secret.
    pub secret_digest: [u8; 32],
    /// Local authoritative instant when the claim was generated.
    pub created_at: UnixMicros,
}

/// Durable lifecycle of one node-local claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalClaimState {
    /// The verifier may be presented exactly once.
    Active,
    /// A successful claim atomically consumed the verifier.
    Consumed,
    /// Local control invalidated this verifier while issuing another.
    Rotated,
}

/// Complete digest-only local claim evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalClaimRecord {
    /// Stable claim identity.
    pub claim_id: ClaimId,
    /// Bound node public-key fingerprint.
    pub node_public_key_fingerprint: [u8; 32],
    /// Secret verifier digest.
    pub secret_digest: [u8; 32],
    /// Current durable lifecycle state.
    pub state: LocalClaimState,
    /// Claim creation instant.
    pub created_at: UnixMicros,
    /// Successful consumption instant.
    pub consumed_at: Option<UnixMicros>,
    /// Local rotation instant.
    pub rotated_at: Option<UnixMicros>,
    /// Monotonic local claim-state revision.
    pub revision: Revision,
}

/// Idempotent outcome of one local claim mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalClaimMutationDisposition {
    /// The requested transition became durable.
    Applied,
    /// The exact requested transition was already durable after a lost response.
    Replayed,
}

/// Stable local claim persistence failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocalClaimError {
    /// SQLite rejected or could not durably commit the operation.
    #[error("local claim persistence failed")]
    Store,
    /// Persisted or proposed claim evidence violates the closed record contract.
    #[error("local claim evidence is invalid")]
    Invalid,
    /// Another claim or terminal history conflicts with the requested transition.
    #[error("local claim state conflicts with the requested transition")]
    Conflict,
    /// The presented claim identity or verifier was not accepted.
    #[error("local claim was not accepted")]
    Rejected,
}

impl From<rusqlite::Error> for LocalClaimError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Store
    }
}

impl LocalDatabase {
    /// Creates the first active claim or replays the exact already-durable creation.
    ///
    /// # Errors
    ///
    /// Rejects zero evidence, any conflicting history, corrupt persisted state or a store failure.
    pub fn create_local_claim(
        &mut self,
        claim: NewLocalClaim,
    ) -> Result<LocalClaimMutationDisposition, LocalClaimError> {
        validate_new_claim(claim)?;
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active = load_active(&transaction)?;
        if let Some(active) = active {
            return if matches_new(active, claim) && active.revision == Revision::new(1) {
                Ok(LocalClaimMutationDisposition::Replayed)
            } else {
                Err(LocalClaimError::Conflict)
            };
        }
        let count: i64 = transaction.query_row(
            "SELECT count(*) FROM local_claim_bundles LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        if count != 0 {
            return Err(LocalClaimError::Conflict);
        }
        insert_active(&transaction, claim, Revision::new(1))?;
        transaction.commit()?;
        Ok(LocalClaimMutationDisposition::Applied)
    }

    /// Invalidates the expected active claim and creates its replacement atomically.
    ///
    /// # Errors
    ///
    /// Rejects changed replay input, stale identity, invalid evidence/time or a store failure.
    pub fn rotate_local_claim(
        &mut self,
        expected_claim_id: ClaimId,
        replacement: NewLocalClaim,
        rotated_at: UnixMicros,
    ) -> Result<LocalClaimMutationDisposition, LocalClaimError> {
        validate_new_claim(replacement)?;
        if expected_claim_id == replacement.claim_id {
            return Err(LocalClaimError::Invalid);
        }
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(active) = load_active(&transaction)? {
            if active.claim_id != expected_claim_id {
                return if active.claim_id == replacement.claim_id {
                    validate_rotation_replay(
                        &transaction,
                        expected_claim_id,
                        replacement,
                        rotated_at,
                    )
                } else {
                    Err(LocalClaimError::Conflict)
                };
            }
            validate_rotation(active, replacement, rotated_at)?;
            let revision = next_revision(active.revision)?;
            let changed = transaction.execute(
                "UPDATE local_claim_bundles
                 SET state = ?1, rotated_at = ?2, revision = ?3
                 WHERE claim_id = ?4 AND state = ?5 AND revision = ?6",
                params![
                    ROTATED,
                    rotated_at.get(),
                    revision_i64(revision)?,
                    expected_claim_id.as_bytes().as_slice(),
                    ACTIVE,
                    revision_i64(active.revision)?,
                ],
            )?;
            if changed != 1 {
                return Err(LocalClaimError::Conflict);
            }
            insert_active(&transaction, replacement, revision)?;
            transaction.commit()?;
            return Ok(LocalClaimMutationDisposition::Applied);
        }
        validate_rotation_replay(&transaction, expected_claim_id, replacement, rotated_at)
    }

    /// Consumes one exact active claim verifier or replays the exact terminal outcome.
    ///
    /// # Errors
    ///
    /// Rejects a missing, rotated or mismatched claim without revealing which field disagreed.
    pub fn consume_local_claim(
        &mut self,
        claim_id: ClaimId,
        presented_secret_digest: [u8; 32],
        consumed_at: UnixMicros,
    ) -> Result<LocalClaimMutationDisposition, LocalClaimError> {
        if presented_secret_digest == [0; 32] {
            return Err(LocalClaimError::Rejected);
        }
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let disposition =
            consume_in_transaction(&transaction, claim_id, presented_secret_digest, consumed_at)?;
        if disposition == LocalClaimMutationDisposition::Applied {
            transaction.commit()?;
        }
        Ok(disposition)
    }

    /// Loads and independently validates the current active claim, if one exists.
    ///
    /// # Errors
    ///
    /// Rejects corrupt persisted evidence or a store failure.
    pub fn active_local_claim(&self) -> Result<Option<LocalClaimRecord>, LocalClaimError> {
        load_active(self.connection())
    }

    /// Loads and independently validates one claim by its public identity.
    ///
    /// # Errors
    ///
    /// Rejects corrupt persisted evidence or a store failure.
    pub fn local_claim_record(
        &self,
        claim_id: ClaimId,
    ) -> Result<Option<LocalClaimRecord>, LocalClaimError> {
        load_by_id(self.connection(), claim_id)
    }

    /// Loads the most recently revised claim lifecycle record, if one exists.
    ///
    /// This is used only to distinguish a never-issued claim from terminal local
    /// history when no active claim exists.
    ///
    /// # Errors
    ///
    /// Rejects corrupt persisted evidence or a store failure.
    pub fn latest_local_claim(&self) -> Result<Option<LocalClaimRecord>, LocalClaimError> {
        let record = self
            .connection()
            .query_row(
                "SELECT claim_id, node_public_key_fingerprint, secret_digest, state,
                        created_at, consumed_at, rotated_at, revision
                 FROM local_claim_bundles
                 ORDER BY revision DESC, claim_id DESC LIMIT 1",
                [],
                read_record,
            )
            .optional()?;
        record.map(validate_record).transpose()
    }
}

fn validate_new_claim(claim: NewLocalClaim) -> Result<(), LocalClaimError> {
    if claim.node_public_key_fingerprint == [0; 32] || claim.secret_digest == [0; 32] {
        Err(LocalClaimError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_rotation(
    active: LocalClaimRecord,
    replacement: NewLocalClaim,
    rotated_at: UnixMicros,
) -> Result<(), LocalClaimError> {
    if rotated_at < active.created_at
        || replacement.created_at < rotated_at
        || replacement.secret_digest == active.secret_digest
        || replacement.node_public_key_fingerprint != active.node_public_key_fingerprint
    {
        Err(LocalClaimError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_rotation_replay(
    transaction: &Transaction<'_>,
    expected_claim_id: ClaimId,
    replacement: NewLocalClaim,
    rotated_at: UnixMicros,
) -> Result<LocalClaimMutationDisposition, LocalClaimError> {
    let prior = load_by_id(transaction, expected_claim_id)?.ok_or(LocalClaimError::Conflict)?;
    let active = load_by_id(transaction, replacement.claim_id)?.ok_or(LocalClaimError::Conflict)?;
    if prior.state == LocalClaimState::Rotated
        && prior.rotated_at == Some(rotated_at)
        && prior.created_at <= rotated_at
        && rotated_at <= replacement.created_at
        && prior.node_public_key_fingerprint == replacement.node_public_key_fingerprint
        && prior.secret_digest != replacement.secret_digest
        && active.state == LocalClaimState::Active
        && active.revision == prior.revision
        && matches_new(active, replacement)
    {
        Ok(LocalClaimMutationDisposition::Replayed)
    } else {
        Err(LocalClaimError::Conflict)
    }
}

fn insert_active(
    transaction: &Transaction<'_>,
    claim: NewLocalClaim,
    revision: Revision,
) -> Result<(), LocalClaimError> {
    transaction.execute(
        "INSERT INTO local_claim_bundles(
            claim_id, node_public_key_fingerprint, secret_digest, state,
            created_at, consumed_at, rotated_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6)",
        params![
            claim.claim_id.as_bytes().as_slice(),
            claim.node_public_key_fingerprint.as_slice(),
            claim.secret_digest.as_slice(),
            ACTIVE,
            claim.created_at.get(),
            revision_i64(revision)?,
        ],
    )?;
    Ok(())
}

fn load_active(
    connection: &rusqlite::Connection,
) -> Result<Option<LocalClaimRecord>, LocalClaimError> {
    let record = connection
        .query_row(
            "SELECT claim_id, node_public_key_fingerprint, secret_digest, state,
                    created_at, consumed_at, rotated_at, revision
             FROM local_claim_bundles WHERE state = ?1 LIMIT 2",
            [ACTIVE],
            read_record,
        )
        .optional()?;
    record.map(validate_record).transpose()
}

pub(crate) fn load_by_id(
    connection: &rusqlite::Connection,
    claim_id: ClaimId,
) -> Result<Option<LocalClaimRecord>, LocalClaimError> {
    let record = connection
        .query_row(
            "SELECT claim_id, node_public_key_fingerprint, secret_digest, state,
                    created_at, consumed_at, rotated_at, revision
             FROM local_claim_bundles WHERE claim_id = ?1",
            [claim_id.as_bytes().as_slice()],
            read_record,
        )
        .optional()?;
    record.map(validate_record).transpose()
}

fn read_record(row: &Row<'_>) -> rusqlite::Result<StoredClaim> {
    Ok(StoredClaim {
        claim_id: row.get(0)?,
        node_public_key_fingerprint: row.get(1)?,
        secret_digest: row.get(2)?,
        state: row.get(3)?,
        created_at: row.get(4)?,
        consumed_at: row.get(5)?,
        rotated_at: row.get(6)?,
        revision: row.get(7)?,
    })
}

struct StoredClaim {
    claim_id: Vec<u8>,
    node_public_key_fingerprint: Vec<u8>,
    secret_digest: Vec<u8>,
    state: i64,
    created_at: i64,
    consumed_at: Option<i64>,
    rotated_at: Option<i64>,
    revision: i64,
}

fn validate_record(stored: StoredClaim) -> Result<LocalClaimRecord, LocalClaimError> {
    let state = match stored.state {
        ACTIVE => LocalClaimState::Active,
        CONSUMED => LocalClaimState::Consumed,
        ROTATED => LocalClaimState::Rotated,
        _ => return Err(LocalClaimError::Invalid),
    };
    let record = LocalClaimRecord {
        claim_id: ClaimId::from_bytes(fixed(stored.claim_id)?)
            .map_err(|_| LocalClaimError::Invalid)?,
        node_public_key_fingerprint: fixed(stored.node_public_key_fingerprint)?,
        secret_digest: fixed(stored.secret_digest)?,
        state,
        created_at: UnixMicros::new(stored.created_at),
        consumed_at: stored.consumed_at.map(UnixMicros::new),
        rotated_at: stored.rotated_at.map(UnixMicros::new),
        revision: Revision::new(
            u64::try_from(stored.revision).map_err(|_| LocalClaimError::Invalid)?,
        ),
    };
    if record.node_public_key_fingerprint == [0; 32]
        || record.secret_digest == [0; 32]
        || record.revision == Revision::ZERO
    {
        return Err(LocalClaimError::Invalid);
    }
    Ok(record)
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], LocalClaimError> {
    value.try_into().map_err(|_| LocalClaimError::Invalid)
}

fn next_revision(revision: Revision) -> Result<Revision, LocalClaimError> {
    revision.next().map_err(|_| LocalClaimError::Invalid)
}

fn revision_i64(revision: Revision) -> Result<i64, LocalClaimError> {
    i64::try_from(revision.get()).map_err(|_| LocalClaimError::Invalid)
}

fn matches_new(record: LocalClaimRecord, claim: NewLocalClaim) -> bool {
    record.claim_id == claim.claim_id
        && record.node_public_key_fingerprint == claim.node_public_key_fingerprint
        && record.secret_digest == claim.secret_digest
        && record.created_at == claim.created_at
        && record.state == LocalClaimState::Active
        && record.consumed_at.is_none()
        && record.rotated_at.is_none()
}

pub(crate) fn digests_match(expected: [u8; 32], presented: [u8; 32]) -> bool {
    expected
        .iter()
        .zip(presented)
        .fold(0_u8, |difference, (expected, presented)| {
            difference | (expected ^ presented)
        })
        == 0
}

pub(crate) fn consume_in_transaction(
    transaction: &Transaction<'_>,
    claim_id: ClaimId,
    presented_secret_digest: [u8; 32],
    consumed_at: UnixMicros,
) -> Result<LocalClaimMutationDisposition, LocalClaimError> {
    if presented_secret_digest == [0; 32] {
        return Err(LocalClaimError::Rejected);
    }
    let record = load_by_id(transaction, claim_id)?.ok_or(LocalClaimError::Rejected)?;
    if !digests_match(record.secret_digest, presented_secret_digest) {
        return Err(LocalClaimError::Rejected);
    }
    match record.state {
        LocalClaimState::Active => {
            if consumed_at < record.created_at {
                return Err(LocalClaimError::Invalid);
            }
            let revision = next_revision(record.revision)?;
            let changed = transaction.execute(
                "UPDATE local_claim_bundles
                 SET state = ?1, consumed_at = ?2, revision = ?3
                 WHERE claim_id = ?4 AND state = ?5 AND revision = ?6",
                params![
                    CONSUMED,
                    consumed_at.get(),
                    revision_i64(revision)?,
                    claim_id.as_bytes().as_slice(),
                    ACTIVE,
                    revision_i64(record.revision)?,
                ],
            )?;
            if changed != 1 {
                return Err(LocalClaimError::Conflict);
            }
            Ok(LocalClaimMutationDisposition::Applied)
        }
        LocalClaimState::Consumed if record.consumed_at == Some(consumed_at) => {
            Ok(LocalClaimMutationDisposition::Replayed)
        }
        LocalClaimState::Consumed | LocalClaimState::Rotated => Err(LocalClaimError::Rejected),
    }
}
