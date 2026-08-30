// SPDX-License-Identifier: GPL-2.0-only

//! Crash-safe node-local consumption of one replicated federated storage allocation.

mod persistence;
mod record;

use meshspan_contracts::ShardIdentity;
use meshspan_domain::{
    FederationStorageAction, FederationStorageAllocationId, OperationId, UnixMicros,
};
use rusqlite::TransactionBehavior;
use thiserror::Error;

use crate::{FederationStorageAllocationAuthority, LocalDatabase};
use persistence::{
    hold_capacity, insert_reservation, install_or_validate_usage, persist_unique_shard,
    reject_nonce_reuse, release_capacity, replace_reservation_with_committed_usage,
    validate_completion_replay, validate_release_replay, validate_reservation_replay,
};
use record::{load_reservation, load_usage};

/// Maximum lifetime of one capacity-changing storage capability: five minutes.
pub const MAXIMUM_FEDERATED_STORAGE_WRITE_LIFETIME_MICROS: u64 = 300_000_000;

const RESERVED: i64 = 1;
const COMMITTED: i64 = 2;
const RELEASED: i64 = 3;

/// Exact untrusted request fields bound into one local capacity reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageWriteReservationRequest {
    /// Idempotency identity shared by exact retries.
    pub operation_id: OperationId,
    /// Canonical digest of the complete authenticated request.
    pub request_digest: [u8; 32],
    /// Fresh nonce returned inside the provider capability.
    pub capability_nonce: [u8; 32],
    /// Exact immutable shard generation.
    pub shard: ShardIdentity,
    /// Capacity-changing action (`put` or `repair`).
    pub action: FederationStorageAction,
    /// Digest of the exact data-plane permit bytes.
    pub permit_digest: [u8; 32],
    /// Exclusive permit expiry.
    pub expires_at: UnixMicros,
    /// Quorum-derived issuance instant.
    pub issued_at: UnixMicros,
}

/// Local durable completion after the provider has persisted and verified the shard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageWriteCompletion {
    /// Exact reservation operation.
    pub operation_id: OperationId,
    /// Exact permit digest returned at reservation time.
    pub permit_digest: [u8; 32],
    /// Actual durable byte length.
    pub affected_bytes: u64,
    /// Digest calculated from the durable shard bytes.
    pub content_digest: [u8; 32],
    /// Digest of the provider's complete result evidence.
    pub result_digest: [u8; 32],
    /// Local mesh time after durability was established.
    pub completed_at: UnixMicros,
}

/// Evidence that an expired reservation left no matching durable provider shard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageWriteAbsence {
    /// Exact reservation operation.
    pub operation_id: OperationId,
    /// Exact permit digest returned at reservation time.
    pub permit_digest: [u8; 32],
    /// Digest of the provider absence probe and exact shard identity.
    pub absence_evidence_digest: [u8; 32],
    /// Local mesh time at or after capability expiry.
    pub completed_at: UnixMicros,
}

/// Durable reservation lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationStorageWriteState {
    /// Capacity is held while the exact write may be in flight.
    Reserved,
    /// Durable shard evidence was atomically charged or deduplicated.
    Committed,
    /// An expiry-time provider probe proved that no matching shard exists.
    Released,
}

/// Complete durable reservation evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageWriteReservation {
    /// Exact operation identity.
    pub operation_id: OperationId,
    /// Replicated allocation being consumed.
    pub allocation_id: FederationStorageAllocationId,
    /// Exact request digest.
    pub request_digest: [u8; 32],
    /// Exact capability nonce.
    pub capability_nonce: [u8; 32],
    /// Immutable shard generation.
    pub shard: ShardIdentity,
    /// Put or repair.
    pub action: FederationStorageAction,
    /// Maximum reserved byte count.
    pub maximum_bytes: u64,
    /// Exact data-plane permit digest.
    pub permit_digest: [u8; 32],
    /// Exclusive expiry.
    pub expires_at: UnixMicros,
    /// Current lifecycle state.
    pub state: FederationStorageWriteState,
    /// Actual durable bytes, once committed.
    pub affected_bytes: Option<u64>,
    /// Bytes newly charged after exact shard deduplication, once committed.
    pub charged_bytes: Option<u64>,
    /// Durable content digest, once committed.
    pub content_digest: Option<[u8; 32]>,
    /// Provider result digest, once committed.
    pub result_digest: Option<[u8; 32]>,
    /// Absence proof digest, once safely released.
    pub absence_evidence_digest: Option<[u8; 32]>,
    /// Issuance instant.
    pub issued_at: UnixMicros,
    /// Terminal transition instant.
    pub completed_at: Option<UnixMicros>,
}

/// Current allocation counters from the local crash-safe ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageUsage {
    /// Exact replicated allocation.
    pub allocation_id: FederationStorageAllocationId,
    /// Immutable allocation ceiling.
    pub maximum_bytes: u64,
    /// Bytes owned by unique durable shard records.
    pub committed_bytes: u64,
    /// Maximum bytes held by in-flight reservations.
    pub reserved_bytes: u64,
}

/// Idempotent local quota transition outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationStorageQuotaDisposition {
    /// New durable state was committed atomically.
    Applied,
    /// The exact prior outcome was returned without changing counters.
    Replayed,
}

impl LocalDatabase {
    /// Atomically holds allocation capacity before a write permit is returned.
    ///
    /// # Errors
    ///
    /// Rejects stale/substituted authority, conflicting replay, invalid bounds and exhausted quota.
    pub fn reserve_federated_storage_write(
        &mut self,
        authority: FederationStorageAllocationAuthority,
        request: FederationStorageWriteReservationRequest,
    ) -> Result<
        (
            FederationStorageQuotaDisposition,
            FederationStorageWriteReservation,
        ),
        FederationStorageQuotaError,
    > {
        reserve(self, authority, request)
    }

    /// Atomically replaces a reservation with exact durable shard accounting.
    ///
    /// # Errors
    ///
    /// Rejects missing/conflicting reservations, excessive bytes and substituted result evidence.
    pub fn commit_federated_storage_write(
        &mut self,
        completion: FederationStorageWriteCompletion,
    ) -> Result<
        (
            FederationStorageQuotaDisposition,
            FederationStorageWriteReservation,
        ),
        FederationStorageQuotaError,
    > {
        commit(self, completion)
    }

    /// Releases an expired reservation only after an exact provider absence probe.
    ///
    /// # Errors
    ///
    /// Rejects early release, missing/conflicting reservations and empty evidence digests.
    pub fn release_absent_federated_storage_write(
        &mut self,
        absence: FederationStorageWriteAbsence,
    ) -> Result<
        (
            FederationStorageQuotaDisposition,
            FederationStorageWriteReservation,
        ),
        FederationStorageQuotaError,
    > {
        release(self, absence)
    }

    /// Loads one independently validated reservation record.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed identifiers, actions, digests, counters or lifecycle shape.
    pub fn federated_storage_write(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<FederationStorageWriteReservation>, FederationStorageQuotaError> {
        load_reservation(self.connection(), operation_id)
    }

    /// Loads current independently validated allocation counters.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed identifiers or impossible counters.
    pub fn federated_storage_usage(
        &self,
        allocation_id: FederationStorageAllocationId,
    ) -> Result<Option<FederationStorageUsage>, FederationStorageQuotaError> {
        load_usage(self.connection(), allocation_id)
    }
}

fn reserve(
    database: &mut LocalDatabase,
    authority: FederationStorageAllocationAuthority,
    request: FederationStorageWriteReservationRequest,
) -> Result<
    (
        FederationStorageQuotaDisposition,
        FederationStorageWriteReservation,
    ),
    FederationStorageQuotaError,
> {
    validate_reservation(database, authority, request)?;
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(stored) = load_reservation(&transaction, request.operation_id)? {
        validate_reservation_replay(&stored, authority, request)?;
        transaction.commit()?;
        return Ok((FederationStorageQuotaDisposition::Replayed, stored));
    }
    reject_nonce_reuse(&transaction, request.capability_nonce)?;
    install_or_validate_usage(&transaction, authority, request.issued_at)?;
    hold_capacity(&transaction, authority, request.issued_at)?;
    insert_reservation(&transaction, authority, request)?;
    let stored = load_reservation(&transaction, request.operation_id)?
        .ok_or(FederationStorageQuotaError::CorruptState)?;
    transaction.commit()?;
    Ok((FederationStorageQuotaDisposition::Applied, stored))
}

fn commit(
    database: &mut LocalDatabase,
    completion: FederationStorageWriteCompletion,
) -> Result<
    (
        FederationStorageQuotaDisposition,
        FederationStorageWriteReservation,
    ),
    FederationStorageQuotaError,
> {
    validate_completion(completion)?;
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = load_reservation(&transaction, completion.operation_id)?
        .ok_or(FederationStorageQuotaError::Conflict)?;
    if stored.state == FederationStorageWriteState::Committed {
        validate_completion_replay(&stored, completion)?;
        transaction.commit()?;
        return Ok((FederationStorageQuotaDisposition::Replayed, stored));
    }
    if stored.state != FederationStorageWriteState::Reserved
        || stored.permit_digest != completion.permit_digest
        || completion.affected_bytes > stored.maximum_bytes
        || completion.completed_at < stored.issued_at
    {
        return Err(FederationStorageQuotaError::Conflict);
    }
    let charged = persist_unique_shard(&transaction, &stored, completion)?;
    replace_reservation_with_committed_usage(&transaction, &stored, charged, completion)?;
    let completed = load_reservation(&transaction, completion.operation_id)?
        .ok_or(FederationStorageQuotaError::CorruptState)?;
    transaction.commit()?;
    Ok((FederationStorageQuotaDisposition::Applied, completed))
}

fn release(
    database: &mut LocalDatabase,
    absence: FederationStorageWriteAbsence,
) -> Result<
    (
        FederationStorageQuotaDisposition,
        FederationStorageWriteReservation,
    ),
    FederationStorageQuotaError,
> {
    if !valid_digest(absence.permit_digest) || !valid_digest(absence.absence_evidence_digest) {
        return Err(FederationStorageQuotaError::Invalid);
    }
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = load_reservation(&transaction, absence.operation_id)?
        .ok_or(FederationStorageQuotaError::Conflict)?;
    if stored.state == FederationStorageWriteState::Released {
        validate_release_replay(&stored, absence)?;
        transaction.commit()?;
        return Ok((FederationStorageQuotaDisposition::Replayed, stored));
    }
    if stored.state != FederationStorageWriteState::Reserved
        || stored.permit_digest != absence.permit_digest
        || absence.completed_at < stored.expires_at
    {
        return Err(FederationStorageQuotaError::Conflict);
    }
    release_capacity(&transaction, &stored, absence)?;
    let released = load_reservation(&transaction, absence.operation_id)?
        .ok_or(FederationStorageQuotaError::CorruptState)?;
    transaction.commit()?;
    Ok((FederationStorageQuotaDisposition::Applied, released))
}

fn validate_reservation(
    database: &LocalDatabase,
    authority: FederationStorageAllocationAuthority,
    request: FederationStorageWriteReservationRequest,
) -> Result<(), FederationStorageQuotaError> {
    let allocation = authority.allocation();
    let lifetime = request
        .expires_at
        .get()
        .checked_sub(request.issued_at.get())
        .and_then(|value| u64::try_from(value).ok());
    let valid = allocation.provider_node_id() == database.node_id()
        && request.action.reserves_capacity()
        && request.issued_at == authority.observed_at()
        && request.issued_at.get() > 0
        && request.expires_at <= allocation.valid_until()
        && lifetime.is_some_and(|value| {
            value > 0 && value <= MAXIMUM_FEDERATED_STORAGE_WRITE_LIFETIME_MICROS
        })
        && request.shard.generation > 0
        && valid_digest(request.shard.manifest_digest)
        && valid_digest(request.request_digest)
        && valid_digest(request.capability_nonce)
        && valid_digest(request.permit_digest);
    if valid {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::Invalid)
    }
}

fn validate_completion(
    completion: FederationStorageWriteCompletion,
) -> Result<(), FederationStorageQuotaError> {
    if completion.affected_bytes > 0
        && completion.completed_at.get() > 0
        && valid_digest(completion.permit_digest)
        && valid_digest(completion.content_digest)
        && valid_digest(completion.result_digest)
    {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::Invalid)
    }
}

fn valid_digest(digest: [u8; 32]) -> bool {
    digest != [0; 32]
}

/// Stable local quota failure categories.
#[derive(Debug, Error)]
pub enum FederationStorageQuotaError {
    /// Input was malformed, stale or outside explicit bounds.
    #[error("federated storage quota input is invalid")]
    Invalid,
    /// An operation identity, nonce, shard or terminal result conflicts with durable evidence.
    #[error("federated storage quota evidence conflicts")]
    Conflict,
    /// The exact disjoint allocation has insufficient remaining capacity.
    #[error("federated storage allocation capacity is exhausted")]
    CapacityExceeded,
    /// Durable local rows contradict their declared shape or counters.
    #[error("federated storage quota state is corrupt")]
    CorruptState,
    /// SQLite rejected the atomic local transition.
    #[error("federated storage quota database operation failed")]
    Database(#[from] rusqlite::Error),
}
