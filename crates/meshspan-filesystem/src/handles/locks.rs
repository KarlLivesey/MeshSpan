// SPDX-License-Identifier: GPL-2.0-only

//! Fenced leased byte-range lock admission and release.

use meshspan_domain::{HandleId, LockId, NodeId, OperationId, PrincipalId, UnixMicros};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::state::{ActiveHandle, load_active};
use super::{
    HandleError, PublicationDisposition, array, expire_stale_handles, identifier,
    reject_operation_collision, to_i64,
};

const UNLOCK_OPERATION: u8 = 3;

/// Non-empty bounded half-open byte range `[start, start + length)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    start: u64,
    length: u64,
}

impl ByteRange {
    /// Constructs a range representable by SQLite without overflow.
    ///
    /// # Errors
    ///
    /// Rejects zero length, arithmetic overflow and values outside signed SQLite integers.
    pub fn new(start: u64, length: u64) -> Result<Self, HandleError> {
        let end = start.checked_add(length).ok_or(HandleError::InvalidInput)?;
        if length == 0 || end > 9_223_372_036_854_775_807 {
            Err(HandleError::InvalidInput)
        } else {
            Ok(Self { start, length })
        }
    }

    /// First locked byte.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Number of locked bytes.
    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }

    pub(super) fn end(self) -> u64 {
        self.start + self.length
    }
}

/// Compatibility class of one range lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeLockKind {
    /// Compatible with overlapping shared locks; requires handle read access.
    Shared,
    /// Conflicts with every overlapping lock; requires handle write access.
    Exclusive,
}

impl RangeLockKind {
    const fn code(self) -> u8 {
        match self {
            Self::Shared => 1,
            Self::Exclusive => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, HandleError> {
        match code {
            1 => Ok(Self::Shared),
            2 => Ok(Self::Exclusive),
            _ => Err(HandleError::Corrupt),
        }
    }
}

/// Exact request to acquire one leased byte-range lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockRangeRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Stable lock identity.
    pub lock_id: LockId,
    /// Owning handle.
    pub handle_id: HandleId,
    /// Current handle fence.
    pub handle_fence: u64,
    /// Authenticated handle principal.
    pub principal_id: PrincipalId,
    /// Current gateway lease holder.
    pub gateway_node_id: NodeId,
    /// Exact half-open range.
    pub range: ByteRange,
    /// Shared or exclusive compatibility.
    pub kind: RangeLockKind,
    /// Exclusive lock lease deadline, no later than the handle lease.
    pub lease_expires_at: UnixMicros,
    /// Authoritative acquisition instant.
    pub observed_at: UnixMicros,
}

/// Durable lock acquisition result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockRangeReceipt {
    /// Whether this call applied or replayed the exact acquisition.
    pub disposition: PublicationDisposition,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Durable lock identity.
    pub lock_id: LockId,
    /// Owning handle.
    pub handle_id: HandleId,
    /// Exact request digest.
    pub request_digest: [u8; 32],
    /// Handle fence under which the lock is valid.
    pub handle_fence: u64,
    /// Locked range.
    pub range: ByteRange,
    /// Lock compatibility class.
    pub kind: RangeLockKind,
    /// Exclusive lock deadline.
    pub lease_expires_at: UnixMicros,
    /// Digest binding the complete durable result.
    pub result_digest: [u8; 32],
}

/// Exact fenced request to release one lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnlockRangeRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Lock being released.
    pub lock_id: LockId,
    /// Owning handle.
    pub handle_id: HandleId,
    /// Current handle fence.
    pub handle_fence: u64,
    /// Authenticated handle principal.
    pub principal_id: PrincipalId,
    /// Current gateway lease holder.
    pub gateway_node_id: NodeId,
    /// Authoritative release instant.
    pub observed_at: UnixMicros,
}

/// Durable range-lock release result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnlockRangeReceipt {
    /// Whether this call applied or replayed the exact release.
    pub disposition: PublicationDisposition,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Released lock identity.
    pub lock_id: LockId,
    /// Owning handle.
    pub handle_id: HandleId,
    /// Exact request digest.
    pub request_digest: [u8; 32],
    /// Fence that authorised release.
    pub handle_fence: u64,
    /// Authoritative release instant.
    pub released_at: UnixMicros,
    /// Digest binding the complete durable result.
    pub result_digest: [u8; 32],
}

struct StoredLockReceipt {
    lock: Vec<u8>,
    request_digest: Vec<u8>,
    handle: Vec<u8>,
    acquired_handle_fence: i64,
    start: i64,
    length: i64,
    kind: i64,
    expires_at: i64,
    result_digest: Vec<u8>,
}

struct StoredUnlockReceipt {
    operation_kind: i64,
    handle: Vec<u8>,
    request_digest: Vec<u8>,
    resulting_fence: i64,
    result_code: i64,
    result_digest: Vec<u8>,
    result_value: Option<i64>,
    result_identity: Option<Vec<u8>>,
}

pub(crate) fn lock_range(
    connection: &mut Connection,
    request: LockRangeRequest,
) -> Result<LockRangeReceipt, HandleError> {
    validate_lock_request(request)?;
    let request_digest = lock_request_digest(request);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = load_lock_receipt(
        &transaction,
        request.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return matching_lock_replay(receipt, request, request_digest);
    }
    reject_operation_collision(&transaction, request.operation_id)?;
    expire_stale_handles(&transaction, request.observed_at)?;
    let handle = load_active(&transaction, request.handle_id, request.observed_at)?;
    validate_lock_owner(request, &handle)?;
    reject_lock_identity_collision(&transaction, request.lock_id)?;
    reject_overlapping_lock(&transaction, request, &handle)?;
    let receipt = persist_lock(&transaction, request, request_digest)?;
    transaction.commit()?;
    Ok(receipt)
}

pub(crate) fn unlock_range(
    connection: &mut Connection,
    request: UnlockRangeRequest,
) -> Result<UnlockRangeReceipt, HandleError> {
    validate_unlock_request(request)?;
    let request_digest = unlock_request_digest(request);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = load_unlock_receipt(
        &transaction,
        request.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return matching_unlock_replay(receipt, request, request_digest);
    }
    reject_operation_collision(&transaction, request.operation_id)?;
    expire_stale_handles(&transaction, request.observed_at)?;
    let handle = load_active(&transaction, request.handle_id, request.observed_at)?;
    validate_unlock_owner(request, &handle)?;
    release_lock(&transaction, request)?;
    let receipt = persist_unlock(&transaction, request, request_digest)?;
    transaction.commit()?;
    Ok(receipt)
}

fn validate_lock_request(request: LockRangeRequest) -> Result<(), HandleError> {
    if request.handle_fence == 0 || request.lease_expires_at <= request.observed_at {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_lock_owner(
    request: LockRangeRequest,
    handle: &ActiveHandle,
) -> Result<(), HandleError> {
    if handle.fence != request.handle_fence
        || handle.principal != request.principal_id
        || handle.gateway != request.gateway_node_id
        || request.lease_expires_at > handle.lease_expires_at
    {
        return Err(HandleError::StaleHandle);
    }
    match request.kind {
        RangeLockKind::Shared if handle.desired_access.reads() => Ok(()),
        RangeLockKind::Exclusive if handle.desired_access.writes() => Ok(()),
        RangeLockKind::Shared | RangeLockKind::Exclusive => Err(HandleError::InvalidInput),
    }
}

fn reject_lock_identity_collision(
    transaction: &Transaction<'_>,
    lock_id: LockId,
) -> Result<(), HandleError> {
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM range_locks WHERE lock_id = ?1)",
        [lock_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if exists == 0 {
        Ok(())
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn reject_overlapping_lock(
    transaction: &Transaction<'_>,
    request: LockRangeRequest,
    handle: &ActiveHandle,
) -> Result<(), HandleError> {
    let conflicts: i64 = transaction.query_row(
        "SELECT count(*) FROM range_locks locks
         JOIN open_handles owners ON owners.handle_id = locks.handle_id
         WHERE owners.branch_id = ?1 AND owners.volume_id = ?2 AND owners.object_id = ?3
           AND locks.state = 1 AND locks.lease_expires_at > ?4
           AND locks.byte_start < ?5
           AND ?6 < locks.byte_start + locks.byte_length
           AND (?7 = 2 OR locks.lock_kind = 2)",
        params![
            handle.branch.as_bytes().as_slice(),
            handle.volume.as_bytes().as_slice(),
            handle.object.as_bytes().as_slice(),
            request.observed_at.get(),
            to_i64(request.range.end())?,
            to_i64(request.range.start())?,
            request.kind.code(),
        ],
        |row| row.get(0),
    )?;
    if conflicts == 0 {
        Ok(())
    } else {
        Err(HandleError::LockConflict)
    }
}

fn persist_lock(
    transaction: &Transaction<'_>,
    request: LockRangeRequest,
    request_digest: [u8; 32],
) -> Result<LockRangeReceipt, HandleError> {
    let result_digest = lock_result_digest(request, request_digest);
    transaction.execute(
        "INSERT INTO range_locks(
            lock_id, operation_id, request_digest, handle_id, handle_fence,
            acquired_handle_fence,
            byte_start, byte_length, lock_kind, lease_expires_at, state,
            created_at, released_at, receipt_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9, 1, ?10, NULL, ?11)",
        params![
            request.lock_id.as_bytes().as_slice(),
            request.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            request.handle_id.as_bytes().as_slice(),
            to_i64(request.handle_fence)?,
            to_i64(request.range.start())?,
            to_i64(request.range.length())?,
            request.kind.code(),
            request.lease_expires_at.get(),
            request.observed_at.get(),
            result_digest.as_slice(),
        ],
    )?;
    Ok(LockRangeReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: request.operation_id,
        lock_id: request.lock_id,
        handle_id: request.handle_id,
        request_digest,
        handle_fence: request.handle_fence,
        range: request.range,
        kind: request.kind,
        lease_expires_at: request.lease_expires_at,
        result_digest,
    })
}

fn load_lock_receipt(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<LockRangeReceipt>, HandleError> {
    let stored: Option<StoredLockReceipt> = connection
        .query_row(
            "SELECT lock_id, request_digest, handle_id, acquired_handle_fence, byte_start,
                    byte_length, lock_kind, lease_expires_at, receipt_digest
             FROM range_locks WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredLockReceipt {
                    lock: row.get(0)?,
                    request_digest: row.get(1)?,
                    handle: row.get(2)?,
                    acquired_handle_fence: row.get(3)?,
                    start: row.get(4)?,
                    length: row.get(5)?,
                    kind: row.get(6)?,
                    expires_at: row.get(7)?,
                    result_digest: row.get(8)?,
                })
            },
        )
        .optional()?;
    stored
        .as_ref()
        .map(|stored| decode_lock_receipt(operation_id, disposition, stored))
        .transpose()
}

fn decode_lock_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredLockReceipt,
) -> Result<LockRangeReceipt, HandleError> {
    let lock_id = identifier(&stored.lock, LockId::from_bytes)?;
    let request_digest = array(&stored.request_digest)?;
    let handle_id = identifier(&stored.handle, HandleId::from_bytes)?;
    let handle_fence =
        u64::try_from(stored.acquired_handle_fence).map_err(|_| HandleError::Corrupt)?;
    let start = u64::try_from(stored.start).map_err(|_| HandleError::Corrupt)?;
    let length = u64::try_from(stored.length).map_err(|_| HandleError::Corrupt)?;
    let range = ByteRange::new(start, length).map_err(|_| HandleError::Corrupt)?;
    let kind =
        RangeLockKind::from_code(u8::try_from(stored.kind).map_err(|_| HandleError::Corrupt)?)?;
    let lease_expires_at = UnixMicros::new(stored.expires_at);
    let result_digest = array(&stored.result_digest)?;
    let receipt = LockRangeReceipt {
        disposition,
        operation_id,
        lock_id,
        handle_id,
        request_digest,
        handle_fence,
        range,
        kind,
        lease_expires_at,
        result_digest,
    };
    if handle_fence == 0 || result_digest != lock_receipt_digest(receipt) {
        return Err(HandleError::Corrupt);
    }
    Ok(receipt)
}

fn matching_lock_replay(
    receipt: LockRangeReceipt,
    request: LockRangeRequest,
    request_digest: [u8; 32],
) -> Result<LockRangeReceipt, HandleError> {
    if receipt.lock_id == request.lock_id
        && receipt.handle_id == request.handle_id
        && receipt.request_digest == request_digest
    {
        Ok(receipt)
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn validate_unlock_request(request: UnlockRangeRequest) -> Result<(), HandleError> {
    if request.handle_fence == 0 {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_unlock_owner(
    request: UnlockRangeRequest,
    handle: &ActiveHandle,
) -> Result<(), HandleError> {
    if handle.fence == request.handle_fence
        && handle.principal == request.principal_id
        && handle.gateway == request.gateway_node_id
    {
        Ok(())
    } else {
        Err(HandleError::StaleHandle)
    }
}

fn release_lock(
    transaction: &Transaction<'_>,
    request: UnlockRangeRequest,
) -> Result<(), HandleError> {
    let changed = transaction.execute(
        "UPDATE range_locks SET state = 2, released_at = ?1
         WHERE lock_id = ?2 AND handle_id = ?3 AND handle_fence = ?4
           AND state = 1 AND lease_expires_at > ?1",
        params![
            request.observed_at.get(),
            request.lock_id.as_bytes().as_slice(),
            request.handle_id.as_bytes().as_slice(),
            to_i64(request.handle_fence)?,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(HandleError::StaleLock)
    }
}

fn persist_unlock(
    transaction: &Transaction<'_>,
    request: UnlockRangeRequest,
    request_digest: [u8; 32],
) -> Result<UnlockRangeReceipt, HandleError> {
    let result_digest = unlock_result_digest(request, request_digest);
    transaction.execute(
        "INSERT INTO handle_mutation_operations(
            operation_id, operation_kind, handle_id, request_digest, resulting_fence,
            result_code, result_digest, committed_at, result_value, result_identity
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?7, ?8)",
        params![
            request.operation_id.as_bytes().as_slice(),
            UNLOCK_OPERATION,
            request.handle_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            to_i64(request.handle_fence)?,
            result_digest.as_slice(),
            request.observed_at.get(),
            request.lock_id.as_bytes().as_slice(),
        ],
    )?;
    Ok(UnlockRangeReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: request.operation_id,
        lock_id: request.lock_id,
        handle_id: request.handle_id,
        request_digest,
        handle_fence: request.handle_fence,
        released_at: request.observed_at,
        result_digest,
    })
}

fn load_unlock_receipt(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<UnlockRangeReceipt>, HandleError> {
    let stored: Option<StoredUnlockReceipt> = connection
        .query_row(
            "SELECT operation_kind, handle_id, request_digest, resulting_fence,
                    result_code, result_digest, result_value, result_identity
             FROM handle_mutation_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredUnlockReceipt {
                    operation_kind: row.get(0)?,
                    handle: row.get(1)?,
                    request_digest: row.get(2)?,
                    resulting_fence: row.get(3)?,
                    result_code: row.get(4)?,
                    result_digest: row.get(5)?,
                    result_value: row.get(6)?,
                    result_identity: row.get(7)?,
                })
            },
        )
        .optional()?;
    stored
        .as_ref()
        .map(|stored| decode_unlock_receipt(operation_id, disposition, stored))
        .transpose()
}

fn decode_unlock_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredUnlockReceipt,
) -> Result<UnlockRangeReceipt, HandleError> {
    if stored.operation_kind != i64::from(UNLOCK_OPERATION) || stored.result_code != 1 {
        return Err(HandleError::OperationConflict);
    }
    let lock_id = identifier(
        stored
            .result_identity
            .as_deref()
            .ok_or(HandleError::Corrupt)?,
        LockId::from_bytes,
    )?;
    let handle_id = identifier(&stored.handle, HandleId::from_bytes)?;
    let request_digest = array(&stored.request_digest)?;
    let handle_fence = u64::try_from(stored.resulting_fence).map_err(|_| HandleError::Corrupt)?;
    let released_at = UnixMicros::new(stored.result_value.ok_or(HandleError::Corrupt)?);
    let result_digest = array(&stored.result_digest)?;
    let receipt = UnlockRangeReceipt {
        disposition,
        operation_id,
        lock_id,
        handle_id,
        request_digest,
        handle_fence,
        released_at,
        result_digest,
    };
    if handle_fence == 0 || result_digest != unlock_receipt_digest(receipt) {
        return Err(HandleError::Corrupt);
    }
    Ok(receipt)
}

fn matching_unlock_replay(
    receipt: UnlockRangeReceipt,
    request: UnlockRangeRequest,
    request_digest: [u8; 32],
) -> Result<UnlockRangeReceipt, HandleError> {
    if receipt.lock_id == request.lock_id
        && receipt.handle_id == request.handle_id
        && receipt.request_digest == request_digest
    {
        Ok(receipt)
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn lock_request_digest(request: LockRangeRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.lock-range-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.lock_id.as_bytes());
    digest.update(&request.handle_id.as_bytes());
    digest.update(&request.handle_fence.to_be_bytes());
    digest.update(&request.principal_id.as_bytes());
    digest.update(&request.gateway_node_id.as_bytes());
    digest.update(&request.range.start().to_be_bytes());
    digest.update(&request.range.length().to_be_bytes());
    digest.update(&[request.kind.code()]);
    digest.update(&request.lease_expires_at.get().to_be_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn lock_result_digest(request: LockRangeRequest, request_digest: [u8; 32]) -> [u8; 32] {
    lock_result_digest_fields(
        request.operation_id,
        request.lock_id,
        request.handle_id,
        request_digest,
        request.handle_fence,
        request.range,
        request.kind,
        request.lease_expires_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn lock_result_digest_fields(
    operation_id: OperationId,
    lock_id: LockId,
    handle_id: HandleId,
    request_digest: [u8; 32],
    handle_fence: u64,
    range: ByteRange,
    kind: RangeLockKind,
    lease_expires_at: UnixMicros,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.lock-range-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&lock_id.as_bytes());
    digest.update(&handle_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&handle_fence.to_be_bytes());
    digest.update(&range.start().to_be_bytes());
    digest.update(&range.length().to_be_bytes());
    digest.update(&[kind.code()]);
    digest.update(&lease_expires_at.get().to_be_bytes());
    digest.finalize().into()
}

fn lock_receipt_digest(receipt: LockRangeReceipt) -> [u8; 32] {
    lock_result_digest_fields(
        receipt.operation_id,
        receipt.lock_id,
        receipt.handle_id,
        receipt.request_digest,
        receipt.handle_fence,
        receipt.range,
        receipt.kind,
        receipt.lease_expires_at,
    )
}

fn unlock_request_digest(request: UnlockRangeRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.unlock-range-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.lock_id.as_bytes());
    digest.update(&request.handle_id.as_bytes());
    digest.update(&request.handle_fence.to_be_bytes());
    digest.update(&request.principal_id.as_bytes());
    digest.update(&request.gateway_node_id.as_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn unlock_result_digest(request: UnlockRangeRequest, request_digest: [u8; 32]) -> [u8; 32] {
    unlock_result_digest_fields(
        request.operation_id,
        request.lock_id,
        request.handle_id,
        request_digest,
        request.handle_fence,
        request.observed_at,
    )
}

fn unlock_receipt_digest(receipt: UnlockRangeReceipt) -> [u8; 32] {
    unlock_result_digest_fields(
        receipt.operation_id,
        receipt.lock_id,
        receipt.handle_id,
        receipt.request_digest,
        receipt.handle_fence,
        receipt.released_at,
    )
}

fn unlock_result_digest_fields(
    operation_id: OperationId,
    lock_id: LockId,
    handle_id: HandleId,
    request_digest: [u8; 32],
    handle_fence: u64,
    released_at: UnixMicros,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.unlock-range-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&lock_id.as_bytes());
    digest.update(&handle_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&handle_fence.to_be_bytes());
    digest.update(&released_at.get().to_be_bytes());
    digest.finalize().into()
}
