// SPDX-License-Identifier: GPL-2.0-only

//! Fenced lease renewal, gateway takeover and delete-aware handle close.

use meshspan_domain::{HandleId, NodeId, OperationId, PrincipalId, Revision, UnixMicros};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::state::{ActiveHandle, load_active};
use super::{
    HandleError, PublicationDisposition, array, expire_stale_handles, identifier,
    reject_operation_collision, to_i64,
};

const RENEW_OPERATION: u8 = 1;
const CLOSE_OPERATION: u8 = 2;

/// Exact request to extend or transfer one live handle lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleLeaseRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Handle being renewed or resumed.
    pub handle_id: HandleId,
    /// Current fencing generation required by the caller.
    pub expected_fence: u64,
    /// Authenticated principal that originally opened the handle.
    pub principal_id: PrincipalId,
    /// Newly revalidated committed authorisation revision.
    pub authorization_revision: Revision,
    /// Gateway accepting responsibility for future renewal.
    pub gateway_node_id: NodeId,
    /// Whether to issue a new fence and invalidate the previous gateway token.
    pub takeover: bool,
    /// New exclusive lease deadline.
    pub lease_expires_at: UnixMicros,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Durable lease result, including a new fence only for explicit takeover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleLeaseReceipt {
    /// Whether this call applied or replayed the exact operation.
    pub disposition: PublicationDisposition,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Renewed handle.
    pub handle_id: HandleId,
    /// Exact request digest.
    pub request_digest: [u8; 32],
    /// Current fencing generation after renewal/takeover.
    pub handle_fence: u64,
    /// Gateway holding that generation.
    pub gateway_node_id: NodeId,
    /// Exclusive renewed deadline.
    pub lease_expires_at: UnixMicros,
    /// Digest binding the complete durable result.
    pub result_digest: [u8; 32],
}

/// Exact fenced close request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseHandleRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Handle to close.
    pub handle_id: HandleId,
    /// Current fencing generation.
    pub expected_fence: u64,
    /// Authenticated owning principal.
    pub principal_id: PrincipalId,
    /// Gateway currently holding the lease.
    pub gateway_node_id: NodeId,
    /// Authoritative close instant.
    pub observed_at: UnixMicros,
}

/// Namespace deletion state produced by closing one handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseHandleOutcome {
    /// Handle closed and no object deletion is pending.
    Closed,
    /// Delete-on-close is durable but another live handle still pins the object.
    DeleteDeferred,
    /// No live handle remains and the pending delete may enter a namespace transaction.
    DeleteReady,
}

impl CloseHandleOutcome {
    const fn code(self) -> u8 {
        match self {
            Self::Closed => 1,
            Self::DeleteDeferred => 2,
            Self::DeleteReady => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, HandleError> {
        match code {
            1 => Ok(Self::Closed),
            2 => Ok(Self::DeleteDeferred),
            3 => Ok(Self::DeleteReady),
            _ => Err(HandleError::Corrupt),
        }
    }
}

/// Durable close result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseHandleReceipt {
    /// Whether this call applied or replayed the exact operation.
    pub disposition: PublicationDisposition,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Closed handle.
    pub handle_id: HandleId,
    /// Exact request digest.
    pub request_digest: [u8; 32],
    /// Fence that authorised closure.
    pub handle_fence: u64,
    /// Resulting deletion readiness.
    pub outcome: CloseHandleOutcome,
    /// Authoritative close instant.
    pub closed_at: UnixMicros,
    /// Digest binding the complete durable result.
    pub result_digest: [u8; 32],
}

struct StoredLeaseReceipt {
    operation_kind: i64,
    handle: Vec<u8>,
    request_digest: Vec<u8>,
    resulting_fence: i64,
    result_code: i64,
    result_digest: Vec<u8>,
    result_value: Option<i64>,
    result_identity: Option<Vec<u8>>,
}

struct StoredCloseReceipt {
    operation_kind: i64,
    handle: Vec<u8>,
    request_digest: Vec<u8>,
    resulting_fence: i64,
    result_code: i64,
    result_digest: Vec<u8>,
    result_value: Option<i64>,
}

pub(crate) fn renew(
    connection: &mut Connection,
    request: HandleLeaseRequest,
) -> Result<HandleLeaseReceipt, HandleError> {
    validate_lease(request)?;
    let request_digest = lease_request_digest(request);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = load_lease_receipt(
        &transaction,
        request.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return matching_lease_replay(receipt, request, request_digest);
    }
    reject_operation_collision(&transaction, request.operation_id)?;
    expire_stale_handles(&transaction, request.observed_at)?;
    let handle = load_active(&transaction, request.handle_id, request.observed_at)?;
    validate_lease_owner(request, &handle)?;
    let resulting_fence = if request.takeover {
        request
            .expected_fence
            .checked_add(1)
            .ok_or(HandleError::InvalidInput)?
    } else {
        request.expected_fence
    };
    update_lease(&transaction, request, resulting_fence)?;
    let receipt = persist_lease_operation(&transaction, request, request_digest, resulting_fence)?;
    transaction.commit()?;
    Ok(receipt)
}

pub(crate) fn close(
    connection: &mut Connection,
    request: CloseHandleRequest,
) -> Result<CloseHandleReceipt, HandleError> {
    validate_close(request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = resolve_close_request(&transaction, request)? {
        return Ok(receipt);
    }
    let request_digest = close_request_digest(request);
    reject_operation_collision(&transaction, request.operation_id)?;
    expire_stale_handles(&transaction, request.observed_at)?;
    let handle = load_active(&transaction, request.handle_id, request.observed_at)?;
    validate_close_owner(request, &handle)?;
    close_handle_row(&transaction, request)?;
    release_handle_locks(&transaction, request)?;
    if handle.delete_on_close {
        persist_pending_delete(&transaction, request, &handle)?;
    }
    let outcome = advance_pending_delete(&transaction, request, &handle)?;
    let receipt = persist_close_operation(&transaction, request, request_digest, outcome)?;
    transaction.commit()?;
    Ok(receipt)
}

pub(crate) fn resolve_close_request(
    connection: &Connection,
    request: CloseHandleRequest,
) -> Result<Option<CloseHandleReceipt>, HandleError> {
    validate_close(request)?;
    let request_digest = close_request_digest(request);
    load_close_receipt(
        connection,
        request.operation_id,
        PublicationDisposition::Replayed,
    )?
    .map(|receipt| matching_close_replay(receipt, request, request_digest))
    .transpose()
}

fn validate_lease(request: HandleLeaseRequest) -> Result<(), HandleError> {
    if request.expected_fence == 0
        || request.authorization_revision == Revision::ZERO
        || request.lease_expires_at <= request.observed_at
    {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_lease_owner(
    request: HandleLeaseRequest,
    handle: &ActiveHandle,
) -> Result<(), HandleError> {
    if handle.handle != request.handle_id
        || handle.fence != request.expected_fence
        || handle.principal != request.principal_id
        || request.authorization_revision < handle.authorization_revision
        || request.lease_expires_at < handle.lease_expires_at
    {
        return Err(HandleError::StaleHandle);
    }
    if !request.takeover && handle.gateway != request.gateway_node_id {
        return Err(HandleError::GatewayMismatch);
    }
    Ok(())
}

fn update_lease(
    transaction: &Transaction<'_>,
    request: HandleLeaseRequest,
    resulting_fence: u64,
) -> Result<(), HandleError> {
    let changed = transaction.execute(
        "UPDATE open_handles SET gateway_node_id = ?1, authorization_revision = ?2,
                handle_fence = ?3, lease_expires_at = ?4
         WHERE handle_id = ?5 AND state = 1 AND handle_fence = ?6
           AND lease_expires_at > ?7",
        params![
            request.gateway_node_id.as_bytes().as_slice(),
            to_i64(request.authorization_revision.get())?,
            to_i64(resulting_fence)?,
            request.lease_expires_at.get(),
            request.handle_id.as_bytes().as_slice(),
            to_i64(request.expected_fence)?,
            request.observed_at.get(),
        ],
    )?;
    if changed != 1 {
        return Err(HandleError::StaleHandle);
    }
    if request.takeover {
        transaction.execute(
            "UPDATE range_locks SET handle_fence = ?1
             WHERE handle_id = ?2 AND state = 1",
            params![
                to_i64(resulting_fence)?,
                request.handle_id.as_bytes().as_slice()
            ],
        )?;
    }
    Ok(())
}

fn persist_lease_operation(
    transaction: &Transaction<'_>,
    request: HandleLeaseRequest,
    request_digest: [u8; 32],
    resulting_fence: u64,
) -> Result<HandleLeaseReceipt, HandleError> {
    let result_digest = lease_result_digest(
        request.operation_id,
        request.handle_id,
        request_digest,
        resulting_fence,
        request.gateway_node_id,
        request.lease_expires_at,
    );
    transaction.execute(
        "INSERT INTO handle_mutation_operations(
            operation_id, operation_kind, handle_id, request_digest, resulting_fence,
            result_code, result_digest, committed_at, result_value, result_identity
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9)",
        params![
            request.operation_id.as_bytes().as_slice(),
            RENEW_OPERATION,
            request.handle_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            to_i64(resulting_fence)?,
            result_digest.as_slice(),
            request.observed_at.get(),
            request.lease_expires_at.get(),
            request.gateway_node_id.as_bytes().as_slice(),
        ],
    )?;
    Ok(HandleLeaseReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: request.operation_id,
        handle_id: request.handle_id,
        request_digest,
        handle_fence: resulting_fence,
        gateway_node_id: request.gateway_node_id,
        lease_expires_at: request.lease_expires_at,
        result_digest,
    })
}

fn load_lease_receipt(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<HandleLeaseReceipt>, HandleError> {
    let stored: Option<StoredLeaseReceipt> = connection
        .query_row(
            "SELECT operation_kind, handle_id, request_digest, resulting_fence,
                    result_code, result_digest, result_value, result_identity
             FROM handle_mutation_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredLeaseReceipt {
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
        .map(|stored| decode_lease_receipt(operation_id, disposition, stored))
        .transpose()
}

fn decode_lease_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredLeaseReceipt,
) -> Result<HandleLeaseReceipt, HandleError> {
    if stored.operation_kind != i64::from(RENEW_OPERATION) || stored.result_code != 1 {
        return Err(HandleError::OperationConflict);
    }
    let handle_id = identifier(&stored.handle, HandleId::from_bytes)?;
    let request_digest = array(&stored.request_digest)?;
    let handle_fence = u64::try_from(stored.resulting_fence).map_err(|_| HandleError::Corrupt)?;
    let result_digest = array(&stored.result_digest)?;
    let lease_expires_at = UnixMicros::new(stored.result_value.ok_or(HandleError::Corrupt)?);
    let gateway_node_id = identifier(
        stored
            .result_identity
            .as_deref()
            .ok_or(HandleError::Corrupt)?,
        NodeId::from_bytes,
    )?;
    let expected = lease_result_digest(
        operation_id,
        handle_id,
        request_digest,
        handle_fence,
        gateway_node_id,
        lease_expires_at,
    );
    if handle_fence == 0 || result_digest != expected {
        return Err(HandleError::Corrupt);
    }
    Ok(HandleLeaseReceipt {
        disposition,
        operation_id,
        handle_id,
        request_digest,
        handle_fence,
        gateway_node_id,
        lease_expires_at,
        result_digest,
    })
}

fn matching_lease_replay(
    receipt: HandleLeaseReceipt,
    request: HandleLeaseRequest,
    request_digest: [u8; 32],
) -> Result<HandleLeaseReceipt, HandleError> {
    if receipt.handle_id == request.handle_id && receipt.request_digest == request_digest {
        Ok(receipt)
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn validate_close(request: CloseHandleRequest) -> Result<(), HandleError> {
    if request.expected_fence == 0 {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_close_owner(
    request: CloseHandleRequest,
    handle: &ActiveHandle,
) -> Result<(), HandleError> {
    if handle.handle == request.handle_id
        && handle.fence == request.expected_fence
        && handle.principal == request.principal_id
        && handle.gateway == request.gateway_node_id
    {
        Ok(())
    } else {
        Err(HandleError::StaleHandle)
    }
}

fn close_handle_row(
    transaction: &Transaction<'_>,
    request: CloseHandleRequest,
) -> Result<(), HandleError> {
    let changed = transaction.execute(
        "UPDATE open_handles SET state = 2, closed_at = ?1
         WHERE handle_id = ?2 AND state = 1 AND handle_fence = ?3
           AND lease_expires_at > ?1",
        params![
            request.observed_at.get(),
            request.handle_id.as_bytes().as_slice(),
            to_i64(request.expected_fence)?,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(HandleError::StaleHandle)
    }
}

fn release_handle_locks(
    transaction: &Transaction<'_>,
    request: CloseHandleRequest,
) -> Result<(), HandleError> {
    transaction.execute(
        "UPDATE range_locks SET state = 2, released_at = ?1
         WHERE handle_id = ?2 AND state = 1",
        params![
            request.observed_at.get(),
            request.handle_id.as_bytes().as_slice()
        ],
    )?;
    Ok(())
}

fn persist_pending_delete(
    transaction: &Transaction<'_>,
    request: CloseHandleRequest,
    handle: &ActiveHandle,
) -> Result<(), HandleError> {
    transaction.execute(
        "INSERT INTO pending_object_deletes(
            branch_id, volume_id, object_id, requesting_handle_id,
            object_revision_id, version_id, state, requested_at, ready_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, NULL)
         ON CONFLICT(branch_id, object_id) DO NOTHING",
        params![
            handle.branch.as_bytes().as_slice(),
            handle.volume.as_bytes().as_slice(),
            handle.object.as_bytes().as_slice(),
            request.handle_id.as_bytes().as_slice(),
            handle.object_revision.as_bytes().as_slice(),
            handle.version.as_bytes().as_slice(),
            request.observed_at.get(),
        ],
    )?;
    Ok(())
}

fn advance_pending_delete(
    transaction: &Transaction<'_>,
    request: CloseHandleRequest,
    handle: &ActiveHandle,
) -> Result<CloseHandleOutcome, HandleError> {
    let pending: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM pending_object_deletes
            WHERE branch_id = ?1 AND volume_id = ?2 AND object_id = ?3
         )",
        params![
            handle.branch.as_bytes().as_slice(),
            handle.volume.as_bytes().as_slice(),
            handle.object.as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if pending == 0 {
        return Ok(CloseHandleOutcome::Closed);
    }
    let live: i64 = transaction.query_row(
        "SELECT count(*) FROM open_handles
         WHERE branch_id = ?1 AND volume_id = ?2 AND object_id = ?3
           AND state = 1 AND lease_expires_at > ?4",
        params![
            handle.branch.as_bytes().as_slice(),
            handle.volume.as_bytes().as_slice(),
            handle.object.as_bytes().as_slice(),
            request.observed_at.get(),
        ],
        |row| row.get(0),
    )?;
    if live != 0 {
        return Ok(CloseHandleOutcome::DeleteDeferred);
    }
    transaction.execute(
        "UPDATE pending_object_deletes SET state = 2, ready_at = ?1
         WHERE branch_id = ?2 AND object_id = ?3 AND state = 1",
        params![
            request.observed_at.get(),
            handle.branch.as_bytes().as_slice(),
            handle.object.as_bytes().as_slice(),
        ],
    )?;
    Ok(CloseHandleOutcome::DeleteReady)
}

fn persist_close_operation(
    transaction: &Transaction<'_>,
    request: CloseHandleRequest,
    request_digest: [u8; 32],
    outcome: CloseHandleOutcome,
) -> Result<CloseHandleReceipt, HandleError> {
    let result_digest = close_result_digest(
        request.operation_id,
        request.handle_id,
        request_digest,
        request.expected_fence,
        outcome,
        request.observed_at,
    );
    transaction.execute(
        "INSERT INTO handle_mutation_operations(
            operation_id, operation_kind, handle_id, request_digest, resulting_fence,
            result_code, result_digest, committed_at, result_value, result_identity
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, NULL)",
        params![
            request.operation_id.as_bytes().as_slice(),
            CLOSE_OPERATION,
            request.handle_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            to_i64(request.expected_fence)?,
            outcome.code(),
            result_digest.as_slice(),
            request.observed_at.get(),
        ],
    )?;
    Ok(CloseHandleReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: request.operation_id,
        handle_id: request.handle_id,
        request_digest,
        handle_fence: request.expected_fence,
        outcome,
        closed_at: request.observed_at,
        result_digest,
    })
}

fn load_close_receipt(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<CloseHandleReceipt>, HandleError> {
    let stored: Option<StoredCloseReceipt> = connection
        .query_row(
            "SELECT operation_kind, handle_id, request_digest, resulting_fence,
                    result_code, result_digest, result_value
             FROM handle_mutation_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredCloseReceipt {
                    operation_kind: row.get(0)?,
                    handle: row.get(1)?,
                    request_digest: row.get(2)?,
                    resulting_fence: row.get(3)?,
                    result_code: row.get(4)?,
                    result_digest: row.get(5)?,
                    result_value: row.get(6)?,
                })
            },
        )
        .optional()?;
    stored
        .as_ref()
        .map(|stored| decode_close_receipt(operation_id, disposition, stored))
        .transpose()
}

fn decode_close_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredCloseReceipt,
) -> Result<CloseHandleReceipt, HandleError> {
    if stored.operation_kind != i64::from(CLOSE_OPERATION) {
        return Err(HandleError::OperationConflict);
    }
    let handle_id = identifier(&stored.handle, HandleId::from_bytes)?;
    let request_digest = array(&stored.request_digest)?;
    let handle_fence = u64::try_from(stored.resulting_fence).map_err(|_| HandleError::Corrupt)?;
    let outcome = CloseHandleOutcome::from_code(
        u8::try_from(stored.result_code).map_err(|_| HandleError::Corrupt)?,
    )?;
    let result_digest = array(&stored.result_digest)?;
    let closed_at = UnixMicros::new(stored.result_value.ok_or(HandleError::Corrupt)?);
    let expected = close_result_digest(
        operation_id,
        handle_id,
        request_digest,
        handle_fence,
        outcome,
        closed_at,
    );
    if handle_fence == 0 || result_digest != expected {
        return Err(HandleError::Corrupt);
    }
    Ok(CloseHandleReceipt {
        disposition,
        operation_id,
        handle_id,
        request_digest,
        handle_fence,
        outcome,
        closed_at,
        result_digest,
    })
}

fn matching_close_replay(
    receipt: CloseHandleReceipt,
    request: CloseHandleRequest,
    request_digest: [u8; 32],
) -> Result<CloseHandleReceipt, HandleError> {
    if receipt.handle_id == request.handle_id && receipt.request_digest == request_digest {
        Ok(receipt)
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn lease_request_digest(request: HandleLeaseRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.handle-lease-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.handle_id.as_bytes());
    digest.update(&request.expected_fence.to_be_bytes());
    digest.update(&request.principal_id.as_bytes());
    digest.update(&request.authorization_revision.get().to_be_bytes());
    digest.update(&request.gateway_node_id.as_bytes());
    digest.update(&[u8::from(request.takeover)]);
    digest.update(&request.lease_expires_at.get().to_be_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn lease_result_digest(
    operation_id: OperationId,
    handle_id: HandleId,
    request_digest: [u8; 32],
    fence: u64,
    gateway: NodeId,
    expires_at: UnixMicros,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.handle-lease-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&handle_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&fence.to_be_bytes());
    digest.update(&gateway.as_bytes());
    digest.update(&expires_at.get().to_be_bytes());
    digest.finalize().into()
}

fn close_request_digest(request: CloseHandleRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.close-handle-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.handle_id.as_bytes());
    digest.update(&request.expected_fence.to_be_bytes());
    digest.update(&request.principal_id.as_bytes());
    digest.update(&request.gateway_node_id.as_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn close_result_digest(
    operation_id: OperationId,
    handle_id: HandleId,
    request_digest: [u8; 32],
    fence: u64,
    outcome: CloseHandleOutcome,
    closed_at: UnixMicros,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.close-handle-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&handle_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&fence.to_be_bytes());
    digest.update(&[outcome.code()]);
    digest.update(&closed_at.get().to_be_bytes());
    digest.finalize().into()
}
