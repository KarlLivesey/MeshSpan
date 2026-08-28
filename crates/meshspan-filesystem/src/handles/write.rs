// SPDX-License-Identifier: GPL-2.0-only

//! Durable handle-write admission ordered against current fences and byte-range locks.

use meshspan_domain::{HandleId, NodeId, OperationId, PrincipalId, Revision, UnixMicros};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::locks::ByteRange;
use super::state::{ActiveHandle, load_active};
use super::{
    HandleError, PublicationDisposition, array, expire_stale_handles, identifier,
    reject_operation_collision, to_i64,
};

/// Authority input for one immutable private-stage write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleWriteAdmissionRequest {
    /// Stable operation identity, shared with the private-stage write.
    pub operation_id: OperationId,
    /// Handle whose private stage receives the bytes.
    pub handle_id: HandleId,
    /// Exact current handle/stage fence.
    pub handle_fence: u64,
    /// Authenticated principal bound to the handle.
    pub principal_id: PrincipalId,
    /// Exact authorisation revision revalidated for this write.
    pub authorization_revision: Revision,
    /// Gateway currently holding the handle lease.
    pub gateway_node_id: NodeId,
    /// Exact non-empty byte range being staged.
    pub range: ByteRange,
    /// BLAKE3 digest of the complete submitted bytes.
    pub content_digest: [u8; 32],
    /// Authoritative admission instant.
    pub observed_at: UnixMicros,
}

/// Durable proof that one write was ordered before subsequently admitted locks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleWriteAdmissionReceipt {
    /// Whether the exact admission was newly applied or durably replayed.
    pub disposition: PublicationDisposition,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Owning handle.
    pub handle_id: HandleId,
    /// Exact request digest.
    pub request_digest: [u8; 32],
    /// Fence that authorised the admission.
    pub handle_fence: u64,
    /// Exact admitted range.
    pub range: ByteRange,
    /// Submitted content identity.
    pub content_digest: [u8; 32],
    /// Authoritative admission instant.
    pub admitted_at: UnixMicros,
    /// Digest binding the complete durable result.
    pub result_digest: [u8; 32],
}

struct StoredAdmission {
    request_digest: Vec<u8>,
    handle: Vec<u8>,
    handle_fence: i64,
    start: i64,
    length: i64,
    content_digest: Vec<u8>,
    admitted_at: i64,
    result_digest: Vec<u8>,
}

pub(crate) fn admit_write(
    connection: &mut Connection,
    request: HandleWriteAdmissionRequest,
) -> Result<HandleWriteAdmissionReceipt, HandleError> {
    validate_request(request)?;
    let request_digest = write_request_digest(request);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = load_receipt(
        &transaction,
        request.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return matching_replay(receipt, request, request_digest);
    }
    reject_operation_collision(&transaction, request.operation_id)?;
    expire_stale_handles(&transaction, request.observed_at)?;
    let handle = load_active(&transaction, request.handle_id, request.observed_at)?;
    validate_authority(request, &handle)?;
    reject_conflicting_lock(&transaction, request, &handle)?;
    let receipt = persist(&transaction, request, request_digest)?;
    transaction.commit()?;
    Ok(receipt)
}

fn validate_request(request: HandleWriteAdmissionRequest) -> Result<(), HandleError> {
    if request.handle_fence == 0 || request.authorization_revision == Revision::ZERO {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_authority(
    request: HandleWriteAdmissionRequest,
    handle: &ActiveHandle,
) -> Result<(), HandleError> {
    if handle.fence != request.handle_fence
        || handle.principal != request.principal_id
        || handle.gateway != request.gateway_node_id
        || handle.authorization_revision != request.authorization_revision
    {
        return Err(HandleError::StaleHandle);
    }
    if handle.desired_access.writes() {
        Ok(())
    } else {
        Err(HandleError::InvalidInput)
    }
}

fn reject_conflicting_lock(
    transaction: &rusqlite::Transaction<'_>,
    request: HandleWriteAdmissionRequest,
    handle: &ActiveHandle,
) -> Result<(), HandleError> {
    let conflict: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM range_locks locks
            JOIN open_handles owners ON owners.handle_id = locks.handle_id
            WHERE owners.branch_id = ?1 AND owners.volume_id = ?2 AND owners.object_id = ?3
              AND locks.handle_id != ?4 AND locks.state = 1
              AND locks.lease_expires_at > ?5
              AND locks.byte_start < ?6
              AND ?7 < locks.byte_start + locks.byte_length
         )",
        params![
            handle.branch.as_bytes().as_slice(),
            handle.volume.as_bytes().as_slice(),
            handle.object.as_bytes().as_slice(),
            request.handle_id.as_bytes().as_slice(),
            request.observed_at.get(),
            to_i64(request.range.end())?,
            to_i64(request.range.start())?,
        ],
        |row| row.get(0),
    )?;
    if conflict == 0 {
        Ok(())
    } else {
        Err(HandleError::LockConflict)
    }
}

fn persist(
    transaction: &rusqlite::Transaction<'_>,
    request: HandleWriteAdmissionRequest,
    request_digest: [u8; 32],
) -> Result<HandleWriteAdmissionReceipt, HandleError> {
    let result_digest = write_result_digest(request, request_digest);
    transaction.execute(
        "INSERT INTO handle_write_admissions(
            operation_id, request_digest, handle_id, handle_fence, principal_id,
            authorization_revision, gateway_node_id, byte_start, byte_length,
            content_digest, admitted_at, receipt_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            request.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            request.handle_id.as_bytes().as_slice(),
            to_i64(request.handle_fence)?,
            request.principal_id.as_bytes().as_slice(),
            to_i64(request.authorization_revision.get())?,
            request.gateway_node_id.as_bytes().as_slice(),
            to_i64(request.range.start())?,
            to_i64(request.range.length())?,
            request.content_digest.as_slice(),
            request.observed_at.get(),
            result_digest.as_slice(),
        ],
    )?;
    Ok(receipt(
        PublicationDisposition::Applied,
        request,
        request_digest,
        result_digest,
    ))
}

fn load_receipt(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<HandleWriteAdmissionReceipt>, HandleError> {
    let stored: Option<StoredAdmission> = connection
        .query_row(
            "SELECT request_digest, handle_id, handle_fence, byte_start, byte_length,
                    content_digest, admitted_at, receipt_digest
             FROM handle_write_admissions WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredAdmission {
                    request_digest: row.get(0)?,
                    handle: row.get(1)?,
                    handle_fence: row.get(2)?,
                    start: row.get(3)?,
                    length: row.get(4)?,
                    content_digest: row.get(5)?,
                    admitted_at: row.get(6)?,
                    result_digest: row.get(7)?,
                })
            },
        )
        .optional()?;
    stored
        .as_ref()
        .map(|stored| decode_receipt(operation_id, disposition, stored))
        .transpose()
}

fn decode_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredAdmission,
) -> Result<HandleWriteAdmissionReceipt, HandleError> {
    let handle_id = identifier(&stored.handle, HandleId::from_bytes)?;
    let handle_fence = u64::try_from(stored.handle_fence).map_err(|_| HandleError::Corrupt)?;
    let start = u64::try_from(stored.start).map_err(|_| HandleError::Corrupt)?;
    let length = u64::try_from(stored.length).map_err(|_| HandleError::Corrupt)?;
    let range = ByteRange::new(start, length).map_err(|_| HandleError::Corrupt)?;
    let request_digest = array(&stored.request_digest)?;
    let content_digest = array(&stored.content_digest)?;
    let result_digest = array(&stored.result_digest)?;
    let receipt = HandleWriteAdmissionReceipt {
        disposition,
        operation_id,
        handle_id,
        request_digest,
        handle_fence,
        range,
        content_digest,
        admitted_at: UnixMicros::new(stored.admitted_at),
        result_digest,
    };
    if handle_fence == 0 || result_digest != receipt_result_digest(receipt) {
        Err(HandleError::Corrupt)
    } else {
        Ok(receipt)
    }
}

fn matching_replay(
    receipt: HandleWriteAdmissionReceipt,
    request: HandleWriteAdmissionRequest,
    request_digest: [u8; 32],
) -> Result<HandleWriteAdmissionReceipt, HandleError> {
    if receipt.handle_id == request.handle_id && receipt.request_digest == request_digest {
        Ok(receipt)
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn receipt(
    disposition: PublicationDisposition,
    request: HandleWriteAdmissionRequest,
    request_digest: [u8; 32],
    result_digest: [u8; 32],
) -> HandleWriteAdmissionReceipt {
    HandleWriteAdmissionReceipt {
        disposition,
        operation_id: request.operation_id,
        handle_id: request.handle_id,
        request_digest,
        handle_fence: request.handle_fence,
        range: request.range,
        content_digest: request.content_digest,
        admitted_at: request.observed_at,
        result_digest,
    }
}

fn write_request_digest(request: HandleWriteAdmissionRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.handle-write-admission-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.handle_id.as_bytes());
    digest.update(&request.handle_fence.to_be_bytes());
    digest.update(&request.principal_id.as_bytes());
    digest.update(&request.authorization_revision.get().to_be_bytes());
    digest.update(&request.gateway_node_id.as_bytes());
    digest.update(&request.range.start().to_be_bytes());
    digest.update(&request.range.length().to_be_bytes());
    digest.update(&request.content_digest);
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn write_result_digest(request: HandleWriteAdmissionRequest, request_digest: [u8; 32]) -> [u8; 32] {
    write_result_digest_fields(
        request.operation_id,
        request.handle_id,
        request_digest,
        request.handle_fence,
        request.range,
        request.content_digest,
        request.observed_at,
    )
}

fn receipt_result_digest(receipt: HandleWriteAdmissionReceipt) -> [u8; 32] {
    write_result_digest_fields(
        receipt.operation_id,
        receipt.handle_id,
        receipt.request_digest,
        receipt.handle_fence,
        receipt.range,
        receipt.content_digest,
        receipt.admitted_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_result_digest_fields(
    operation_id: OperationId,
    handle_id: HandleId,
    request_digest: [u8; 32],
    handle_fence: u64,
    range: ByteRange,
    content_digest: [u8; 32],
    admitted_at: UnixMicros,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.handle-write-admission-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&handle_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&handle_fence.to_be_bytes());
    digest.update(&range.start().to_be_bytes());
    digest.update(&range.length().to_be_bytes());
    digest.update(&content_digest);
    digest.update(&admitted_at.get().to_be_bytes());
    digest.finalize().into()
}
