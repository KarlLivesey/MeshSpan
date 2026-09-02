// SPDX-License-Identifier: GPL-2.0-only

//! Fenced, idempotent mutations of durable live-handle information.

use meshspan_domain::{HandleId, NodeId, OperationId, PrincipalId, UnixMicros};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::state::{ActiveHandle, load_active};
use super::{HandleError, PublicationDisposition, array, reject_operation_collision, to_i64};

const SET_LENGTH_OPERATION: u8 = 1;
const SET_DISPOSITION_OPERATION: u8 = 2;

/// Exact fenced request to change one private working file length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetHandleLengthRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Live writable handle.
    pub handle_id: HandleId,
    /// Exact current handle fence.
    pub handle_fence: u64,
    /// Authenticated owning principal.
    pub principal_id: PrincipalId,
    /// Gateway currently holding the lease.
    pub gateway_node_id: NodeId,
    /// Exact new logical length.
    pub logical_length: u64,
    /// Authoritative mutation instant.
    pub observed_at: UnixMicros,
}

/// Exact fenced request to set or clear delete-on-close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetHandleDispositionRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Live delete-capable handle.
    pub handle_id: HandleId,
    /// Exact current handle fence.
    pub handle_fence: u64,
    /// Authenticated owning principal.
    pub principal_id: PrincipalId,
    /// Gateway currently holding the lease.
    pub gateway_node_id: NodeId,
    /// Whether final close requests logical deletion.
    pub delete_on_close: bool,
    /// Authoritative mutation instant.
    pub observed_at: UnixMicros,
}

/// Durable state after one handle-information mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleInformationReceipt {
    /// Whether the exact mutation was applied or replayed.
    pub disposition: PublicationDisposition,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Mutated handle.
    pub handle_id: HandleId,
    /// Exact request digest.
    pub request_digest: [u8; 32],
    /// Fence that admitted the mutation.
    pub handle_fence: u64,
    /// Resulting private working length.
    pub working_logical_length: u64,
    /// Resulting delete-on-close state.
    pub delete_on_close: bool,
    /// Authoritative commit instant.
    pub changed_at: UnixMicros,
    /// Digest binding the complete durable result.
    pub result_digest: [u8; 32],
}

#[derive(Clone, Copy)]
enum InformationMutation {
    Length(SetHandleLengthRequest),
    Disposition(SetHandleDispositionRequest),
}

impl InformationMutation {
    const fn operation_id(self) -> OperationId {
        match self {
            Self::Length(request) => request.operation_id,
            Self::Disposition(request) => request.operation_id,
        }
    }

    const fn handle_id(self) -> HandleId {
        match self {
            Self::Length(request) => request.handle_id,
            Self::Disposition(request) => request.handle_id,
        }
    }

    const fn handle_fence(self) -> u64 {
        match self {
            Self::Length(request) => request.handle_fence,
            Self::Disposition(request) => request.handle_fence,
        }
    }

    const fn principal_id(self) -> PrincipalId {
        match self {
            Self::Length(request) => request.principal_id,
            Self::Disposition(request) => request.principal_id,
        }
    }

    const fn gateway_node_id(self) -> NodeId {
        match self {
            Self::Length(request) => request.gateway_node_id,
            Self::Disposition(request) => request.gateway_node_id,
        }
    }

    const fn observed_at(self) -> UnixMicros {
        match self {
            Self::Length(request) => request.observed_at,
            Self::Disposition(request) => request.observed_at,
        }
    }

    const fn kind(self) -> u8 {
        match self {
            Self::Length(_) => SET_LENGTH_OPERATION,
            Self::Disposition(_) => SET_DISPOSITION_OPERATION,
        }
    }
}

struct StoredReceipt {
    kind: i64,
    handle_id: Vec<u8>,
    request_digest: Vec<u8>,
    handle_fence: i64,
    logical_length: i64,
    delete_on_close: i64,
    changed_at: i64,
    result_digest: Vec<u8>,
}

pub(crate) fn set_length(
    connection: &mut Connection,
    request: SetHandleLengthRequest,
) -> Result<HandleInformationReceipt, HandleError> {
    apply(connection, InformationMutation::Length(request))
}

pub(crate) fn set_disposition(
    connection: &mut Connection,
    request: SetHandleDispositionRequest,
) -> Result<HandleInformationReceipt, HandleError> {
    apply(connection, InformationMutation::Disposition(request))
}

fn apply(
    connection: &mut Connection,
    mutation: InformationMutation,
) -> Result<HandleInformationReceipt, HandleError> {
    validate_request(mutation)?;
    let request_digest = mutation_request_digest(mutation);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = load_receipt(
        &transaction,
        mutation.operation_id(),
        PublicationDisposition::Replayed,
    )? {
        return matching_replay(receipt, mutation, request_digest);
    }
    reject_operation_collision(&transaction, mutation.operation_id())?;
    super::expire_stale_handles(&transaction, mutation.observed_at())?;
    let handle = load_active(&transaction, mutation.handle_id(), mutation.observed_at())?;
    validate_authority(mutation, &handle)?;
    let state = resulting_state(mutation, &handle);
    update_handle(&transaction, mutation, state)?;
    let receipt = persist_receipt(&transaction, mutation, request_digest, state)?;
    transaction.commit()?;
    Ok(receipt)
}

fn validate_request(mutation: InformationMutation) -> Result<(), HandleError> {
    if mutation.handle_fence() == 0
        || matches!(mutation, InformationMutation::Length(request) if request.logical_length > i64::MAX as u64)
    {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_authority(
    mutation: InformationMutation,
    handle: &ActiveHandle,
) -> Result<(), HandleError> {
    if handle.fence != mutation.handle_fence()
        || handle.principal != mutation.principal_id()
        || handle.gateway != mutation.gateway_node_id()
    {
        return Err(HandleError::StaleHandle);
    }
    let permitted = match mutation {
        InformationMutation::Length(_) => handle.desired_access.writes(),
        InformationMutation::Disposition(_) => handle.desired_access.deletes(),
    };
    if permitted {
        Ok(())
    } else {
        Err(HandleError::InvalidInput)
    }
}

fn resulting_state(mutation: InformationMutation, handle: &ActiveHandle) -> (u64, bool) {
    match mutation {
        InformationMutation::Length(request) => (request.logical_length, handle.delete_on_close),
        InformationMutation::Disposition(request) => {
            (handle.working_logical_length, request.delete_on_close)
        }
    }
}

fn update_handle(
    transaction: &Transaction<'_>,
    mutation: InformationMutation,
    state: (u64, bool),
) -> Result<(), HandleError> {
    let changed = transaction.execute(
        "UPDATE open_handles
         SET working_logical_length = ?1, delete_on_close = ?2
         WHERE handle_id = ?3 AND state = 1 AND handle_fence = ?4
           AND lease_expires_at > ?5",
        params![
            to_i64(state.0)?,
            state.1,
            mutation.handle_id().as_bytes().as_slice(),
            to_i64(mutation.handle_fence())?,
            mutation.observed_at().get(),
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(HandleError::StaleHandle)
    }
}

fn persist_receipt(
    transaction: &Transaction<'_>,
    mutation: InformationMutation,
    request_digest: [u8; 32],
    state: (u64, bool),
) -> Result<HandleInformationReceipt, HandleError> {
    let result_digest = mutation_result_digest(mutation, request_digest, state);
    transaction.execute(
        "INSERT INTO handle_information_operations(
            operation_id, operation_kind, handle_id, request_digest, handle_fence,
            working_logical_length, delete_on_close, changed_at, result_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            mutation.operation_id().as_bytes().as_slice(),
            mutation.kind(),
            mutation.handle_id().as_bytes().as_slice(),
            request_digest.as_slice(),
            to_i64(mutation.handle_fence())?,
            to_i64(state.0)?,
            state.1,
            mutation.observed_at().get(),
            result_digest.as_slice(),
        ],
    )?;
    Ok(build_receipt(
        PublicationDisposition::Applied,
        mutation,
        request_digest,
        state,
        result_digest,
    ))
}

fn load_receipt(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<HandleInformationReceipt>, HandleError> {
    let stored = connection
        .query_row(
            "SELECT operation_kind, handle_id, request_digest, handle_fence,
                    working_logical_length, delete_on_close, changed_at, result_digest
             FROM handle_information_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredReceipt {
                    kind: row.get(0)?,
                    handle_id: row.get(1)?,
                    request_digest: row.get(2)?,
                    handle_fence: row.get(3)?,
                    logical_length: row.get(4)?,
                    delete_on_close: row.get(5)?,
                    changed_at: row.get(6)?,
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
    stored: &StoredReceipt,
) -> Result<HandleInformationReceipt, HandleError> {
    let kind = u8::try_from(stored.kind).map_err(|_| HandleError::Corrupt)?;
    if !matches!(kind, SET_LENGTH_OPERATION | SET_DISPOSITION_OPERATION)
        || !matches!(stored.delete_on_close, 0 | 1)
    {
        return Err(HandleError::Corrupt);
    }
    let handle_id = super::identifier(&stored.handle_id, HandleId::from_bytes)?;
    let request_digest = array(&stored.request_digest)?;
    let handle_fence = u64::try_from(stored.handle_fence).map_err(|_| HandleError::Corrupt)?;
    let logical_length = u64::try_from(stored.logical_length).map_err(|_| HandleError::Corrupt)?;
    let result_digest = array(&stored.result_digest)?;
    let receipt = HandleInformationReceipt {
        disposition,
        operation_id,
        handle_id,
        request_digest,
        handle_fence,
        working_logical_length: logical_length,
        delete_on_close: stored.delete_on_close == 1,
        changed_at: UnixMicros::new(stored.changed_at),
        result_digest,
    };
    if result_digest == receipt_result_digest(kind, receipt) {
        Ok(receipt)
    } else {
        Err(HandleError::Corrupt)
    }
}

fn matching_replay(
    receipt: HandleInformationReceipt,
    mutation: InformationMutation,
    request_digest: [u8; 32],
) -> Result<HandleInformationReceipt, HandleError> {
    if receipt.handle_id == mutation.handle_id() && receipt.request_digest == request_digest {
        Ok(receipt)
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn build_receipt(
    disposition: PublicationDisposition,
    mutation: InformationMutation,
    request_digest: [u8; 32],
    state: (u64, bool),
    result_digest: [u8; 32],
) -> HandleInformationReceipt {
    HandleInformationReceipt {
        disposition,
        operation_id: mutation.operation_id(),
        handle_id: mutation.handle_id(),
        request_digest,
        handle_fence: mutation.handle_fence(),
        working_logical_length: state.0,
        delete_on_close: state.1,
        changed_at: mutation.observed_at(),
        result_digest,
    }
}

fn mutation_request_digest(mutation: InformationMutation) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.handle-information-request.v1\0");
    digest.update(&[mutation.kind()]);
    digest.update(&mutation.operation_id().as_bytes());
    digest.update(&mutation.handle_id().as_bytes());
    digest.update(&mutation.handle_fence().to_be_bytes());
    digest.update(&mutation.principal_id().as_bytes());
    digest.update(&mutation.gateway_node_id().as_bytes());
    match mutation {
        InformationMutation::Length(request) => {
            digest.update(&request.logical_length.to_be_bytes());
        }
        InformationMutation::Disposition(request) => {
            digest.update(&[u8::from(request.delete_on_close)]);
        }
    }
    digest.update(&mutation.observed_at().get().to_be_bytes());
    digest.finalize().into()
}

fn mutation_result_digest(
    mutation: InformationMutation,
    request_digest: [u8; 32],
    state: (u64, bool),
) -> [u8; 32] {
    result_digest_fields(
        mutation.kind(),
        mutation.operation_id(),
        mutation.handle_id(),
        request_digest,
        mutation.handle_fence(),
        state,
        mutation.observed_at(),
    )
}

fn receipt_result_digest(kind: u8, receipt: HandleInformationReceipt) -> [u8; 32] {
    result_digest_fields(
        kind,
        receipt.operation_id,
        receipt.handle_id,
        receipt.request_digest,
        receipt.handle_fence,
        (receipt.working_logical_length, receipt.delete_on_close),
        receipt.changed_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn result_digest_fields(
    kind: u8,
    operation_id: OperationId,
    handle_id: HandleId,
    request_digest: [u8; 32],
    handle_fence: u64,
    state: (u64, bool),
    changed_at: UnixMicros,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.handle-information-result.v1\0");
    digest.update(&[kind]);
    digest.update(&operation_id.as_bytes());
    digest.update(&handle_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&handle_fence.to_be_bytes());
    digest.update(&state.0.to_be_bytes());
    digest.update(&[u8::from(state.1)]);
    digest.update(&changed_at.get().to_be_bytes());
    digest.finalize().into()
}
