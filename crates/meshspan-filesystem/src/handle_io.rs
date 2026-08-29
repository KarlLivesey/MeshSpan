// SPDX-License-Identifier: GPL-2.0-only

//! Cross-database orchestration for fenced handles and private write stages.

use meshspan_domain::{HandleId, NodeId, OperationId, PrincipalId, Revision, StageId, UnixMicros};
use thiserror::Error;

use crate::{
    ByteRange, Checkpoint, DurableStageStore, HandleError, HandleLeaseReceipt, HandleLeaseRequest,
    HandleWriteAdmissionReceipt, HandleWriteAdmissionRequest, OpenHandleReceipt, OpenHandleRequest,
    RootFileCommitRequest, StageLeaseRequest, StageRegistration, StageStoreError, StageWrite,
    StageWriteOutcome, VersionPublicationStore,
};

/// Complete open intent including the private-stage bound required by a writable handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemHandleOpenRequest {
    /// Authority-owned logical open request.
    pub handle: OpenHandleRequest,
    /// Maximum logical size admitted for a writable handle's private stage.
    ///
    /// This must be present for writable handles and absent for read-only handles.
    pub maximum_stage_bytes: Option<u64>,
}

/// Complete caller-reserved identity set for an atomic create-or-open operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemHandleCreateRequest {
    /// Handle admission and private-stage policy used whether the file exists or is created.
    pub open: FilesystemHandleOpenRequest,
    /// Exact empty initial file and namespace mutation used only when the path is absent.
    pub initial_file: RootFileCommitRequest,
}

/// Durable outcome of an atomic create-or-open operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemHandleCreateReceipt {
    /// Authoritative handle reservation.
    pub handle: OpenHandleReceipt,
    /// Namespace publication when this operation created the file; absent when it opened one.
    pub creation: Option<crate::NamespacePublicationReceipt>,
}

/// One exact range write through a live authority-owned handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemHandleWriteRequest {
    /// Handle receiving the private copy-on-write mutation.
    pub handle_id: HandleId,
    /// Authenticated principal bound to the handle.
    pub principal_id: PrincipalId,
    /// Exact currently revalidated authorisation revision.
    pub authorization_revision: Revision,
    /// Gateway holding the current lease.
    pub gateway_node_id: NodeId,
    /// Immutable idempotent stage write. Its fence is also the handle fence.
    pub write: StageWrite,
    /// Authoritative attempt instant.
    pub observed_at: UnixMicros,
}

/// Cross-domain outcome for one handle write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemHandleWriteReceipt {
    /// Durable authority admission, which may predate stage recovery.
    pub admission: HandleWriteAdmissionReceipt,
    /// Whether immutable stage bytes were newly recorded or exactly replayed.
    pub stage_outcome: StageWriteOutcome,
    /// Exact durable checkpoint after the write.
    pub checkpoint: Checkpoint,
}

/// Exact durable-publication intent for one selected writable-handle checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemHandleFlushRequest {
    /// Stable end-to-end flush identity.
    pub operation_id: OperationId,
    /// Handle whose private checkpoint is selected.
    pub handle_id: HandleId,
    /// Exact current handle/stage fence.
    pub handle_fence: u64,
    /// Authenticated principal bound to the handle.
    pub principal_id: PrincipalId,
    /// Exact currently revalidated file authorisation revision.
    pub authorization_revision: Revision,
    /// Gateway holding the current lease.
    pub gateway_node_id: NodeId,
    /// Exact durable stage sequence selected by this flush.
    pub expected_stage_sequence: u64,
    /// Exact resulting logical length.
    pub final_length: u64,
    /// Whether missing ranges represent explicit logical zeroes.
    pub sparse: bool,
    /// Whether the superseded version enters ordinary history.
    pub retain_superseded_history: bool,
    /// Exact replicated retention-policy sequence used for that decision.
    pub retention_policy_sequence: u64,
    /// Selected manifest format.
    pub manifest_format_version: u16,
    /// Authority revision admitting durable content placement.
    pub content_authorization_revision: Revision,
    /// Exclusive provider-work deadline, bounded by the handle lease.
    pub content_deadline: UnixMicros,
    /// Authoritative planning instant.
    pub observed_at: UnixMicros,
}

/// One close request with the exact flush plan required when private changes are dirty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemHandleCloseRequest {
    /// Final fenced handle transition.
    pub close: crate::CloseHandleRequest,
    /// Required for dirty writable stages and absent for clean/read-only handles.
    pub flush: Option<FilesystemHandleFlushRequest>,
}

/// Durable result of flushing when required and then closing the handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemHandleCloseReceipt {
    /// Namespace publication produced by a dirty close.
    pub flush: Option<crate::NamespacePublicationReceipt>,
    /// Final handle release and delete-on-close readiness.
    pub close: crate::CloseHandleReceipt,
}

/// Stable failures from handle/stage composition.
#[derive(Debug, Error)]
pub enum HandleIoError {
    /// Open/write fields or cross-field relationships are malformed.
    #[error("handle IO input is invalid")]
    InvalidInput,
    /// Handle authority, share mode, lock or durable receipt rejected the operation.
    #[error("handle IO authority rejected the operation")]
    Handle(#[from] HandleError),
    /// Private-stage persistence or fencing rejected the operation.
    #[error("handle IO private stage failed")]
    Stage(#[from] StageStoreError),
}

pub(crate) fn open(
    stages: &mut DurableStageStore,
    publications: &mut VersionPublicationStore,
    request: &FilesystemHandleOpenRequest,
) -> Result<OpenHandleReceipt, HandleIoError> {
    let replay = publications
        .resolve_open_handle(request.handle.operation_id)?
        .is_some();
    if !replay {
        publications.preflight_open_handle(&request.handle)?;
    }
    prepare_stage(stages, request, true)?;
    publications
        .open_handle(&request.handle)
        .map_err(Into::into)
}

pub(crate) fn prepare_stage(
    stages: &mut DurableStageStore,
    request: &FilesystemHandleOpenRequest,
    existing_file: bool,
) -> Result<(), HandleIoError> {
    match (
        request.handle.desired_access.writes(),
        request.maximum_stage_bytes,
    ) {
        (true, Some(maximum_bytes)) => {
            let stage_id = stage_id(request.handle.handle_id)?;
            stages.register(StageRegistration {
                stage_id,
                stage_fence: 1,
                maximum_bytes,
                created_at: request.handle.opened_at,
                expires_at: request.handle.lease_expires_at,
            })?;
            if existing_file && request.handle.create_disposition.truncates_existing() {
                stages.initialise_truncation(
                    stage_id,
                    request.handle.operation_id,
                    1,
                    request.handle.opened_at,
                )?;
            }
        }
        (false, None) => {}
        (true, None) | (false, Some(_)) => return Err(HandleIoError::InvalidInput),
    }
    Ok(())
}

pub(crate) fn write(
    stages: &mut DurableStageStore,
    publications: &mut VersionPublicationStore,
    request: &FilesystemHandleWriteRequest,
) -> Result<FilesystemHandleWriteReceipt, HandleIoError> {
    let length =
        u64::try_from(request.write.bytes.len()).map_err(|_| HandleIoError::InvalidInput)?;
    let range = ByteRange::new(request.write.offset, length)?;
    if blake3::hash(request.write.bytes.as_slice()).as_bytes() != &request.write.digest {
        return Err(HandleIoError::InvalidInput);
    }
    let admission = publications.admit_handle_write(HandleWriteAdmissionRequest {
        operation_id: request.write.operation_id,
        handle_id: request.handle_id,
        handle_fence: request.write.stage_fence,
        principal_id: request.principal_id,
        authorization_revision: request.authorization_revision,
        gateway_node_id: request.gateway_node_id,
        range,
        content_digest: request.write.digest,
        observed_at: request.observed_at,
    })?;
    let stage = stage_id(request.handle_id)?;
    let stage_outcome = stages.write(stage, &request.write, request.observed_at)?;
    let checkpoint = stages.checkpoint(stage)?;
    Ok(FilesystemHandleWriteReceipt {
        admission,
        stage_outcome,
        checkpoint,
    })
}

pub(crate) fn renew_lease(
    stages: &mut DurableStageStore,
    publications: &mut VersionPublicationStore,
    request: HandleLeaseRequest,
) -> Result<HandleLeaseReceipt, HandleIoError> {
    let uses_stage = publications.handle_uses_private_stage(request.handle_id)?;
    let stage_request = StageLeaseRequest {
        operation_id: request.operation_id,
        stage_id: stage_id(request.handle_id)?,
        expected_fence: request.expected_fence,
        takeover: request.takeover,
        lease_expires_at: request.lease_expires_at,
        observed_at: request.observed_at,
    };
    if uses_stage {
        stages.preflight_lease(stage_request)?;
    }
    let receipt = publications.renew_handle_lease(request)?;
    if uses_stage {
        let stage_receipt = stages.renew_lease(stage_request)?;
        if stage_receipt.stage_fence != receipt.handle_fence
            || stage_receipt.lease_expires_at != receipt.lease_expires_at
        {
            return Err(HandleIoError::Stage(StageStoreError::Corrupt));
        }
    }
    Ok(receipt)
}

pub(crate) fn stage_id(handle_id: HandleId) -> Result<StageId, HandleIoError> {
    StageId::from_bytes(handle_id.as_bytes()).map_err(|_| HandleIoError::InvalidInput)
}

#[cfg(test)]
#[path = "handle_io_tests.rs"]
mod tests;
