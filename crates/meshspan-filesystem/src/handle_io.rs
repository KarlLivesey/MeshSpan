// SPDX-License-Identifier: GPL-2.0-only

//! Cross-database orchestration for fenced handles and private write stages.

use meshspan_domain::{HandleId, NodeId, PrincipalId, Revision, StageId, UnixMicros};
use thiserror::Error;

use crate::{
    ByteRange, Checkpoint, DurableStageStore, HandleError, HandleWriteAdmissionReceipt,
    HandleWriteAdmissionRequest, OpenHandleReceipt, OpenHandleRequest, StageRegistration,
    StageStoreError, StageWrite, StageWriteOutcome, VersionPublicationStore,
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
    match (
        request.handle.desired_access.writes(),
        request.maximum_stage_bytes,
    ) {
        (true, Some(maximum_bytes)) => stages.register(StageRegistration {
            stage_id: stage_id(request.handle.handle_id)?,
            stage_fence: 1,
            maximum_bytes,
            created_at: request.handle.opened_at,
            expires_at: request.handle.lease_expires_at,
        })?,
        (false, None) => {}
        (true, None) | (false, Some(_)) => return Err(HandleIoError::InvalidInput),
    }
    publications
        .open_handle(&request.handle)
        .map_err(Into::into)
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

fn stage_id(handle_id: HandleId) -> Result<StageId, HandleIoError> {
    StageId::from_bytes(handle_id.as_bytes()).map_err(|_| HandleIoError::InvalidInput)
}

#[cfg(test)]
#[path = "handle_io_tests.rs"]
mod tests;
