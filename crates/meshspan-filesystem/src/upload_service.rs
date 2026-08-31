// SPDX-License-Identifier: GPL-2.0-only

//! Crash-recoverable composition of upload-session authority and private stages.

use meshspan_domain::{Revision, UnixMicros};
use thiserror::Error;

use crate::upload_store::{UploadSessionStore, UploadStoreError};
use crate::{
    DurableStageStore, StageAbortRequest, StageRegistration, StageStoreError, UploadAbortRequest,
    UploadBeginRequest, UploadSession, UploadState, UploadStatusReceipt, UploadStatusRequest,
    UploadWriteReceipt, UploadWriteRequest,
};

pub(crate) fn begin(
    sessions: &mut UploadSessionStore,
    stages: &mut DurableStageStore,
    request: &UploadBeginRequest,
) -> Result<UploadSession, UploadServiceError> {
    sessions.prepare(request)?;
    stages.register(StageRegistration {
        stage_id: request.stage_id,
        stage_fence: 1,
        maximum_bytes: request.maximum_bytes,
        created_at: request.created_at,
        expires_at: request.expires_at,
    })?;
    sessions.activate(request.upload_id)?;
    sessions.load(request.upload_id).map_err(Into::into)
}

pub(crate) fn write(
    sessions: &UploadSessionStore,
    stages: &mut DurableStageStore,
    request: &UploadWriteRequest,
) -> Result<UploadWriteReceipt, UploadServiceError> {
    let session = sessions.load(request.upload_id)?;
    validate_live_authority(
        &session,
        request.principal_id,
        request.authorization_revision,
        request.stage_fence,
        request.observed_at,
    )?;
    let outcome = stages.write(
        session.stage_id,
        &request.stage_write(),
        request.observed_at,
    )?;
    let checkpoint = stages.checkpoint(session.stage_id)?;
    Ok(UploadWriteReceipt {
        outcome,
        checkpoint,
    })
}

pub(crate) fn status(
    sessions: &UploadSessionStore,
    stages: &DurableStageStore,
    request: UploadStatusRequest,
) -> Result<UploadStatusReceipt, UploadServiceError> {
    let session = sessions.load(request.upload_id)?;
    if session.principal_id != request.principal_id
        || request.authorization_revision == Revision::ZERO
    {
        return Err(UploadServiceError::StaleAuthority);
    }
    if session.state == UploadState::Active && session.expires_at <= request.observed_at {
        return Err(UploadServiceError::StaleAuthority);
    }
    let checkpoint = stages.checkpoint(session.stage_id)?;
    Ok(UploadStatusReceipt {
        session,
        checkpoint,
    })
}

pub(crate) fn abort(
    sessions: &mut UploadSessionStore,
    stages: &mut DurableStageStore,
    request: UploadAbortRequest,
) -> Result<UploadSession, UploadServiceError> {
    let session = sessions.begin_abort(request)?;
    if session.principal_id != request.principal_id
        || request.authorization_revision == Revision::ZERO
        || session.stage_fence != request.stage_fence
    {
        return Err(UploadServiceError::StaleAuthority);
    }
    stages.abort(StageAbortRequest {
        operation_id: request.operation_id,
        stage_id: session.stage_id,
        stage_fence: request.stage_fence,
        observed_at: request.observed_at,
    })?;
    sessions.finish_abort(request).map_err(Into::into)
}

fn validate_live_authority(
    session: &UploadSession,
    principal_id: meshspan_domain::PrincipalId,
    authorization_revision: Revision,
    stage_fence: u64,
    observed_at: UnixMicros,
) -> Result<(), UploadServiceError> {
    if session.state != UploadState::Active
        || session.principal_id != principal_id
        || authorization_revision == Revision::ZERO
        || session.stage_fence != stage_fence
        || session.expires_at <= observed_at
    {
        Err(UploadServiceError::StaleAuthority)
    } else {
        Ok(())
    }
}

/// Stable failures from resumable upload-session and private-stage composition.
#[derive(Debug, Error)]
pub enum UploadServiceError {
    /// Input, bounds or time relationships are invalid.
    #[error("upload input is invalid")]
    InvalidInput,
    /// An idempotency or upload identity belongs to different canonical input.
    #[error("upload operation conflicts with durable state")]
    OperationConflict,
    /// Current identity, permission, fence, lifecycle or expiry does not permit the operation.
    #[error("upload authority is stale")]
    StaleAuthority,
    /// A recoverable cross-database transition has not completed yet.
    #[error("upload transition is temporarily unavailable")]
    Unavailable,
    /// Durable upload state violates an internal invariant.
    #[error("upload state is corrupt")]
    Corrupt,
    /// Durable private-stage work failed.
    #[error("upload private-stage operation failed")]
    Stage(#[from] StageStoreError),
}

impl From<UploadStoreError> for UploadServiceError {
    fn from(error: UploadStoreError) -> Self {
        match error {
            UploadStoreError::InvalidInput => Self::InvalidInput,
            UploadStoreError::OperationConflict => Self::OperationConflict,
            UploadStoreError::Stale => Self::StaleAuthority,
            UploadStoreError::Unavailable => Self::Unavailable,
            UploadStoreError::Corrupt | UploadStoreError::Io(_) | UploadStoreError::Sqlite(_) => {
                Self::Corrupt
            }
        }
    }
}
