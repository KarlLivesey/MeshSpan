// SPDX-License-Identifier: GPL-2.0-only

//! Crash-recoverable composition of upload-session authority and private stages.

use meshspan_domain::{Revision, UnixMicros};
use thiserror::Error;

use crate::upload_store::{UploadCommitTransition, UploadSessionStore, UploadStoreError};
use crate::{
    DurableStageStore, StageAbortRequest, StageRegistration, StageStoreError, UploadAbortRequest,
    UploadBeginRequest, UploadCommitRequest, UploadDisposition, UploadSession, UploadState,
    UploadStatusReceipt, UploadStatusRequest, UploadWriteReceipt, UploadWriteRequest,
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

pub(crate) fn begin_commit(
    sessions: &mut UploadSessionStore,
    stages: &DurableStageStore,
    request: &UploadCommitRequest,
) -> Result<UploadCommitTransition, UploadServiceError> {
    let session = sessions.load(request.upload_id)?;
    validate_commit(&session, request)?;
    let checkpoint = stages.checkpoint(session.stage_id)?;
    if checkpoint.sequence != request.expected_sequence
        || (!request.sparse
            && !crate::staging::covers(&checkpoint.initialised_ranges, request.final_length))
    {
        return Err(UploadServiceError::Incomplete);
    }
    let transition = commit_transition(request);
    sessions.begin_commit(transition)?;
    Ok(transition)
}

pub(crate) fn finish_commit(
    sessions: &mut UploadSessionStore,
    transition: UploadCommitTransition,
) -> Result<UploadSession, UploadServiceError> {
    sessions.finish_commit(transition).map_err(Into::into)
}

fn validate_commit(
    session: &UploadSession,
    request: &UploadCommitRequest,
) -> Result<(), UploadServiceError> {
    let completion = request.publication.completion;
    let disposition_matches = match session.disposition {
        UploadDisposition::CreateNew => request.publication.expected_current_version_id.is_none(),
        UploadDisposition::ReplaceIfVersion(version) => {
            request.publication.expected_current_version_id == Some(version)
        }
        UploadDisposition::ReplaceCurrent => {
            request.publication.expected_current_version_id.is_some()
        }
    };
    let exact = session.state != UploadState::Aborted
        && session.principal_id == request.principal_id
        && request.authorization_revision != Revision::ZERO
        && session.stage_fence == request.stage_fence
        && session.expires_at > request.observed_at
        && request.final_length <= session.maximum_bytes
        && completion.operation_id == request.operation_id
        && completion.stage_id == session.stage_id
        && completion.stage_fence == request.stage_fence
        && completion.expected_sequence == request.expected_sequence
        && completion.final_length == request.final_length
        && completion.sparse == request.sparse
        && completion.observed_at == request.observed_at
        && request.publication.volume_id == session.volume_id
        && request.publication.path.path() == &session.path
        && request.publication.created_by == request.principal_id
        && request.publication.created_at == request.observed_at
        && request.publication.content_authorization_revision == request.authorization_revision
        && disposition_matches;
    if exact {
        Ok(())
    } else {
        Err(UploadServiceError::StaleAuthority)
    }
}

fn commit_transition(request: &UploadCommitRequest) -> UploadCommitTransition {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.upload-commit.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.upload_id.as_bytes());
    digest.update(&request.principal_id.as_bytes());
    digest.update(&request.authorization_revision.get().to_be_bytes());
    digest.update(&request.stage_fence.to_be_bytes());
    digest.update(&request.expected_sequence.to_be_bytes());
    digest.update(&request.final_length.to_be_bytes());
    digest.update(&[u8::from(request.sparse)]);
    digest.update(&crate::commit_service::commit_request_digest(
        &request.publication,
    ));
    digest.update(&request.observed_at.get().to_be_bytes());
    UploadCommitTransition {
        operation_id: request.operation_id,
        upload_id: request.upload_id,
        principal_id: request.principal_id,
        stage_fence: request.stage_fence,
        request_digest: digest.finalize().into(),
        object_id: request.publication.object_id,
        version_id: request.publication.version_id,
        observed_at: request.observed_at,
    }
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
    /// The selected exact checkpoint does not initialise the complete non-sparse file.
    #[error("upload checkpoint is incomplete")]
    Incomplete,
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
