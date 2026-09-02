// SPDX-License-Identifier: GPL-2.0-only

//! Native upload contract composition over the common authorised filesystem.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    AbortUploadRequest, AbortUploadResponse, BeginUploadRequest, BeginUploadResponse,
    CommitUploadRequest, CommitUploadResponse, GetObjectQuery, ListUploadRangesResponse,
    NamespacePath as ApiNamespacePath, OperationId as ApiOperationId, UploadId as ApiUploadId,
    UploadRange, UploadState as ApiUploadState, UploadStatusResponse, VolumeId as ApiVolumeId,
    WriteAcknowledgement, WriteDurabilityScope, WriteUploadRangeResponse,
};
use meshspan_domain::{
    DurabilityScope, DurationMicros, OperationId, StageId, UnixMicros, UploadId, VolumeId,
};
use meshspan_filesystem::{
    AdapterStatRequest, AdapterUploadAbortRequest, AdapterUploadBeginRequest,
    AdapterUploadCommitRequest, AdapterUploadRangePageRequest, AdapterUploadStatusRequest,
    AdapterUploadWriteRequest, FilesystemAccessContext, FilesystemFileAdapter,
    FilesystemUploadAdapter, NamespaceLimits, NamespacePath, UploadDisposition, UploadState,
    UploadStatusReceipt,
};
use sha2::{Digest, Sha256};

use super::codec::decode_digest;
use super::{
    NativeUploadController, NativeUploadError, UploadRangePageRequest, UploadRangeWriteRequest,
};
use crate::create_mesh_setup::parse_uuid;
use crate::object_stat_api::object_stat_response;
use crate::{
    FileApiAuthenticationError, FileApiFailure, NativeFileApiAuthenticator,
    NativeFileRequestProtection,
};

/// Daemon-owned upload lifetime and content-publication deadline policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeUploadServicePolicy {
    upload_lifetime: DurationMicros,
    content_deadline: DurationMicros,
}

impl NativeUploadServicePolicy {
    /// Validates non-zero bounded server-side upload timings.
    #[must_use]
    pub const fn new(
        upload_lifetime: DurationMicros,
        content_deadline: DurationMicros,
    ) -> Option<Self> {
        if upload_lifetime.get() == 0 || content_deadline.get() == 0 {
            None
        } else {
            Some(Self {
                upload_lifetime,
                content_deadline,
            })
        }
    }
}

/// Complete native upload application service over replaceable boundaries.
pub struct NativeUploadService<A, F, M> {
    authenticator: A,
    filesystem: F,
    classify_error: M,
    policy: NativeUploadServicePolicy,
}

impl<A, F, M> NativeUploadService<A, F, M> {
    /// Composes authentication, the common filesystem and closed error classification.
    #[must_use]
    pub const fn new(
        authenticator: A,
        filesystem: F,
        classify_error: M,
        policy: NativeUploadServicePolicy,
    ) -> Self {
        Self {
            authenticator,
            filesystem,
            classify_error,
            policy,
        }
    }
}

impl<A, F, M, E> NativeUploadController for NativeUploadService<A, F, M>
where
    A: NativeFileApiAuthenticator,
    F: FilesystemUploadAdapter<Error = E> + FilesystemFileAdapter<Error = E> + Send + 'static,
    M: Fn(&E) -> FileApiFailure + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError> {
        self.authenticator
            .authenticate_file_request(headers, protection, now)
    }

    fn begin_upload(
        &mut self,
        context: FilesystemAccessContext,
        volume_id: &str,
        request: BeginUploadRequest,
    ) -> Result<BeginUploadResponse, NativeUploadError> {
        let volume_id = domain_volume(volume_id)?;
        let operation_id = domain_operation(&request.operation_id)?;
        let upload_id = derived_identifier(operation_id, b"upload", UploadId::from_bytes)?;
        let stage_id = derived_identifier(operation_id, b"stage", StageId::from_bytes)?;
        let expires_at = context
            .now
            .checked_add(self.policy.upload_lifetime)
            .ok_or(NativeUploadError::Unavailable)?;
        let receipt = self
            .filesystem
            .begin_upload(
                context,
                &AdapterUploadBeginRequest {
                    operation_id,
                    upload_id,
                    stage_id,
                    volume_id,
                    path: domain_path(request.path.as_str())?,
                    disposition: domain_disposition(&request.disposition)?,
                    maximum_bytes: request.maximum_bytes,
                    expires_at,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        status_response(&receipt)
    }

    fn get_upload(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: &str,
    ) -> Result<UploadStatusResponse, NativeUploadError> {
        let receipt = self
            .filesystem
            .upload_status(
                context,
                AdapterUploadStatusRequest {
                    upload_id: domain_upload(upload_id)?,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        status_response(&receipt)
    }

    fn list_upload_ranges(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: &str,
        request: UploadRangePageRequest,
    ) -> Result<ListUploadRangesResponse, NativeUploadError> {
        let upload_id = domain_upload(upload_id)?;
        let page = self
            .filesystem
            .upload_range_page(
                context,
                AdapterUploadRangePageRequest {
                    upload_id,
                    expected_sequence: request.cursor.map(|value| value.checkpoint_sequence),
                    after_start: request.cursor.map(|value| value.after_start),
                    limit: request.limit,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        range_page_response(page)
    }

    fn write_upload_range(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: &str,
        request: UploadRangeWriteRequest,
    ) -> Result<WriteUploadRangeResponse, NativeUploadError> {
        let upload_id = domain_upload(upload_id)?;
        self.filesystem
            .write_upload(
                context,
                &AdapterUploadWriteRequest {
                    upload_id,
                    operation_id: domain_operation(&request.operation_id)?,
                    stage_fence: request.stage_fence,
                    offset: request.offset,
                    bytes: request.bytes,
                    digest: request.content_blake3,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        self.current_status(context, upload_id)
    }

    fn commit_upload(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: &str,
        request: CommitUploadRequest,
    ) -> Result<CommitUploadResponse, NativeUploadError> {
        let upload_id = domain_upload(upload_id)?;
        let content_deadline = context
            .now
            .checked_add(self.policy.content_deadline)
            .ok_or(NativeUploadError::Unavailable)?;
        let expected_content_digest = request
            .expected_blake3
            .as_deref()
            .map(decode_digest)
            .transpose()?;
        let receipt = self
            .filesystem
            .commit_upload(
                context,
                AdapterUploadCommitRequest {
                    operation_id: domain_operation(&request.operation_id)?,
                    upload_id,
                    stage_fence: request.stage_fence,
                    expected_sequence: request.expected_sequence,
                    final_length: request.final_length,
                    sparse: request.sparse,
                    expected_content_digest,
                    content_deadline,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        let upload = self.current_status(context, upload_id)?;
        let path = domain_path(upload.path.as_str())?;
        let stat = self
            .filesystem
            .stat(
                context,
                &AdapterStatRequest {
                    volume_id: domain_volume(upload.volume_id.as_str())?,
                    path,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        if stat.file_version_id != Some(receipt.publication.file_version_id) {
            return Err(NativeUploadError::Failed);
        }
        let object = object_stat_response(
            upload.volume_id.clone(),
            GetObjectQuery {
                path: upload.path.clone(),
            },
            &stat,
        )
        .map_err(|_| NativeUploadError::Failed)?;
        Ok(CommitUploadResponse {
            upload,
            object,
            acknowledgement: acknowledgement_response(receipt.acknowledgement),
        })
    }

    fn abort_upload(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: &str,
        request: AbortUploadRequest,
    ) -> Result<AbortUploadResponse, NativeUploadError> {
        let upload_id = domain_upload(upload_id)?;
        self.filesystem
            .abort_upload(
                context,
                AdapterUploadAbortRequest {
                    operation_id: domain_operation(&request.operation_id)?,
                    upload_id,
                    stage_fence: request.stage_fence,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        self.current_status(context, upload_id)
    }
}

impl<A, F, M> NativeUploadService<A, F, M> {
    fn map_error<E>(&self, error: &E) -> NativeUploadError
    where
        M: Fn(&E) -> FileApiFailure,
    {
        match (self.classify_error)(error) {
            FileApiFailure::InvalidInput => NativeUploadError::InvalidInput,
            FileApiFailure::NotFound => NativeUploadError::NotFound,
            FileApiFailure::AccessDenied => NativeUploadError::AccessDenied,
            FileApiFailure::StaleCursor => NativeUploadError::StateConflict,
            FileApiFailure::Conflict => NativeUploadError::OperationConflict,
            FileApiFailure::Unavailable => NativeUploadError::Unavailable,
            FileApiFailure::Failed => NativeUploadError::Failed,
        }
    }

    fn current_status<E>(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: UploadId,
    ) -> Result<UploadStatusResponse, NativeUploadError>
    where
        F: FilesystemUploadAdapter<Error = E>,
        M: Fn(&E) -> FileApiFailure,
    {
        let receipt = self
            .filesystem
            .upload_status(
                context,
                AdapterUploadStatusRequest {
                    upload_id,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        status_response(&receipt)
    }
}

fn acknowledgement_response(
    receipt: meshspan_filesystem::PublicationAcknowledgement,
) -> WriteAcknowledgement {
    WriteAcknowledgement {
        configured_consistency: acknowledgement_class(receipt.configured_class),
        acknowledged_consistency: acknowledgement_class(receipt.acknowledged_class),
        fallback_applied: receipt.fallback_applied,
        durability_scope: match receipt.durability_scope {
            DurabilityScope::NodeLocal => WriteDurabilityScope::NodeLocal,
            DurabilityScope::CellReplicated => WriteDurabilityScope::CellReplicated,
            DurabilityScope::GloballyConverged => WriteDurabilityScope::GloballyConverged,
        },
        policy_committed: receipt.policy_committed,
        required_shard_receipts: receipt.required_shard_receipts,
        eventual_shard_receipts: receipt.eventual_shard_receipts,
        pending_eventual_shards: receipt.pending_eventual_shards,
        policy_evidence_blake3: blake3::Hash::from_bytes(receipt.policy_evidence_digest)
            .to_hex()
            .to_string(),
        achieved_protection_blake3: blake3::Hash::from_bytes(receipt.achieved_protection_digest)
            .to_hex()
            .to_string(),
        pending_debt_blake3: blake3::Hash::from_bytes(receipt.pending_debt_digest)
            .to_hex()
            .to_string(),
    }
}

const fn acknowledgement_class(
    class: meshspan_filesystem::ContentAcknowledgementClass,
) -> meshspan_api_contract::AcknowledgementConsistency {
    match class {
        meshspan_filesystem::ContentAcknowledgementClass::Eventual => {
            meshspan_api_contract::AcknowledgementConsistency::Eventual
        }
        meshspan_filesystem::ContentAcknowledgementClass::Strong => {
            meshspan_api_contract::AcknowledgementConsistency::Strong
        }
    }
}

fn status_response(
    receipt: &UploadStatusReceipt,
) -> Result<UploadStatusResponse, NativeUploadError> {
    let session = &receipt.session;
    let upload_id = api_upload(session.upload_id)?;
    Ok(UploadStatusResponse {
        upload_id: upload_id.clone(),
        volume_id: ApiVolumeId::from_uuid_bytes(session.volume_id.as_bytes())
            .ok_or(NativeUploadError::Failed)?,
        path: api_path(&session.path)?,
        state: match session.state {
            UploadState::Active => ApiUploadState::Active,
            UploadState::Committing => ApiUploadState::Committing,
            UploadState::Committed => ApiUploadState::Committed,
            UploadState::Aborted => ApiUploadState::Aborted,
        },
        stage_fence: session.stage_fence,
        maximum_bytes: session.maximum_bytes,
        checkpoint_sequence: receipt.checkpoint.sequence,
        logical_extent: receipt.checkpoint.logical_extent,
        expires_at_epoch_micros: session.expires_at.get(),
        committed_object_id: session
            .committed_object_id
            .map(|value| meshspan_api_contract::ObjectId::from_uuid_bytes(value.as_bytes()))
            .transpose_option()?,
        committed_version_id: session
            .committed_version_id
            .map(|value| meshspan_api_contract::FileVersionId::from_uuid_bytes(value.as_bytes()))
            .transpose_option()?,
        ranges_url: format!("/api/latest/uploads/{}/ranges", upload_id.as_str()),
    })
}

fn range_page_response(
    page: meshspan_filesystem::UploadRangePageReceipt,
) -> Result<ListUploadRangesResponse, NativeUploadError> {
    let upload_id = api_upload(page.upload_id)?;
    let ranges = page
        .ranges
        .into_iter()
        .map(|range| UploadRange {
            start: range.start,
            end: range.end,
        })
        .collect();
    let next_page_url = page.next_after_start.map(|after| {
        format!(
            "/api/latest/uploads/{}/ranges?cursor=v1.{}.{}",
            upload_id.as_str(),
            page.checkpoint_sequence,
            after
        )
    });
    Ok(ListUploadRangesResponse {
        upload_id,
        checkpoint_sequence: page.checkpoint_sequence,
        ranges,
        next_page_url,
    })
}

fn domain_volume(value: &str) -> Result<VolumeId, NativeUploadError> {
    VolumeId::from_bytes(parse_uuid(value).map_err(|_| NativeUploadError::InvalidInput)?)
        .map_err(|_| NativeUploadError::InvalidInput)
}

fn domain_upload(value: &str) -> Result<UploadId, NativeUploadError> {
    UploadId::from_bytes(parse_uuid(value).map_err(|_| NativeUploadError::InvalidInput)?)
        .map_err(|_| NativeUploadError::InvalidInput)
}

fn domain_operation(value: &ApiOperationId) -> Result<OperationId, NativeUploadError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| NativeUploadError::InvalidInput)?,
    )
    .map_err(|_| NativeUploadError::InvalidInput)
}

fn domain_path(value: &str) -> Result<NamespacePath, NativeUploadError> {
    NamespacePath::from_components(value.split('/'), NamespaceLimits::PORTABLE)
        .map_err(|_| NativeUploadError::InvalidInput)
}

fn domain_disposition(
    value: &meshspan_api_contract::UploadDisposition,
) -> Result<UploadDisposition, NativeUploadError> {
    Ok(match value {
        meshspan_api_contract::UploadDisposition::CreateNew => UploadDisposition::CreateNew,
        meshspan_api_contract::UploadDisposition::ReplaceCurrent => {
            UploadDisposition::ReplaceCurrent
        }
        meshspan_api_contract::UploadDisposition::ReplaceIfVersion { version_id } => {
            UploadDisposition::ReplaceIfVersion(
                meshspan_domain::FileVersionId::from_bytes(
                    parse_uuid(version_id.as_str()).map_err(|_| NativeUploadError::InvalidInput)?,
                )
                .map_err(|_| NativeUploadError::InvalidInput)?,
            )
        }
    })
}

fn api_path(value: &NamespacePath) -> Result<ApiNamespacePath, NativeUploadError> {
    ApiNamespacePath::from_decoded(
        value
            .components()
            .iter()
            .map(meshspan_filesystem::NamespaceComponent::display)
            .collect::<Vec<_>>()
            .join("/"),
    )
    .ok_or(NativeUploadError::Failed)
}

fn api_upload(value: UploadId) -> Result<ApiUploadId, NativeUploadError> {
    ApiUploadId::from_uuid_bytes(value.as_bytes()).ok_or(NativeUploadError::Failed)
}

fn derived_identifier<T>(
    operation_id: OperationId,
    purpose: &[u8],
    constructor: impl FnOnce([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, NativeUploadError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.daemon.native-upload-identity.v1\0");
    digest.update(operation_id.as_bytes());
    digest.update((purpose.len() as u64).to_be_bytes());
    digest.update(purpose);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    constructor(meshspan_domain::uuid_v8(bytes)).map_err(|_| NativeUploadError::Failed)
}

trait TransposeOption<T> {
    fn transpose_option(self) -> Result<Option<T>, NativeUploadError>;
}

impl<T> TransposeOption<T> for Option<Option<T>> {
    fn transpose_option(self) -> Result<Option<T>, NativeUploadError> {
        match self {
            None => Ok(None),
            Some(Some(value)) => Ok(Some(value)),
            Some(None) => Err(NativeUploadError::Failed),
        }
    }
}
