// SPDX-License-Identifier: GPL-2.0-only

//! Native namespace-mutation composition over the common authorised filesystem.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    CreateDirectoryRequest, CreateDirectoryResponse, DeleteObjectRequest, DeleteObjectResponse,
    DeleteObjectScope, DirectoryEntryKind as ApiDirectoryEntryKind,
    NamespaceCommitId as ApiNamespaceCommitId, ObjectId as ApiObjectId,
    ObjectRevisionId as ApiObjectRevisionId, OperationId as ApiOperationId, RenameObjectRequest,
    RenameObjectResponse, VolumeId as ApiVolumeId,
};
use meshspan_domain::{OperationId, UnixMicros, VolumeId};
use meshspan_filesystem::{
    AdapterCreateDirectoryRequest, AdapterRenameRequest, AdapterUnlinkRequest, DirectoryEntryKind,
    FilesystemAccessContext, FilesystemFileAdapter, NamespaceLimits, NamespacePath,
};

use super::{NativeNamespaceMutationController, NativeNamespaceMutationError};
use crate::create_mesh_setup::{format_uuid, parse_uuid};
use crate::{
    FileApiAuthenticationError, FileApiFailure, NativeFileApiAuthenticator,
    NativeFileRequestProtection,
};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Complete native namespace-mutation application service over replaceable boundaries.
pub struct NativeNamespaceMutationService<A, F, M> {
    authenticator: A,
    filesystem: F,
    classify_error: M,
}

impl<A, F, M> NativeNamespaceMutationService<A, F, M> {
    /// Composes authentication, the common filesystem and closed error classification.
    #[must_use]
    pub const fn new(authenticator: A, filesystem: F, classify_error: M) -> Self {
        Self {
            authenticator,
            filesystem,
            classify_error,
        }
    }
}

impl<A, F, M, E> NativeNamespaceMutationController for NativeNamespaceMutationService<A, F, M>
where
    A: NativeFileApiAuthenticator,
    F: FilesystemFileAdapter<Error = E> + Send + 'static,
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

    fn create_directory(
        &mut self,
        context: FilesystemAccessContext,
        volume_id: &str,
        request: CreateDirectoryRequest,
    ) -> Result<CreateDirectoryResponse, NativeNamespaceMutationError> {
        let volume_id = domain_volume(volume_id)?;
        let path = domain_path(request.path.as_str())?;
        let receipt = self
            .filesystem
            .create_directory(
                context,
                &AdapterCreateDirectoryRequest {
                    operation_id: domain_operation(&request.operation_id)?,
                    volume_id,
                    path,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        require_safe_sequence(receipt.head_sequence)?;
        Ok(CreateDirectoryResponse {
            operation_id: api_operation(receipt.operation_id)?,
            volume_id: api_volume(volume_id)?,
            path: request.path,
            object_id: ApiObjectId::from_uuid_bytes(receipt.directory_object_id.as_bytes())
                .ok_or(NativeNamespaceMutationError::Failed)?,
            object_revision_id: ApiObjectRevisionId::from_uuid_bytes(
                receipt.directory_object_revision_id.as_bytes(),
            )
            .ok_or(NativeNamespaceMutationError::Failed)?,
            namespace_commit_id: ApiNamespaceCommitId::from_uuid_bytes(
                receipt.namespace_commit_id.as_bytes(),
            )
            .ok_or(NativeNamespaceMutationError::Failed)?,
            head_sequence: receipt.head_sequence,
        })
    }

    fn rename_object(
        &mut self,
        context: FilesystemAccessContext,
        volume_id: &str,
        request: RenameObjectRequest,
    ) -> Result<RenameObjectResponse, NativeNamespaceMutationError> {
        let volume_id = domain_volume(volume_id)?;
        let receipt = self
            .filesystem
            .rename(
                context,
                &AdapterRenameRequest {
                    operation_id: domain_operation(&request.operation_id)?,
                    volume_id,
                    source: domain_path(request.source_path.as_str())?,
                    target: domain_path(request.target_path.as_str())?,
                    requesting_handle_id: None,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        require_safe_sequence(receipt.head_sequence)?;
        Ok(RenameObjectResponse {
            operation_id: api_operation(receipt.operation_id)?,
            volume_id: api_volume(volume_id)?,
            source_path: request.source_path,
            target_path: request.target_path,
            object_id: ApiObjectId::from_uuid_bytes(receipt.object_id.as_bytes())
                .ok_or(NativeNamespaceMutationError::Failed)?,
            object_revision_id: ApiObjectRevisionId::from_uuid_bytes(
                receipt.object_revision_id.as_bytes(),
            )
            .ok_or(NativeNamespaceMutationError::Failed)?,
            namespace_commit_id: ApiNamespaceCommitId::from_uuid_bytes(
                receipt.namespace_commit_id.as_bytes(),
            )
            .ok_or(NativeNamespaceMutationError::Failed)?,
            head_sequence: receipt.head_sequence,
        })
    }

    fn delete_object(
        &mut self,
        context: FilesystemAccessContext,
        volume_id: &str,
        request: DeleteObjectRequest,
    ) -> Result<DeleteObjectResponse, NativeNamespaceMutationError> {
        let volume_id = domain_volume(volume_id)?;
        let receipt = self
            .filesystem
            .unlink(
                context,
                &AdapterUnlinkRequest {
                    operation_id: domain_operation(&request.operation_id)?,
                    volume_id,
                    path: domain_path(request.path.as_str())?,
                    requesting_handle_id: None,
                    observed_at: context.now,
                },
            )
            .map_err(|error| self.map_error(&error))?;
        require_safe_sequence(receipt.head_sequence)?;
        Ok(DeleteObjectResponse {
            operation_id: api_operation(receipt.operation_id)?,
            volume_id: api_volume(volume_id)?,
            path: request.path,
            object_id: ApiObjectId::from_uuid_bytes(receipt.object_id.as_bytes())
                .ok_or(NativeNamespaceMutationError::Failed)?,
            object_revision_id: ApiObjectRevisionId::from_uuid_bytes(
                receipt.object_revision_id.as_bytes(),
            )
            .ok_or(NativeNamespaceMutationError::Failed)?,
            object_kind: match receipt.object_kind {
                DirectoryEntryKind::Directory => ApiDirectoryEntryKind::Directory,
                DirectoryEntryKind::File => ApiDirectoryEntryKind::File,
            },
            namespace_commit_id: ApiNamespaceCommitId::from_uuid_bytes(
                receipt.namespace_commit_id.as_bytes(),
            )
            .ok_or(NativeNamespaceMutationError::Failed)?,
            head_sequence: receipt.head_sequence,
            scope: DeleteObjectScope::BranchDeleted,
        })
    }
}

impl<A, F, M> NativeNamespaceMutationService<A, F, M> {
    fn map_error<E>(&self, error: &E) -> NativeNamespaceMutationError
    where
        M: Fn(&E) -> FileApiFailure,
    {
        match (self.classify_error)(error) {
            FileApiFailure::InvalidInput => NativeNamespaceMutationError::InvalidInput,
            FileApiFailure::NotFound => NativeNamespaceMutationError::NotFound,
            FileApiFailure::AccessDenied => NativeNamespaceMutationError::AccessDenied,
            FileApiFailure::StaleCursor => NativeNamespaceMutationError::StateConflict,
            FileApiFailure::Conflict => NativeNamespaceMutationError::OperationConflict,
            FileApiFailure::Unavailable => NativeNamespaceMutationError::Unavailable,
            FileApiFailure::Failed => NativeNamespaceMutationError::Failed,
        }
    }
}

fn domain_volume(value: &str) -> Result<VolumeId, NativeNamespaceMutationError> {
    VolumeId::from_bytes(parse_uuid(value).map_err(|_| NativeNamespaceMutationError::InvalidInput)?)
        .map_err(|_| NativeNamespaceMutationError::InvalidInput)
}

fn domain_operation(value: &ApiOperationId) -> Result<OperationId, NativeNamespaceMutationError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| NativeNamespaceMutationError::InvalidInput)?,
    )
    .map_err(|_| NativeNamespaceMutationError::InvalidInput)
}

fn domain_path(value: &str) -> Result<NamespacePath, NativeNamespaceMutationError> {
    NamespacePath::from_components(value.split('/'), NamespaceLimits::PORTABLE)
        .map_err(|_| NativeNamespaceMutationError::InvalidInput)
}

fn api_operation(value: OperationId) -> Result<ApiOperationId, NativeNamespaceMutationError> {
    ApiOperationId::parse(&format_uuid(value.as_bytes()))
        .ok_or(NativeNamespaceMutationError::Failed)
}

fn api_volume(value: VolumeId) -> Result<ApiVolumeId, NativeNamespaceMutationError> {
    ApiVolumeId::from_uuid_bytes(value.as_bytes()).ok_or(NativeNamespaceMutationError::Failed)
}

const fn require_safe_sequence(value: u64) -> Result<(), NativeNamespaceMutationError> {
    if value == 0 || value > MAX_SAFE_INTEGER {
        Err(NativeNamespaceMutationError::Failed)
    } else {
        Ok(())
    }
}
