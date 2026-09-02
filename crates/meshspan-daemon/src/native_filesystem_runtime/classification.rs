// SPDX-License-Identifier: GPL-2.0-only

//! Stable public failure classification for the production native filesystem.

use meshspan_cluster::MetadataFilesystemAuthorityError;
use meshspan_filesystem::{
    AuthorisedFilesystemError, ContentPublicationError, FilesystemCommitError, HandleError,
};
use meshspan_metadata::RepositoryError;

use super::{NativeFilesystemRuntimeError, ProductionFilesystemError};
use crate::FileApiFailure;

/// Maps detailed internal failures to non-secret public API categories.
pub(crate) fn classify_native_filesystem_error(
    error: &NativeFilesystemRuntimeError,
) -> FileApiFailure {
    match error {
        NativeFilesystemRuntimeError::Unavailable => FileApiFailure::Unavailable,
        NativeFilesystemRuntimeError::Operation(error) => classify_operation_error(error),
    }
}

fn classify_operation_error(error: &ProductionFilesystemError) -> FileApiFailure {
    match error {
        AuthorisedFilesystemError::InvalidInput => FileApiFailure::InvalidInput,
        AuthorisedFilesystemError::TargetUnavailable => FileApiFailure::NotFound,
        AuthorisedFilesystemError::InvalidGrant
        | AuthorisedFilesystemError::HandleIo(_)
        | AuthorisedFilesystemError::Read(_) => FileApiFailure::Failed,
        AuthorisedFilesystemError::Commit(commit) => classify_commit_error(commit),
        AuthorisedFilesystemError::Authority(authority) => match authority {
            MetadataFilesystemAuthorityError::Denied(_) => FileApiFailure::AccessDenied,
            MetadataFilesystemAuthorityError::VolumeUnavailable => FileApiFailure::NotFound,
            MetadataFilesystemAuthorityError::Repository(repository) => {
                classify_repository_error(repository)
            }
        },
        AuthorisedFilesystemError::Handle(handle) => classify_handle_error(handle),
        AuthorisedFilesystemError::Query(query) => match query {
            meshspan_filesystem::NamespaceQueryError::NotFound => FileApiFailure::NotFound,
            meshspan_filesystem::NamespaceQueryError::InvalidInput => FileApiFailure::InvalidInput,
            meshspan_filesystem::NamespaceQueryError::StaleCursor => FileApiFailure::StaleCursor,
            meshspan_filesystem::NamespaceQueryError::Corrupt
            | meshspan_filesystem::NamespaceQueryError::Sqlite(_)
            | meshspan_filesystem::NamespaceQueryError::Directory(_) => FileApiFailure::Failed,
        },
        AuthorisedFilesystemError::Upload(upload) => classify_upload_error(upload),
    }
}

fn classify_commit_error(error: &FilesystemCommitError) -> FileApiFailure {
    match error {
        FilesystemCommitError::Content(
            ContentPublicationError::Unavailable | ContentPublicationError::StrongBarrierPending,
        ) => FileApiFailure::Unavailable,
        FilesystemCommitError::InvalidInput => FileApiFailure::InvalidInput,
        FilesystemCommitError::Content(ContentPublicationError::Conflict) => {
            FileApiFailure::Conflict
        }
        FilesystemCommitError::Content(ContentPublicationError::StrongBarrierDeadline) => {
            FileApiFailure::StaleCursor
        }
        FilesystemCommitError::Stage(_)
        | FilesystemCommitError::Upload(_)
        | FilesystemCommitError::Content(
            ContentPublicationError::InvalidInput
            | ContentPublicationError::Corrupt
            | ContentPublicationError::Io(_),
        )
        | FilesystemCommitError::Publication(_)
        | FilesystemCommitError::Handle(_) => FileApiFailure::Failed,
    }
}

fn classify_upload_error(error: &meshspan_filesystem::UploadServiceError) -> FileApiFailure {
    match error {
        meshspan_filesystem::UploadServiceError::InvalidInput => FileApiFailure::InvalidInput,
        meshspan_filesystem::UploadServiceError::OperationConflict => FileApiFailure::Conflict,
        meshspan_filesystem::UploadServiceError::StaleAuthority => FileApiFailure::StaleCursor,
        meshspan_filesystem::UploadServiceError::Unavailable => FileApiFailure::Unavailable,
        meshspan_filesystem::UploadServiceError::Incomplete
        | meshspan_filesystem::UploadServiceError::ContentMismatch
        | meshspan_filesystem::UploadServiceError::Corrupt
        | meshspan_filesystem::UploadServiceError::Stage(_) => FileApiFailure::Failed,
    }
}

fn classify_handle_error(error: &HandleError) -> FileApiFailure {
    match error {
        HandleError::InvalidInput => FileApiFailure::InvalidInput,
        HandleError::NotFound => FileApiFailure::NotFound,
        HandleError::OperationConflict => FileApiFailure::Conflict,
        HandleError::AlreadyExists
        | HandleError::CreationRequired
        | HandleError::SharingViolation
        | HandleError::DeletePending
        | HandleError::StaleHandle
        | HandleError::GatewayMismatch
        | HandleError::LockConflict
        | HandleError::FlushInProgress
        | HandleError::DirectoryNotEmpty
        | HandleError::StaleLock => FileApiFailure::StaleCursor,
        HandleError::Corrupt | HandleError::Namespace(_) | HandleError::Sqlite(_) => {
            FileApiFailure::Failed
        }
    }
}

fn classify_repository_error(error: &RepositoryError) -> FileApiFailure {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            FileApiFailure::Unavailable
        }
        _ => FileApiFailure::Failed,
    }
}
