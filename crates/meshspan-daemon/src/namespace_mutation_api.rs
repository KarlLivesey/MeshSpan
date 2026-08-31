// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated logical namespace mutations in the specialised native API.

mod http;
mod service;

use axum::http::HeaderMap;
use meshspan_api_contract::{
    CreateDirectoryRequest, CreateDirectoryResponse, DeleteObjectRequest, DeleteObjectResponse,
    RenameObjectRequest, RenameObjectResponse,
};
use meshspan_domain::UnixMicros;
use meshspan_filesystem::FilesystemAccessContext;
use thiserror::Error;

use crate::{FileApiAuthenticationError, NativeFileRequestProtection};

pub use http::{NativeNamespaceMutationApiError, native_namespace_mutation_api_router};
pub use service::NativeNamespaceMutationService;

/// Synchronous authenticated namespace mutations executed on Tokio's blocking pool.
pub trait NativeNamespaceMutationController: Send + 'static {
    /// Authenticates before any request body is consumed.
    ///
    /// # Errors
    ///
    /// Rejects malformed, revoked, expired or unavailable current authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError>;

    /// Atomically creates one empty logical directory.
    ///
    /// # Errors
    ///
    /// Returns a closed public category without exposing authority details.
    fn create_directory(
        &mut self,
        context: FilesystemAccessContext,
        volume_id: &str,
        request: CreateDirectoryRequest,
    ) -> Result<CreateDirectoryResponse, NativeNamespaceMutationError>;

    /// Atomically renames or moves one logical object within its volume.
    ///
    /// # Errors
    ///
    /// Returns a closed public category without exposing authority details.
    fn rename_object(
        &mut self,
        context: FilesystemAccessContext,
        volume_id: &str,
        request: RenameObjectRequest,
    ) -> Result<RenameObjectResponse, NativeNamespaceMutationError>;

    /// Atomically removes one file or empty directory from the logical namespace.
    ///
    /// # Errors
    ///
    /// Returns a closed public category without exposing authority details.
    fn delete_object(
        &mut self,
        context: FilesystemAccessContext,
        volume_id: &str,
        request: DeleteObjectRequest,
    ) -> Result<DeleteObjectResponse, NativeNamespaceMutationError>;
}

/// Stable non-secret namespace-mutation failure categories exposed by HTTP.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NativeNamespaceMutationError {
    /// Path, identity, bound or relationship is invalid.
    #[error("native namespace mutation input is invalid")]
    InvalidInput,
    /// The selected logical object or parent does not exist.
    #[error("native namespace mutation target was not found")]
    NotFound,
    /// Current authority intentionally denied the target.
    #[error("native namespace mutation access was denied")]
    AccessDenied,
    /// The operation identity was reused with different canonical input.
    #[error("native namespace mutation operation conflicts with existing input")]
    OperationConflict,
    /// Namespace, sharing or target state is no longer current.
    #[error("native namespace mutation conflicts with current state")]
    StateConflict,
    /// Required committed authority or metadata is temporarily unavailable.
    #[error("native namespace mutation authority is unavailable")]
    Unavailable,
    /// Internal integrity or persistence failed closed.
    #[error("native namespace mutation failed closed")]
    Failed,
}
