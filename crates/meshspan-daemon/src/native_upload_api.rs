// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated resumable uploads in `MeshSpan`'s specialised native HTTPS API.

mod codec;
mod http;

use axum::http::HeaderMap;
use meshspan_api_contract::{
    AbortUploadRequest, AbortUploadResponse, BeginUploadRequest, BeginUploadResponse,
    CommitUploadRequest, CommitUploadResponse, ListUploadRangesResponse, OperationId,
    UploadStatusResponse, WriteUploadRangeResponse,
};
use meshspan_contracts::BoundedBytes;
use meshspan_domain::UnixMicros;
use meshspan_filesystem::FilesystemAccessContext;
use thiserror::Error;

use crate::{FileApiAuthenticationError, NativeFileRequestProtection};

pub use http::{NativeUploadApiError, native_upload_api_router};

/// Exact decoded continuation for an immutable upload range traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadRangeCursor {
    /// Checkpoint selected by the first page.
    pub checkpoint_sequence: u64,
    /// Exclusive start of the last returned merged range.
    pub after_start: u64,
}

/// One bounded range page request after strict query decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadRangePageRequest {
    /// Optional pinned continuation.
    pub cursor: Option<UploadRangeCursor>,
    /// Positive requested result bound.
    pub limit: u16,
}

/// One hostile raw range reduced to bounded verified HTTP fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadRangeWriteRequest {
    /// Client-generated idempotency identity.
    pub operation_id: OperationId,
    /// Exact current upload fence.
    pub stage_fence: u64,
    /// First replaced logical byte.
    pub offset: u64,
    /// Caller-declared digest, verified again by durable storage.
    pub content_blake3: [u8; 32],
    /// Non-empty raw payload beneath the public operation limit.
    pub bytes: BoundedBytes,
}

/// Synchronous authenticated upload operations executed on Tokio's blocking pool.
pub trait NativeUploadController: Send + 'static {
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

    /// Starts or exactly resumes one private upload.
    ///
    /// # Errors
    ///
    /// Returns a closed public category without exposing authority details.
    fn begin_upload(
        &mut self,
        context: FilesystemAccessContext,
        volume_id: &str,
        request: BeginUploadRequest,
    ) -> Result<BeginUploadResponse, NativeUploadError>;

    /// Returns current durable upload state.
    ///
    /// # Errors
    ///
    /// Returns a closed public category without exposing authority details.
    fn get_upload(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: &str,
    ) -> Result<UploadStatusResponse, NativeUploadError>;

    /// Returns one bounded checkpoint-pinned page of exact coverage.
    ///
    /// # Errors
    ///
    /// Returns a closed public category without exposing authority details.
    fn list_upload_ranges(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: &str,
        request: UploadRangePageRequest,
    ) -> Result<ListUploadRangesResponse, NativeUploadError>;

    /// Durably records one independently idempotent raw range.
    ///
    /// # Errors
    ///
    /// Returns a closed public category without exposing authority details.
    fn write_upload_range(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: &str,
        request: UploadRangeWriteRequest,
    ) -> Result<WriteUploadRangeResponse, NativeUploadError>;

    /// Explicitly publishes one exact complete checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a closed public category without exposing authority details.
    fn commit_upload(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: &str,
        request: CommitUploadRequest,
    ) -> Result<CommitUploadResponse, NativeUploadError>;

    /// Permanently abandons one unpublished upload.
    ///
    /// # Errors
    ///
    /// Returns a closed public category without exposing authority details.
    fn abort_upload(
        &mut self,
        context: FilesystemAccessContext,
        upload_id: &str,
        request: AbortUploadRequest,
    ) -> Result<AbortUploadResponse, NativeUploadError>;
}

/// Stable non-secret upload failure categories exposed by HTTP.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NativeUploadError {
    /// Path, identity, bound, cursor or relationship is invalid.
    #[error("native upload input is invalid")]
    InvalidInput,
    /// Current authority intentionally denied the target.
    #[error("native upload access was denied")]
    AccessDenied,
    /// Upload, volume or destination target does not exist.
    #[error("native upload target was not found")]
    NotFound,
    /// Idempotency identity belongs to different canonical input.
    #[error("native upload operation conflicts with existing input")]
    OperationConflict,
    /// Fence, checkpoint, cursor or namespace precondition is stale.
    #[error("native upload state is stale")]
    StateConflict,
    /// Selected non-sparse checkpoint has uninitialised bytes.
    #[error("native upload checkpoint is incomplete")]
    Incomplete,
    /// Current authority, storage or metadata is temporarily unavailable.
    #[error("native upload service is unavailable")]
    Unavailable,
    /// Persisted evidence or an internal invariant failed closed.
    #[error("native upload service failed closed")]
    Failed,
}
