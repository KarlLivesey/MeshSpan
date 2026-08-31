// SPDX-License-Identifier: GPL-2.0-only

//! Connector-neutral authentication, authority and filesystem composition.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    ListDirectoryQuery, ListDirectoryResponse, VolumeId as ApiVolumeId,
    validate_list_directory_query,
};
use meshspan_domain::{AssuranceLevel, AuthenticationService, UnixMicros, VolumeId};
use meshspan_filesystem::{
    AdapterListRequest, FilesystemAccessContext, FilesystemFileAdapter, NamespaceLimits,
    NamespaceListPage, NamespacePath,
};
use thiserror::Error;

use super::codec::{decode_cursor, response};
use crate::create_mesh_setup::parse_uuid;
use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, BrowserSessionAuthority,
    FileApiAuthenticationError,
};

const DEFAULT_PAGE_LIMIT: u16 = 100;

/// Credential proof required by one native file-API operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFileRequestProtection {
    /// Safe metadata or content read.
    Read,
    /// State-changing request; browser sessions also require bound CSRF proof.
    Mutation,
}

/// Authentication evidence accepted by the native specialised file API.
pub trait NativeFileApiAuthenticator: Send + 'static {
    /// Authenticates one request and returns only connector-neutral filesystem evidence.
    ///
    /// # Errors
    ///
    /// Rejects malformed, expired, revoked or unavailable current authority.
    fn authenticate_file_request(
        &self,
        headers: &HeaderMap,
        protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError>;
}

impl<A> NativeFileApiAuthenticator for BrowserSessionAuthenticator<A>
where
    A: BrowserSessionAuthority + Send + 'static,
{
    fn authenticate_file_request(
        &self,
        headers: &HeaderMap,
        protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError> {
        let (capability, evidence) = self
            .authenticate_with_evidence(
                headers,
                match protection {
                    NativeFileRequestProtection::Read => BrowserRequestProtection::Read,
                    NativeFileRequestProtection::Mutation => BrowserRequestProtection::Mutation,
                },
                AssuranceLevel::SingleFactor,
                now,
            )
            .map_err(FileApiAuthenticationError::from)?;
        Ok(FilesystemAccessContext {
            authentication_service: AuthenticationService::Https,
            credential_digest: evidence.token_digest,
            required_assurance: AssuranceLevel::SingleFactor,
            gateway_node_id: capability.gateway_node_id,
            gateway_incarnation: capability.gateway_incarnation,
            now,
        })
    }
}

/// Narrow connector-neutral directory capability used by the HTTP boundary.
pub trait DirectoryLister: Send + 'static {
    /// Adapter-specific closed failure.
    type Error;

    /// Returns one authorised immutable directory page.
    ///
    /// # Errors
    ///
    /// Returns the adapter's typed authority, query or integrity failure.
    fn list_directory(
        &self,
        context: FilesystemAccessContext,
        request: &AdapterListRequest,
    ) -> Result<NamespaceListPage, Self::Error>;
}

impl<T> DirectoryLister for T
where
    T: FilesystemFileAdapter + Send + 'static,
{
    type Error = T::Error;

    fn list_directory(
        &self,
        context: FilesystemAccessContext,
        request: &AdapterListRequest,
    ) -> Result<NamespaceListPage, Self::Error> {
        self.list(context, request)
    }
}

/// Publicly meaningful category selected by the daemon composition for an adapter error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileApiFailure {
    /// Request or continuation is malformed.
    InvalidInput,
    /// Volume or directory does not exist for this caller.
    NotFound,
    /// Current authority intentionally denied access.
    AccessDenied,
    /// Continuation belongs to an obsolete immutable view.
    StaleCursor,
    /// A live connector share or mutation conflicts with this operation.
    Conflict,
    /// Required committed authority is temporarily unavailable.
    Unavailable,
    /// Persisted evidence or an internal invariant failed closed.
    Failed,
}

/// Native file-API composition over replaceable authentication and filesystem adapters.
pub struct DirectoryListingService<A, F, M> {
    authenticator: A,
    filesystem: F,
    classify_error: M,
}

impl<A, F, M> DirectoryListingService<A, F, M> {
    /// Composes one native file-API directory service.
    #[must_use]
    pub const fn new(authenticator: A, filesystem: F, classify_error: M) -> Self {
        Self {
            authenticator,
            filesystem,
            classify_error,
        }
    }
}

/// Synchronous native file-API operation executed on a blocking worker.
pub trait DirectoryListingController: Send + 'static {
    /// Authenticates, authorises and returns one complete immutable directory page.
    ///
    /// # Errors
    ///
    /// Returns one non-secret public failure category.
    fn list_directory(
        &mut self,
        headers: &HeaderMap,
        volume_id: &str,
        query: &ListDirectoryQuery,
        now: UnixMicros,
    ) -> Result<ListDirectoryResponse, DirectoryListingError>;
}

impl<A, F, M> DirectoryListingController for DirectoryListingService<A, F, M>
where
    A: NativeFileApiAuthenticator,
    F: DirectoryLister,
    M: Fn(&F::Error) -> FileApiFailure + Send + 'static,
{
    fn list_directory(
        &mut self,
        headers: &HeaderMap,
        volume_id: &str,
        query: &ListDirectoryQuery,
        now: UnixMicros,
    ) -> Result<ListDirectoryResponse, DirectoryListingError> {
        validate_list_directory_query(query).map_err(|_| DirectoryListingError::InvalidInput)?;
        let context = self.authenticator.authenticate_file_request(
            headers,
            NativeFileRequestProtection::Read,
            now,
        )?;
        let api_volume =
            ApiVolumeId::parse(volume_id).ok_or(DirectoryListingError::InvalidInput)?;
        let volume = VolumeId::from_bytes(
            parse_uuid(api_volume.as_str()).map_err(|_| DirectoryListingError::InvalidInput)?,
        )
        .map_err(|_| DirectoryListingError::InvalidInput)?;
        let path = query
            .path
            .as_ref()
            .map(|path| {
                NamespacePath::from_components(path.as_str().split('/'), NamespaceLimits::PORTABLE)
            })
            .transpose()
            .map_err(|_| DirectoryListingError::InvalidInput)?;
        let cursor = query.cursor.as_ref().map(decode_cursor).transpose()?;
        let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        let page = self
            .filesystem
            .list_directory(
                context,
                &AdapterListRequest {
                    volume_id: volume,
                    directory_path: path,
                    cursor,
                    maximum_results: limit,
                    observed_at: now,
                },
            )
            .map_err(|error| map_filesystem_failure((self.classify_error)(&error)))?;
        response(api_volume, query, limit, page)
    }
}

fn map_filesystem_failure(value: FileApiFailure) -> DirectoryListingError {
    match value {
        FileApiFailure::InvalidInput => DirectoryListingError::InvalidInput,
        FileApiFailure::NotFound => DirectoryListingError::NotFound,
        FileApiFailure::AccessDenied => DirectoryListingError::AccessDenied,
        FileApiFailure::StaleCursor => DirectoryListingError::StaleCursor,
        FileApiFailure::Unavailable => DirectoryListingError::Unavailable,
        FileApiFailure::Conflict | FileApiFailure::Failed => DirectoryListingError::Failed,
    }
}

/// Closed directory-listing application failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DirectoryListingError {
    /// Authentication failed without credential details.
    #[error("native file API authentication failed")]
    Authentication(#[from] FileApiAuthenticationError),
    /// Public path, identifier, cursor or page bound is invalid.
    #[error("directory listing input is invalid")]
    InvalidInput,
    /// Current authority denied this logical target.
    #[error("directory listing access was denied")]
    AccessDenied,
    /// Current volume or directory was not found.
    #[error("directory listing target was not found")]
    NotFound,
    /// Continuation no longer names the current immutable view.
    #[error("directory listing cursor is stale")]
    StaleCursor,
    /// Required authority is temporarily unavailable.
    #[error("directory listing authority is unavailable")]
    Unavailable,
    /// Stored evidence, conversion or an invariant failed closed.
    #[error("directory listing failed closed")]
    Failed,
}
