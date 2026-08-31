// SPDX-License-Identifier: GPL-2.0-only

//! Authentication, authority and filesystem composition for object metadata.

use axum::http::HeaderMap;
use meshspan_api_contract::{GetObjectQuery, GetObjectResponse, VolumeId as ApiVolumeId};
use meshspan_domain::{UnixMicros, VolumeId};
use meshspan_filesystem::{
    AdapterStatRequest, FilesystemAccessContext, FilesystemFileAdapter, NamespaceLimits,
    NamespaceObjectStat, NamespacePath,
};
use thiserror::Error;

use super::codec::response;
use crate::create_mesh_setup::parse_uuid;
use crate::{FileApiAuthenticationError, FileApiAuthenticator, FileApiFailure};

/// Narrow connector-neutral stat capability used by the HTTP boundary.
pub trait ObjectStatReader: Send + 'static {
    /// Adapter-specific closed failure.
    type Error;

    /// Returns authorised immutable metadata for one path.
    ///
    /// # Errors
    ///
    /// Returns the adapter's typed authority, query or integrity failure.
    fn stat_object(
        &self,
        context: FilesystemAccessContext,
        request: &AdapterStatRequest,
    ) -> Result<NamespaceObjectStat, Self::Error>;
}

impl<T> ObjectStatReader for T
where
    T: FilesystemFileAdapter + Send + 'static,
{
    type Error = T::Error;

    fn stat_object(
        &self,
        context: FilesystemAccessContext,
        request: &AdapterStatRequest,
    ) -> Result<NamespaceObjectStat, Self::Error> {
        self.stat(context, request)
    }
}

/// Native object-metadata composition over replaceable authentication and filesystem adapters.
pub struct ObjectStatService<A, F, M> {
    authenticator: A,
    filesystem: F,
    classify_error: M,
}

impl<A, F, M> ObjectStatService<A, F, M> {
    /// Composes one native object-metadata service.
    #[must_use]
    pub const fn new(authenticator: A, filesystem: F, classify_error: M) -> Self {
        Self {
            authenticator,
            filesystem,
            classify_error,
        }
    }
}

/// Synchronous object-metadata operation executed on a blocking worker.
pub trait ObjectStatController: Send + 'static {
    /// Authenticates, authorises and returns one immutable object description.
    ///
    /// # Errors
    ///
    /// Returns one non-secret public failure category.
    fn get_object(
        &mut self,
        headers: &HeaderMap,
        volume_id: &str,
        query: GetObjectQuery,
        now: UnixMicros,
    ) -> Result<GetObjectResponse, ObjectStatError>;
}

impl<A, F, M> ObjectStatController for ObjectStatService<A, F, M>
where
    A: FileApiAuthenticator,
    F: ObjectStatReader,
    M: Fn(&F::Error) -> FileApiFailure + Send + 'static,
{
    fn get_object(
        &mut self,
        headers: &HeaderMap,
        volume_id: &str,
        query: GetObjectQuery,
        now: UnixMicros,
    ) -> Result<GetObjectResponse, ObjectStatError> {
        meshspan_api_contract::validate_get_object_query(&query)
            .map_err(|_| ObjectStatError::InvalidInput)?;
        let context = self.authenticator.authenticate_file_read(headers, now)?;
        let api_volume = ApiVolumeId::parse(volume_id).ok_or(ObjectStatError::InvalidInput)?;
        let volume = VolumeId::from_bytes(
            parse_uuid(api_volume.as_str()).map_err(|_| ObjectStatError::InvalidInput)?,
        )
        .map_err(|_| ObjectStatError::InvalidInput)?;
        let path = NamespacePath::from_components(
            query.path.as_str().split('/'),
            NamespaceLimits::PORTABLE,
        )
        .map_err(|_| ObjectStatError::InvalidInput)?;
        let stat = self
            .filesystem
            .stat_object(
                context,
                &AdapterStatRequest {
                    volume_id: volume,
                    path,
                    observed_at: now,
                },
            )
            .map_err(|error| map_filesystem_failure((self.classify_error)(&error)))?;
        response(api_volume, query, &stat)
    }
}

fn map_filesystem_failure(value: FileApiFailure) -> ObjectStatError {
    match value {
        FileApiFailure::InvalidInput | FileApiFailure::StaleCursor => ObjectStatError::InvalidInput,
        FileApiFailure::NotFound => ObjectStatError::NotFound,
        FileApiFailure::AccessDenied => ObjectStatError::AccessDenied,
        FileApiFailure::Unavailable => ObjectStatError::Unavailable,
        FileApiFailure::Failed => ObjectStatError::Failed,
    }
}

/// Closed object-metadata application failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ObjectStatError {
    /// Authentication failed without credential details.
    #[error("native object metadata authentication failed")]
    Authentication(#[from] FileApiAuthenticationError),
    /// Public path or volume identity is invalid.
    #[error("object metadata input is invalid")]
    InvalidInput,
    /// Current authority denied this logical target.
    #[error("object metadata access was denied")]
    AccessDenied,
    /// Current volume or logical path was not found.
    #[error("object metadata target was not found")]
    NotFound,
    /// Required committed authority is temporarily unavailable.
    #[error("object metadata authority is unavailable")]
    Unavailable,
    /// Stored evidence, conversion or an invariant failed closed.
    #[error("object metadata failed closed")]
    Failed,
}
