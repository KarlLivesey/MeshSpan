// SPDX-License-Identifier: GPL-2.0-only

//! Authentication, handle lifecycle and verified content-read composition.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    MAX_FILE_READ_BYTES, ReadFileQuery, VolumeId as ApiVolumeId, validate_read_file_query,
};
use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    DurationMicros, FileVersionId, HandleId, OperationId, RandomSource, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    AdapterCloseFileRequest, AdapterOpenFileRequest, AdapterReadFileRequest, CloseHandleOutcome,
    FilesystemAccessContext, FilesystemFileAdapter, FilesystemHandleCloseReceipt,
    FilesystemHandleReadReceipt, HandleAccess, HandleShare, NamespaceLimits, NamespacePath,
    OpenHandleReceipt,
};
use thiserror::Error;

use crate::create_mesh_setup::parse_uuid;
use crate::{
    FileApiAuthenticationError, FileApiFailure, NativeFileApiAuthenticator,
    NativeFileRequestProtection,
};

const READ_LEASE_MICROS: u64 = 30 * 1_000_000;

/// Narrow lifecycle used by one native read without exposing adapter internals to HTTP.
pub trait FileRangeReader: Send + 'static {
    /// Connector-specific closed error.
    type Error;

    /// Opens one read-only logical handle.
    ///
    /// # Errors
    ///
    /// Returns the connector's typed authority, sharing or durability failure.
    fn open_file(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterOpenFileRequest,
    ) -> Result<OpenHandleReceipt, Self::Error>;

    /// Reads one bounded range through the opened handle.
    ///
    /// # Errors
    ///
    /// Returns the connector's typed authority, content or integrity failure.
    fn read_range(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterReadFileRequest,
    ) -> Result<FilesystemHandleReadReceipt, Self::Error>;

    /// Releases the exact handle fence, including after a failed read.
    ///
    /// # Errors
    ///
    /// Returns the connector's typed fence or durability failure.
    fn close_file(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterCloseFileRequest,
    ) -> Result<FilesystemHandleCloseReceipt, Self::Error>;
}

impl<T> FileRangeReader for T
where
    T: FilesystemFileAdapter + Send + 'static,
{
    type Error = T::Error;

    fn open_file(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterOpenFileRequest,
    ) -> Result<OpenHandleReceipt, Self::Error> {
        self.open_existing_file(context, request)
    }

    fn read_range(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterReadFileRequest,
    ) -> Result<FilesystemHandleReadReceipt, Self::Error> {
        self.read_file(context, request)
    }

    fn close_file(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterCloseFileRequest,
    ) -> Result<FilesystemHandleCloseReceipt, Self::Error> {
        FilesystemFileAdapter::close_file(self, context, request)
    }
}

/// Verified bytes and immutable identity returned to the HTTP boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileReadResult {
    /// First logical byte represented by `bytes`.
    pub offset: u64,
    /// Exact immutable version pinned by the temporary handle.
    pub file_version_id: FileVersionId,
    /// Verified bounded plaintext bytes.
    pub bytes: BoundedBytes,
}

/// Native file-read composition over replaceable auth, filesystem and entropy boundaries.
pub struct FileReadService<A, F, M, R> {
    authenticator: A,
    filesystem: F,
    classify_error: M,
    random: R,
}

impl<A, F, M, R> FileReadService<A, F, M, R> {
    /// Composes one native bounded-file reader.
    #[must_use]
    pub const fn new(authenticator: A, filesystem: F, classify_error: M, random: R) -> Self {
        Self {
            authenticator,
            filesystem,
            classify_error,
            random,
        }
    }
}

/// Synchronous file-content operation executed on a blocking worker.
pub trait FileReadController: Send + 'static {
    /// Authenticates and returns one bounded verified file range.
    ///
    /// # Errors
    ///
    /// Returns one non-secret public failure category.
    fn read_file(
        &mut self,
        headers: &HeaderMap,
        volume_id: &str,
        query: ReadFileQuery,
        now: UnixMicros,
    ) -> Result<FileReadResult, FileReadError>;
}

impl<A, F, M, R> FileReadController for FileReadService<A, F, M, R>
where
    A: NativeFileApiAuthenticator,
    F: FileRangeReader,
    M: Fn(&F::Error) -> FileApiFailure + Send + 'static,
    R: RandomSource + Send + 'static,
{
    fn read_file(
        &mut self,
        headers: &HeaderMap,
        volume_id: &str,
        query: ReadFileQuery,
        now: UnixMicros,
    ) -> Result<FileReadResult, FileReadError> {
        validate_read_file_query(&query).map_err(|_| FileReadError::InvalidInput)?;
        let context = self.authenticator.authenticate_file_request(
            headers,
            NativeFileRequestProtection::Read,
            now,
        )?;
        let target = read_target(volume_id, &query)?;
        let identities = FileReadIdentities::allocate(&mut self.random)?;
        let deadline = now
            .checked_add(DurationMicros::new(READ_LEASE_MICROS))
            .ok_or(FileReadError::Unavailable)?;
        let desired_access =
            HandleAccess::new(true, false, false).map_err(|_| FileReadError::Failed)?;
        let open = self
            .filesystem
            .open_file(
                context,
                &AdapterOpenFileRequest {
                    operation_id: identities.open_operation,
                    handle_id: identities.handle,
                    volume_id: target.volume_id,
                    path: target.path,
                    desired_access,
                    share_access: HandleShare::new(true, true, true),
                    delete_on_close: false,
                    maximum_stage_bytes: None,
                    lease_expires_at: deadline,
                    observed_at: now,
                },
            )
            .map_err(|error| map_failure((self.classify_error)(&error)))?;
        validate_open(open, identities)?;
        let read = self.filesystem.read_range(
            context,
            AdapterReadFileRequest {
                operation_id: identities.read_operation,
                handle_id: identities.handle,
                handle_fence: open.handle_fence,
                offset: target.offset,
                length: u64::from(target.length),
                content_deadline: deadline,
                observed_at: now,
            },
        );
        let close = self.filesystem.close_file(
            context,
            AdapterCloseFileRequest {
                operation_id: identities.close_operation,
                delete_operation_id: identities.delete_operation,
                handle_id: identities.handle,
                handle_fence: open.handle_fence,
                flush: None,
                observed_at: now,
            },
        );
        let read = read.map_err(|error| map_failure((self.classify_error)(&error)))?;
        let close = close.map_err(|error| map_failure((self.classify_error)(&error)))?;
        validate_result(open, &read, &close, identities, target.length)?;
        Ok(FileReadResult {
            offset: target.offset,
            file_version_id: read.opened_version_id,
            bytes: read.bytes,
        })
    }
}

struct FileReadTarget {
    volume_id: VolumeId,
    path: NamespacePath,
    offset: u64,
    length: u32,
}

fn read_target(volume_id: &str, query: &ReadFileQuery) -> Result<FileReadTarget, FileReadError> {
    let api_volume = ApiVolumeId::parse(volume_id).ok_or(FileReadError::InvalidInput)?;
    let volume_id = VolumeId::from_bytes(
        parse_uuid(api_volume.as_str()).map_err(|_| FileReadError::InvalidInput)?,
    )
    .map_err(|_| FileReadError::InvalidInput)?;
    let path =
        NamespacePath::from_components(query.path.as_str().split('/'), NamespaceLimits::PORTABLE)
            .map_err(|_| FileReadError::InvalidInput)?;
    Ok(FileReadTarget {
        volume_id,
        path,
        offset: query.offset.unwrap_or(0),
        length: query.length.unwrap_or(MAX_FILE_READ_BYTES),
    })
}

#[derive(Clone, Copy)]
struct FileReadIdentities {
    open_operation: OperationId,
    read_operation: OperationId,
    close_operation: OperationId,
    delete_operation: OperationId,
    handle: HandleId,
}

impl FileReadIdentities {
    fn allocate(random: &mut impl RandomSource) -> Result<Self, FileReadError> {
        let mut bytes = [[0_u8; 16]; 5];
        for value in &mut bytes {
            random
                .fill_bytes(value)
                .map_err(|_| FileReadError::Unavailable)?;
            if *value == [0; 16] {
                return Err(FileReadError::Unavailable);
            }
            value[6] = (value[6] & 0x0f) | 0x40;
            value[8] = (value[8] & 0x3f) | 0x80;
        }
        Ok(Self {
            open_operation: OperationId::from_bytes(bytes[0])
                .map_err(|_| FileReadError::Unavailable)?,
            read_operation: OperationId::from_bytes(bytes[1])
                .map_err(|_| FileReadError::Unavailable)?,
            close_operation: OperationId::from_bytes(bytes[2])
                .map_err(|_| FileReadError::Unavailable)?,
            delete_operation: OperationId::from_bytes(bytes[3])
                .map_err(|_| FileReadError::Unavailable)?,
            handle: HandleId::from_bytes(bytes[4]).map_err(|_| FileReadError::Unavailable)?,
        })
    }
}

fn validate_open(
    open: OpenHandleReceipt,
    identities: FileReadIdentities,
) -> Result<(), FileReadError> {
    if open.operation_id != identities.open_operation
        || open.handle_id != identities.handle
        || open.handle_fence == 0
        || open.truncate_on_first_write
    {
        return Err(FileReadError::Failed);
    }
    Ok(())
}

fn validate_result(
    open: OpenHandleReceipt,
    read: &FilesystemHandleReadReceipt,
    close: &FilesystemHandleCloseReceipt,
    identities: FileReadIdentities,
    requested_length: u32,
) -> Result<(), FileReadError> {
    if read.opened_version_id != open.opened_version_id
        || read.checkpoint_sequence != 0
        || read.bytes.len() > requested_length as usize
        || close.flush.is_some()
        || close.close.operation_id != identities.close_operation
        || close.close.handle_id != identities.handle
        || close.close.handle_fence != open.handle_fence
        || close.close.outcome != CloseHandleOutcome::Closed
    {
        return Err(FileReadError::Failed);
    }
    Ok(())
}

fn map_failure(value: FileApiFailure) -> FileReadError {
    match value {
        FileApiFailure::InvalidInput | FileApiFailure::StaleCursor => FileReadError::InvalidInput,
        FileApiFailure::NotFound => FileReadError::NotFound,
        FileApiFailure::AccessDenied => FileReadError::AccessDenied,
        FileApiFailure::Conflict => FileReadError::Conflict,
        FileApiFailure::Unavailable => FileReadError::Unavailable,
        FileApiFailure::Failed => FileReadError::Failed,
    }
}

/// Closed native file-content application failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FileReadError {
    /// Authentication failed without disclosing credential details.
    #[error("native file read authentication failed")]
    Authentication(#[from] FileApiAuthenticationError),
    /// Public path, range or volume identity is invalid.
    #[error("native file read input is invalid")]
    InvalidInput,
    /// Current authority denied this logical target.
    #[error("native file read access was denied")]
    AccessDenied,
    /// Current volume or regular file was not found.
    #[error("native file read target was not found")]
    NotFound,
    /// A live handle's share contract rejected this read.
    #[error("native file read conflicts with a live handle")]
    Conflict,
    /// Required committed authority, entropy or content is temporarily unavailable.
    #[error("native file read authority is unavailable")]
    Unavailable,
    /// Persisted evidence, conversion or an invariant failed closed.
    #[error("native file read failed closed")]
    Failed,
}
