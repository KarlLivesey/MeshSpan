// SPDX-License-Identifier: GPL-2.0-only

//! Mapping from authenticated SMB file commands to the common logical filesystem boundary.

use std::collections::BTreeMap;

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{DurationMicros, HandleId, LockId, OperationId, UnixMicros, VolumeId};
use meshspan_filesystem::{
    AdapterCloseFileRequest, AdapterCreateFileRequest, AdapterFlushFileRequest, AdapterLockRequest,
    AdapterReadFileRequest, AdapterUnlockRequest, AdapterWriteFileRequest, ByteRange,
    CreateDisposition as FilesystemDisposition, FilesystemAccessContext, FilesystemFileAdapter,
    HandleAccess, HandleShare, NamespaceLimits, NamespacePath, RangeLockKind,
};
use sha2::{Digest, Sha256};

use crate::{
    CloseRequest, CloseResponse, CloseResponseAttributes, CreateAction, CreateDisposition,
    CreateRequest, CreateResponse, CreateResponseValues, CreateTargetKind, FlushRequest, LockKind,
    LockRequest, LockResponse, ReadRequest, ReadResponse, SmbFileId, WriteRequest, WriteResponse,
};

const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// One connected SMB share and its exact logical namespace root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmbTreeBinding {
    session_id: u64,
    tree_id: u32,
    volume_id: VolumeId,
    root_components: Vec<String>,
    namespace_limits: NamespaceLimits,
}

impl SmbTreeBinding {
    /// Validates a session/tree binding before it becomes visible to file commands.
    ///
    /// # Errors
    ///
    /// Rejects reserved SMB identities or an invalid optional folder root.
    pub fn new(
        session_id: u64,
        tree_id: u32,
        volume_id: VolumeId,
        root_components: Vec<String>,
        namespace_limits: NamespaceLimits,
    ) -> Result<Self, SmbFilesystemAdapterError<core::convert::Infallible>> {
        if session_id == 0 || tree_id == 0 {
            return Err(SmbFilesystemAdapterError::InvalidIdentity);
        }
        if !root_components.is_empty() {
            NamespacePath::from_components(
                root_components.iter().map(String::as_str),
                namespace_limits,
            )
            .map_err(|_| SmbFilesystemAdapterError::InvalidPath)?;
        }
        Ok(Self {
            session_id,
            tree_id,
            volume_id,
            root_components,
            namespace_limits,
        })
    }
}

/// Daemon-owned resource and deadline bounds for one SMB adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmbFilesystemLimits {
    maximum_writable_file_bytes: u64,
    handle_lease: DurationMicros,
    content_timeout: DurationMicros,
}

impl SmbFilesystemLimits {
    /// Constructs positive, explicit service bounds.
    ///
    /// # Errors
    ///
    /// Rejects zero-sized files or deadlines.
    pub const fn new(
        maximum_writable_file_bytes: u64,
        handle_lease: DurationMicros,
        content_timeout: DurationMicros,
    ) -> Result<Self, SmbFilesystemAdapterError<core::convert::Infallible>> {
        if maximum_writable_file_bytes == 0 || handle_lease.get() == 0 || content_timeout.get() == 0
        {
            Err(SmbFilesystemAdapterError::InvalidConfiguration)
        } else {
            Ok(Self {
                maximum_writable_file_bytes,
                handle_lease,
                content_timeout,
            })
        }
    }
}

/// Successful SMB create/open response and the assigned connection-visible file identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmbCreateOutcome {
    /// Encoded SMB response before session protection.
    pub response: CreateResponse,
    /// Exact identity required by subsequent commands.
    pub file_id: SmbFileId,
}

/// Connection-local SMB file service over the shared logical filesystem contract.
pub struct SmbFilesystemAdapter<F> {
    filesystem: F,
    tree: SmbTreeBinding,
    limits: SmbFilesystemLimits,
    handles: BTreeMap<SmbFileId, OpenFile>,
    locks: BTreeMap<(SmbFileId, u64, u64), LockId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OpenFile {
    handle_id: HandleId,
    fence: u64,
    checkpoint_sequence: u64,
    logical_length: u64,
    lease_expires_at: UnixMicros,
    dirty: bool,
}

impl<F> SmbFilesystemAdapter<F>
where
    F: FilesystemFileAdapter,
{
    /// Binds one authenticated tree to the connector-neutral filesystem adapter.
    #[must_use]
    pub fn new(filesystem: F, tree: SmbTreeBinding, limits: SmbFilesystemLimits) -> Self {
        Self {
            filesystem,
            tree,
            limits,
            handles: BTreeMap::new(),
            locks: BTreeMap::new(),
        }
    }

    /// Returns the common filesystem adapter for orderly connection shutdown.
    #[must_use]
    pub fn into_inner(self) -> F {
        self.filesystem
    }

    /// Creates or opens one regular file and retains only its fenced logical handle state.
    ///
    /// # Errors
    ///
    /// Rejects mismatched tree identities, directory/root opens, unsafe paths, invalid bounds or
    /// any common authority/filesystem failure.
    pub fn create_file(
        &mut self,
        context: FilesystemAccessContext,
        request: &CreateRequest,
    ) -> Result<SmbCreateOutcome, SmbFilesystemAdapterError<F::Error>> {
        self.validate_header(request.header.session_id, request.header.tree_id)?;
        if request.path_components.is_empty()
            || request.options.target_kind == CreateTargetKind::Directory
        {
            return Err(SmbFilesystemAdapterError::UnsupportedTarget);
        }
        let path = self.path(&request.path_components)?;
        let file_id = derive_file_id(
            request.header.session_id,
            request.header.tree_id,
            request.header.message_id,
        )?;
        if self.handles.contains_key(&file_id) {
            return Err(SmbFilesystemAdapterError::DuplicateFileIdentity);
        }
        let handle_id = HandleId::from_bytes(file_id.identity_bytes())
            .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)?;
        let desired_access = HandleAccess::new(
            request.desired_access.read_data,
            request.desired_access.write_data,
            request.desired_access.delete,
        )
        .map_err(|_| SmbFilesystemAdapterError::InvalidAccess)?;
        let lease_expires_at = deadline(context.now, self.limits.handle_lease)?;
        let content_deadline = deadline(context.now, self.limits.content_timeout)?;
        let operation_id = operation_id(request.header, b"create")?;
        let receipt = self
            .filesystem
            .create_file(
                context,
                &AdapterCreateFileRequest {
                    operation_id,
                    handle_id,
                    volume_id: self.tree.volume_id,
                    path,
                    create_disposition: map_disposition(request.disposition),
                    desired_access,
                    share_access: HandleShare::new(
                        request.share_access.read,
                        request.share_access.write,
                        request.share_access.delete,
                    ),
                    delete_on_close: request.options.delete_on_close,
                    maximum_stage_bytes: request
                        .desired_access
                        .write_data
                        .then_some(self.limits.maximum_writable_file_bytes),
                    lease_expires_at,
                    content_deadline,
                    observed_at: context.now,
                },
            )
            .map_err(SmbFilesystemAdapterError::Filesystem)?;
        let logical_length = if receipt.handle.truncate_on_first_write {
            0
        } else {
            receipt.handle.opened_logical_length
        };
        let action = if receipt.creation.is_some() {
            CreateAction::Created
        } else if receipt.handle.truncate_on_first_write {
            CreateAction::Overwritten
        } else {
            CreateAction::Opened
        };
        let response = CreateResponse::encode(
            request,
            CreateResponseValues {
                action,
                creation_time: unix_micros_to_filetime(context.now)?,
                last_access_time: unix_micros_to_filetime(context.now)?,
                last_write_time: unix_micros_to_filetime(context.now)?,
                change_time: unix_micros_to_filetime(context.now)?,
                allocation_size: logical_length,
                end_of_file: logical_length,
                file_attributes: if request.file_attributes == 0 {
                    FILE_ATTRIBUTE_NORMAL
                } else {
                    request.file_attributes
                },
                file_id,
            },
        )
        .map_err(|_| SmbFilesystemAdapterError::InvalidResponse)?;
        self.handles.insert(
            file_id,
            OpenFile {
                handle_id,
                fence: receipt.handle.handle_fence,
                checkpoint_sequence: 0,
                logical_length,
                lease_expires_at,
                dirty: receipt.handle.truncate_on_first_write,
            },
        );
        Ok(SmbCreateOutcome { response, file_id })
    }

    /// Reads one verified bounded range from an exact live SMB open.
    ///
    /// # Errors
    ///
    /// Rejects mismatched or stale identities, invalid deadlines, common authority/filesystem
    /// failures and responses that cannot be represented by the bounded SMB profile.
    pub fn read_file(
        &mut self,
        context: FilesystemAccessContext,
        request: ReadRequest,
    ) -> Result<ReadResponse, SmbFilesystemAdapterError<F::Error>> {
        self.validate_header(request.header.session_id, request.header.tree_id)?;
        let open = self.open(request.file_id)?;
        let receipt = self
            .filesystem
            .read_file(
                context,
                AdapterReadFileRequest {
                    operation_id: operation_id(request.header, b"read")?,
                    handle_id: open.handle_id,
                    handle_fence: open.fence,
                    offset: request.offset,
                    length: u64::from(request.length),
                    content_deadline: deadline(context.now, self.limits.content_timeout)?,
                    observed_at: context.now,
                },
            )
            .map_err(SmbFilesystemAdapterError::Filesystem)?;
        ReadResponse::encode(request, receipt.bytes.as_slice())
            .map_err(|_| SmbFilesystemAdapterError::InvalidResponse)
    }

    /// Durably stages one complete SMB write and publishes it before success when requested.
    ///
    /// # Errors
    ///
    /// Rejects mismatched or stale identities, excessive ranges, common authority/filesystem
    /// failures and any partial successful write.
    pub fn write_file(
        &mut self,
        context: FilesystemAccessContext,
        request: &WriteRequest,
    ) -> Result<WriteResponse, SmbFilesystemAdapterError<F::Error>> {
        self.validate_header(request.header.session_id, request.header.tree_id)?;
        let open = *self.open(request.file_id)?;
        let write_end = request
            .offset
            .checked_add(
                u64::try_from(request.bytes.len())
                    .map_err(|_| SmbFilesystemAdapterError::LimitExceeded)?,
            )
            .filter(|end| *end <= self.limits.maximum_writable_file_bytes)
            .ok_or(SmbFilesystemAdapterError::LimitExceeded)?;
        let receipt = self
            .filesystem
            .write_file(
                context,
                &AdapterWriteFileRequest {
                    operation_id: operation_id(request.header, b"write")?,
                    handle_id: open.handle_id,
                    handle_fence: open.fence,
                    offset: request.offset,
                    bytes: BoundedBytes::from_vec(request.bytes.clone(), request.bytes.len())
                        .map_err(|_| SmbFilesystemAdapterError::LimitExceeded)?,
                    observed_at: context.now,
                },
            )
            .map_err(SmbFilesystemAdapterError::Filesystem)?;
        let state = self.open_mut(request.file_id)?;
        state.checkpoint_sequence = receipt.checkpoint.sequence;
        state.logical_length = state.logical_length.max(write_end);
        state.dirty = true;
        if request.write_through {
            self.flush_open(
                context,
                request.file_id,
                operation_id(request.header, b"write-flush")?,
            )?;
        }
        WriteResponse::encode(
            request,
            u32::try_from(request.bytes.len())
                .map_err(|_| SmbFilesystemAdapterError::LimitExceeded)?,
        )
        .map_err(|_| SmbFilesystemAdapterError::InvalidResponse)
    }

    /// Publishes the exact current private checkpoint before returning SMB success.
    ///
    /// # Errors
    ///
    /// Rejects mismatched or stale identities, invalid deadlines and publication failures.
    pub fn flush_file(
        &mut self,
        context: FilesystemAccessContext,
        request: FlushRequest,
    ) -> Result<[u8; 68], SmbFilesystemAdapterError<F::Error>> {
        self.validate_header(request.header.session_id, request.header.tree_id)?;
        self.flush_open(
            context,
            request.file_id,
            operation_id(request.header, b"flush")?,
        )?;
        Ok(request.success_response())
    }

    /// Applies each lock or unlock in wire order against the common fenced handle authority.
    ///
    /// Successfully applied earlier elements remain effective if a later element fails, matching
    /// SMB's prescribed partial-array processing semantics.
    ///
    /// # Errors
    ///
    /// Rejects mismatched or stale identities, malformed ranges, duplicate/unknown local locks or
    /// a common authority/filesystem failure.
    pub fn lock_ranges(
        &mut self,
        context: FilesystemAccessContext,
        request: &LockRequest,
    ) -> Result<LockResponse, SmbFilesystemAdapterError<F::Error>> {
        self.validate_header(request.header.session_id, request.header.tree_id)?;
        let open = *self.open(request.file_id)?;
        for (index, element) in request.elements.iter().copied().enumerate() {
            let range = ByteRange::new(element.offset, element.length)
                .map_err(|_| SmbFilesystemAdapterError::InvalidRange)?;
            let key = (request.file_id, element.offset, element.length);
            match element.kind {
                LockKind::Shared { .. } | LockKind::Exclusive { .. } => {
                    if self.locks.contains_key(&key) {
                        return Err(SmbFilesystemAdapterError::DuplicateLock);
                    }
                    let lock_id = indexed_lock_id(request.header, index)?;
                    self.filesystem
                        .lock_range(
                            context,
                            AdapterLockRequest {
                                operation_id: indexed_operation_id(request.header, b"lock", index)?,
                                lock_id,
                                handle_id: open.handle_id,
                                handle_fence: open.fence,
                                range,
                                kind: match element.kind {
                                    LockKind::Shared { .. } => RangeLockKind::Shared,
                                    LockKind::Exclusive { .. } => RangeLockKind::Exclusive,
                                    LockKind::Unlock => {
                                        return Err(SmbFilesystemAdapterError::InvalidRange);
                                    }
                                },
                                lease_expires_at: open.lease_expires_at,
                                observed_at: context.now,
                            },
                        )
                        .map_err(SmbFilesystemAdapterError::Filesystem)?;
                    self.locks.insert(key, lock_id);
                }
                LockKind::Unlock => {
                    let lock_id = *self
                        .locks
                        .get(&key)
                        .ok_or(SmbFilesystemAdapterError::UnknownLock)?;
                    self.filesystem
                        .unlock_range(
                            context,
                            AdapterUnlockRequest {
                                operation_id: indexed_operation_id(
                                    request.header,
                                    b"unlock",
                                    index,
                                )?,
                                lock_id,
                                handle_id: open.handle_id,
                                handle_fence: open.fence,
                                observed_at: context.now,
                            },
                        )
                        .map_err(SmbFilesystemAdapterError::Filesystem)?;
                    self.locks.remove(&key);
                }
            }
        }
        Ok(request.success_response())
    }

    /// Publishes dirty content when required and releases the exact common handle.
    ///
    /// # Errors
    ///
    /// Rejects mismatched or stale identities, failed dirty publication, close failure or
    /// unrepresentable response time.
    pub fn close_file(
        &mut self,
        context: FilesystemAccessContext,
        request: CloseRequest,
    ) -> Result<CloseResponse, SmbFilesystemAdapterError<F::Error>> {
        self.validate_header(request.header.session_id, request.header.tree_id)?;
        let open = *self.open(request.file_id)?;
        let flush = if open.dirty {
            Some(AdapterFlushFileRequest {
                operation_id: operation_id(request.header, b"close-flush")?,
                handle_id: open.handle_id,
                handle_fence: open.fence,
                expected_stage_sequence: open.checkpoint_sequence,
                final_length: open.logical_length,
                sparse: false,
                content_deadline: deadline(context.now, self.limits.content_timeout)?,
                observed_at: context.now,
            })
        } else {
            None
        };
        self.filesystem
            .close_file(
                context,
                AdapterCloseFileRequest {
                    operation_id: operation_id(request.header, b"close")?,
                    handle_id: open.handle_id,
                    handle_fence: open.fence,
                    flush,
                    observed_at: context.now,
                },
            )
            .map_err(SmbFilesystemAdapterError::Filesystem)?;
        self.handles.remove(&request.file_id);
        self.locks
            .retain(|(file_id, _, _), _| *file_id != request.file_id);
        Ok(CloseResponse::encode(
            request,
            Some(CloseResponseAttributes {
                creation_time: 0,
                last_access_time: 0,
                last_write_time: unix_micros_to_filetime(context.now)?,
                change_time: unix_micros_to_filetime(context.now)?,
                allocation_size: open.logical_length,
                end_of_file: open.logical_length,
                file_attributes: FILE_ATTRIBUTE_NORMAL,
            }),
        ))
    }

    fn flush_open(
        &mut self,
        context: FilesystemAccessContext,
        file_id: SmbFileId,
        operation_id: OperationId,
    ) -> Result<(), SmbFilesystemAdapterError<F::Error>> {
        let open = *self.open(file_id)?;
        if !open.dirty {
            return Ok(());
        }
        self.filesystem
            .flush_file(
                context,
                AdapterFlushFileRequest {
                    operation_id,
                    handle_id: open.handle_id,
                    handle_fence: open.fence,
                    expected_stage_sequence: open.checkpoint_sequence,
                    final_length: open.logical_length,
                    sparse: false,
                    content_deadline: deadline(context.now, self.limits.content_timeout)?,
                    observed_at: context.now,
                },
            )
            .map_err(SmbFilesystemAdapterError::Filesystem)?;
        self.open_mut(file_id)?.dirty = false;
        Ok(())
    }

    fn path(
        &self,
        request_components: &[String],
    ) -> Result<NamespacePath, SmbFilesystemAdapterError<F::Error>> {
        let mut components =
            Vec::with_capacity(self.tree.root_components.len() + request_components.len());
        components.extend(self.tree.root_components.iter().map(String::as_str));
        components.extend(request_components.iter().map(String::as_str));
        NamespacePath::from_components(components, self.tree.namespace_limits)
            .map_err(|_| SmbFilesystemAdapterError::InvalidPath)
    }

    fn validate_header(
        &self,
        session_id: u64,
        tree_id: u32,
    ) -> Result<(), SmbFilesystemAdapterError<F::Error>> {
        if session_id == self.tree.session_id && tree_id == self.tree.tree_id {
            Ok(())
        } else {
            Err(SmbFilesystemAdapterError::InvalidIdentity)
        }
    }

    fn open(&self, file_id: SmbFileId) -> Result<&OpenFile, SmbFilesystemAdapterError<F::Error>> {
        self.handles
            .get(&file_id)
            .ok_or(SmbFilesystemAdapterError::UnknownFile)
    }

    fn open_mut(
        &mut self,
        file_id: SmbFileId,
    ) -> Result<&mut OpenFile, SmbFilesystemAdapterError<F::Error>> {
        self.handles
            .get_mut(&file_id)
            .ok_or(SmbFilesystemAdapterError::UnknownFile)
    }
}

fn map_disposition(disposition: CreateDisposition) -> FilesystemDisposition {
    match disposition {
        CreateDisposition::OpenExisting => FilesystemDisposition::OpenExisting,
        CreateDisposition::CreateNew => FilesystemDisposition::CreateNew,
        CreateDisposition::OpenOrCreate => FilesystemDisposition::OpenOrCreate,
        CreateDisposition::OverwriteExisting => FilesystemDisposition::OverwriteExisting,
        CreateDisposition::OverwriteOrCreate => FilesystemDisposition::OverwriteOrCreate,
    }
}

fn derive_file_id<E>(
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> Result<SmbFileId, SmbFilesystemAdapterError<E>> {
    let digest = identity_digest(session_id, tree_id, message_id, b"file");
    let persistent = u64::from_le_bytes(
        digest[..8]
            .try_into()
            .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)?,
    );
    let volatile = u64::from_le_bytes(
        digest[8..16]
            .try_into()
            .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)?,
    );
    SmbFileId::new(persistent, volatile).map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)
}

fn operation_id<E>(
    header: crate::Smb2Header,
    phase: &[u8],
) -> Result<OperationId, SmbFilesystemAdapterError<E>> {
    let digest = identity_digest(header.session_id, header.tree_id, header.message_id, phase);
    OperationId::from_bytes(
        digest[..16]
            .try_into()
            .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)?,
    )
    .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)
}

fn indexed_operation_id<E>(
    header: crate::Smb2Header,
    phase: &[u8],
    index: usize,
) -> Result<OperationId, SmbFilesystemAdapterError<E>> {
    let digest = indexed_identity_digest(header, phase, index);
    OperationId::from_bytes(
        digest[..16]
            .try_into()
            .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)?,
    )
    .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)
}

fn indexed_lock_id<E>(
    header: crate::Smb2Header,
    index: usize,
) -> Result<LockId, SmbFilesystemAdapterError<E>> {
    let digest = indexed_identity_digest(header, b"lock-id", index);
    LockId::from_bytes(
        digest[..16]
            .try_into()
            .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)?,
    )
    .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)
}

fn indexed_identity_digest(header: crate::Smb2Header, phase: &[u8], index: usize) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(identity_digest(
        header.session_id,
        header.tree_id,
        header.message_id,
        phase,
    ));
    digest.update((index as u64).to_be_bytes());
    digest.finalize().into()
}

fn identity_digest(session_id: u64, tree_id: u32, message_id: u64, phase: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.smb.filesystem-identity.v1\0");
    digest.update(session_id.to_be_bytes());
    digest.update(tree_id.to_be_bytes());
    digest.update(message_id.to_be_bytes());
    digest.update((phase.len() as u64).to_be_bytes());
    digest.update(phase);
    digest.finalize().into()
}

fn deadline<E>(
    now: UnixMicros,
    duration: DurationMicros,
) -> Result<UnixMicros, SmbFilesystemAdapterError<E>> {
    now.checked_add(duration)
        .ok_or(SmbFilesystemAdapterError::InvalidTime)
}

fn unix_micros_to_filetime<E>(instant: UnixMicros) -> Result<u64, SmbFilesystemAdapterError<E>> {
    const WINDOWS_EPOCH_MICROS: i128 = 11_644_473_600_000_000;
    let micros = i128::from(instant.get()) + WINDOWS_EPOCH_MICROS;
    u64::try_from(
        micros
            .checked_mul(10)
            .ok_or(SmbFilesystemAdapterError::InvalidTime)?,
    )
    .map_err(|_| SmbFilesystemAdapterError::InvalidTime)
}

/// Closed failures from the SMB-to-filesystem mapping boundary.
#[derive(Debug, thiserror::Error)]
pub enum SmbFilesystemAdapterError<E> {
    /// Daemon resource or deadline policy is invalid.
    #[error("SMB filesystem adapter configuration is invalid")]
    InvalidConfiguration,
    /// The command does not belong to the bound session and tree.
    #[error("SMB filesystem identity is invalid")]
    InvalidIdentity,
    /// The logical path is invalid for the selected volume.
    #[error("SMB filesystem path is invalid")]
    InvalidPath,
    /// This initial mapping accepts regular-file targets only.
    #[error("SMB target kind is not supported by this mapping")]
    UnsupportedTarget,
    /// The requested access cannot form a common handle contract.
    #[error("SMB requested access is invalid")]
    InvalidAccess,
    /// A request exceeds a daemon-owned resource bound.
    #[error("SMB filesystem request exceeds its resource bound")]
    LimitExceeded,
    /// A lock range cannot be represented by the common durable lock service.
    #[error("SMB lock range is invalid")]
    InvalidRange,
    /// A deterministic file identity collided with another live open.
    #[error("SMB file identity is already live")]
    DuplicateFileIdentity,
    /// The same connection-local range is already locked by this open.
    #[error("SMB range is already locked by this open")]
    DuplicateLock,
    /// The requested unlock does not identify a live connection-local lock.
    #[error("SMB range does not identify a live lock")]
    UnknownLock,
    /// The connection-visible file identity is absent or already closed.
    #[error("SMB file identity is not live")]
    UnknownFile,
    /// Authoritative time or a derived deadline is not representable.
    #[error("SMB filesystem time is invalid")]
    InvalidTime,
    /// Common state could not be safely represented in an SMB response.
    #[error("SMB filesystem response is invalid")]
    InvalidResponse,
    /// The common authority/filesystem service rejected the operation.
    #[error("SMB filesystem operation failed")]
    Filesystem(E),
}

#[cfg(test)]
#[path = "filesystem_adapter_tests.rs"]
mod tests;
