// SPDX-License-Identifier: GPL-2.0-only

//! Semantic connector boundary for logical file-handle operations.

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{BranchId, HandleId, LockId, OperationId, UnixMicros, VolumeId};

use crate::{
    AdapterUploadAbortRequest, AdapterUploadBeginRequest, AdapterUploadCommitRequest,
    AdapterUploadRangePageRequest, AdapterUploadStatusRequest, AdapterUploadWriteRequest,
    AuthorisedFilesystemError, AuthorisedFilesystemService, CreateDisposition,
    DurableContentPublisher, DurableContentReader, FilesystemAccessAuthority,
    FilesystemAccessContext, FilesystemHandleCloseReceipt, FilesystemHandleFlushRequest,
    FilesystemHandleReadReceipt, FilesystemHandleWriteReceipt, HandleAccess, HandleLeaseReceipt,
    HandleShare, LockRangeReceipt, NamespaceListPage, NamespaceObjectStat, NamespacePath,
    NamespacePublicationReceipt, OpenHandleReceipt, RangeLockKind, UnlockRangeReceipt,
    UploadCommitReceipt, UploadRangePageReceipt, UploadSession, UploadStatusReceipt,
    UploadWriteReceipt,
};

/// Daemon-owned publication policy that access connectors cannot override.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemAdapterPolicy {
    /// Whether a superseded ordinary version enters history.
    pub retain_superseded_history: bool,
    /// Exact replicated retention-policy sequence applied to new versions.
    pub retention_policy_sequence: u64,
    /// Internal immutable-content manifest format selected by the daemon.
    pub manifest_format_version: u16,
}

impl FilesystemAdapterPolicy {
    /// Validates one daemon-owned policy.
    ///
    /// # Errors
    ///
    /// Rejects zero policy or format revisions.
    pub const fn new(
        retain_superseded_history: bool,
        retention_policy_sequence: u64,
        manifest_format_version: u16,
    ) -> Result<Self, FilesystemAdapterConfigurationError> {
        if retention_policy_sequence == 0 || manifest_format_version == 0 {
            Err(FilesystemAdapterConfigurationError)
        } else {
            Ok(Self {
                retain_superseded_history,
                retention_policy_sequence,
                manifest_format_version,
            })
        }
    }
}

/// Invalid daemon-owned connector policy.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
#[error("filesystem adapter policy is invalid")]
pub struct FilesystemAdapterConfigurationError;

/// Semantic existing-file open supplied by an access connector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterOpenFileRequest {
    /// Stable idempotency identity allocated by the connector boundary.
    pub operation_id: OperationId,
    /// Opaque handle identity allocated for the connector session.
    pub handle_id: HandleId,
    /// Logical volume selected by the authenticated request.
    pub volume_id: VolumeId,
    /// Canonical bounded logical path; never a provider or host path.
    pub path: NamespacePath,
    /// Protocol-neutral requested access.
    pub desired_access: HandleAccess,
    /// Protocol-neutral sharing contract.
    pub share_access: HandleShare,
    /// Whether final close requests a namespace unlink.
    pub delete_on_close: bool,
    /// Maximum logical private-stage size for a writable handle.
    pub maximum_stage_bytes: Option<u64>,
    /// Exclusive daemon-authoritative handle lease deadline.
    pub lease_expires_at: UnixMicros,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic bounded read supplied by an access connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterReadFileRequest {
    /// Stable provider-attempt identity.
    pub operation_id: OperationId,
    /// Opaque open handle returned by this service.
    pub handle_id: HandleId,
    /// Exact current handle fence returned by open or lease transfer.
    pub handle_fence: u64,
    /// First requested logical byte.
    pub offset: u64,
    /// Maximum requested bytes.
    pub length: u64,
    /// Exclusive deadline for content-provider work.
    pub content_deadline: UnixMicros,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic bounded private write supplied by an access connector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterWriteFileRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Opaque open handle returned by this service.
    pub handle_id: HandleId,
    /// Exact current handle fence returned by open or lease transfer.
    pub handle_fence: u64,
    /// First logical byte replaced by this write.
    pub offset: u64,
    /// Already bounded untrusted bytes; the service derives its own integrity digest.
    pub bytes: BoundedBytes,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic publication barrier supplied by an access connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterFlushFileRequest {
    /// Stable end-to-end flush identity.
    pub operation_id: OperationId,
    /// Opaque open handle returned by this service.
    pub handle_id: HandleId,
    /// Exact current handle fence returned by open or lease transfer.
    pub handle_fence: u64,
    /// Exact private checkpoint selected by the caller.
    pub expected_stage_sequence: u64,
    /// Exact resulting logical length.
    pub final_length: u64,
    /// Whether uncovered ranges are explicit logical zeroes.
    pub sparse: bool,
    /// Exclusive deadline for content-provider work.
    pub content_deadline: UnixMicros,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic immutable-attribute query supplied by an access connector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterStatRequest {
    /// Logical volume selected by the authenticated request.
    pub volume_id: VolumeId,
    /// Canonical bounded logical path.
    pub path: NamespacePath,
    /// Authoritative query instant.
    pub observed_at: UnixMicros,
}

/// Semantic bounded directory query supplied by an access connector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterListRequest {
    /// Logical volume selected by the authenticated request.
    pub volume_id: VolumeId,
    /// Directory path, or `None` for the volume root.
    pub directory_path: Option<NamespacePath>,
    /// Exact prior-page continuation returned by the service.
    pub cursor: Option<crate::DirectoryListCursor>,
    /// Positive result bound no greater than the compiled service limit.
    pub maximum_results: u16,
    /// Authoritative query instant.
    pub observed_at: UnixMicros,
}

/// Semantic empty-directory creation supplied by an access connector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterCreateDirectoryRequest {
    /// Stable end-to-end idempotency identity.
    pub operation_id: OperationId,
    /// Logical volume selected by the authenticated request.
    pub volume_id: VolumeId,
    /// Canonical bounded logical path of the new directory.
    pub path: NamespacePath,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic atomic create/open of one file and its handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterCreateFileRequest {
    /// Stable end-to-end handle-open identity.
    pub operation_id: OperationId,
    /// Opaque handle identity allocated for the connector session.
    pub handle_id: HandleId,
    /// Logical volume selected by the authenticated request.
    pub volume_id: VolumeId,
    /// Canonical bounded logical path of the selected or new file.
    pub path: NamespacePath,
    /// Creation-capable atomic create/open behaviour requested by the connector.
    pub create_disposition: CreateDisposition,
    /// Protocol-neutral access requested for the newly created handle.
    pub desired_access: HandleAccess,
    /// Protocol-neutral sharing contract.
    pub share_access: HandleShare,
    /// Whether final close requests logical unlink.
    pub delete_on_close: bool,
    /// Maximum private-stage size, required exactly when write access is requested.
    pub maximum_stage_bytes: Option<u64>,
    /// Exclusive daemon-authoritative handle lease deadline.
    pub lease_expires_at: UnixMicros,
    /// Exclusive deadline for initial empty-content durability work.
    pub content_deadline: UnixMicros,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic logical namespace removal supplied by an access connector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterUnlinkRequest {
    /// Stable end-to-end idempotency identity.
    pub operation_id: OperationId,
    /// Logical volume selected by the authenticated request.
    pub volume_id: VolumeId,
    /// Canonical bounded logical path to remove.
    pub path: NamespacePath,
    /// Optional live delete-capable handle carrying connector share-mode authority.
    pub requesting_handle_id: Option<HandleId>,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic same-volume namespace rename or move supplied by an access connector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterRenameRequest {
    /// Stable end-to-end idempotency identity.
    pub operation_id: OperationId,
    /// Logical volume selected by the authenticated request.
    pub volume_id: VolumeId,
    /// Canonical bounded current path.
    pub source: NamespacePath,
    /// Canonical bounded unoccupied destination, or the same canonical name with new display case.
    pub target: NamespacePath,
    /// Optional live delete-capable handle carrying connector share-mode authority.
    pub requesting_handle_id: Option<HandleId>,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic close, optionally including the exact dirty checkpoint to publish first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterCloseFileRequest {
    /// Stable idempotency identity for final handle release.
    pub operation_id: OperationId,
    /// Opaque open handle returned by this service.
    pub handle_id: HandleId,
    /// Exact current handle fence.
    pub handle_fence: u64,
    /// Required publication barrier for a dirty handle, otherwise absent.
    pub flush: Option<AdapterFlushFileRequest>,
    /// Authoritative close instant.
    pub observed_at: UnixMicros,
}

/// Semantic lease renewal or explicit gateway transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterLeaseRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Opaque open handle returned by this service.
    pub handle_id: HandleId,
    /// Exact current handle fence.
    pub expected_fence: u64,
    /// Whether this gateway explicitly takes ownership and advances the fence.
    pub takeover: bool,
    /// Exclusive new lease deadline.
    pub lease_expires_at: UnixMicros,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic leased byte-range lock acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterLockRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Stable connector-owned lock identity.
    pub lock_id: LockId,
    /// Opaque open handle returned by this service.
    pub handle_id: HandleId,
    /// Exact current handle fence.
    pub handle_fence: u64,
    /// Validated non-empty half-open range.
    pub range: crate::ByteRange,
    /// Shared or exclusive compatibility class.
    pub kind: RangeLockKind,
    /// Exclusive lock deadline no later than the handle lease.
    pub lease_expires_at: UnixMicros,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic exact byte-range lock release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterUnlockRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Stable lock identity returned by acquisition.
    pub lock_id: LockId,
    /// Opaque owning handle.
    pub handle_id: HandleId,
    /// Exact current handle fence.
    pub handle_fence: u64,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic exact working-length mutation supplied by an access connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterSetLengthRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Opaque live writable handle.
    pub handle_id: HandleId,
    /// Exact current handle fence.
    pub handle_fence: u64,
    /// Exact new logical length.
    pub logical_length: u64,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// Semantic delete-on-close mutation supplied by an access connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterSetDispositionRequest {
    /// Stable idempotency identity.
    pub operation_id: OperationId,
    /// Opaque live delete-capable handle.
    pub handle_id: HandleId,
    /// Exact current handle fence.
    pub handle_fence: u64,
    /// Whether final close requests logical deletion.
    pub delete_on_close: bool,
    /// Authoritative operation instant.
    pub observed_at: UnixMicros,
}

/// File-handle service consumed by embedded or replaceable access connectors.
///
/// The connector supplies semantic logical operations only. Branch selection, principal identity,
/// current authorisation revision, gateway identity, content digests and publication policy remain
/// daemon-owned. SQL, provider paths and shard authority are absent from this contract.
pub trait FilesystemFileAdapter {
    /// Stable composed authority/filesystem error.
    type Error;

    /// Opens one existing logical file.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, namespace, sharing, handle or durability failure.
    fn open_existing_file(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterOpenFileRequest,
    ) -> Result<OpenHandleReceipt, Self::Error>;

    /// Reads one bounded logical range.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, fence, content or integrity failure.
    fn read_file(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterReadFileRequest,
    ) -> Result<FilesystemHandleReadReceipt, Self::Error>;

    /// Writes one bounded private copy-on-write range.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, fence, lock, stage or durability failure.
    fn write_file(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterWriteFileRequest,
    ) -> Result<FilesystemHandleWriteReceipt, Self::Error>;

    /// Publishes one exact private checkpoint as a new immutable version.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, checkpoint, content, namespace or durability failure.
    fn flush_file(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterFlushFileRequest,
    ) -> Result<NamespacePublicationReceipt, Self::Error>;

    /// Reads verified immutable attributes for one logical path.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, namespace, cursor or integrity failure.
    fn stat(
        &self,
        context: FilesystemAccessContext,
        request: &AdapterStatRequest,
    ) -> Result<NamespaceObjectStat, Self::Error>;

    /// Enumerates one bounded verified directory page.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, namespace, cursor or integrity failure.
    fn list(
        &self,
        context: FilesystemAccessContext,
        request: &AdapterListRequest,
    ) -> Result<NamespaceListPage, Self::Error>;

    /// Creates one empty logical directory beneath an authorised current parent.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, path, collision, stale-head or durability failure.
    fn create_directory(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterCreateDirectoryRequest,
    ) -> Result<crate::DirectoryPublicationReceipt, Self::Error>;

    /// Atomically creates or opens one logical file according to its disposition.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, collision, stage, content, namespace or durability failure.
    fn create_file(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterCreateFileRequest,
    ) -> Result<crate::FilesystemHandleCreateReceipt, Self::Error>;

    /// Logically removes one exact current file or empty directory name.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, sharing, non-empty-directory, stale-head or durability failure.
    fn unlink(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterUnlinkRequest,
    ) -> Result<crate::NamespaceUnlinkReceipt, Self::Error>;

    /// Atomically renames or moves one exact current object within its volume.
    ///
    /// # Errors
    ///
    /// Returns a typed source/destination authority, cycle, sharing, collision or durability
    /// failure.
    fn rename(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterRenameRequest,
    ) -> Result<crate::NamespaceRenameReceipt, Self::Error>;

    /// Flushes when required and then releases one exact live handle.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, fence, publication or durability failure.
    fn close_file(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterCloseFileRequest,
    ) -> Result<FilesystemHandleCloseReceipt, Self::Error>;

    /// Renews or explicitly transfers one live handle lease.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, gateway, fence or durability failure.
    fn renew_lease(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterLeaseRequest,
    ) -> Result<HandleLeaseReceipt, Self::Error>;

    /// Acquires one leased byte-range lock.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, overlap, fence or durability failure.
    fn lock_range(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterLockRequest,
    ) -> Result<LockRangeReceipt, Self::Error>;

    /// Releases one exact byte-range lock.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, identity, fence or durability failure.
    fn unlock_range(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterUnlockRequest,
    ) -> Result<UnlockRangeReceipt, Self::Error>;

    /// Sets one exact private working length under the live handle fence.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, access, fence, bound or durability failure.
    fn set_length(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterSetLengthRequest,
    ) -> Result<crate::FilesystemHandleLengthReceipt, Self::Error>;

    /// Sets or clears delete-on-close under the live handle fence.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, access, fence or durability failure.
    fn set_disposition(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterSetDispositionRequest,
    ) -> Result<crate::HandleInformationReceipt, Self::Error>;
}

/// Connector-neutral resumable-upload boundary with operation-time authority on every call.
pub trait FilesystemUploadAdapter {
    /// Closed connector-specific authority or durability error.
    type Error;

    /// Begins or exactly resumes one private upload.
    ///
    /// # Errors
    ///
    /// Rejects invalid destinations, stale authority and unavailable durable state.
    fn begin_upload(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterUploadBeginRequest,
    ) -> Result<UploadStatusReceipt, Self::Error>;

    /// Reads exact current durable upload state.
    ///
    /// # Errors
    ///
    /// Rejects absent uploads, stale authority and corrupt durable state.
    fn upload_status(
        &self,
        context: FilesystemAccessContext,
        request: AdapterUploadStatusRequest,
    ) -> Result<UploadStatusReceipt, Self::Error>;

    /// Writes one independently idempotent bounded range.
    ///
    /// # Errors
    ///
    /// Rejects stale fences or authority, conflicting retries and persistence failure.
    fn write_upload(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterUploadWriteRequest,
    ) -> Result<UploadWriteReceipt, Self::Error>;

    /// Lists one checkpoint-pinned bounded coverage page.
    ///
    /// # Errors
    ///
    /// Rejects stale cursors or authority, invalid bounds and corrupt durable state.
    fn upload_range_page(
        &self,
        context: FilesystemAccessContext,
        request: AdapterUploadRangePageRequest,
    ) -> Result<UploadRangePageReceipt, Self::Error>;

    /// Permanently abandons one unpublished upload.
    ///
    /// # Errors
    ///
    /// Rejects stale fences or authority, conflicting retries and persistence failure.
    fn abort_upload(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterUploadAbortRequest,
    ) -> Result<UploadSession, Self::Error>;

    /// Atomically publishes one complete exact upload checkpoint.
    ///
    /// # Errors
    ///
    /// Rejects stale authority or namespace state, incomplete content and durability failure.
    fn commit_upload(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterUploadCommitRequest,
    ) -> Result<UploadCommitReceipt, Self::Error>;
}

/// Daemon composition binding semantic connector operations to one local branch and policy.
pub struct BoundFilesystemAdapter<P, A> {
    filesystem: AuthorisedFilesystemService<P, A>,
    branch_id: BranchId,
    policy: FilesystemAdapterPolicy,
}

impl<P, A> BoundFilesystemAdapter<P, A> {
    /// Binds one authorised filesystem engine to daemon-owned branch and publication policy.
    #[must_use]
    pub const fn new(
        filesystem: AuthorisedFilesystemService<P, A>,
        branch_id: BranchId,
        policy: FilesystemAdapterPolicy,
    ) -> Self {
        Self {
            filesystem,
            branch_id,
            policy,
        }
    }

    /// Returns the authorised engine for orderly shutdown or restart composition.
    #[must_use]
    pub fn into_inner(self) -> AuthorisedFilesystemService<P, A> {
        self.filesystem
    }
}

impl<P, A> FilesystemFileAdapter for BoundFilesystemAdapter<P, A>
where
    P: DurableContentPublisher + DurableContentReader,
    A: FilesystemAccessAuthority,
{
    type Error = AuthorisedFilesystemError<A::Error>;

    fn open_existing_file(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterOpenFileRequest,
    ) -> Result<OpenHandleReceipt, Self::Error> {
        self.filesystem
            .adapter_open_existing(self.branch_id, context, request)
    }

    fn read_file(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterReadFileRequest,
    ) -> Result<FilesystemHandleReadReceipt, Self::Error> {
        self.filesystem.adapter_read(context, request)
    }

    fn write_file(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterWriteFileRequest,
    ) -> Result<FilesystemHandleWriteReceipt, Self::Error> {
        self.filesystem.adapter_write(context, request)
    }

    fn flush_file(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterFlushFileRequest,
    ) -> Result<NamespacePublicationReceipt, Self::Error> {
        self.filesystem.adapter_flush(context, request, self.policy)
    }

    fn stat(
        &self,
        context: FilesystemAccessContext,
        request: &AdapterStatRequest,
    ) -> Result<NamespaceObjectStat, Self::Error> {
        self.filesystem
            .adapter_stat(self.branch_id, context, request)
    }

    fn list(
        &self,
        context: FilesystemAccessContext,
        request: &AdapterListRequest,
    ) -> Result<NamespaceListPage, Self::Error> {
        self.filesystem
            .adapter_list(self.branch_id, context, request)
    }

    fn create_directory(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterCreateDirectoryRequest,
    ) -> Result<crate::DirectoryPublicationReceipt, Self::Error> {
        self.filesystem
            .adapter_create_directory(self.branch_id, context, request)
    }

    fn create_file(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterCreateFileRequest,
    ) -> Result<crate::FilesystemHandleCreateReceipt, Self::Error> {
        self.filesystem
            .adapter_create_file(self.branch_id, context, request, self.policy)
    }

    fn unlink(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterUnlinkRequest,
    ) -> Result<crate::NamespaceUnlinkReceipt, Self::Error> {
        self.filesystem
            .adapter_unlink(self.branch_id, context, request)
    }

    fn rename(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterRenameRequest,
    ) -> Result<crate::NamespaceRenameReceipt, Self::Error> {
        self.filesystem
            .adapter_rename(self.branch_id, context, request)
    }

    fn close_file(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterCloseFileRequest,
    ) -> Result<FilesystemHandleCloseReceipt, Self::Error> {
        self.filesystem.adapter_close(context, request, self.policy)
    }

    fn renew_lease(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterLeaseRequest,
    ) -> Result<HandleLeaseReceipt, Self::Error> {
        self.filesystem.adapter_renew_lease(context, request)
    }

    fn lock_range(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterLockRequest,
    ) -> Result<LockRangeReceipt, Self::Error> {
        self.filesystem.adapter_lock(context, request)
    }

    fn unlock_range(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterUnlockRequest,
    ) -> Result<UnlockRangeReceipt, Self::Error> {
        self.filesystem.adapter_unlock(context, request)
    }

    fn set_length(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterSetLengthRequest,
    ) -> Result<crate::FilesystemHandleLengthReceipt, Self::Error> {
        self.filesystem.adapter_set_length(context, request)
    }

    fn set_disposition(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterSetDispositionRequest,
    ) -> Result<crate::HandleInformationReceipt, Self::Error> {
        self.filesystem.adapter_set_disposition(context, request)
    }
}

impl<P, A> FilesystemUploadAdapter for BoundFilesystemAdapter<P, A>
where
    P: DurableContentPublisher,
    A: FilesystemAccessAuthority,
{
    type Error = AuthorisedFilesystemError<A::Error>;

    fn begin_upload(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterUploadBeginRequest,
    ) -> Result<UploadStatusReceipt, Self::Error> {
        self.filesystem
            .adapter_begin_upload(self.branch_id, context, request)
    }

    fn upload_status(
        &self,
        context: FilesystemAccessContext,
        request: AdapterUploadStatusRequest,
    ) -> Result<UploadStatusReceipt, Self::Error> {
        self.filesystem.adapter_upload_status(context, request)
    }

    fn write_upload(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterUploadWriteRequest,
    ) -> Result<UploadWriteReceipt, Self::Error> {
        self.filesystem.adapter_write_upload(context, request)
    }

    fn upload_range_page(
        &self,
        context: FilesystemAccessContext,
        request: AdapterUploadRangePageRequest,
    ) -> Result<UploadRangePageReceipt, Self::Error> {
        self.filesystem.adapter_upload_range_page(context, request)
    }

    fn abort_upload(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterUploadAbortRequest,
    ) -> Result<UploadSession, Self::Error> {
        self.filesystem.adapter_abort_upload(context, request)
    }

    fn commit_upload(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterUploadCommitRequest,
    ) -> Result<UploadCommitReceipt, Self::Error> {
        self.filesystem
            .adapter_commit_upload(self.branch_id, context, request, self.policy)
    }
}

pub(crate) fn prepared_flush(
    request: AdapterFlushFileRequest,
    target: crate::HandleAuthorityTarget,
    context: FilesystemAccessContext,
    policy: FilesystemAdapterPolicy,
    content_authorization_revision: meshspan_domain::Revision,
) -> FilesystemHandleFlushRequest {
    FilesystemHandleFlushRequest {
        operation_id: request.operation_id,
        handle_id: request.handle_id,
        handle_fence: request.handle_fence,
        principal_id: target.principal_id,
        authorization_revision: target.authorization_revision,
        gateway_node_id: context.gateway_node_id,
        expected_stage_sequence: request.expected_stage_sequence,
        final_length: request.final_length,
        sparse: request.sparse,
        retain_superseded_history: policy.retain_superseded_history,
        retention_policy_sequence: policy.retention_policy_sequence,
        manifest_format_version: policy.manifest_format_version,
        content_authorization_revision,
        content_deadline: request.content_deadline,
        observed_at: request.observed_at,
    }
}

pub(crate) fn valid_adapter_context(
    context: FilesystemAccessContext,
    observed_at: UnixMicros,
) -> bool {
    context.now == observed_at
        && context.gateway_incarnation > 0
        && context.credential_digest != [0; 32]
}
