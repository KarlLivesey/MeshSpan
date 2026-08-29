// SPDX-License-Identifier: GPL-2.0-only

//! Semantic connector boundary for logical file-handle operations.

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{BranchId, HandleId, OperationId, UnixMicros, VolumeId};

use crate::{
    AuthorisedFilesystemError, AuthorisedFilesystemService, DurableContentPublisher,
    DurableContentReader, FilesystemAccessAuthority, FilesystemAccessContext,
    FilesystemHandleFlushRequest, FilesystemHandleReadReceipt, FilesystemHandleWriteReceipt,
    HandleAccess, HandleShare, NamespacePath, NamespacePublicationReceipt, OpenHandleReceipt,
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
}

pub(crate) fn prepared_flush(
    request: AdapterFlushFileRequest,
    target: crate::HandleAuthorityTarget,
    context: FilesystemAccessContext,
    policy: FilesystemAdapterPolicy,
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
        content_authorization_revision: target.authorization_revision,
        content_deadline: request.content_deadline,
        observed_at: request.observed_at,
    }
}

pub(crate) fn valid_adapter_context(
    context: FilesystemAccessContext,
    observed_at: UnixMicros,
) -> bool {
    context.now == observed_at && context.gateway_incarnation > 0 && context.token_digest != [0; 32]
}
