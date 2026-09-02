// SPDX-License-Identifier: GPL-2.0-only

//! Connector-neutral operation-time authority for the logical filesystem service.

use meshspan_domain::{
    AssuranceLevel, AuthenticationService, BranchId, NodeId, ObjectId, PrincipalId, Revision,
    Rights, UnixMicros, VolumeId,
};
use thiserror::Error;

use crate::{
    AdapterCloseFileRequest, AdapterCreateDirectoryRequest, AdapterCreateFileRequest,
    AdapterFlushFileRequest, AdapterLeaseRequest, AdapterListRequest, AdapterLockRequest,
    AdapterOpenFileRequest, AdapterReadFileRequest, AdapterRenameRequest,
    AdapterSetDispositionRequest, AdapterSetLengthRequest, AdapterStatRequest,
    AdapterUnlinkRequest, AdapterUnlockRequest, AdapterUploadAbortRequest,
    AdapterUploadBeginRequest, AdapterUploadCommitRequest, AdapterUploadRangePageRequest,
    AdapterUploadStatusRequest, AdapterUploadWriteRequest, AdapterWriteFileRequest,
    CloseHandleOutcome, DirectoryPublication, DurableContentPublisher, DurableContentReader,
    FilesystemAdapterPolicy, FilesystemCommitError, FilesystemCommitService,
    FilesystemHandleCloseReceipt, FilesystemHandleCloseRequest, FilesystemHandleCreateReceipt,
    FilesystemHandleCreateRequest, FilesystemHandleFlushRequest, FilesystemHandleLengthReceipt,
    FilesystemHandleOpenRequest, FilesystemHandleReadReceipt, FilesystemHandleReadRequest,
    FilesystemHandleWriteReceipt, FilesystemHandleWriteRequest, HandleAccess, HandleError,
    HandleInformationReceipt, HandleIoError, HandleLeaseReceipt, HandleLeaseRequest,
    HandleReadError, LockRangeReceipt, LockRangeRequest, NamespaceListRequest,
    NamespacePublicationReceipt, NamespaceQueryError, NamespaceRenamePublication,
    NamespaceRenameReceipt, NamespaceStatRequest, NamespaceUnlinkPublication,
    NamespaceUnlinkReceipt, OpenHandleReceipt, OpenHandleRequest, RangeLockKind,
    SetHandleDispositionRequest, SetHandleLengthRequest, StageWrite, UnlockRangeReceipt,
    UnlockRangeRequest, UploadAbortRequest, UploadBeginRequest, UploadCommitReceipt,
    UploadCommitRequest, UploadRangePageReceipt, UploadRangePageRequest, UploadSession,
    UploadStatusReceipt, UploadStatusRequest, UploadWriteReceipt, UploadWriteRequest,
};

/// Authenticated connector context supplied independently of a filesystem operation payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemAccessContext {
    /// Connector family against which the credential must be validated.
    pub authentication_service: AuthenticationService,
    /// Digest of the presented session or API-key secret; raw credentials never enter state.
    pub credential_digest: [u8; 32],
    /// Minimum authentication assurance required by the connector operation.
    pub required_assurance: AssuranceLevel,
    /// Gateway executing the operation.
    pub gateway_node_id: NodeId,
    /// Exact live process incarnation of that gateway.
    pub gateway_incarnation: u64,
    /// Authoritative mesh instant used for the decision and operation.
    pub now: UnixMicros,
}

/// One exact operation-time access query after logical path or handle resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemAuthorityRequest {
    /// Authenticated connector and gateway context.
    pub context: FilesystemAccessContext,
    /// Volume containing the exact logical target.
    pub volume_id: VolumeId,
    /// Stable logical object identity, never a provider location.
    pub object_id: ObjectId,
    /// Non-empty protocol-neutral rights required atomically.
    pub requested_rights: Rights,
}

/// Bounded proof returned by a replaceable committed access authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemAuthorityGrant {
    /// Authenticated user receiving access.
    pub principal_id: PrincipalId,
    /// Gateway to which the decision is fenced.
    pub gateway_node_id: NodeId,
    /// Exact live process incarnation of the gateway.
    pub gateway_incarnation: u64,
    /// Exact target volume.
    pub volume_id: VolumeId,
    /// Exact target object.
    pub object_id: ObjectId,
    /// Rights proved by this decision.
    pub requested_rights: Rights,
    /// Current identity and permission revision.
    pub identity_revision: Revision,
    /// Current namespace authority revision.
    pub namespace_revision: Revision,
    /// Current target-object authority revision.
    pub object_revision: Revision,
    /// Current gateway record revision.
    pub gateway_revision: Revision,
    /// Exclusive decision expiry.
    pub expires_at: UnixMicros,
    /// Canonical authority evidence digest.
    pub evidence_digest: [u8; 32],
}

/// Replaceable committed authority used by every access connector.
pub trait FilesystemAccessAuthority {
    /// Stable implementation error, including access denial and unavailable committed authority.
    type Error;

    /// Evaluates one exact logical object and returns a bounded grant or fails closed.
    ///
    /// # Errors
    ///
    /// Returns the implementation's stable denial or unavailable-authority error.
    fn authorise(
        &self,
        request: FilesystemAuthorityRequest,
    ) -> Result<FilesystemAuthorityGrant, Self::Error>;

    /// Resolves and authorises the committed root object of one volume.
    ///
    /// This is deliberately an authority operation rather than a caller-supplied object lookup:
    /// a newly created volume has no local namespace head from which a connector can safely learn
    /// its root identity. Implementations must resolve the root from committed metadata and return
    /// the same exact-object grant that [`Self::authorise`] would return for that root.
    ///
    /// # Errors
    ///
    /// Returns the implementation's stable denial or unavailable-authority error when the volume
    /// is absent, the caller is unauthenticated or the requested rights are not currently granted.
    fn authorise_volume_root(
        &self,
        context: FilesystemAccessContext,
        volume_id: VolumeId,
        requested_rights: Rights,
    ) -> Result<FilesystemAuthorityGrant, Self::Error>;
}

/// Filesystem service that cannot mutate or publish without a live committed authority decision.
pub struct AuthorisedFilesystemService<P, A> {
    filesystem: FilesystemCommitService<P>,
    authority: A,
}

impl<P, A> AuthorisedFilesystemService<P, A>
where
    P: DurableContentPublisher,
    A: FilesystemAccessAuthority,
{
    /// Composes the lower filesystem durability engine with one access authority.
    #[must_use]
    pub const fn new(filesystem: FilesystemCommitService<P>, authority: A) -> Self {
        Self {
            filesystem,
            authority,
        }
    }

    /// Opens one exact existing object after resolving the path before authority evaluation.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, denial, target substitution and lower durability failures.
    pub fn open_handle(
        &mut self,
        context: FilesystemAccessContext,
        request: &FilesystemHandleOpenRequest,
    ) -> Result<OpenHandleReceipt, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, request.handle.opened_at)?;
        let object_id = self
            .filesystem
            .resolve_open_object(&request.handle)
            .map_err(AuthorisedFilesystemError::Handle)?
            .ok_or(AuthorisedFilesystemError::TargetUnavailable)?;
        let grant = self.authorise(
            context,
            request.handle.volume_id,
            object_id,
            rights_for_access(request.handle.desired_access),
        )?;
        validate_open_grant(grant, request)?;
        self.filesystem
            .open_handle_at(request, object_id)
            .map_err(AuthorisedFilesystemError::HandleIo)
    }

    /// Opens an existing file or creates an empty file after authorising its exact object or
    /// destination parent respectively.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, denial, target races and lower durability failures.
    pub fn open_or_create_handle(
        &mut self,
        context: FilesystemAccessContext,
        request: &FilesystemHandleCreateRequest,
    ) -> Result<FilesystemHandleCreateReceipt, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, request.open.handle.opened_at)?;
        let existing = self
            .filesystem
            .resolve_open_object(&request.open.handle)
            .map_err(AuthorisedFilesystemError::Handle)?;
        let (object_id, rights) = existing.map_or_else(
            || {
                (
                    publication_parent(
                        request.initial_file.root_object_id,
                        &request.initial_file.path,
                    ),
                    Rights::CREATE_CHILD,
                )
            },
            |object_id| {
                (
                    object_id,
                    rights_for_access(request.open.handle.desired_access),
                )
            },
        );
        let grant = self.authorise(context, request.open.handle.volume_id, object_id, rights)?;
        validate_principal_and_gateway(
            grant,
            request.open.handle.principal_id,
            request.open.handle.gateway_node_id,
        )?;
        if grant.identity_revision != request.open.handle.authorization_revision {
            return Err(AuthorisedFilesystemError::InvalidGrant);
        }
        if existing.is_none() && grant.principal_id != request.initial_file.created_by {
            return Err(AuthorisedFilesystemError::InvalidGrant);
        }
        self.filesystem
            .open_or_create_handle_at(request, existing)
            .map_err(AuthorisedFilesystemError::Commit)
    }

    /// Revalidates write permission against the current target before any stage admission.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, denial, stale handles and stage durability failures.
    pub fn write_handle(
        &mut self,
        context: FilesystemAccessContext,
        request: &FilesystemHandleWriteRequest,
    ) -> Result<FilesystemHandleWriteReceipt, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        self.authorise_handle(context, target, Rights::WRITE_DATA)?;
        validate_handle_caller(
            target,
            request.principal_id,
            request.gateway_node_id,
            request.authorization_revision,
        )?;
        self.filesystem
            .write_handle(request)
            .map_err(AuthorisedFilesystemError::HandleIo)
    }

    /// Reads one bounded immutable/private-overlay range after revalidating current read access.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, denial, stale handles and content or stage verification failure.
    pub fn read_handle(
        &mut self,
        context: FilesystemAccessContext,
        request: FilesystemHandleReadRequest,
    ) -> Result<FilesystemHandleReadReceipt, AuthorisedFilesystemError<A::Error>>
    where
        P: DurableContentReader,
    {
        require_same_time(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        self.authorise_handle(context, target, Rights::READ_DATA)?;
        validate_handle_caller(
            target,
            request.principal_id,
            request.gateway_node_id,
            request.authorization_revision,
        )?;
        self.filesystem
            .read_handle(request)
            .map_err(AuthorisedFilesystemError::Read)
    }

    /// Revalidates write permission before immutable content or a namespace head can advance.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, denial, stale handles and publication failures.
    pub fn flush_handle(
        &mut self,
        context: FilesystemAccessContext,
        request: FilesystemHandleFlushRequest,
    ) -> Result<NamespacePublicationReceipt, AuthorisedFilesystemError<A::Error>>
    where
        P: DurableContentReader,
    {
        require_same_time(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        let grant = self.authorise_handle(context, target, Rights::WRITE_DATA)?;
        validate_handle_caller(
            target,
            request.principal_id,
            request.gateway_node_id,
            request.authorization_revision,
        )?;
        if request.content_authorization_revision != grant.identity_revision {
            return Err(AuthorisedFilesystemError::InvalidGrant);
        }
        self.filesystem
            .flush_handle(request)
            .map_err(AuthorisedFilesystemError::Commit)
    }

    /// Closes a handle only for its currently authorised owner and never publishes a dirty
    /// checkpoint after write revocation.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, denied dirty publication and lower close failures.
    pub fn close_handle(
        &mut self,
        context: FilesystemAccessContext,
        request: FilesystemHandleCloseRequest,
    ) -> Result<FilesystemHandleCloseReceipt, AuthorisedFilesystemError<A::Error>>
    where
        P: DurableContentReader,
    {
        require_same_time(context, request.close.observed_at)?;
        let target = self.handle_target(request.close.handle_id, context.now)?;
        validate_handle_identity(
            target,
            request.close.principal_id,
            request.close.gateway_node_id,
        )?;
        if let Some(flush) = request.flush {
            let grant = self.authorise_handle(context, target, Rights::WRITE_DATA)?;
            validate_handle_caller(
                target,
                flush.principal_id,
                flush.gateway_node_id,
                flush.authorization_revision,
            )?;
            if flush.content_authorization_revision != grant.identity_revision {
                return Err(AuthorisedFilesystemError::InvalidGrant);
            }
        } else {
            self.authorise_handle(context, target, release_right(target.desired_access))?;
        }
        self.filesystem
            .close_handle(request)
            .map_err(AuthorisedFilesystemError::Commit)
    }

    /// Revalidates the handle's full access set before renewing or transferring its lease.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, denial, stale ownership and lease durability failures.
    pub fn renew_handle_lease(
        &mut self,
        context: FilesystemAccessContext,
        request: HandleLeaseRequest,
    ) -> Result<HandleLeaseReceipt, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        let grant = self.authorise(
            context,
            target.volume_id,
            target.object_id,
            rights_for_access(target.desired_access),
        )?;
        validate_principal_and_gateway(grant, request.principal_id, request.gateway_node_id)?;
        if request.principal_id != target.principal_id
            || !request.takeover && request.gateway_node_id != target.gateway_node_id
        {
            return Err(AuthorisedFilesystemError::InvalidInput);
        }
        self.filesystem
            .renew_handle_lease(request)
            .map_err(AuthorisedFilesystemError::HandleIo)
    }

    /// Acquires a shared or exclusive range lock only while its corresponding data right remains
    /// live on the exact opened object.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, denial, stale handles and lock conflicts or persistence errors.
    pub fn lock_range(
        &mut self,
        context: FilesystemAccessContext,
        request: LockRangeRequest,
    ) -> Result<LockRangeReceipt, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        let rights = match request.kind {
            RangeLockKind::Shared => Rights::READ_DATA,
            RangeLockKind::Exclusive => Rights::WRITE_DATA,
        };
        self.authorise_handle(context, target, rights)?;
        validate_handle_identity(target, request.principal_id, request.gateway_node_id)?;
        self.filesystem
            .lock_range(request)
            .map_err(AuthorisedFilesystemError::Handle)
    }

    /// Releases a range lock through its existing handle fence and one still-live handle right.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, caller substitution, stale locks and persistence errors.
    pub fn unlock_range(
        &mut self,
        context: FilesystemAccessContext,
        request: UnlockRangeRequest,
    ) -> Result<UnlockRangeReceipt, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        validate_handle_identity(target, request.principal_id, request.gateway_node_id)?;
        self.authorise_handle(context, target, release_right(target.desired_access))?;
        self.filesystem
            .unlock_range(request)
            .map_err(AuthorisedFilesystemError::Handle)
    }

    /// Creates a directory only after proving `CREATE_CHILD` on its exact parent.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, denial, actor substitution and publication failures.
    pub fn create_directory(
        &mut self,
        context: FilesystemAccessContext,
        publication: &DirectoryPublication,
    ) -> Result<crate::DirectoryPublicationReceipt, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, publication.created_at)?;
        let parent = publication_parent(publication.root_object_id, &publication.path);
        let grant = self.authorise(context, publication.volume_id, parent, Rights::CREATE_CHILD)?;
        validate_actor(grant, publication.created_by)?;
        self.filesystem
            .create_directory(publication)
            .map_err(AuthorisedFilesystemError::Commit)
    }

    /// Returns immutable logical attributes only after authorising the resolved stable object.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, absent/corrupt paths, denial and substituted authority grants.
    pub fn stat_namespace(
        &self,
        context: FilesystemAccessContext,
        request: &NamespaceStatRequest,
    ) -> Result<crate::NamespaceObjectStat, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, request.observed_at)?;
        let stat = self
            .filesystem
            .stat_namespace(request)
            .map_err(AuthorisedFilesystemError::Query)?;
        self.authorise(
            context,
            request.volume_id,
            stat.object_id,
            Rights::READ_ATTRIBUTES,
        )?;
        Ok(stat)
    }

    /// Lists one bounded immutable directory page after authorising the directory itself.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, invalid/stale cursors, denial and corrupt namespace records.
    pub fn list_namespace(
        &self,
        context: FilesystemAccessContext,
        request: &NamespaceListRequest,
    ) -> Result<crate::NamespaceListPage, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, request.observed_at)?;
        let target = self
            .filesystem
            .list_authority_target(request)
            .map_err(AuthorisedFilesystemError::Query)?;
        self.authorise(context, request.volume_id, target.object, Rights::LIST)?;
        self.filesystem
            .list_namespace(request)
            .map_err(AuthorisedFilesystemError::Query)
    }

    /// Renames within a volume after proving source rename and destination creation authority.
    ///
    /// # Errors
    ///
    /// Rejects either authority decision, actor substitution and atomic rename failures.
    pub fn rename_namespace(
        &mut self,
        context: FilesystemAccessContext,
        publication: &NamespaceRenamePublication,
    ) -> Result<NamespaceRenameReceipt, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, publication.created_at)?;
        let source = self.authorise(
            context,
            publication.volume_id,
            publication.expected_object_id,
            Rights::RENAME,
        )?;
        validate_actor(source, publication.created_by)?;
        let destination_parent =
            publication_parent(publication.root_object_id, &publication.target);
        let destination = self.authorise(
            context,
            publication.volume_id,
            destination_parent,
            Rights::CREATE_CHILD,
        )?;
        validate_actor(destination, publication.created_by)?;
        self.filesystem
            .rename_namespace(publication)
            .map_err(AuthorisedFilesystemError::Handle)
    }

    /// Removes a namespace entry only after proving delete authority on its stable object.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, denial, target substitution and unlink failures.
    pub fn unlink_namespace(
        &mut self,
        context: FilesystemAccessContext,
        publication: &NamespaceUnlinkPublication,
    ) -> Result<NamespaceUnlinkReceipt, AuthorisedFilesystemError<A::Error>> {
        require_same_time(context, publication.created_at)?;
        let grant = self.authorise(
            context,
            publication.volume_id,
            publication.expected_object_id,
            Rights::DELETE,
        )?;
        validate_actor(grant, publication.created_by)?;
        self.filesystem
            .unlink_namespace(publication)
            .map_err(AuthorisedFilesystemError::Handle)
    }

    pub(crate) fn adapter_open_existing(
        &mut self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: &AdapterOpenFileRequest,
    ) -> Result<OpenHandleReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let object_id = self
            .filesystem
            .resolve_path_object(branch_id, request.volume_id, &request.path)
            .map_err(AuthorisedFilesystemError::Handle)?
            .ok_or(AuthorisedFilesystemError::TargetUnavailable)?;
        let grant = self.authorise(
            context,
            request.volume_id,
            object_id,
            rights_for_access(request.desired_access),
        )?;
        let prepared = FilesystemHandleOpenRequest {
            handle: OpenHandleRequest {
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                branch_id,
                volume_id: request.volume_id,
                path: request.path.clone(),
                principal_id: grant.principal_id,
                authorization_revision: grant.identity_revision,
                gateway_node_id: context.gateway_node_id,
                desired_access: request.desired_access,
                share_access: request.share_access,
                create_disposition: crate::CreateDisposition::OpenExisting,
                delete_on_close: request.delete_on_close,
                lease_expires_at: request.lease_expires_at,
                opened_at: request.observed_at,
            },
            maximum_stage_bytes: request.maximum_stage_bytes,
        };
        self.filesystem
            .open_handle_at(&prepared, object_id)
            .map_err(AuthorisedFilesystemError::HandleIo)
    }

    pub(crate) fn adapter_read(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterReadFileRequest,
    ) -> Result<FilesystemHandleReadReceipt, AuthorisedFilesystemError<A::Error>>
    where
        P: DurableContentReader,
    {
        require_adapter_context(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        self.read_handle(
            context,
            FilesystemHandleReadRequest {
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                handle_fence: request.handle_fence,
                principal_id: target.principal_id,
                authorization_revision: target.authorization_revision,
                gateway_node_id: context.gateway_node_id,
                offset: request.offset,
                length: request.length,
                content_deadline: request.content_deadline,
                observed_at: request.observed_at,
            },
        )
    }

    pub(crate) fn adapter_write(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterWriteFileRequest,
    ) -> Result<FilesystemHandleWriteReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        let prepared = FilesystemHandleWriteRequest {
            handle_id: request.handle_id,
            principal_id: target.principal_id,
            authorization_revision: target.authorization_revision,
            gateway_node_id: context.gateway_node_id,
            write: StageWrite {
                operation_id: request.operation_id,
                stage_fence: request.handle_fence,
                offset: request.offset,
                bytes: request.bytes.clone(),
                digest: blake3::hash(request.bytes.as_slice()).into(),
            },
            observed_at: request.observed_at,
        };
        self.write_handle(context, &prepared)
    }

    pub(crate) fn adapter_flush(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterFlushFileRequest,
        policy: FilesystemAdapterPolicy,
    ) -> Result<NamespacePublicationReceipt, AuthorisedFilesystemError<A::Error>>
    where
        P: DurableContentReader,
    {
        require_adapter_context(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        let grant = self.authorise_handle(context, target, Rights::WRITE_DATA)?;
        let prepared = crate::adapter::prepared_flush(
            request,
            target,
            context,
            policy,
            grant.identity_revision,
        );
        self.flush_handle(context, prepared)
    }

    pub(crate) fn adapter_stat(
        &self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: &AdapterStatRequest,
    ) -> Result<crate::NamespaceObjectStat, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        self.stat_namespace(
            context,
            &NamespaceStatRequest {
                branch_id,
                volume_id: request.volume_id,
                path: request.path.clone(),
                observed_at: request.observed_at,
            },
        )
    }

    pub(crate) fn adapter_list(
        &self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: &AdapterListRequest,
    ) -> Result<crate::NamespaceListPage, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        self.list_namespace(
            context,
            &NamespaceListRequest {
                branch_id,
                volume_id: request.volume_id,
                directory_path: request.directory_path.clone(),
                cursor: request.cursor.clone(),
                maximum_results: request.maximum_results,
                observed_at: request.observed_at,
            },
        )
    }

    pub(crate) fn adapter_create_directory(
        &mut self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: &AdapterCreateDirectoryRequest,
    ) -> Result<crate::DirectoryPublicationReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let grant = match self.filesystem.adapter_directory_parent(branch_id, request) {
            Ok(parent) => {
                self.authorise(context, request.volume_id, parent, Rights::CREATE_CHILD)?
            }
            Err(HandleError::NotFound) => self
                .authority
                .authorise_volume_root(context, request.volume_id, Rights::CREATE_CHILD)
                .map_err(AuthorisedFilesystemError::Authority)?,
            Err(error) => return Err(AuthorisedFilesystemError::Handle(error)),
        };
        validate_grant(
            FilesystemAuthorityRequest {
                context,
                volume_id: request.volume_id,
                object_id: grant.object_id,
                requested_rights: Rights::CREATE_CHILD,
            },
            grant,
        )?;
        let parent = grant.object_id;
        let publication = self
            .filesystem
            .prepare_adapter_directory(branch_id, request, grant.principal_id, parent)
            .map_err(AuthorisedFilesystemError::Handle)?;
        self.create_directory(context, &publication)
    }

    pub(crate) fn adapter_create_file(
        &mut self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: &AdapterCreateFileRequest,
        policy: FilesystemAdapterPolicy,
    ) -> Result<FilesystemHandleCreateReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let (target, grant) = match self
            .filesystem
            .adapter_file_create_target(branch_id, context, request)
        {
            Ok(target) => {
                let rights = if target.existing_object_id.is_some() {
                    rights_for_access(request.desired_access)
                } else {
                    Rights::CREATE_CHILD
                };
                let grant = self.authorise(context, request.volume_id, target.object_id, rights)?;
                (target, grant)
            }
            Err(HandleError::NotFound)
                if matches!(
                    request.create_disposition,
                    crate::CreateDisposition::CreateNew
                        | crate::CreateDisposition::OpenOrCreate
                        | crate::CreateDisposition::OverwriteOrCreate
                ) =>
            {
                let grant = self
                    .authority
                    .authorise_volume_root(context, request.volume_id, Rights::CREATE_CHILD)
                    .map_err(AuthorisedFilesystemError::Authority)?;
                (
                    crate::namespace_planning::create_file::FileCreateAuthorityTarget {
                        object_id: grant.object_id,
                        existing_object_id: None,
                    },
                    grant,
                )
            }
            Err(error) => return Err(AuthorisedFilesystemError::Handle(error)),
        };
        validate_grant(
            FilesystemAuthorityRequest {
                context,
                volume_id: request.volume_id,
                object_id: target.object_id,
                requested_rights: if target.existing_object_id.is_some() {
                    rights_for_access(request.desired_access)
                } else {
                    Rights::CREATE_CHILD
                },
            },
            grant,
        )?;
        let prepared = self
            .filesystem
            .prepare_adapter_file_create(branch_id, context, request, policy, grant, target)
            .map_err(AuthorisedFilesystemError::Handle)?;
        self.filesystem
            .open_or_create_handle_at(&prepared, target.existing_object_id)
            .map_err(AuthorisedFilesystemError::Commit)
    }

    pub(crate) fn adapter_unlink(
        &mut self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: &AdapterUnlinkRequest,
    ) -> Result<NamespaceUnlinkReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let target = self
            .filesystem
            .adapter_unlink_target(branch_id, request)
            .map_err(AuthorisedFilesystemError::Handle)?;
        let grant = self.authorise(context, request.volume_id, target, Rights::DELETE)?;
        let publication = self
            .filesystem
            .prepare_adapter_unlink(branch_id, request, grant.principal_id, target)
            .map_err(AuthorisedFilesystemError::Handle)?;
        self.unlink_namespace(context, &publication)
    }

    pub(crate) fn adapter_rename(
        &mut self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: &AdapterRenameRequest,
    ) -> Result<NamespaceRenameReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let targets = self
            .filesystem
            .adapter_rename_targets(branch_id, request)
            .map_err(AuthorisedFilesystemError::Handle)?;
        let source = self.authorise(
            context,
            request.volume_id,
            targets.source_object,
            Rights::RENAME,
        )?;
        let destination = self.authorise(
            context,
            request.volume_id,
            targets.target_parent_object,
            Rights::CREATE_CHILD,
        )?;
        if source.principal_id != destination.principal_id {
            return Err(AuthorisedFilesystemError::InvalidGrant);
        }
        let publication = self
            .filesystem
            .prepare_adapter_rename(branch_id, request, source.principal_id, targets)
            .map_err(AuthorisedFilesystemError::Handle)?;
        self.rename_namespace(context, &publication)
    }

    pub(crate) fn adapter_close(
        &mut self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: AdapterCloseFileRequest,
        policy: FilesystemAdapterPolicy,
    ) -> Result<FilesystemHandleCloseReceipt, AuthorisedFilesystemError<A::Error>>
    where
        P: DurableContentReader,
    {
        require_adapter_context(context, request.observed_at)?;
        if request.flush.is_some_and(|flush| {
            flush.handle_id != request.handle_id || flush.observed_at != request.observed_at
        }) {
            return Err(AuthorisedFilesystemError::InvalidInput);
        }
        let target = self.handle_target(request.handle_id, context.now)?;
        let flush = request
            .flush
            .map(|flush| {
                self.authorise_handle(context, target, Rights::WRITE_DATA)
                    .map(|grant| {
                        crate::adapter::prepared_flush(
                            flush,
                            target,
                            context,
                            policy,
                            grant.identity_revision,
                        )
                    })
            })
            .transpose()?;
        let mut receipt = self.close_handle(
            context,
            FilesystemHandleCloseRequest {
                close: crate::CloseHandleRequest {
                    operation_id: request.operation_id,
                    handle_id: request.handle_id,
                    expected_fence: request.handle_fence,
                    principal_id: target.principal_id,
                    gateway_node_id: context.gateway_node_id,
                    observed_at: request.observed_at,
                },
                flush,
            },
        )?;
        if receipt.close.outcome == CloseHandleOutcome::DeleteReady {
            receipt.delete =
                Some(self.complete_adapter_delete_on_close(branch_id, context, request, target)?);
        }
        Ok(receipt)
    }

    fn complete_adapter_delete_on_close(
        &mut self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: AdapterCloseFileRequest,
        target: crate::HandleAuthorityTarget,
    ) -> Result<NamespaceUnlinkReceipt, AuthorisedFilesystemError<A::Error>> {
        if let Some(existing) = self
            .filesystem
            .resolve_namespace_unlink(request.delete_operation_id)
            .map_err(AuthorisedFilesystemError::Handle)?
        {
            return if existing.object_id == target.object_id {
                Ok(existing)
            } else {
                Err(AuthorisedFilesystemError::InvalidInput)
            };
        }
        let ready = self
            .filesystem
            .ready_namespace_delete(request.handle_id, request.observed_at)
            .map_err(AuthorisedFilesystemError::Handle)?;
        if ready.branch_id != branch_id
            || ready.volume_id != target.volume_id
            || ready.object_id != target.object_id
        {
            return Err(AuthorisedFilesystemError::InvalidInput);
        }
        let publication = self
            .filesystem
            .prepare_ready_namespace_delete(
                request.delete_operation_id,
                &ready,
                target.principal_id,
                request.observed_at,
            )
            .map_err(AuthorisedFilesystemError::Handle)?;
        self.unlink_namespace(context, &publication)
    }

    pub(crate) fn adapter_renew_lease(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterLeaseRequest,
    ) -> Result<HandleLeaseReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        let grant = self.authorise(
            context,
            target.volume_id,
            target.object_id,
            rights_for_access(target.desired_access),
        )?;
        validate_principal_and_gateway(grant, target.principal_id, context.gateway_node_id)?;
        if !request.takeover && context.gateway_node_id != target.gateway_node_id {
            return Err(AuthorisedFilesystemError::InvalidInput);
        }
        self.filesystem
            .renew_handle_lease(HandleLeaseRequest {
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                expected_fence: request.expected_fence,
                principal_id: target.principal_id,
                authorization_revision: grant.identity_revision,
                gateway_node_id: context.gateway_node_id,
                takeover: request.takeover,
                lease_expires_at: request.lease_expires_at,
                observed_at: request.observed_at,
            })
            .map_err(AuthorisedFilesystemError::HandleIo)
    }

    pub(crate) fn adapter_lock(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterLockRequest,
    ) -> Result<LockRangeReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        self.lock_range(
            context,
            LockRangeRequest {
                operation_id: request.operation_id,
                lock_id: request.lock_id,
                handle_id: request.handle_id,
                handle_fence: request.handle_fence,
                principal_id: target.principal_id,
                gateway_node_id: context.gateway_node_id,
                range: request.range,
                kind: request.kind,
                lease_expires_at: request.lease_expires_at,
                observed_at: request.observed_at,
            },
        )
    }

    pub(crate) fn adapter_unlock(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterUnlockRequest,
    ) -> Result<UnlockRangeReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        self.unlock_range(
            context,
            UnlockRangeRequest {
                operation_id: request.operation_id,
                lock_id: request.lock_id,
                handle_id: request.handle_id,
                handle_fence: request.handle_fence,
                principal_id: target.principal_id,
                gateway_node_id: context.gateway_node_id,
                observed_at: request.observed_at,
            },
        )
    }

    pub(crate) fn adapter_set_length(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterSetLengthRequest,
    ) -> Result<FilesystemHandleLengthReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        self.authorise_handle(context, target, Rights::WRITE_DATA)?;
        self.filesystem
            .set_handle_length(SetHandleLengthRequest {
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                handle_fence: request.handle_fence,
                principal_id: target.principal_id,
                gateway_node_id: context.gateway_node_id,
                logical_length: request.logical_length,
                observed_at: request.observed_at,
            })
            .map_err(AuthorisedFilesystemError::HandleIo)
    }

    pub(crate) fn adapter_set_disposition(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterSetDispositionRequest,
    ) -> Result<HandleInformationReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let target = self.handle_target(request.handle_id, context.now)?;
        self.authorise_handle(context, target, Rights::DELETE)?;
        self.filesystem
            .set_handle_disposition(SetHandleDispositionRequest {
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                handle_fence: request.handle_fence,
                principal_id: target.principal_id,
                gateway_node_id: context.gateway_node_id,
                delete_on_close: request.delete_on_close,
                observed_at: request.observed_at,
            })
            .map_err(AuthorisedFilesystemError::Handle)
    }

    pub(crate) fn adapter_begin_upload(
        &mut self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: &AdapterUploadBeginRequest,
    ) -> Result<UploadStatusReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let existing = self.filesystem.upload_session(request.upload_id).ok();
        let (target, created_at, expires_at, grant) = if let Some(session) = existing.as_ref() {
            validate_upload_begin_replay(session, request)?;
            (
                session.authority_object_id,
                session.created_at,
                session.expires_at,
                self.authorise(
                    context,
                    request.volume_id,
                    session.authority_object_id,
                    upload_rights(request.disposition),
                )?,
            )
        } else {
            let grant = match self.filesystem.upload_authority_target(
                branch_id,
                request.volume_id,
                &request.path,
                request.disposition,
            ) {
                Ok(target) => self.authorise(
                    context,
                    request.volume_id,
                    target,
                    upload_rights(request.disposition),
                )?,
                Err(HandleError::NotFound)
                    if request.disposition == crate::UploadDisposition::CreateNew =>
                {
                    let grant = self
                        .authority
                        .authorise_volume_root(context, request.volume_id, Rights::CREATE_CHILD)
                        .map_err(AuthorisedFilesystemError::Authority)?;
                    validate_grant(
                        FilesystemAuthorityRequest {
                            context,
                            volume_id: request.volume_id,
                            object_id: grant.object_id,
                            requested_rights: Rights::CREATE_CHILD,
                        },
                        grant,
                    )?;
                    grant
                }
                Err(error) => return Err(AuthorisedFilesystemError::Handle(error)),
            };
            (
                grant.object_id,
                request.observed_at,
                request.expires_at,
                grant,
            )
        };
        let prepared = UploadBeginRequest {
            operation_id: request.operation_id,
            upload_id: request.upload_id,
            stage_id: request.stage_id,
            volume_id: request.volume_id,
            authority_object_id: target,
            path: request.path.clone(),
            principal_id: grant.principal_id,
            authorization_revision: grant.identity_revision,
            disposition: request.disposition,
            maximum_bytes: request.maximum_bytes,
            created_at,
            expires_at,
        };
        self.filesystem
            .begin_upload(&prepared)
            .map_err(AuthorisedFilesystemError::Upload)?;
        self.filesystem
            .upload_status(UploadStatusRequest {
                upload_id: request.upload_id,
                principal_id: grant.principal_id,
                authorization_revision: grant.identity_revision,
                observed_at: request.observed_at,
            })
            .map_err(AuthorisedFilesystemError::Upload)
    }

    pub(crate) fn adapter_upload_status(
        &self,
        context: FilesystemAccessContext,
        request: AdapterUploadStatusRequest,
    ) -> Result<UploadStatusReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let (session, grant) = self.authorise_upload(context, request.upload_id)?;
        self.filesystem
            .upload_status(UploadStatusRequest {
                upload_id: request.upload_id,
                principal_id: session.principal_id,
                authorization_revision: grant.identity_revision,
                observed_at: request.observed_at,
            })
            .map_err(AuthorisedFilesystemError::Upload)
    }

    pub(crate) fn adapter_write_upload(
        &mut self,
        context: FilesystemAccessContext,
        request: &AdapterUploadWriteRequest,
    ) -> Result<UploadWriteReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let (session, grant) = self.authorise_upload(context, request.upload_id)?;
        self.filesystem
            .write_upload(&UploadWriteRequest {
                upload_id: request.upload_id,
                principal_id: session.principal_id,
                authorization_revision: grant.identity_revision,
                operation_id: request.operation_id,
                stage_fence: request.stage_fence,
                offset: request.offset,
                bytes: request.bytes.clone(),
                digest: request.digest,
                observed_at: request.observed_at,
            })
            .map_err(AuthorisedFilesystemError::Upload)
    }

    pub(crate) fn adapter_upload_range_page(
        &self,
        context: FilesystemAccessContext,
        request: AdapterUploadRangePageRequest,
    ) -> Result<UploadRangePageReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let (session, grant) = self.authorise_upload(context, request.upload_id)?;
        self.filesystem
            .upload_range_page(UploadRangePageRequest {
                upload_id: request.upload_id,
                principal_id: session.principal_id,
                authorization_revision: grant.identity_revision,
                expected_sequence: request.expected_sequence,
                after_start: request.after_start,
                limit: request.limit,
                observed_at: request.observed_at,
            })
            .map_err(AuthorisedFilesystemError::Upload)
    }

    pub(crate) fn adapter_abort_upload(
        &mut self,
        context: FilesystemAccessContext,
        request: AdapterUploadAbortRequest,
    ) -> Result<UploadSession, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let (session, grant) = self.authorise_upload(context, request.upload_id)?;
        self.filesystem
            .abort_upload(UploadAbortRequest {
                operation_id: request.operation_id,
                upload_id: request.upload_id,
                principal_id: session.principal_id,
                authorization_revision: grant.identity_revision,
                stage_fence: request.stage_fence,
                observed_at: request.observed_at,
            })
            .map_err(AuthorisedFilesystemError::Upload)
    }

    pub(crate) fn adapter_commit_upload(
        &mut self,
        branch_id: BranchId,
        context: FilesystemAccessContext,
        request: AdapterUploadCommitRequest,
        policy: FilesystemAdapterPolicy,
    ) -> Result<UploadCommitReceipt, AuthorisedFilesystemError<A::Error>> {
        require_adapter_context(context, request.observed_at)?;
        let (session, grant) = self.authorise_upload(context, request.upload_id)?;
        let publication = self
            .filesystem
            .prepare_upload_publication(branch_id, &session, request, policy, grant)
            .map_err(AuthorisedFilesystemError::Handle)?;
        self.filesystem
            .commit_upload(&UploadCommitRequest {
                operation_id: request.operation_id,
                upload_id: request.upload_id,
                principal_id: session.principal_id,
                authorization_revision: grant.identity_revision,
                stage_fence: request.stage_fence,
                expected_sequence: request.expected_sequence,
                final_length: request.final_length,
                sparse: request.sparse,
                expected_content_digest: request.expected_content_digest,
                publication,
                observed_at: request.observed_at,
            })
            .map_err(AuthorisedFilesystemError::Commit)
    }

    /// Returns the owned parts for orderly shutdown and composition tests.
    #[must_use]
    pub fn into_parts(self) -> (FilesystemCommitService<P>, A) {
        (self.filesystem, self.authority)
    }

    fn handle_target(
        &self,
        handle_id: meshspan_domain::HandleId,
        now: UnixMicros,
    ) -> Result<crate::HandleAuthorityTarget, AuthorisedFilesystemError<A::Error>> {
        self.filesystem
            .handle_authority_target(handle_id, now)
            .map_err(AuthorisedFilesystemError::Handle)
    }

    fn authorise_handle(
        &self,
        context: FilesystemAccessContext,
        target: crate::HandleAuthorityTarget,
        rights: Rights,
    ) -> Result<FilesystemAuthorityGrant, AuthorisedFilesystemError<A::Error>> {
        let grant = self.authorise(context, target.volume_id, target.object_id, rights)?;
        validate_principal_and_gateway(grant, target.principal_id, target.gateway_node_id)?;
        Ok(grant)
    }

    fn authorise_upload(
        &self,
        context: FilesystemAccessContext,
        upload_id: meshspan_domain::UploadId,
    ) -> Result<(UploadSession, FilesystemAuthorityGrant), AuthorisedFilesystemError<A::Error>>
    {
        let session = self
            .filesystem
            .upload_session(upload_id)
            .map_err(AuthorisedFilesystemError::Upload)?;
        let rights = match session.disposition {
            crate::UploadDisposition::CreateNew => Rights::CREATE_CHILD,
            crate::UploadDisposition::ReplaceIfVersion(_)
            | crate::UploadDisposition::ReplaceCurrent => Rights::WRITE_DATA,
        };
        let grant = self.authorise(
            context,
            session.volume_id,
            session.authority_object_id,
            rights,
        )?;
        if grant.principal_id != session.principal_id {
            return Err(AuthorisedFilesystemError::InvalidGrant);
        }
        Ok((session, grant))
    }

    fn authorise(
        &self,
        context: FilesystemAccessContext,
        volume_id: VolumeId,
        object_id: ObjectId,
        requested_rights: Rights,
    ) -> Result<FilesystemAuthorityGrant, AuthorisedFilesystemError<A::Error>> {
        if context.gateway_incarnation == 0 || requested_rights == Rights::default() {
            return Err(AuthorisedFilesystemError::InvalidInput);
        }
        let request = FilesystemAuthorityRequest {
            context,
            volume_id,
            object_id,
            requested_rights,
        };
        let grant = self
            .authority
            .authorise(request)
            .map_err(AuthorisedFilesystemError::Authority)?;
        validate_grant(request, grant)?;
        Ok(grant)
    }
}

fn require_adapter_context<E>(
    context: FilesystemAccessContext,
    observed_at: UnixMicros,
) -> Result<(), AuthorisedFilesystemError<E>> {
    if crate::adapter::valid_adapter_context(context, observed_at) {
        Ok(())
    } else {
        Err(AuthorisedFilesystemError::InvalidInput)
    }
}

fn validate_upload_begin_replay<E>(
    session: &UploadSession,
    request: &AdapterUploadBeginRequest,
) -> Result<(), AuthorisedFilesystemError<E>> {
    if session.begin_operation_id != request.operation_id
        || session.upload_id != request.upload_id
        || session.stage_id != request.stage_id
        || session.volume_id != request.volume_id
        || session.path != request.path
        || session.disposition != request.disposition
        || session.maximum_bytes != request.maximum_bytes
    {
        Err(AuthorisedFilesystemError::InvalidInput)
    } else {
        Ok(())
    }
}

const fn upload_rights(disposition: crate::UploadDisposition) -> Rights {
    match disposition {
        crate::UploadDisposition::CreateNew => Rights::CREATE_CHILD,
        crate::UploadDisposition::ReplaceIfVersion(_)
        | crate::UploadDisposition::ReplaceCurrent => Rights::WRITE_DATA,
    }
}

fn validate_grant<E>(
    request: FilesystemAuthorityRequest,
    grant: FilesystemAuthorityGrant,
) -> Result<(), AuthorisedFilesystemError<E>> {
    if grant.gateway_node_id != request.context.gateway_node_id
        || grant.gateway_incarnation != request.context.gateway_incarnation
        || grant.volume_id != request.volume_id
        || grant.object_id != request.object_id
        || grant.requested_rights != request.requested_rights
        || grant.identity_revision == Revision::ZERO
        || grant.namespace_revision == Revision::ZERO
        || grant.object_revision == Revision::ZERO
        || grant.gateway_revision == Revision::ZERO
        || grant.expires_at <= request.context.now
        || grant.evidence_digest == [0; 32]
    {
        Err(AuthorisedFilesystemError::InvalidGrant)
    } else {
        Ok(())
    }
}

fn validate_open_grant<E>(
    grant: FilesystemAuthorityGrant,
    request: &FilesystemHandleOpenRequest,
) -> Result<(), AuthorisedFilesystemError<E>> {
    validate_principal_and_gateway(
        grant,
        request.handle.principal_id,
        request.handle.gateway_node_id,
    )?;
    if grant.identity_revision == request.handle.authorization_revision {
        Ok(())
    } else {
        Err(AuthorisedFilesystemError::InvalidGrant)
    }
}

fn validate_actor<E>(
    grant: FilesystemAuthorityGrant,
    expected: PrincipalId,
) -> Result<(), AuthorisedFilesystemError<E>> {
    if grant.principal_id == expected {
        Ok(())
    } else {
        Err(AuthorisedFilesystemError::InvalidGrant)
    }
}

fn validate_principal_and_gateway<E>(
    grant: FilesystemAuthorityGrant,
    principal_id: PrincipalId,
    gateway_node_id: NodeId,
) -> Result<(), AuthorisedFilesystemError<E>> {
    if grant.principal_id == principal_id && grant.gateway_node_id == gateway_node_id {
        Ok(())
    } else {
        Err(AuthorisedFilesystemError::InvalidGrant)
    }
}

fn validate_handle_caller<E>(
    target: crate::HandleAuthorityTarget,
    principal_id: PrincipalId,
    gateway_node_id: NodeId,
    authorization_revision: Revision,
) -> Result<(), AuthorisedFilesystemError<E>> {
    if target.principal_id == principal_id
        && target.gateway_node_id == gateway_node_id
        && target.authorization_revision == authorization_revision
    {
        Ok(())
    } else {
        Err(AuthorisedFilesystemError::InvalidInput)
    }
}

fn validate_handle_identity<E>(
    target: crate::HandleAuthorityTarget,
    principal_id: PrincipalId,
    gateway_node_id: NodeId,
) -> Result<(), AuthorisedFilesystemError<E>> {
    if target.principal_id == principal_id && target.gateway_node_id == gateway_node_id {
        Ok(())
    } else {
        Err(AuthorisedFilesystemError::InvalidInput)
    }
}

fn require_same_time<E>(
    context: FilesystemAccessContext,
    operation_time: UnixMicros,
) -> Result<(), AuthorisedFilesystemError<E>> {
    if context.now == operation_time && context.credential_digest != [0; 32] {
        Ok(())
    } else {
        Err(AuthorisedFilesystemError::InvalidInput)
    }
}

fn rights_for_access(access: HandleAccess) -> Rights {
    let mut rights = Rights::default();
    if access.reads() {
        rights = rights.union(Rights::READ_DATA);
    }
    if access.writes() {
        rights = rights.union(Rights::WRITE_DATA);
    }
    if access.deletes() {
        rights = rights.union(Rights::DELETE);
    }
    rights
}

fn release_right(access: HandleAccess) -> Rights {
    if access.writes() {
        Rights::WRITE_DATA
    } else if access.reads() {
        Rights::READ_DATA
    } else {
        Rights::DELETE
    }
}

fn publication_parent(
    root_object_id: ObjectId,
    path: &crate::NamespacePublicationPath,
) -> ObjectId {
    path.ancestors()
        .last()
        .map_or(root_object_id, |ancestor| ancestor.object_id())
}

/// Stable operation boundary failures; authority denial never reaches a provider or stage write.
#[derive(Debug, Error)]
pub enum AuthorisedFilesystemError<E> {
    /// Connector context or its relationship to the operation is malformed.
    #[error("authorised filesystem input is invalid")]
    InvalidInput,
    /// The logical path did not resolve to an authority target.
    #[error("authorised filesystem target is unavailable")]
    TargetUnavailable,
    /// The authority returned a grant that did not exactly bind the request.
    #[error("filesystem authority returned an invalid grant")]
    InvalidGrant,
    /// Committed authority denied or could not safely evaluate the operation.
    #[error("filesystem access authority rejected the operation")]
    Authority(#[source] E),
    /// Handle authority or namespace resolution rejected the operation.
    #[error("authorised filesystem handle operation failed")]
    Handle(#[source] HandleError),
    /// Cross-database handle/stage orchestration rejected the operation.
    #[error("authorised filesystem handle IO failed")]
    HandleIo(#[source] HandleIoError),
    /// Durable resumable-upload orchestration rejected the operation.
    #[error("authorised filesystem upload operation failed")]
    Upload(#[source] crate::UploadServiceError),
    /// Content or namespace publication rejected the operation.
    #[error("authorised filesystem commit failed")]
    Commit(#[source] FilesystemCommitError),
    /// Verified handle read failed after authority admission.
    #[error("authorised filesystem read failed")]
    Read(#[source] HandleReadError),
    /// Immutable namespace query failed before any record was returned.
    #[error("authorised filesystem namespace query failed")]
    Query(#[source] NamespaceQueryError),
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
