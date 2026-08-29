// SPDX-License-Identifier: GPL-2.0-only

//! Connector-neutral operation-time authority for the logical filesystem service.

use meshspan_domain::{
    AssuranceLevel, NodeId, ObjectId, PrincipalId, Revision, Rights, UnixMicros, VolumeId,
};
use thiserror::Error;

use crate::{
    DirectoryPublication, DurableContentPublisher, DurableContentReader, FilesystemCommitError,
    FilesystemCommitService, FilesystemHandleCloseReceipt, FilesystemHandleCloseRequest,
    FilesystemHandleCreateReceipt, FilesystemHandleCreateRequest, FilesystemHandleFlushRequest,
    FilesystemHandleOpenRequest, FilesystemHandleWriteReceipt, FilesystemHandleWriteRequest,
    HandleAccess, HandleError, HandleIoError, HandleLeaseReceipt, HandleLeaseRequest,
    LockRangeReceipt, LockRangeRequest, NamespacePublicationReceipt, NamespaceRenamePublication,
    NamespaceRenameReceipt, NamespaceUnlinkPublication, NamespaceUnlinkReceipt, OpenHandleReceipt,
    RangeLockKind, UnlockRangeReceipt, UnlockRangeRequest,
};

/// Authenticated connector context supplied independently of a filesystem operation payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemAccessContext {
    /// Digest of the presented session secret; raw credentials never enter filesystem state.
    pub token_digest: [u8; 32],
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
        self.authorise_handle(context, target, Rights::WRITE_DATA)?;
        validate_handle_caller(
            target,
            request.principal_id,
            request.gateway_node_id,
            request.authorization_revision,
        )?;
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
            self.authorise_handle(context, target, Rights::WRITE_DATA)?;
            validate_handle_caller(
                target,
                flush.principal_id,
                flush.gateway_node_id,
                flush.authorization_revision,
            )?;
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
    if context.now == operation_time && context.token_digest != [0; 32] {
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
    /// Content or namespace publication rejected the operation.
    #[error("authorised filesystem commit failed")]
    Commit(#[source] FilesystemCommitError),
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
