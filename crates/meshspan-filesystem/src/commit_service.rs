// SPDX-License-Identifier: GPL-2.0-only

//! Recoverable composition of private stage completion, durable content and namespace publication.

use std::io::Write;
use std::path::Path;

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    PrincipalId, Revision, UnixMicros, VolumeId,
};
use thiserror::Error;

use crate::{
    CompletedStage, DirectoryPublication, DirectoryPublicationReceipt, DurableStageStore,
    FilePublication, ManifestPublication, NamespacePublicationPath, NamespacePublicationReceipt,
    PublicationError, RootFilePublication, StageCompletionRequest, StageStoreError,
    VersionPublicationStore,
};
use crate::{
    FilesystemHandleCloseReceipt, FilesystemHandleCloseRequest, FilesystemHandleCreateReceipt,
    FilesystemHandleCreateRequest, FilesystemHandleOpenRequest, FilesystemHandleWriteReceipt,
    FilesystemHandleWriteRequest,
};

const MAXIMUM_SQLITE_INTEGER: u64 = 9_223_372_036_854_775_807;

/// Exact stage and manifest identity presented to a replaceable durable-content publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentPublicationRequest {
    /// Idempotency identity shared with the namespace publication.
    pub operation_id: meshspan_domain::OperationId,
    /// Digest binding the stage checkpoint and complete namespace mutation intent.
    pub request_digest: [u8; 32],
    /// Stable identity reserved for the resulting manifest root.
    pub manifest_id: ContentManifestId,
    /// Selected manifest encoding version.
    pub format_version: u16,
    /// Exact logical length expected from stage completion.
    pub logical_length: u64,
    /// Authoritative revision that admitted storage publication.
    pub authorization_revision: Revision,
    /// Exclusive deadline for new provider work.
    pub deadline: UnixMicros,
    /// Current authoritative attempt time; exact retry may advance this value.
    pub observed_at: UnixMicros,
}

impl ContentPublicationRequest {
    /// Compares immutable operation intent while excluding the advancing attempt time.
    #[must_use]
    pub fn same_intent(self, other: Self) -> bool {
        self.operation_id == other.operation_id
            && self.request_digest == other.request_digest
            && self.manifest_id == other.manifest_id
            && self.format_version == other.format_version
            && self.logical_length == other.logical_length
            && self.authorization_revision == other.authorization_revision
            && self.deadline == other.deadline
    }
}

/// Replaceable boundary that turns an exact logical byte stream into a durable manifest.
///
/// `finish` may return success only after all bytes required by the returned manifest are durable
/// and independently verified. Exact retries must either resolve the same manifest or reject
/// conflicting input; an interrupted unpublished sink must never be reported as durable content.
pub trait DurableContentPublisher {
    /// Private, unpublished destination for one completion attempt.
    type Sink: Write;

    /// Resolves an already durable exact publication without restreaming the stage.
    ///
    /// # Errors
    ///
    /// Rejects conflicting operation reuse, corrupt durable state and unavailable persistence.
    fn resolve(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentPublicationError>;

    /// Starts or resumes one private content-publication attempt.
    ///
    /// # Errors
    ///
    /// Rejects conflicting input, unsafe bounds and unavailable private storage.
    fn begin(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Self::Sink, ContentPublicationError>;

    /// Verifies and durably publishes the completed sink as one immutable manifest.
    ///
    /// # Errors
    ///
    /// Rejects byte/digest mismatch, conflicting replay and incomplete durability evidence.
    fn finish(
        &mut self,
        request: ContentPublicationRequest,
        sink: Self::Sink,
        completed: CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError>;
}

/// Complete root-file save intent excluding the manifest produced from the selected stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootFileCommitRequest {
    /// Exact private stage checkpoint and completion rules.
    pub completion: StageCompletionRequest,
    /// Writable local/cell branch receiving the version.
    pub branch_id: BranchId,
    /// Volume containing the stable file object.
    pub volume_id: VolumeId,
    /// Stable file identity.
    pub object_id: ObjectId,
    /// Exact prior current version, or none for creation.
    pub expected_current_version_id: Option<FileVersionId>,
    /// New immutable file-version identity.
    pub version_id: FileVersionId,
    /// Whether the superseded current version enters ordinary version history.
    pub retain_superseded_history: bool,
    /// Exact replicated retention-policy sequence used for the history decision.
    pub retention_policy_sequence: u64,
    /// Reserved immutable content-manifest identity.
    pub manifest_id: ContentManifestId,
    /// Selected content-manifest encoding version.
    pub manifest_format_version: u16,
    /// Authoritative revision that admitted content placement.
    pub content_authorization_revision: Revision,
    /// Exclusive deadline for new content-provider work.
    pub content_deadline: UnixMicros,
    /// Stable volume-root directory identity.
    pub root_object_id: ObjectId,
    /// Exact prior namespace commit, or none for initial creation.
    pub expected_namespace_commit_id: Option<NamespaceCommitId>,
    /// Exact prior file-object revision selected by the old root.
    pub expected_file_object_revision_id: Option<ObjectRevisionId>,
    /// New file-object revision identity.
    pub file_object_revision_id: ObjectRevisionId,
    /// New root-directory object revision identity.
    pub root_object_revision_id: ObjectRevisionId,
    /// New immutable namespace-commit identity.
    pub namespace_commit_id: NamespaceCommitId,
    /// Validated root-relative path and exact existing child-directory transitions.
    pub path: NamespacePublicationPath,
    /// Stable name-reuse generation.
    pub entry_generation: u64,
    /// Principal responsible for the save.
    pub created_by: PrincipalId,
    /// Authoritative save instant.
    pub created_at: UnixMicros,
}

impl RootFileCommitRequest {
    /// Derives the exact content-publication contract shared with recovery and verified reads.
    #[must_use]
    pub fn content_publication_request(&self) -> ContentPublicationRequest {
        ContentPublicationRequest {
            operation_id: self.completion.operation_id,
            request_digest: commit_request_digest(self),
            manifest_id: self.manifest_id,
            format_version: self.manifest_format_version,
            logical_length: self.completion.final_length,
            authorization_revision: self.content_authorization_revision,
            deadline: self.content_deadline,
            observed_at: self.completion.observed_at,
        }
    }
}

/// Filesystem save service over independent stage, content and branch durability domains.
pub struct FilesystemCommitService<P> {
    stages: DurableStageStore,
    publications: VersionPublicationStore,
    content: P,
}

impl<P: DurableContentPublisher> FilesystemCommitService<P> {
    /// Opens the private-stage and branch stores beneath one daemon state directory.
    ///
    /// # Errors
    ///
    /// Rejects migration drift, integrity failure and state-directory IO errors.
    pub fn open(
        state_directory: &Path,
        opened_at: UnixMicros,
        content: P,
    ) -> Result<Self, FilesystemCommitError> {
        Ok(Self {
            stages: DurableStageStore::open(state_directory, opened_at)?,
            publications: VersionPublicationStore::open(state_directory, opened_at)?,
            content,
        })
    }

    /// Gives controlled access to the private stage service before commit.
    #[must_use]
    pub fn stages_mut(&mut self) -> &mut DurableStageStore {
        &mut self.stages
    }

    /// Opens a logical file and establishes its bounded private stage before a writable handle
    /// can be returned.
    ///
    /// An interrupted attempt may leave an empty unreachable stage, but never an acknowledged
    /// writable handle without its exact stage. Exact retry reuses both identities.
    ///
    /// # Errors
    ///
    /// Rejects malformed stage policy, unsafe opens, sharing conflicts, stale authority,
    /// corrupt durable state and persistence failure.
    pub fn open_handle(
        &mut self,
        request: &FilesystemHandleOpenRequest,
    ) -> Result<crate::OpenHandleReceipt, crate::HandleIoError> {
        crate::handle_io::open(&mut self.stages, &mut self.publications, request)
    }

    /// Atomically opens an existing file or creates its empty first version and reserves a handle.
    ///
    /// Durable empty content is prepared before the final transaction. Namespace visibility and
    /// handle admission then commit together, so no observer can race into the newly created path
    /// before the creator owns its requested share mode. Interrupted content work may leave only
    /// unreachable immutable bytes; exact retry resolves the same content and metadata identities.
    ///
    /// # Errors
    ///
    /// Rejects non-creating dispositions, non-empty or mismatched creation plans, unsafe stage
    /// policy, stale namespace bases, sharing conflicts, identity reuse and persistence failure.
    pub fn open_or_create_handle(
        &mut self,
        request: &FilesystemHandleCreateRequest,
    ) -> Result<FilesystemHandleCreateReceipt, FilesystemCommitError> {
        validate_handle_creation(request)?;
        if let Some(handle) = self
            .publications
            .resolve_open_request(&request.open.handle)?
        {
            let creation = self
                .publications
                .resolve_namespace_publication(request.initial_file.completion.operation_id)?;
            validate_creation_replay(request, handle, creation)?;
            return Ok(FilesystemHandleCreateReceipt { handle, creation });
        }

        match self
            .publications
            .preflight_open_handle(&request.open.handle)
        {
            Ok(()) => {
                let handle =
                    crate::handle_io::open(&mut self.stages, &mut self.publications, &request.open)
                        .map_err(map_handle_io)?;
                Ok(FilesystemHandleCreateReceipt {
                    handle,
                    creation: None,
                })
            }
            Err(crate::HandleError::CreationRequired) => {
                crate::handle_io::prepare_stage(&mut self.stages, &request.open, false)
                    .map_err(map_handle_io)?;
                let manifest = self.publish_empty_creation_content(&request.initial_file)?;
                let publication = root_publication(&request.initial_file, manifest);
                let (creation, handle) = self
                    .publications
                    .publish_root_file_and_open(&publication, &request.open.handle)?;
                Ok(FilesystemHandleCreateReceipt {
                    handle,
                    creation: Some(creation),
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    fn publish_empty_creation_content(
        &mut self,
        request: &RootFileCommitRequest,
    ) -> Result<ManifestPublication, FilesystemCommitError> {
        let content_request = request.content_publication_request();
        let manifest = if let Some(manifest) = self.content.resolve(content_request)? {
            manifest
        } else {
            let sink = self.content.begin(content_request)?;
            self.content.finish(
                content_request,
                sink,
                CompletedStage {
                    logical_length: 0,
                    content_digest: *blake3::hash(&[]).as_bytes(),
                },
            )?
        };
        validate_manifest(content_request, manifest, None)?;
        Ok(manifest)
    }

    /// Orders one range against live locks before durably writing immutable private-stage bytes.
    ///
    /// The authority admission and stage journal deliberately use separate databases. A crash
    /// between them leaves a replayable admission but no falsely acknowledged bytes; exact retry
    /// completes or resolves the stage write.
    ///
    /// # Errors
    ///
    /// Rejects stale/substituted handles, missing write access, conflicting locks, forged bytes,
    /// unsafe bounds, corrupt receipts and persistence failure.
    pub fn write_handle(
        &mut self,
        request: &FilesystemHandleWriteRequest,
    ) -> Result<FilesystemHandleWriteReceipt, crate::HandleIoError> {
        crate::handle_io::write(&mut self.stages, &mut self.publications, request)
    }

    /// Renews a handle and its private stage, or transfers both under one higher fence.
    ///
    /// The stage transition is preflighted, then the authoritative handle transition is durable,
    /// then the stage follows. A crash between databases exposes no successful service response;
    /// exact retry replays the handle receipt and completes the stage transition.
    ///
    /// # Errors
    ///
    /// Rejects stale fences, substituted authority, shrinking/expired leases, operation conflicts,
    /// corrupt state and persistence failure.
    pub fn renew_handle_lease(
        &mut self,
        request: crate::HandleLeaseRequest,
    ) -> Result<crate::HandleLeaseReceipt, crate::HandleIoError> {
        crate::handle_io::renew_lease(&mut self.stages, &mut self.publications, request)
    }

    /// Publishes one exact durable handle checkpoint as a new immutable file version.
    ///
    /// The authority first persists the selected namespace basis and derived identities. Content
    /// durability then precedes the atomic namespace transition. Exact retry resolves a completed
    /// result or reconstructs the original plan; it never silently rebases onto a newer head.
    ///
    /// # Errors
    ///
    /// Rejects stale/substituted authority, stale checkpoints or namespace bases, incomplete
    /// non-sparse content, conflicting retries, corrupt evidence and persistence failures.
    pub fn flush_handle(
        &mut self,
        request: crate::FilesystemHandleFlushRequest,
    ) -> Result<NamespacePublicationReceipt, FilesystemCommitError>
    where
        P: crate::DurableContentReader,
    {
        let plan = self.publications.prepare_handle_flush(request)?;
        if let Some(receipt) = self.resolve(request.operation_id)? {
            return Ok(receipt);
        }
        let base = self.publications.handle_base_content(request.handle_id)?;
        self.commit_handle_plan(&plan, base, request)
    }

    /// Flushes an exact dirty checkpoint when required, then releases the fenced handle.
    ///
    /// A failed or interrupted flush leaves the handle live. A crash after publication but before
    /// close is recovered by replaying the same flush plan and then applying the close exactly
    /// once; clean and read-only closes perform no content work.
    ///
    /// # Errors
    ///
    /// Rejects missing or unnecessary flush plans, stale checkpoints/fences, substituted
    /// authority, incomplete content and every underlying durable-state failure.
    pub fn close_handle(
        &mut self,
        request: FilesystemHandleCloseRequest,
    ) -> Result<FilesystemHandleCloseReceipt, FilesystemCommitError>
    where
        P: crate::DurableContentReader,
    {
        validate_close_flush(request)?;
        if let Some(close) = self.publications.resolve_close_request(request.close)? {
            let flush = request
                .flush
                .map(|flush| self.flush_handle(flush))
                .transpose()?;
            return Ok(FilesystemHandleCloseReceipt { flush, close });
        }

        let uses_stage = self
            .publications
            .handle_uses_private_stage(request.close.handle_id)?;
        let (checkpoint_sequence, committed_sequence) = if uses_stage {
            let stage_id =
                crate::handle_io::stage_id(request.close.handle_id).map_err(map_handle_io)?;
            (
                self.stages.checkpoint(stage_id)?.sequence,
                self.publications
                    .handle_committed_stage_sequence(request.close.handle_id)?,
            )
        } else {
            (0, 0)
        };
        if checkpoint_sequence < committed_sequence {
            return Err(crate::HandleError::Corrupt.into());
        }
        let dirty = checkpoint_sequence > committed_sequence;
        let flush_already_published = request
            .flush
            .map(|flush| self.resolve(flush.operation_id))
            .transpose()?
            .flatten()
            .is_some();
        match (dirty, request.flush, flush_already_published) {
            (true, None, _) | (false, Some(_), false) => {
                return Err(FilesystemCommitError::InvalidInput);
            }
            _ => {}
        }
        let flush = request
            .flush
            .map(|flush| self.flush_handle(flush))
            .transpose()?;
        let close = self.publications.close_handle(request.close)?;
        Ok(FilesystemHandleCloseReceipt { flush, close })
    }

    fn commit_handle_plan(
        &mut self,
        request: &RootFileCommitRequest,
        base: Option<crate::PublishedContentReference>,
        flush: crate::FilesystemHandleFlushRequest,
    ) -> Result<NamespacePublicationReceipt, FilesystemCommitError>
    where
        P: crate::DurableContentReader,
    {
        validate_request(request)?;
        let content_request = request.content_publication_request();
        let (manifest, completed) = if let Some(manifest) = self.content.resolve(content_request)? {
            (manifest, None)
        } else {
            let mut sink = self.content.begin(content_request)?;
            let completed = if let Some(base) = base {
                let prefix = base
                    .manifest
                    .logical_length
                    .min(request.completion.final_length);
                let read = crate::ContentReadRequest {
                    operation_id: flush.operation_id,
                    content: base,
                    offset: 0,
                    length: prefix,
                    authorization_revision: flush.authorization_revision,
                    deadline: flush.content_deadline,
                    observed_at: flush.observed_at,
                };
                let stages = &mut self.stages;
                let content = &mut self.content;
                stages.stream_complete_with_base(
                    request.completion,
                    base.manifest.logical_length,
                    |destination| {
                        content
                            .stream_range(read, destination)
                            .map_err(map_content_read_to_stage)
                    },
                    &mut sink,
                )?
            } else {
                self.stages.stream_complete(request.completion, &mut sink)?
            };
            (
                self.content.finish(content_request, sink, completed)?,
                Some(completed),
            )
        };
        validate_manifest(content_request, manifest, completed)?;
        self.publications
            .publish_root_file(&root_publication(request, manifest))
            .map_err(Into::into)
    }

    /// Creates one empty directory and atomically publishes every copied ancestor revision.
    ///
    /// # Errors
    ///
    /// Rejects malformed paths, stale namespace state, conflicting identities, corruption and
    /// persistence failure. Exact retries resolve the original durable result.
    pub fn create_directory(
        &mut self,
        publication: &DirectoryPublication,
    ) -> Result<DirectoryPublicationReceipt, FilesystemCommitError> {
        self.publications
            .create_directory(publication)
            .map_err(Into::into)
    }

    /// Commits one exact stage as durable content and then atomically advances the namespace head.
    ///
    /// Content publication is independently idempotent and precedes namespace visibility. A crash
    /// may leave unreachable immutable content, but never a visible file without its complete
    /// manifest. Exact retry resolves content before touching an expired stage and the namespace
    /// transaction resolves a lost final response by the same operation identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed relationships, stale stages/heads, conflicting identity reuse, corrupt
    /// content evidence and every persistence failure.
    pub fn commit_root_file(
        &mut self,
        request: &RootFileCommitRequest,
    ) -> Result<NamespacePublicationReceipt, FilesystemCommitError> {
        validate_request(request)?;
        let content_request = request.content_publication_request();
        let (manifest, completed) = if let Some(manifest) = self.content.resolve(content_request)? {
            (manifest, None)
        } else {
            let mut sink = self.content.begin(content_request)?;
            let completed = self.stages.stream_complete(request.completion, &mut sink)?;
            (
                self.content.finish(content_request, sink, completed)?,
                Some(completed),
            )
        };
        validate_manifest(content_request, manifest, completed)?;
        self.publications
            .publish_root_file(&root_publication(request, manifest))
            .map_err(Into::into)
    }

    /// Resolves the final atomic namespace result after a lost response.
    ///
    /// # Errors
    ///
    /// Rejects malformed or corrupt durable branch records.
    pub fn resolve(
        &self,
        operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<NamespacePublicationReceipt>, FilesystemCommitError> {
        self.publications
            .resolve_namespace_publication(operation_id)
            .map_err(Into::into)
    }

    /// Returns the owned content publisher, primarily for orderly daemon shutdown and tests.
    #[must_use]
    pub fn into_content_publisher(self) -> P {
        self.content
    }
}

/// Stable failures from the durable-content boundary.
#[derive(Debug, Error)]
pub enum ContentPublicationError {
    /// Input fields, bounds or relationships are invalid.
    #[error("content publication input is invalid")]
    InvalidInput,
    /// An idempotency or immutable identity belongs to different canonical input.
    #[error("content publication identity conflicts with durable state")]
    Conflict,
    /// Stored bytes, receipts or manifest records violate an invariant.
    #[error("content publication state is corrupt")]
    Corrupt,
    /// Required storage or authority is temporarily unavailable.
    #[error("content publication is unavailable")]
    Unavailable,
    /// Private content IO failed.
    #[error("content publication IO failed")]
    Io(#[from] std::io::Error),
}

/// Stable failures from the complete filesystem save composition.
#[derive(Debug, Error)]
pub enum FilesystemCommitError {
    /// Save fields or relationships are invalid before any content is published.
    #[error("filesystem commit input is invalid")]
    InvalidInput,
    /// Private stage completion failed.
    #[error("filesystem commit stage failed")]
    Stage(#[from] StageStoreError),
    /// Durable content publication failed.
    #[error("filesystem commit content publication failed")]
    Content(#[from] ContentPublicationError),
    /// Atomic namespace publication failed.
    #[error("filesystem commit namespace publication failed")]
    Publication(#[from] PublicationError),
    /// Handle authority rejected planning before content IO began.
    #[error("filesystem commit handle authority failed")]
    Handle(#[from] crate::HandleError),
}

fn validate_request(request: &RootFileCommitRequest) -> Result<(), FilesystemCommitError> {
    if request.manifest_format_version == 0
        || request.retention_policy_sequence == 0
        || request.retention_policy_sequence > MAXIMUM_SQLITE_INTEGER
        || request.content_deadline <= request.completion.observed_at
        || request.entry_generation == 0
        || request.object_id == request.root_object_id
        || request.file_object_revision_id == request.root_object_revision_id
    {
        Err(FilesystemCommitError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_handle_creation(
    request: &FilesystemHandleCreateRequest,
) -> Result<(), FilesystemCommitError> {
    validate_request(&request.initial_file)?;
    let open = &request.open.handle;
    let file = &request.initial_file;
    let creates = matches!(
        open.create_disposition,
        crate::CreateDisposition::CreateNew
            | crate::CreateDisposition::OpenOrCreate
            | crate::CreateDisposition::OverwriteOrCreate
    );
    let stage_id = crate::handle_io::stage_id(open.handle_id).map_err(map_handle_io)?;
    if !creates
        || file.completion.operation_id == open.operation_id
        || file.completion.stage_id != stage_id
        || file.completion.stage_fence != 1
        || file.completion.expected_sequence != 0
        || file.completion.final_length != 0
        || file.completion.sparse
        || file.expected_current_version_id.is_some()
        || file.expected_file_object_revision_id.is_some()
        || file.branch_id != open.branch_id
        || file.volume_id != open.volume_id
        || file.path.path() != &open.path
        || file.created_by != open.principal_id
        || file.created_at != open.opened_at
        || file.content_authorization_revision != open.authorization_revision
    {
        Err(FilesystemCommitError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_close_flush(
    request: FilesystemHandleCloseRequest,
) -> Result<(), FilesystemCommitError> {
    if let Some(flush) = request.flush
        && (flush.operation_id == request.close.operation_id
            || flush.handle_id != request.close.handle_id
            || flush.handle_fence != request.close.expected_fence
            || flush.principal_id != request.close.principal_id
            || flush.gateway_node_id != request.close.gateway_node_id
            || flush.observed_at > request.close.observed_at)
    {
        return Err(FilesystemCommitError::InvalidInput);
    }
    Ok(())
}

fn validate_creation_replay(
    request: &FilesystemHandleCreateRequest,
    handle: crate::OpenHandleReceipt,
    creation: Option<NamespacePublicationReceipt>,
) -> Result<(), FilesystemCommitError> {
    let handle_matches_creation = handle.object_id == request.initial_file.object_id
        && handle.object_revision_id == request.initial_file.file_object_revision_id
        && handle.opened_version_id == request.initial_file.version_id
        && handle.namespace_commit_id == request.initial_file.namespace_commit_id;
    match (handle_matches_creation, creation) {
        (true, Some(creation))
            if creation.operation_id == request.initial_file.completion.operation_id
                && creation.file_version_id == request.initial_file.version_id
                && creation.namespace_commit_id == request.initial_file.namespace_commit_id =>
        {
            Ok(())
        }
        (false, None) => Ok(()),
        (true, None) => Err(crate::HandleError::Corrupt.into()),
        (true | false, Some(_)) => Err(crate::HandleError::OperationConflict.into()),
    }
}

fn map_handle_io(error: crate::HandleIoError) -> FilesystemCommitError {
    match error {
        crate::HandleIoError::InvalidInput => FilesystemCommitError::InvalidInput,
        crate::HandleIoError::Handle(error) => FilesystemCommitError::Handle(error),
        crate::HandleIoError::Stage(error) => FilesystemCommitError::Stage(error),
    }
}

fn validate_manifest(
    request: ContentPublicationRequest,
    manifest: ManifestPublication,
    completed: Option<CompletedStage>,
) -> Result<(), FilesystemCommitError> {
    if manifest.manifest_id != request.manifest_id
        || manifest.format_version != request.format_version
        || manifest.logical_length != request.logical_length
        || completed.is_some_and(|completed| {
            manifest.logical_length != completed.logical_length
                || manifest.content_digest != completed.content_digest
        })
    {
        Err(ContentPublicationError::Corrupt.into())
    } else {
        Ok(())
    }
}

fn map_content_read_to_stage(error: crate::ContentReadError) -> StageStoreError {
    match error {
        crate::ContentReadError::InvalidInput => StageStoreError::InvalidInput,
        crate::ContentReadError::Conflict => StageStoreError::OperationConflict,
        crate::ContentReadError::Corrupt => StageStoreError::Corrupt,
        crate::ContentReadError::Unavailable => StageStoreError::Unavailable,
        crate::ContentReadError::Io(error) => StageStoreError::Io(error),
    }
}

fn root_publication(
    request: &RootFileCommitRequest,
    manifest: ManifestPublication,
) -> RootFilePublication {
    RootFilePublication {
        file: FilePublication {
            operation_id: request.completion.operation_id,
            branch_id: request.branch_id,
            volume_id: request.volume_id,
            object_id: request.object_id,
            expected_current_version_id: request.expected_current_version_id,
            version_id: request.version_id,
            parent_version_id: request.expected_current_version_id,
            retain_superseded_history: request.retain_superseded_history,
            retention_policy_sequence: request.retention_policy_sequence,
            manifest,
            created_by: request.created_by,
            created_at: request.created_at,
        },
        root_object_id: request.root_object_id,
        expected_namespace_commit_id: request.expected_namespace_commit_id,
        expected_file_object_revision_id: request.expected_file_object_revision_id,
        file_object_revision_id: request.file_object_revision_id,
        root_object_revision_id: request.root_object_revision_id,
        namespace_commit_id: request.namespace_commit_id,
        path: request.path.clone(),
        entry_generation: request.entry_generation,
    }
}

pub(crate) fn commit_request_digest(request: &RootFileCommitRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.commit-root-file.v2\0");
    digest.update(&request.completion.operation_id.as_bytes());
    digest.update(&request.completion.stage_id.as_bytes());
    digest.update(&request.completion.stage_fence.to_be_bytes());
    digest.update(&request.completion.expected_sequence.to_be_bytes());
    digest.update(&request.completion.final_length.to_be_bytes());
    digest.update(&[u8::from(request.completion.sparse)]);
    digest.update(&request.branch_id.as_bytes());
    digest.update(&request.volume_id.as_bytes());
    digest.update(&request.object_id.as_bytes());
    update_optional(
        &mut digest,
        request
            .expected_current_version_id
            .map(FileVersionId::as_bytes),
    );
    digest.update(&request.version_id.as_bytes());
    digest.update(&[u8::from(request.retain_superseded_history)]);
    digest.update(&request.retention_policy_sequence.to_be_bytes());
    digest.update(&request.manifest_id.as_bytes());
    digest.update(&request.manifest_format_version.to_be_bytes());
    digest.update(&request.content_authorization_revision.get().to_be_bytes());
    digest.update(&request.content_deadline.get().to_be_bytes());
    digest.update(&request.root_object_id.as_bytes());
    update_optional(
        &mut digest,
        request
            .expected_namespace_commit_id
            .map(NamespaceCommitId::as_bytes),
    );
    update_optional(
        &mut digest,
        request
            .expected_file_object_revision_id
            .map(ObjectRevisionId::as_bytes),
    );
    digest.update(&request.file_object_revision_id.as_bytes());
    digest.update(&request.root_object_revision_id.as_bytes());
    digest.update(&request.namespace_commit_id.as_bytes());
    update_publication_path(&mut digest, &request.path);
    digest.update(&request.entry_generation.to_be_bytes());
    digest.update(&request.created_by.as_bytes());
    digest.update(&request.created_at.get().to_be_bytes());
    digest.finalize().into()
}

fn update_optional(digest: &mut blake3::Hasher, value: Option<[u8; 16]>) {
    if let Some(value) = value {
        digest.update(&[1]);
        digest.update(&value);
    } else {
        digest.update(&[0]);
    }
}

fn update_text(digest: &mut blake3::Hasher, value: &str) {
    digest.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value.as_bytes());
}

fn update_publication_path(digest: &mut blake3::Hasher, path: &NamespacePublicationPath) {
    digest.update(
        &u16::try_from(path.path().components().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    for component in path.path().components() {
        update_text(digest, component.canonical());
        update_text(digest, component.display());
    }
    for transition in path.ancestors() {
        digest.update(&transition.object_id().as_bytes());
        digest.update(&transition.expected_revision_id().as_bytes());
        digest.update(&transition.new_revision_id().as_bytes());
    }
}

#[cfg(test)]
#[path = "commit_service_tests.rs"]
mod tests;
