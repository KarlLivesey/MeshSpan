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
}

fn validate_request(request: &RootFileCommitRequest) -> Result<(), FilesystemCommitError> {
    if request.manifest_format_version == 0
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

fn commit_request_digest(request: &RootFileCommitRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.commit-root-file.v1\0");
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
