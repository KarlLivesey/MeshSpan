// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, Revision, StageId, UnixMicros, UploadId, VolumeId,
};
use tempfile::tempdir;

use crate::{
    CompletedStage, ContentPublicationError, ContentPublicationRequest, DurableContentPublisher,
    FilesystemCommitError, FilesystemCommitService, ManifestPublication, NamespaceLimits,
    NamespacePath, NamespacePublicationPath, PublicationDisposition, RootFileCommitRequest,
    StageCompletionRequest, UploadAbortRequest, UploadBeginRequest, UploadCommitRequest,
    UploadDisposition, UploadRangePageRequest, UploadServiceError, UploadState,
    UploadStatusRequest, UploadWriteRequest,
};

#[test]
fn upload_ranges_resume_after_restart_and_abort_never_publish()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let begin = begin_request()?;
    let mut service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(1), UnusedPublisher)?;
    let created = service.begin_upload(&begin)?;
    assert_eq!(created.state, UploadState::Active);
    assert_eq!(service.begin_upload(&begin)?, created);

    let tail = write_request(&begin, 20, 5, b"world")?;
    let head = write_request(&begin, 21, 0, b"hello")?;
    assert_eq!(service.write_upload(&tail)?.checkpoint.sequence, 1);
    assert_eq!(service.write_upload(&head)?.checkpoint.sequence, 2);
    assert_eq!(service.write_upload(&head)?.checkpoint.sequence, 2);
    drop(service);

    let mut reopened =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(4), UnusedPublisher)?;
    let status = reopened.upload_status(status_request(&begin, UnixMicros::new(4)))?;
    assert_eq!(status.session, created);
    assert_eq!(status.checkpoint.sequence, 2);
    assert_eq!(status.checkpoint.logical_extent, 10);
    assert_eq!(status.checkpoint.initialised_ranges, vec![0..10]);

    let abort = UploadAbortRequest {
        operation_id: OperationId::from_bytes([30; 16])?,
        upload_id: begin.upload_id,
        principal_id: begin.principal_id,
        authorization_revision: Revision::new(7),
        stage_fence: 1,
        observed_at: UnixMicros::new(5),
    };
    assert_eq!(reopened.abort_upload(abort)?.state, UploadState::Aborted);
    assert_eq!(reopened.abort_upload(abort)?.state, UploadState::Aborted);
    assert!(matches!(
        reopened.write_upload(&write_request(&begin, 31, 10, b"hidden")?),
        Err(UploadServiceError::StaleAuthority
            | UploadServiceError::Stage(crate::StageStoreError::Stale))
    ));
    Ok(())
}

#[test]
fn upload_identity_and_authority_substitution_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let begin = begin_request()?;
    let mut service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(1), UnusedPublisher)?;
    service.begin_upload(&begin)?;
    let mut conflict = begin.clone();
    conflict.maximum_bytes += 1;
    assert!(matches!(
        service.begin_upload(&conflict),
        Err(UploadServiceError::OperationConflict)
    ));
    let mut substituted = write_request(&begin, 40, 0, b"attack")?;
    substituted.principal_id = PrincipalId::from_bytes([41; 16])?;
    assert!(matches!(
        service.write_upload(&substituted),
        Err(UploadServiceError::StaleAuthority)
    ));
    Ok(())
}

#[test]
fn upload_range_pages_are_bounded_merged_and_checkpoint_pinned()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let begin = begin_request()?;
    let mut service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(1), UnusedPublisher)?;
    service.begin_upload(&begin)?;
    service.write_upload(&write_request(&begin, 42, 0, b"a")?)?;
    service.write_upload(&write_request(&begin, 43, 2, b"b")?)?;
    service.write_upload(&write_request(&begin, 44, 4, b"c")?)?;

    let first = service.upload_range_page(range_page_request(&begin, None, None, 2))?;
    assert_eq!(first.checkpoint_sequence, 3);
    assert_eq!(first.ranges, vec![0..1, 2..3]);
    assert_eq!(first.next_after_start, Some(2));
    let second = service.upload_range_page(range_page_request(
        &begin,
        Some(first.checkpoint_sequence),
        first.next_after_start,
        2,
    ))?;
    assert_eq!(second.ranges, vec![4..5]);
    assert_eq!(second.next_after_start, None);

    service.write_upload(&write_request(&begin, 45, 1, b"x")?)?;
    assert!(matches!(
        service.upload_range_page(range_page_request(&begin, Some(3), Some(2), 2)),
        Err(UploadServiceError::Stage(crate::StageStoreError::Stale))
    ));
    let merged = service.upload_range_page(range_page_request(&begin, None, None, 2))?;
    assert_eq!(merged.checkpoint_sequence, 4);
    assert_eq!(merged.ranges, vec![0..3, 4..5]);
    assert_eq!(merged.next_after_start, None);
    Ok(())
}

#[test]
fn incomplete_commit_stays_writable_then_publishes_once_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let begin = begin_request()?;
    let mut service = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(1),
        RecordingPublisher::default(),
    )?;
    service.begin_upload(&begin)?;
    service.write_upload(&write_request(&begin, 50, 5, b"world")?)?;
    let mut commit = commit_request(&begin, 1, UnixMicros::new(4))?;
    assert!(matches!(
        service.commit_upload(&commit),
        Err(FilesystemCommitError::Upload(
            UploadServiceError::Incomplete
        ))
    ));
    assert_eq!(
        service
            .upload_status(status_request(&begin, UnixMicros::new(5)))?
            .session
            .state,
        UploadState::Active
    );

    service.write_upload(&write_request(&begin, 51, 0, b"hello")?)?;
    commit = commit_request(&begin, 2, UnixMicros::new(6))?;
    commit.expected_content_digest = Some([99; 32]);
    assert!(matches!(
        service.commit_upload(&commit),
        Err(FilesystemCommitError::Upload(
            UploadServiceError::ContentMismatch
        ))
    ));
    assert_eq!(
        service
            .upload_status(status_request(&begin, UnixMicros::new(6)))?
            .session
            .state,
        UploadState::Active
    );
    commit.expected_content_digest = Some(blake3::hash(b"helloworld").into());
    let applied = service.commit_upload(&commit)?;
    assert_eq!(
        applied.publication.disposition,
        PublicationDisposition::Applied
    );
    assert_eq!(applied.session.state, UploadState::Committed);
    assert_eq!(
        applied.session.committed_object_id,
        Some(commit.publication.object_id)
    );
    assert_eq!(
        applied.session.committed_version_id,
        Some(commit.publication.version_id)
    );
    let replayed = service.commit_upload(&commit)?;
    assert_eq!(
        replayed.publication.disposition,
        PublicationDisposition::Replayed
    );
    assert_eq!(replayed.session, applied.session);
    Ok(())
}

fn begin_request() -> Result<UploadBeginRequest, Box<dyn std::error::Error>> {
    Ok(UploadBeginRequest {
        operation_id: OperationId::from_bytes([10; 16])?,
        upload_id: UploadId::from_bytes([11; 16])?,
        stage_id: StageId::from_bytes([12; 16])?,
        volume_id: VolumeId::from_bytes([13; 16])?,
        authority_object_id: ObjectId::from_bytes([15; 16])?,
        path: NamespacePath::from_components(["result.bin"], NamespaceLimits::PORTABLE)?,
        principal_id: PrincipalId::from_bytes([14; 16])?,
        authorization_revision: Revision::new(6),
        disposition: UploadDisposition::CreateNew,
        maximum_bytes: 1_024,
        created_at: UnixMicros::new(1),
        expires_at: UnixMicros::new(100),
    })
}

fn write_request(
    begin: &UploadBeginRequest,
    operation: u8,
    offset: u64,
    bytes: &[u8],
) -> Result<UploadWriteRequest, Box<dyn std::error::Error>> {
    Ok(UploadWriteRequest {
        upload_id: begin.upload_id,
        principal_id: begin.principal_id,
        authorization_revision: Revision::new(7),
        operation_id: OperationId::from_bytes([operation; 16])?,
        stage_fence: 1,
        offset,
        bytes: BoundedBytes::copy_from(bytes, 64)?,
        digest: blake3::hash(bytes).into(),
        observed_at: UnixMicros::new(3),
    })
}

fn status_request(begin: &UploadBeginRequest, observed_at: UnixMicros) -> UploadStatusRequest {
    UploadStatusRequest {
        upload_id: begin.upload_id,
        principal_id: begin.principal_id,
        authorization_revision: Revision::new(7),
        observed_at,
    }
}

fn range_page_request(
    begin: &UploadBeginRequest,
    expected_sequence: Option<u64>,
    after_start: Option<u64>,
    limit: u16,
) -> UploadRangePageRequest {
    UploadRangePageRequest {
        upload_id: begin.upload_id,
        principal_id: begin.principal_id,
        authorization_revision: Revision::new(7),
        expected_sequence,
        after_start,
        limit,
        observed_at: UnixMicros::new(4),
    }
}

fn commit_request(
    begin: &UploadBeginRequest,
    sequence: u64,
    observed_at: UnixMicros,
) -> Result<UploadCommitRequest, Box<dyn std::error::Error>> {
    let operation_id = OperationId::from_bytes([60; 16])?;
    let publication = RootFileCommitRequest {
        completion: StageCompletionRequest {
            operation_id,
            stage_id: begin.stage_id,
            stage_fence: 1,
            expected_sequence: sequence,
            final_length: 10,
            sparse: false,
            observed_at,
        },
        branch_id: BranchId::from_bytes([61; 16])?,
        volume_id: begin.volume_id,
        object_id: ObjectId::from_bytes([62; 16])?,
        expected_current_version_id: None,
        version_id: FileVersionId::from_bytes([63; 16])?,
        retain_superseded_history: true,
        retention_policy_sequence: 1,
        manifest_id: ContentManifestId::from_bytes([64; 16])?,
        manifest_format_version: 1,
        content_authorization_revision: Revision::new(7),
        content_deadline: UnixMicros::new(200),
        root_object_id: ObjectId::from_bytes([65; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([66; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([67; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([68; 16])?,
        path: NamespacePublicationPath::new(begin.path.clone(), Vec::new())?,
        entry_generation: 1,
        created_by: begin.principal_id,
        created_at: observed_at,
    };
    Ok(UploadCommitRequest {
        operation_id,
        upload_id: begin.upload_id,
        principal_id: begin.principal_id,
        authorization_revision: Revision::new(7),
        stage_fence: 1,
        expected_sequence: sequence,
        final_length: 10,
        sparse: false,
        expected_content_digest: None,
        publication,
        observed_at,
    })
}

struct UnusedPublisher;

#[derive(Default)]
struct RecordingPublisher {
    durable: BTreeMap<OperationId, (ContentPublicationRequest, ManifestPublication)>,
}

impl DurableContentPublisher for RecordingPublisher {
    type Sink = Vec<u8>;

    fn acknowledgement_evidence(
        &self,
        request: ContentPublicationRequest,
    ) -> Result<crate::ContentAcknowledgementEvidence, ContentPublicationError> {
        Ok(crate::commit_service::test_acknowledgement_evidence(
            request,
        ))
    }

    fn resolve(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentPublicationError> {
        self.durable
            .get(&request.operation_id)
            .map(|(stored, manifest)| {
                if stored.same_intent(request) {
                    Ok(*manifest)
                } else {
                    Err(ContentPublicationError::Conflict)
                }
            })
            .transpose()
    }

    fn begin(
        &mut self,
        _request: ContentPublicationRequest,
    ) -> Result<Self::Sink, ContentPublicationError> {
        Ok(Vec::new())
    }

    fn finish(
        &mut self,
        request: ContentPublicationRequest,
        sink: Self::Sink,
        completed: CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        if u64::try_from(sink.len()) != Ok(completed.logical_length)
            || blake3::hash(&sink).as_bytes() != &completed.content_digest
        {
            return Err(ContentPublicationError::Corrupt);
        }
        let manifest = ManifestPublication {
            manifest_id: request.manifest_id,
            format_version: request.format_version,
            logical_length: completed.logical_length,
            content_digest: completed.content_digest,
            root_digest: blake3::hash(&sink).into(),
        };
        self.durable
            .insert(request.operation_id, (request, manifest));
        Ok(manifest)
    }
}

impl DurableContentPublisher for UnusedPublisher {
    type Sink = Vec<u8>;

    fn acknowledgement_evidence(
        &self,
        request: ContentPublicationRequest,
    ) -> Result<crate::ContentAcknowledgementEvidence, ContentPublicationError> {
        Ok(crate::commit_service::test_acknowledgement_evidence(
            request,
        ))
    }

    fn resolve(
        &mut self,
        _request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentPublicationError> {
        Err(ContentPublicationError::Unavailable)
    }

    fn begin(
        &mut self,
        _request: ContentPublicationRequest,
    ) -> Result<Self::Sink, ContentPublicationError> {
        Err(ContentPublicationError::Unavailable)
    }

    fn finish(
        &mut self,
        _request: ContentPublicationRequest,
        _sink: Self::Sink,
        _completed: CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        Err(ContentPublicationError::Unavailable)
    }
}
