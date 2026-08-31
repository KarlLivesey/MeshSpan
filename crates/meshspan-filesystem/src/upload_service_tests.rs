// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    OperationId, PrincipalId, Revision, StageId, UnixMicros, UploadId, VolumeId,
};
use tempfile::tempdir;

use crate::{
    CompletedStage, ContentPublicationError, ContentPublicationRequest, DurableContentPublisher,
    FilesystemCommitService, ManifestPublication, NamespaceLimits, NamespacePath,
    UploadAbortRequest, UploadBeginRequest, UploadDisposition, UploadServiceError, UploadState,
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

fn begin_request() -> Result<UploadBeginRequest, Box<dyn std::error::Error>> {
    Ok(UploadBeginRequest {
        operation_id: OperationId::from_bytes([10; 16])?,
        upload_id: UploadId::from_bytes([11; 16])?,
        stage_id: StageId::from_bytes([12; 16])?,
        volume_id: VolumeId::from_bytes([13; 16])?,
        path: NamespacePath::from_components(["reports", "result.bin"], NamespaceLimits::PORTABLE)?,
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

struct UnusedPublisher;

impl DurableContentPublisher for UnusedPublisher {
    type Sink = Vec<u8>;

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
