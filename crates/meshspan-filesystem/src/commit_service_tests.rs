// SPDX-License-Identifier: GPL-2.0-only

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, Revision, StageId, UnixMicros, VolumeId,
};
use tempfile::tempdir;

use super::{
    ContentPublicationError, ContentPublicationRequest, DurableContentPublisher,
    FilesystemCommitError, FilesystemCommitService, RootFileCommitRequest,
};
use crate::{
    CompletedStage, FilePublicationPath, ManifestPublication, NamespaceLimits, NamespacePath,
    PublicationDisposition, StageCompletionRequest, StageRegistration, StageWrite,
};

#[test]
fn durable_content_lost_reply_recovers_after_stage_expiry_and_publishes_once()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let publisher = RecordingPublisher::loses_first_finish_reply();
    let shared = Rc::clone(&publisher.state);
    let mut service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(1), publisher)?;
    prepare_stage(&mut service)?;
    let request = request(UnixMicros::new(4))?;
    assert!(matches!(
        service.commit_root_file(&request),
        Err(FilesystemCommitError::Content(
            ContentPublicationError::Unavailable
        ))
    ));
    assert!(service.resolve(request.completion.operation_id)?.is_none());
    drop(service);

    let publisher = RecordingPublisher::from_state(shared);
    let mut reopened =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(101), publisher)?;
    let expired_retry = RootFileCommitRequest {
        completion: StageCompletionRequest {
            observed_at: UnixMicros::new(101),
            ..request.completion
        },
        ..request.clone()
    };
    let applied = reopened.commit_root_file(&expired_retry)?;
    assert_eq!(applied.disposition, PublicationDisposition::Applied);
    let replayed = reopened.commit_root_file(&expired_retry)?;
    assert_eq!(replayed.disposition, PublicationDisposition::Replayed);
    assert_eq!(applied.result_digest, replayed.result_digest);
    assert_eq!(
        reopened.resolve(request.completion.operation_id)?,
        Some(replayed)
    );

    let publisher = reopened.into_content_publisher();
    let state = publisher.state.borrow();
    let durable = state
        .durable
        .get(&request.completion.operation_id)
        .ok_or("missing durable content")?;
    assert_eq!(durable.bytes, b"helloworld");
    assert_eq!(state.finish_calls, 1);
    Ok(())
}

#[test]
fn conflicting_retry_and_corrupt_manifest_never_advance_the_namespace()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let publisher = RecordingPublisher::corrupts_manifest();
    let mut service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(1), publisher)?;
    prepare_stage(&mut service)?;
    let request = request(UnixMicros::new(4))?;
    assert!(matches!(
        service.commit_root_file(&request),
        Err(FilesystemCommitError::Content(
            ContentPublicationError::Corrupt
        ))
    ));
    assert!(service.resolve(request.completion.operation_id)?.is_none());

    let publisher = service.into_content_publisher();
    publisher.state.borrow_mut().corrupt_manifest = false;
    let mut service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(5), publisher)?;
    let mut conflicting = request.clone();
    conflicting.namespace_commit_id = NamespaceCommitId::from_bytes([40; 16])?;
    assert!(matches!(
        service.commit_root_file(&conflicting),
        Err(FilesystemCommitError::Content(
            ContentPublicationError::Conflict
        ))
    ));
    assert!(service.resolve(request.completion.operation_id)?.is_none());
    Ok(())
}

fn prepare_stage(
    service: &mut FilesystemCommitService<RecordingPublisher>,
) -> Result<(), Box<dyn std::error::Error>> {
    let stage_id = StageId::from_bytes([1; 16])?;
    service.stages_mut().register(StageRegistration {
        stage_id,
        stage_fence: 2,
        maximum_bytes: 64,
        created_at: UnixMicros::new(1),
        expires_at: UnixMicros::new(100),
    })?;
    service
        .stages_mut()
        .write(stage_id, &write(3, 5, b"world")?, UnixMicros::new(2))?;
    service
        .stages_mut()
        .write(stage_id, &write(4, 0, b"hello")?, UnixMicros::new(3))?;
    Ok(())
}

fn write(
    operation: u8,
    offset: u64,
    bytes: &[u8],
) -> Result<StageWrite, Box<dyn std::error::Error>> {
    Ok(StageWrite {
        operation_id: OperationId::from_bytes([operation; 16])?,
        stage_fence: 2,
        offset,
        digest: blake3::hash(bytes).into(),
        bytes: BoundedBytes::copy_from(bytes, 64)?,
    })
}

fn request(observed_at: UnixMicros) -> Result<RootFileCommitRequest, Box<dyn std::error::Error>> {
    Ok(RootFileCommitRequest {
        completion: StageCompletionRequest {
            operation_id: OperationId::from_bytes([10; 16])?,
            stage_id: StageId::from_bytes([1; 16])?,
            stage_fence: 2,
            expected_sequence: 2,
            final_length: 10,
            sparse: false,
            observed_at,
        },
        branch_id: BranchId::from_bytes([11; 16])?,
        volume_id: VolumeId::from_bytes([12; 16])?,
        object_id: ObjectId::from_bytes([13; 16])?,
        expected_current_version_id: None,
        version_id: FileVersionId::from_bytes([14; 16])?,
        manifest_id: ContentManifestId::from_bytes([15; 16])?,
        manifest_format_version: 1,
        content_authorization_revision: Revision::new(1),
        content_deadline: UnixMicros::new(200),
        root_object_id: ObjectId::from_bytes([16; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([17; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([18; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([19; 16])?,
        path: FilePublicationPath::new(
            NamespacePath::from_components(["report.txt"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
        created_by: PrincipalId::from_bytes([20; 16])?,
        created_at: UnixMicros::new(4),
    })
}

#[derive(Clone)]
struct RecordingPublisher {
    state: Rc<RefCell<PublisherState>>,
}

#[derive(Default)]
struct PublisherState {
    durable: BTreeMap<OperationId, DurableContent>,
    lose_finish_reply: bool,
    corrupt_manifest: bool,
    finish_calls: usize,
}

struct DurableContent {
    request: ContentPublicationRequest,
    manifest: ManifestPublication,
    bytes: Vec<u8>,
}

impl RecordingPublisher {
    fn loses_first_finish_reply() -> Self {
        Self {
            state: Rc::new(RefCell::new(PublisherState {
                lose_finish_reply: true,
                ..PublisherState::default()
            })),
        }
    }

    fn corrupts_manifest() -> Self {
        Self {
            state: Rc::new(RefCell::new(PublisherState {
                corrupt_manifest: true,
                ..PublisherState::default()
            })),
        }
    }

    fn from_state(state: Rc<RefCell<PublisherState>>) -> Self {
        Self { state }
    }
}

impl DurableContentPublisher for RecordingPublisher {
    type Sink = Vec<u8>;

    fn resolve(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentPublicationError> {
        let state = self.state.borrow();
        state
            .durable
            .get(&request.operation_id)
            .map(|durable| {
                if durable.request.same_intent(request) {
                    Ok(durable.manifest)
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
        let length =
            u64::try_from(sink.len()).map_err(|_| ContentPublicationError::InvalidInput)?;
        if length != completed.logical_length
            || blake3::hash(&sink).as_bytes() != &completed.content_digest
        {
            return Err(ContentPublicationError::Corrupt);
        }
        let root_digest = manifest_root(&sink, completed);
        let mut manifest = ManifestPublication {
            manifest_id: request.manifest_id,
            format_version: request.format_version,
            logical_length: completed.logical_length,
            content_digest: completed.content_digest,
            root_digest,
        };
        let mut state = self.state.borrow_mut();
        state.finish_calls = state.finish_calls.saturating_add(1);
        if state.corrupt_manifest {
            manifest.logical_length = manifest.logical_length.saturating_add(1);
        }
        state.durable.insert(
            request.operation_id,
            DurableContent {
                request,
                manifest,
                bytes: sink,
            },
        );
        if state.lose_finish_reply {
            state.lose_finish_reply = false;
            Err(ContentPublicationError::Unavailable)
        } else {
            Ok(manifest)
        }
    }
}

fn manifest_root(bytes: &[u8], completed: CompletedStage) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.test.content-manifest.v1\0");
    digest.update(&completed.logical_length.to_be_bytes());
    digest.update(&completed.content_digest);
    digest.update(bytes);
    digest.finalize().into()
}
