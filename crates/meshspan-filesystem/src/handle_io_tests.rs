// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, HandleId, LockId, NamespaceCommitId, NodeId,
    ObjectId, ObjectRevisionId, OperationId, PrincipalId, Revision, StageId, UnixMicros, VolumeId,
};
use tempfile::tempdir;

use super::*;
use crate::{
    ContentPublicationError, ContentPublicationRequest, ContentReadError, ContentReadRequest,
    CreateDisposition, DurableContentPublisher, DurableContentReader, FilePublication,
    FilesystemCommitError, FilesystemCommitService, HandleAccess, HandleShare, LockRangeRequest,
    ManifestPublication, NamespaceLimits, NamespacePath, NamespacePublicationPath,
    PublicationDisposition, RangeLockKind, RootFilePublication, UnlockRangeRequest,
};

#[test]
fn writable_handle_stage_and_write_replay_together_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let open = writable_open(20, 21, 100)?;
    let request = FilesystemHandleOpenRequest {
        handle: open.clone(),
        maximum_stage_bytes: Some(1_024),
    };
    let write = handle_write(22, &open, 4, b"mesh")?;
    {
        let mut service =
            FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
        assert_eq!(
            service.open_handle(&request)?.disposition,
            PublicationDisposition::Applied
        );
        let receipt = service.write_handle(&write)?;
        assert_eq!(
            receipt.admission.disposition,
            PublicationDisposition::Applied
        );
        assert_eq!(receipt.stage_outcome, StageWriteOutcome::Applied);
        assert_eq!(receipt.checkpoint.sequence, 1);
        assert_eq!(receipt.checkpoint.logical_extent, 8);
    }

    let mut reopened =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(3), UnusedPublisher)?;
    assert_eq!(
        reopened.open_handle(&request)?.disposition,
        PublicationDisposition::Replayed
    );
    let replayed = reopened.write_handle(&write)?;
    assert_eq!(
        replayed.admission.disposition,
        PublicationDisposition::Replayed
    );
    assert_eq!(replayed.stage_outcome, StageWriteOutcome::Replayed);
    assert_eq!(replayed.checkpoint.sequence, 1);

    let mut conflicting = write;
    conflicting.write.bytes = BoundedBytes::copy_from(b"fail", 4)?;
    conflicting.write.digest = blake3::hash(b"fail").into();
    assert!(matches!(
        reopened.write_handle(&conflicting),
        Err(HandleIoError::Handle(HandleError::OperationConflict))
    ));
    Ok(())
}

#[test]
fn stage_policy_matches_handle_access_without_partial_open()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let writable = writable_open(30, 31, 100)?;
    let mut service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
    assert!(matches!(
        service.open_handle(&FilesystemHandleOpenRequest {
            handle: writable.clone(),
            maximum_stage_bytes: None,
        }),
        Err(HandleIoError::InvalidInput)
    ));
    let publications = VersionPublicationStore::open(directory.path(), UnixMicros::new(3))?;
    assert!(
        publications
            .resolve_open_handle(writable.operation_id)?
            .is_none()
    );

    let mut read_only = writable_open(32, 33, 100)?;
    read_only.desired_access = HandleAccess::new(true, false, false)?;
    assert!(matches!(
        service.open_handle(&FilesystemHandleOpenRequest {
            handle: read_only.clone(),
            maximum_stage_bytes: Some(1_024),
        }),
        Err(HandleIoError::InvalidInput)
    ));
    assert_eq!(
        service
            .open_handle(&FilesystemHandleOpenRequest {
                handle: read_only,
                maximum_stage_bytes: None,
            })?
            .disposition,
        PublicationDisposition::Applied
    );
    Ok(())
}

#[test]
fn foreign_range_lock_rejects_write_before_stage_mutation() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let writer = writable_open(40, 41, 200)?;
    let owner = writable_open(42, 43, 200)?;
    let mut service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
    for request in [&writer, &owner] {
        service.open_handle(&FilesystemHandleOpenRequest {
            handle: request.clone(),
            maximum_stage_bytes: Some(1_024),
        })?;
    }
    let range = ByteRange::new(0, 10)?;
    let mut publications = VersionPublicationStore::open(directory.path(), UnixMicros::new(3))?;
    let lock = LockRangeRequest {
        operation_id: OperationId::from_bytes([44; 16])?,
        lock_id: LockId::from_bytes([45; 16])?,
        handle_id: owner.handle_id,
        handle_fence: 1,
        principal_id: owner.principal_id,
        gateway_node_id: owner.gateway_node_id,
        range,
        kind: RangeLockKind::Shared,
        lease_expires_at: UnixMicros::new(150),
        observed_at: UnixMicros::new(20),
    };
    publications.lock_range(lock)?;
    let write = handle_write(46, &writer, 5, b"locked")?;
    assert!(matches!(
        service.write_handle(&write),
        Err(HandleIoError::Handle(HandleError::LockConflict))
    ));
    let stages = DurableStageStore::open(directory.path(), UnixMicros::new(4))?;
    assert_eq!(
        stages
            .checkpoint(StageId::from_bytes(writer.handle_id.as_bytes())?)?
            .sequence,
        0
    );

    publications.unlock_range(UnlockRangeRequest {
        operation_id: OperationId::from_bytes([47; 16])?,
        lock_id: lock.lock_id,
        handle_id: owner.handle_id,
        handle_fence: 1,
        principal_id: owner.principal_id,
        gateway_node_id: owner.gateway_node_id,
        observed_at: UnixMicros::new(30),
    })?;
    assert_eq!(
        service.write_handle(&write)?.stage_outcome,
        StageWriteOutcome::Applied
    );
    Ok(())
}

#[test]
fn substituted_authority_and_corrupt_admission_fail_before_stage_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let open = writable_open(50, 51, 200)?;
    let request = FilesystemHandleOpenRequest {
        handle: open.clone(),
        maximum_stage_bytes: Some(1_024),
    };
    let write = handle_write(52, &open, 0, b"safe")?;
    {
        let mut service =
            FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
        service.open_handle(&request)?;
        let mut forged = handle_write(53, &open, 4, b"evil")?;
        forged.gateway_node_id = NodeId::from_bytes([54; 16])?;
        assert!(matches!(
            service.write_handle(&forged),
            Err(HandleIoError::Handle(HandleError::StaleHandle))
        ));
        service.write_handle(&write)?;
    }
    let mut publications = VersionPublicationStore::open(directory.path(), UnixMicros::new(3))?;
    publications.test_connection().execute(
        "UPDATE handle_write_admissions SET receipt_digest = zeroblob(32)
         WHERE operation_id = ?1",
        [write.write.operation_id.as_bytes().as_slice()],
    )?;
    drop(publications);

    let mut reopened =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(4), UnusedPublisher)?;
    assert!(matches!(
        reopened.write_handle(&write),
        Err(HandleIoError::Handle(HandleError::Corrupt))
    ));
    Ok(())
}

#[test]
fn writable_handle_takeover_moves_handle_stage_and_locks_to_one_fence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let open = writable_open(60, 61, 200)?;
    let mut service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
    service.open_handle(&FilesystemHandleOpenRequest {
        handle: open.clone(),
        maximum_stage_bytes: Some(1_024),
    })?;
    service.write_handle(&handle_write(62, &open, 0, b"before")?)?;
    let gateway = NodeId::from_bytes([63; 16])?;
    let takeover = crate::HandleLeaseRequest {
        operation_id: OperationId::from_bytes([64; 16])?,
        handle_id: open.handle_id,
        expected_fence: 1,
        principal_id: open.principal_id,
        authorization_revision: Revision::new(2),
        gateway_node_id: gateway,
        takeover: true,
        lease_expires_at: UnixMicros::new(300),
        observed_at: UnixMicros::new(30),
    };
    let applied = service.renew_handle_lease(takeover)?;
    assert_eq!(applied.handle_fence, 2);
    let old = handle_write(65, &open, 6, b"old")?;
    assert!(matches!(
        service.write_handle(&old),
        Err(HandleIoError::Handle(HandleError::StaleHandle))
    ));
    drop(service);

    let mut reopened =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(3), UnusedPublisher)?;
    assert_eq!(
        reopened.renew_handle_lease(takeover)?.disposition,
        PublicationDisposition::Replayed
    );
    let mut transferred = handle_write(66, &open, 6, b"after")?;
    transferred.gateway_node_id = gateway;
    transferred.authorization_revision = Revision::new(2);
    transferred.write.stage_fence = 2;
    assert_eq!(
        reopened.write_handle(&transferred)?.stage_outcome,
        StageWriteOutcome::Applied
    );
    Ok(())
}

#[test]
fn flush_plan_is_stable_across_restart_and_rejects_changed_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let mut open = writable_open(70, 71, 300)?;
    open.create_disposition = CreateDisposition::OverwriteExisting;
    {
        let mut service =
            FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
        service.open_handle(&FilesystemHandleOpenRequest {
            handle: open.clone(),
            maximum_stage_bytes: Some(1_024),
        })?;
        service.write_handle(&handle_write(72, &open, 0, b"replacement")?)?;
    }
    let request = flush_request(73, &open, 1, 11, 200)?;
    let planned = {
        let mut publications = VersionPublicationStore::open(directory.path(), UnixMicros::new(3))?;
        publications.prepare_handle_flush(request)?
    };
    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(4))?;
    assert_eq!(reopened.prepare_handle_flush(request)?, planned);
    let mut changed = request;
    changed.final_length = 10;
    assert!(matches!(
        reopened.prepare_handle_flush(changed),
        Err(HandleError::OperationConflict)
    ));
    Ok(())
}

#[test]
fn complete_handle_flush_publishes_and_advances_repeatable_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let mut open = writable_open(74, 75, 400)?;
    open.create_disposition = CreateDisposition::OverwriteExisting;
    let mut service = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(2),
        MemoryPublisher::default(),
    )?;
    service.open_handle(&FilesystemHandleOpenRequest {
        handle: open.clone(),
        maximum_stage_bytes: Some(1_024),
    })?;
    service.write_handle(&handle_write(76, &open, 0, b"first")?)?;
    let first = flush_request(77, &open, 1, 5, 200)?;
    assert_eq!(
        service.flush_handle(first)?.disposition,
        PublicationDisposition::Applied
    );
    assert_eq!(
        service.flush_handle(first)?.disposition,
        PublicationDisposition::Replayed
    );

    service.write_handle(&handle_write(78, &open, 0, b"again")?)?;
    let second = flush_request(79, &open, 2, 5, 210)?;
    assert_eq!(
        service.flush_handle(second)?.disposition,
        PublicationDisposition::Applied
    );
    let publisher = service.into_content_publisher();
    assert_eq!(
        publisher.bytes(&first.operation_id),
        Some(b"first".as_slice())
    );
    assert_eq!(
        publisher.bytes(&second.operation_id),
        Some(b"again".as_slice())
    );

    let mut publications = VersionPublicationStore::open(directory.path(), UnixMicros::new(5))?;
    let sequence: i64 = publications.test_connection().query_row(
        "SELECT committed_stage_sequence FROM handle_flush_progress WHERE handle_id = ?1",
        [open.handle_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(sequence, 2);
    Ok(())
}

#[test]
fn incomplete_handle_flush_publishes_no_namespace_version() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let open = writable_open(80, 81, 300)?;
    let mut service = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(2),
        MemoryPublisher::default(),
    )?;
    service.open_handle(&FilesystemHandleOpenRequest {
        handle: open.clone(),
        maximum_stage_bytes: Some(1_024),
    })?;
    service.write_handle(&handle_write(82, &open, 8, b"x")?)?;
    let request = flush_request(83, &open, 1, 9, 200)?;
    assert!(matches!(
        service.flush_handle(request),
        Err(FilesystemCommitError::Stage(
            crate::StageStoreError::Incomplete
        ))
    ));
    assert!(service.resolve(request.operation_id)?.is_none());
    Ok(())
}

#[test]
fn partial_handle_flush_overlays_the_opened_immutable_version()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let open = writable_open(84, 85, 300)?;
    let mut service = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(2),
        MemoryPublisher::with_seed(publication()?.file, b"initial"),
    )?;
    service.open_handle(&FilesystemHandleOpenRequest {
        handle: open.clone(),
        maximum_stage_bytes: Some(1_024),
    })?;
    service.write_handle(&handle_write(86, &open, 2, b"ZZ")?)?;
    let flush = flush_request(87, &open, 1, 7, 200)?;

    assert_eq!(
        service.flush_handle(flush)?.disposition,
        PublicationDisposition::Applied
    );
    let publisher = service.into_content_publisher();
    assert_eq!(
        publisher.bytes(&flush.operation_id),
        Some(b"inZZial".as_slice())
    );
    Ok(())
}

fn flush_request(
    operation: u8,
    open: &OpenHandleRequest,
    sequence: u64,
    final_length: u64,
    deadline: i64,
) -> Result<FilesystemHandleFlushRequest, Box<dyn std::error::Error>> {
    Ok(FilesystemHandleFlushRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        handle_id: open.handle_id,
        handle_fence: 1,
        principal_id: open.principal_id,
        authorization_revision: open.authorization_revision,
        gateway_node_id: open.gateway_node_id,
        expected_stage_sequence: sequence,
        final_length,
        sparse: false,
        retain_superseded_history: true,
        retention_policy_sequence: 1,
        manifest_format_version: 1,
        content_authorization_revision: Revision::new(1),
        content_deadline: UnixMicros::new(deadline),
        observed_at: UnixMicros::new(40),
    })
}

fn handle_write(
    operation: u8,
    open: &OpenHandleRequest,
    offset: u64,
    bytes: &[u8],
) -> Result<FilesystemHandleWriteRequest, Box<dyn std::error::Error>> {
    Ok(FilesystemHandleWriteRequest {
        handle_id: open.handle_id,
        principal_id: open.principal_id,
        authorization_revision: open.authorization_revision,
        gateway_node_id: open.gateway_node_id,
        write: StageWrite {
            operation_id: OperationId::from_bytes([operation; 16])?,
            stage_fence: 1,
            offset,
            bytes: BoundedBytes::copy_from(bytes, bytes.len())?,
            digest: blake3::hash(bytes).into(),
        },
        observed_at: UnixMicros::new(25),
    })
}

fn writable_open(
    operation: u8,
    handle: u8,
    expires_at: i64,
) -> Result<OpenHandleRequest, Box<dyn std::error::Error>> {
    Ok(OpenHandleRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        handle_id: HandleId::from_bytes([handle; 16])?,
        branch_id: BranchId::from_bytes([11; 16])?,
        volume_id: VolumeId::from_bytes([12; 16])?,
        path: NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?,
        principal_id: PrincipalId::from_bytes([18; 16])?,
        authorization_revision: Revision::new(1),
        gateway_node_id: NodeId::from_bytes([19; 16])?,
        desired_access: HandleAccess::new(true, true, false)?,
        share_access: HandleShare::new(true, true, false),
        create_disposition: CreateDisposition::OpenExisting,
        delete_on_close: false,
        lease_expires_at: UnixMicros::new(expires_at),
        opened_at: UnixMicros::new(10),
    })
}

fn seed_file(state: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = VersionPublicationStore::open(state, UnixMicros::new(1))?;
    store.publish_root_file(&publication()?)?;
    Ok(())
}

fn publication() -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    let initial_digest = blake3::hash(b"initial").into();
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([1; 16])?,
            branch_id: BranchId::from_bytes([11; 16])?,
            volume_id: VolumeId::from_bytes([12; 16])?,
            object_id: ObjectId::from_bytes([13; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([14; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([15; 16])?,
                format_version: 1,
                logical_length: 7,
                content_digest: initial_digest,
                root_digest: [17; 32],
            },
            created_by: PrincipalId::from_bytes([18; 16])?,
            created_at: UnixMicros::new(1),
        },
        root_object_id: ObjectId::from_bytes([2; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([3; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([4; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([5; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["Report"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}

struct UnusedPublisher;

#[derive(Default)]
struct MemoryPublisher {
    durable: BTreeMap<OperationId, (ContentPublicationRequest, ManifestPublication, Vec<u8>)>,
}

impl MemoryPublisher {
    fn with_seed(publication: FilePublication, bytes: &[u8]) -> Self {
        let request = ContentPublicationRequest {
            operation_id: publication.operation_id,
            request_digest: [0; 32],
            manifest_id: publication.manifest.manifest_id,
            format_version: publication.manifest.format_version,
            logical_length: publication.manifest.logical_length,
            authorization_revision: Revision::new(1),
            deadline: UnixMicros::new(1),
            observed_at: UnixMicros::new(0),
        };
        Self {
            durable: BTreeMap::from([(
                request.operation_id,
                (request, publication.manifest, bytes.to_vec()),
            )]),
        }
    }

    fn bytes(&self, operation_id: &OperationId) -> Option<&[u8]> {
        self.durable
            .get(operation_id)
            .map(|(_, _, bytes)| bytes.as_slice())
    }
}

impl DurableContentReader for MemoryPublisher {
    fn stream_range(
        &mut self,
        request: ContentReadRequest,
        destination: &mut dyn std::io::Write,
    ) -> Result<(), ContentReadError> {
        if request.authorization_revision.get() == 0
            || request.observed_at >= request.deadline
            || request
                .offset
                .checked_add(request.length)
                .is_none_or(|end| end > request.content.manifest.logical_length)
        {
            return Err(ContentReadError::InvalidInput);
        }
        let Some((_, manifest, bytes)) =
            self.durable.get(&request.content.publication_operation_id)
        else {
            return Err(ContentReadError::Unavailable);
        };
        if *manifest != request.content.manifest
            || u64::try_from(bytes.len()).ok() != Some(manifest.logical_length)
            || blake3::hash(bytes).as_bytes() != &manifest.content_digest
        {
            return Err(ContentReadError::Corrupt);
        }
        let start = usize::try_from(request.offset).map_err(|_| ContentReadError::InvalidInput)?;
        let end = usize::try_from(request.offset + request.length)
            .map_err(|_| ContentReadError::InvalidInput)?;
        destination.write_all(&bytes[start..end])?;
        Ok(())
    }
}

impl DurableContentPublisher for MemoryPublisher {
    type Sink = Vec<u8>;

    fn resolve(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentPublicationError> {
        let Some((stored, manifest, _)) = self.durable.get(&request.operation_id) else {
            return Ok(None);
        };
        if stored.same_intent(request) {
            Ok(Some(*manifest))
        } else {
            Err(ContentPublicationError::Conflict)
        }
    }

    fn begin(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Self::Sink, ContentPublicationError> {
        if self.durable.contains_key(&request.operation_id) {
            Err(ContentPublicationError::Conflict)
        } else {
            Ok(Vec::new())
        }
    }

    fn finish(
        &mut self,
        request: ContentPublicationRequest,
        sink: Self::Sink,
        completed: crate::CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        if u64::try_from(sink.len()).ok() != Some(completed.logical_length)
            || blake3::hash(&sink).as_bytes() != &completed.content_digest
        {
            return Err(ContentPublicationError::Corrupt);
        }
        let mut root = blake3::Hasher::new();
        root.update(b"meshspan.test.memory-publisher.v1\0");
        root.update(&request.manifest_id.as_bytes());
        root.update(&completed.content_digest);
        let manifest = ManifestPublication {
            manifest_id: request.manifest_id,
            format_version: request.format_version,
            logical_length: completed.logical_length,
            content_digest: completed.content_digest,
            root_digest: root.finalize().into(),
        };
        match self.durable.get(&request.operation_id) {
            Some((stored, prior, bytes))
                if stored.same_intent(request) && *prior == manifest && *bytes == sink =>
            {
                Ok(*prior)
            }
            Some(_) => Err(ContentPublicationError::Conflict),
            None => {
                self.durable
                    .insert(request.operation_id, (request, manifest, sink));
                Ok(manifest)
            }
        }
    }
}

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
        _completed: crate::CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        Err(ContentPublicationError::Unavailable)
    }
}
