// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, HandleId, LockId, NamespaceCommitId, NodeId,
    ObjectId, ObjectRevisionId, OperationId, PrincipalId, Revision, StageId, UnixMicros, VolumeId,
};
use tempfile::tempdir;

use super::*;
use crate::{
    ContentPublicationError, ContentPublicationRequest, CreateDisposition, DurableContentPublisher,
    FilePublication, FilesystemCommitService, HandleAccess, HandleShare, LockRangeRequest,
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
                content_digest: [16; 32],
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
