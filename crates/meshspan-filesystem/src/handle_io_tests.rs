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
    CloseHandleRequest, ContentPublicationError, ContentPublicationRequest, ContentReadError,
    ContentReadRequest, CreateDisposition, DurableContentPublisher, DurableContentReader,
    FilePublication, FilesystemCommitError, FilesystemCommitService, FilesystemHandleCreateRequest,
    HandleAccess, HandleShare, LockRangeRequest, ManifestPublication, NamespaceLimits,
    NamespacePath, NamespacePublicationPath, PublicationDisposition, RangeLockKind,
    RootFileCommitRequest, RootFilePublication, StageCompletionRequest, UnlockRangeRequest,
};

#[test]
fn absent_open_or_create_publishes_empty_file_and_handle_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let request = create_request(CreateDisposition::OpenOrCreate)?;
    let mut service = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(1),
        MemoryPublisher::default(),
    )?;

    let receipt = service.open_or_create_handle(&request)?;
    let Some(creation) = receipt.creation else {
        return Err(std::io::Error::other("absent path was not created").into());
    };
    assert_eq!(creation.disposition, PublicationDisposition::Applied);
    assert_eq!(receipt.handle.disposition, PublicationDisposition::Applied);
    assert_eq!(receipt.handle.object_id, request.initial_file.object_id);
    assert_eq!(
        receipt.handle.namespace_commit_id,
        request.initial_file.namespace_commit_id
    );
    assert_eq!(
        receipt.handle.opened_version_id,
        request.initial_file.version_id
    );
    assert_eq!(
        service
            .into_content_publisher()
            .bytes(&request.initial_file.completion.operation_id),
        Some([].as_slice())
    );

    let mut reopened = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(2),
        MemoryPublisher::default(),
    )?;
    let replay = reopened.open_or_create_handle(&request)?;
    assert_eq!(replay.handle.disposition, PublicationDisposition::Replayed);
    let Some(replayed_creation) = replay.creation else {
        return Err(std::io::Error::other("creation receipt did not survive restart").into());
    };
    assert_eq!(
        replayed_creation.disposition,
        PublicationDisposition::Replayed
    );
    let mut conflicting = request;
    conflicting.open.handle.path =
        NamespacePath::from_components(["Different"], NamespaceLimits::PORTABLE)?;
    conflicting.initial_file.path =
        NamespacePublicationPath::new(conflicting.open.handle.path.clone(), Vec::new())?;
    assert!(matches!(
        reopened.open_or_create_handle(&conflicting),
        Err(FilesystemCommitError::Handle(
            HandleError::OperationConflict
        ))
    ));
    Ok(())
}

#[test]
fn existing_open_or_create_does_not_publish_the_reserved_creation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let mut request = create_request(CreateDisposition::OpenOrCreate)?;
    request.open.handle.path =
        NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?;
    request.initial_file.path =
        NamespacePublicationPath::new(request.open.handle.path.clone(), Vec::new())?;
    let mut service = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(2),
        MemoryPublisher::default(),
    )?;

    let receipt = service.open_or_create_handle(&request)?;
    assert!(receipt.creation.is_none());
    assert_eq!(receipt.handle.object_id, ObjectId::from_bytes([13; 16])?);
    assert!(
        service
            .into_content_publisher()
            .bytes(&request.initial_file.completion.operation_id)
            .is_none()
    );
    Ok(())
}

#[test]
fn mismatched_creation_plan_fails_before_content_or_namespace_work()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut request = create_request(CreateDisposition::CreateNew)?;
    request.initial_file.created_by = PrincipalId::from_bytes([99; 16])?;
    let mut service = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(1),
        MemoryPublisher::default(),
    )?;

    assert!(matches!(
        service.open_or_create_handle(&request),
        Err(FilesystemCommitError::InvalidInput)
    ));
    assert!(
        service
            .into_content_publisher()
            .bytes(&request.initial_file.completion.operation_id)
            .is_none()
    );
    let publications = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    assert!(
        publications
            .resolve_open_handle(request.open.handle.operation_id)?
            .is_none()
    );
    assert!(
        publications
            .resolve_namespace_publication(request.initial_file.completion.operation_id)?
            .is_none()
    );
    Ok(())
}

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
fn length_retry_completes_the_private_stage_after_authority_only_crash()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let open = writable_open(23, 24, 200)?;
    let mut service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
    service.open_handle(&FilesystemHandleOpenRequest {
        handle: open.clone(),
        maximum_stage_bytes: Some(1_024),
    })?;
    drop(service);

    let request = crate::SetHandleLengthRequest {
        operation_id: OperationId::from_bytes([25; 16])?,
        handle_id: open.handle_id,
        handle_fence: 1,
        principal_id: open.principal_id,
        gateway_node_id: open.gateway_node_id,
        logical_length: 42,
        observed_at: UnixMicros::new(20),
    };
    let mut publications = VersionPublicationStore::open(directory.path(), UnixMicros::new(3))?;
    assert_eq!(
        publications.set_handle_length(request)?.disposition,
        PublicationDisposition::Applied
    );
    drop(publications);

    let mut recovered =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(4), UnusedPublisher)?;
    let receipt = recovered.set_handle_length(request)?;
    assert_eq!(
        receipt.authority.disposition,
        PublicationDisposition::Replayed
    );
    assert_eq!(receipt.stage.outcome, StageWriteOutcome::Applied);
    assert_eq!(receipt.checkpoint.sequence, 1);
    assert_eq!(receipt.checkpoint.logical_extent, 42);
    recovered.write_handle(&handle_write(26, &open, 50, b"x")?)?;
    drop(recovered);

    let mut replayed =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(5), UnusedPublisher)?;
    let receipt = replayed.set_handle_length(request)?;
    assert_eq!(
        receipt.authority.disposition,
        PublicationDisposition::Replayed
    );
    assert_eq!(receipt.stage.outcome, StageWriteOutcome::Replayed);
    assert_eq!(receipt.checkpoint.sequence, 2);
    assert_eq!(receipt.checkpoint.logical_extent, 51);
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
    let request = flush_request(73, &open, 2, 11, 200)?;
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
    reopened.test_connection().execute(
        "UPDATE handle_flush_plans SET result_digest = zeroblob(32) WHERE operation_id = ?1",
        [request.operation_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        reopened.prepare_handle_flush(request),
        Err(HandleError::Corrupt)
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
    let first = flush_request(77, &open, 2, 5, 200)?;
    assert_eq!(
        service.flush_handle(first)?.disposition,
        PublicationDisposition::Applied
    );
    assert_eq!(
        service.flush_handle(first)?.disposition,
        PublicationDisposition::Replayed
    );

    service.write_handle(&handle_write(78, &open, 0, b"again")?)?;
    let second = flush_request(79, &open, 3, 5, 210)?;
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
    assert_eq!(sequence, 3);
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
fn dirty_close_flushes_once_before_releasing_the_handle() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let mut open = writable_open(84, 85, 300)?;
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
    service.write_handle(&handle_write(86, &open, 0, b"done")?)?;
    let request = FilesystemHandleCloseRequest {
        close: close_request(88, &open, 1, 60)?,
        flush: Some(flush_request(87, &open, 2, 4, 200)?),
    };
    let Some(flush_request) = request.flush else {
        return Err(std::io::Error::other("test close has no flush").into());
    };

    let receipt = service.close_handle(request)?;
    let Some(flush) = receipt.flush else {
        return Err(std::io::Error::other("dirty close did not flush").into());
    };
    assert_eq!(flush.disposition, PublicationDisposition::Applied);
    assert_eq!(receipt.close.disposition, PublicationDisposition::Applied);
    assert_eq!(
        service
            .close_handle(request)?
            .flush
            .ok_or_else(|| std::io::Error::other("flush replay disappeared"))?
            .disposition,
        PublicationDisposition::Replayed
    );
    assert_eq!(
        service
            .into_content_publisher()
            .bytes(&flush_request.operation_id),
        Some(b"done".as_slice())
    );
    Ok(())
}

#[test]
fn delete_on_close_binds_the_revision_committed_by_its_final_flush()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let mut open = writable_open(93, 94, 300)?;
    open.create_disposition = CreateDisposition::OverwriteExisting;
    open.desired_access = HandleAccess::new(true, true, true)?;
    open.share_access = HandleShare::new(true, true, true);
    open.delete_on_close = true;
    let mut service = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(2),
        MemoryPublisher::default(),
    )?;
    service.open_handle(&FilesystemHandleOpenRequest {
        handle: open.clone(),
        maximum_stage_bytes: Some(1_024),
    })?;
    service.write_handle(&handle_write(95, &open, 0, b"new")?)?;
    let request = FilesystemHandleCloseRequest {
        close: close_request(97, &open, 1, 60)?,
        flush: Some(flush_request(96, &open, 2, 3, 200)?),
    };
    let receipt = service.close_handle(request)?;
    assert_eq!(
        receipt.close.outcome,
        crate::CloseHandleOutcome::DeleteReady
    );
    drop(service);

    let mut publications = VersionPublicationStore::open(directory.path(), UnixMicros::new(3))?;
    let exact: i64 = publications.test_connection().query_row(
        "SELECT count(*)
         FROM pending_object_deletes pending
         JOIN handle_flush_progress progress
           ON progress.handle_id = pending.requesting_handle_id
         JOIN open_handles handles ON handles.handle_id = pending.requesting_handle_id
         WHERE pending.object_revision_id = progress.object_revision_id
           AND pending.version_id = progress.version_id
           AND pending.object_revision_id != handles.object_revision_id
           AND pending.version_id != handles.opened_version_id",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(exact, 1);
    Ok(())
}

#[test]
fn clean_read_only_close_performs_no_content_work() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let mut open = writable_open(103, 104, 300)?;
    open.desired_access = HandleAccess::new(true, false, false)?;
    let mut service = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(2),
        MemoryPublisher::default(),
    )?;
    service.open_handle(&FilesystemHandleOpenRequest {
        handle: open.clone(),
        maximum_stage_bytes: None,
    })?;

    let receipt = service.close_handle(FilesystemHandleCloseRequest {
        close: close_request(105, &open, 1, 60)?,
        flush: None,
    })?;
    assert!(receipt.flush.is_none());
    assert_eq!(receipt.close.disposition, PublicationDisposition::Applied);
    Ok(())
}

#[test]
fn overwrite_close_without_writes_publishes_the_empty_truncation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let mut open = writable_open(89, 90, 300)?;
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
    let request = FilesystemHandleCloseRequest {
        close: close_request(92, &open, 1, 60)?,
        flush: Some(flush_request(91, &open, 1, 0, 200)?),
    };
    let Some(flush_request) = request.flush else {
        return Err(std::io::Error::other("test close has no flush").into());
    };

    let receipt = service.close_handle(request)?;
    assert!(receipt.flush.is_some());
    assert_eq!(
        service
            .into_content_publisher()
            .bytes(&flush_request.operation_id),
        Some([].as_slice())
    );
    Ok(())
}

#[test]
fn close_recovers_after_flush_commits_but_before_handle_release()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let mut open = writable_open(98, 99, 300)?;
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
    service.write_handle(&handle_write(100, &open, 0, b"safe")?)?;
    let flush = flush_request(101, &open, 2, 4, 200)?;
    assert_eq!(
        service.flush_handle(flush)?.disposition,
        PublicationDisposition::Applied
    );

    let receipt = service.close_handle(FilesystemHandleCloseRequest {
        close: close_request(102, &open, 1, 60)?,
        flush: Some(flush),
    })?;
    assert_eq!(receipt.close.disposition, PublicationDisposition::Applied);
    assert_eq!(
        receipt
            .flush
            .ok_or_else(|| std::io::Error::other("recovered close omitted flush receipt"))?
            .disposition,
        PublicationDisposition::Replayed
    );
    Ok(())
}

#[test]
fn failed_dirty_close_leaves_the_handle_live_and_unacknowledged()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let mut open = writable_open(93, 94, 300)?;
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
    service.write_handle(&handle_write(95, &open, 8, b"x")?)?;
    let request = FilesystemHandleCloseRequest {
        close: close_request(97, &open, 1, 60)?,
        flush: Some(flush_request(96, &open, 2, 9, 200)?),
    };

    assert!(matches!(
        service.close_handle(FilesystemHandleCloseRequest {
            close: request.close,
            flush: None,
        }),
        Err(FilesystemCommitError::InvalidInput)
    ));
    assert!(matches!(
        service.close_handle(request),
        Err(FilesystemCommitError::Stage(
            crate::StageStoreError::Incomplete
        ))
    ));
    drop(service);
    let publications = VersionPublicationStore::open(directory.path(), UnixMicros::new(3))?;
    assert!(publications.resolve_close_request(request.close)?.is_none());
    assert!(
        publications
            .resolve_open_handle(open.operation_id)?
            .is_some()
    );
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

fn close_request(
    operation: u8,
    open: &OpenHandleRequest,
    fence: u64,
    observed_at: i64,
) -> Result<CloseHandleRequest, Box<dyn std::error::Error>> {
    Ok(CloseHandleRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        handle_id: open.handle_id,
        expected_fence: fence,
        principal_id: open.principal_id,
        gateway_node_id: open.gateway_node_id,
        observed_at: UnixMicros::new(observed_at),
    })
}

fn create_request(
    disposition: CreateDisposition,
) -> Result<FilesystemHandleCreateRequest, Box<dyn std::error::Error>> {
    let mut handle = writable_open(70, 71, 100)?;
    handle.path = NamespacePath::from_components(["New"], NamespaceLimits::PORTABLE)?;
    handle.create_disposition = disposition;
    handle.opened_at = UnixMicros::new(10);
    Ok(FilesystemHandleCreateRequest {
        open: FilesystemHandleOpenRequest {
            handle: handle.clone(),
            maximum_stage_bytes: Some(1_024),
        },
        initial_file: RootFileCommitRequest {
            completion: StageCompletionRequest {
                operation_id: OperationId::from_bytes([72; 16])?,
                stage_id: StageId::from_bytes(handle.handle_id.as_bytes())?,
                stage_fence: 1,
                expected_sequence: 0,
                final_length: 0,
                sparse: false,
                observed_at: UnixMicros::new(10),
            },
            branch_id: handle.branch_id,
            volume_id: handle.volume_id,
            object_id: ObjectId::from_bytes([73; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([74; 16])?,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest_id: ContentManifestId::from_bytes([75; 16])?,
            manifest_format_version: 1,
            content_authorization_revision: handle.authorization_revision,
            content_deadline: UnixMicros::new(90),
            root_object_id: ObjectId::from_bytes([76; 16])?,
            expected_namespace_commit_id: None,
            expected_file_object_revision_id: None,
            file_object_revision_id: ObjectRevisionId::from_bytes([77; 16])?,
            root_object_revision_id: ObjectRevisionId::from_bytes([78; 16])?,
            namespace_commit_id: NamespaceCommitId::from_bytes([79; 16])?,
            path: NamespacePublicationPath::new(handle.path.clone(), Vec::new())?,
            entry_generation: 1,
            created_by: handle.principal_id,
            created_at: handle.opened_at,
        },
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
            volume_id: publication.volume_id,
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
        _completed: crate::CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        Err(ContentPublicationError::Unavailable)
    }
}
