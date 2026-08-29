// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, HandleId, LockId, NamespaceCommitId, NodeId,
    ObjectId, ObjectRevisionId, OperationId, PrincipalId, Revision, UnixMicros, VolumeId,
};
use tempfile::tempdir;

use super::*;
use crate::{
    FilePublication, ManifestPublication, NamespaceLimits, NamespacePath, NamespacePublicationPath,
    RootFilePublication, VersionPublicationStore,
};

#[test]
fn open_resolves_canonical_path_and_replays_exactly_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let request = open_request(20, 21, CreateDisposition::OverwriteExisting, 100)?;
    let applied = {
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&file)?;
        let receipt = store.open_handle(&request)?;
        assert_eq!(receipt.disposition, PublicationDisposition::Applied);
        assert_eq!(receipt.namespace_commit_id, file.namespace_commit_id);
        assert_eq!(receipt.object_id, file.file.object_id);
        assert_eq!(receipt.object_revision_id, file.file_object_revision_id);
        assert_eq!(receipt.opened_version_id, file.file.version_id);
        assert_eq!(receipt.handle_fence, 1);
        assert!(receipt.truncate_on_first_write);
        assert_eq!(
            store.handle_path(request.handle_id)?.components()[0].display(),
            "Report",
            "opening with different case must retain the namespace entry's spelling"
        );
        receipt
    };

    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    let replayed = reopened
        .resolve_open_handle(request.operation_id)?
        .ok_or("missing open receipt")?;
    assert_eq!(replayed.disposition, PublicationDisposition::Replayed);
    assert_eq!(replayed.result_digest, applied.result_digest);
    assert_eq!(
        reopened.open_handle(&request)?.disposition,
        PublicationDisposition::Replayed
    );
    let mut changed = request.clone();
    changed.share_access = HandleShare::new(false, false, false);
    assert!(matches!(
        reopened.open_handle(&changed),
        Err(HandleError::OperationConflict)
    ));
    Ok(())
}

#[test]
fn share_modes_are_bidirectional_and_expired_handles_stop_blocking()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    let mut first = open_request(30, 31, CreateDisposition::OpenExisting, 50)?;
    first.share_access = HandleShare::new(true, false, false);
    store.open_handle(&first)?;

    let mut write = open_request(32, 33, CreateDisposition::OpenExisting, 50)?;
    write.desired_access = HandleAccess::new(false, true, false)?;
    assert!(matches!(
        store.open_handle(&write),
        Err(HandleError::SharingViolation)
    ));
    assert!(store.resolve_open_handle(write.operation_id)?.is_none());

    let mut exclusive_reader = open_request(34, 35, CreateDisposition::OpenExisting, 50)?;
    exclusive_reader.share_access = HandleShare::new(false, false, false);
    assert!(matches!(
        store.open_handle(&exclusive_reader),
        Err(HandleError::SharingViolation)
    ));

    write.opened_at = UnixMicros::new(51);
    write.lease_expires_at = UnixMicros::new(100);
    store.open_handle(&write)?;
    let expired: i64 = store.test_connection().query_row(
        "SELECT count(*) FROM open_handles WHERE state = 3 AND closed_at = 51",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(expired, 1);
    Ok(())
}

#[test]
fn unsafe_or_creation_required_opens_fail_without_a_handle()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;

    let create = open_request(40, 41, CreateDisposition::CreateNew, 100)?;
    assert!(matches!(
        store.open_handle(&create),
        Err(HandleError::AlreadyExists)
    ));
    let mut missing = open_request(42, 43, CreateDisposition::OpenOrCreate, 100)?;
    missing.path = NamespacePath::from_components(["missing"], NamespaceLimits::PORTABLE)?;
    assert!(matches!(
        store.open_handle(&missing),
        Err(HandleError::CreationRequired)
    ));
    let mut invalid = open_request(44, 45, CreateDisposition::OpenExisting, 100)?;
    invalid.authorization_revision = Revision::ZERO;
    assert!(matches!(
        store.open_handle(&invalid),
        Err(HandleError::InvalidInput)
    ));
    let count: i64 =
        store
            .test_connection()
            .query_row("SELECT count(*) FROM open_handles", [], |row| row.get(0))?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn failed_created_handle_admission_rolls_back_the_namespace_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let initial = publication()?;
    let existing_open = open_request(40, 41, CreateDisposition::OpenExisting, 100)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&initial)?;
    store.open_handle(&existing_open)?;

    let mut create_open = open_request(40, 42, CreateDisposition::CreateNew, 100)?;
    create_open.path = NamespacePath::from_components(["new"], NamespaceLimits::PORTABLE)?;
    let creation = RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([43; 16])?,
            branch_id: initial.file.branch_id,
            volume_id: initial.file.volume_id,
            object_id: ObjectId::from_bytes([44; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([45; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([46; 16])?,
                format_version: 1,
                logical_length: 0,
                content_digest: *blake3::hash(&[]).as_bytes(),
                root_digest: [47; 32],
            },
            created_by: create_open.principal_id,
            created_at: create_open.opened_at,
        },
        root_object_id: initial.root_object_id,
        expected_namespace_commit_id: Some(initial.namespace_commit_id),
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([48; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([49; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([50; 16])?,
        path: NamespacePublicationPath::new(create_open.path.clone(), Vec::new())?,
        entry_generation: 1,
    };

    assert!(matches!(
        store.publish_root_file_and_open(&creation, &create_open),
        Err(HandleError::OperationConflict)
    ));
    let Some(head) = store.namespace_head(initial.file.branch_id, initial.file.volume_id)? else {
        return Err(std::io::Error::other("initial namespace head disappeared").into());
    };
    assert_eq!(head.namespace_commit_id, initial.namespace_commit_id);
    assert!(
        store
            .resolve_namespace_publication(creation.file.operation_id)?
            .is_none()
    );
    Ok(())
}

#[test]
fn corrupt_open_receipt_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let request = open_request(50, 51, CreateDisposition::OpenExisting, 100)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    store.open_handle(&request)?;
    store.test_connection().execute(
        "UPDATE open_handles SET receipt_digest = zeroblob(32) WHERE handle_id = ?1",
        [request.handle_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        store.resolve_open_handle(request.operation_id),
        Err(HandleError::Corrupt)
    ));
    Ok(())
}

#[test]
fn corrupt_handle_path_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let request = open_request(55, 56, CreateDisposition::OpenExisting, 100)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    store.open_handle(&request)?;
    store.test_connection().execute(
        "UPDATE open_handle_path_components SET canonical_name = 'forged'
         WHERE handle_id = ?1 AND component_ordinal = 0",
        [request.handle_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        store.handle_path(request.handle_id),
        Err(HandleError::Corrupt)
    ));
    Ok(())
}

#[test]
fn lease_takeover_advances_the_fence_and_rejects_the_old_gateway()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let open = open_request(60, 61, CreateDisposition::OpenExisting, 100)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    store.open_handle(&open)?;
    let renewed = store.renew_handle_lease(HandleLeaseRequest {
        operation_id: OperationId::from_bytes([62; 16])?,
        handle_id: open.handle_id,
        expected_fence: 1,
        principal_id: open.principal_id,
        authorization_revision: Revision::new(2),
        gateway_node_id: open.gateway_node_id,
        takeover: false,
        lease_expires_at: UnixMicros::new(150),
        observed_at: UnixMicros::new(20),
    })?;
    assert_eq!(renewed.handle_fence, 1);
    let takeover_request = HandleLeaseRequest {
        operation_id: OperationId::from_bytes([63; 16])?,
        expected_fence: 1,
        gateway_node_id: NodeId::from_bytes([64; 16])?,
        takeover: true,
        lease_expires_at: UnixMicros::new(200),
        observed_at: UnixMicros::new(30),
        ..HandleLeaseRequest {
            operation_id: OperationId::from_bytes([62; 16])?,
            handle_id: open.handle_id,
            expected_fence: 1,
            principal_id: open.principal_id,
            authorization_revision: Revision::new(2),
            gateway_node_id: open.gateway_node_id,
            takeover: false,
            lease_expires_at: UnixMicros::new(150),
            observed_at: UnixMicros::new(20),
        }
    };
    let takeover = store.renew_handle_lease(takeover_request)?;
    assert_eq!(takeover.handle_fence, 2);
    assert_eq!(
        store.renew_handle_lease(takeover_request)?.disposition,
        PublicationDisposition::Replayed
    );
    assert!(matches!(
        store.close_handle(CloseHandleRequest {
            operation_id: OperationId::from_bytes([65; 16])?,
            handle_id: open.handle_id,
            expected_fence: 1,
            principal_id: open.principal_id,
            gateway_node_id: open.gateway_node_id,
            observed_at: UnixMicros::new(40),
        }),
        Err(HandleError::StaleHandle)
    ));
    Ok(())
}

#[test]
fn delete_on_close_waits_for_the_last_handle_and_blocks_new_opens()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    let mut deleting = open_request(70, 71, CreateDisposition::OpenExisting, 100)?;
    deleting.desired_access = HandleAccess::new(true, false, true)?;
    deleting.share_access = HandleShare::new(true, false, true);
    deleting.delete_on_close = true;
    let mut observer = open_request(72, 73, CreateDisposition::OpenExisting, 100)?;
    observer.desired_access = HandleAccess::new(true, false, false)?;
    observer.share_access = HandleShare::new(true, false, true);
    store.open_handle(&deleting)?;
    store.open_handle(&observer)?;

    let deferred = store.close_handle(close_request(74, &deleting, 1, 20)?)?;
    assert_eq!(deferred.outcome, CloseHandleOutcome::DeleteDeferred);
    let blocked = open_request(75, 76, CreateDisposition::OpenExisting, 100)?;
    assert!(matches!(
        store.open_handle(&blocked),
        Err(HandleError::DeletePending)
    ));
    let ready_request = close_request(77, &observer, 1, 30)?;
    let ready = store.close_handle(ready_request)?;
    assert_eq!(ready.outcome, CloseHandleOutcome::DeleteReady);
    assert_eq!(
        store.close_handle(ready_request)?.disposition,
        PublicationDisposition::Replayed
    );
    Ok(())
}

#[test]
fn expired_delete_on_close_becomes_pending_before_another_open()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    let mut deleting = open_request(80, 81, CreateDisposition::OpenExisting, 50)?;
    deleting.desired_access = HandleAccess::new(true, false, true)?;
    deleting.share_access = HandleShare::new(true, false, true);
    deleting.delete_on_close = true;
    store.open_handle(&deleting)?;
    let mut later = open_request(82, 83, CreateDisposition::OpenExisting, 100)?;
    later.opened_at = UnixMicros::new(51);
    assert!(matches!(
        store.open_handle(&later),
        Err(HandleError::DeletePending)
    ));
    Ok(())
}

#[test]
fn range_locks_enforce_overlap_compatibility_and_allow_adjacency()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    let first = open_request(90, 91, CreateDisposition::OpenExisting, 200)?;
    let second = open_request(92, 93, CreateDisposition::OpenExisting, 200)?;
    store.open_handle(&first)?;
    store.open_handle(&second)?;

    let first_shared = lock_request(94, 95, &first, 1, 0, 100, RangeLockKind::Shared, 100, 20)?;
    store.lock_range(first_shared)?;
    let second_shared = lock_request(96, 97, &second, 1, 50, 25, RangeLockKind::Shared, 100, 20)?;
    store.lock_range(second_shared)?;
    let overlapping = lock_request(98, 99, &second, 1, 99, 2, RangeLockKind::Exclusive, 100, 20)?;
    assert!(matches!(
        store.lock_range(overlapping),
        Err(HandleError::LockConflict)
    ));
    let adjacent = lock_request(
        100,
        101,
        &second,
        1,
        100,
        10,
        RangeLockKind::Exclusive,
        100,
        20,
    )?;
    store.lock_range(adjacent)?;
    let active: i64 = store.test_connection().query_row(
        "SELECT count(*) FROM range_locks WHERE state = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(active, 3);
    Ok(())
}

#[test]
fn range_lock_replay_unlock_and_expiry_are_durable() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let open = open_request(102, 103, CreateDisposition::OpenExisting, 200)?;
    let lock = lock_request(104, 105, &open, 1, 10, 20, RangeLockKind::Exclusive, 50, 20)?;
    {
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&file)?;
        store.open_handle(&open)?;
        let applied = store.lock_range(lock)?;
        assert_eq!(applied.disposition, PublicationDisposition::Applied);
    }
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    assert_eq!(
        store.lock_range(lock)?.disposition,
        PublicationDisposition::Replayed
    );
    let unlock = unlock_request(106, &lock, &open, 1, 30)?;
    assert_eq!(
        store.unlock_range(unlock)?.disposition,
        PublicationDisposition::Applied
    );
    assert_eq!(
        store.unlock_range(unlock)?.disposition,
        PublicationDisposition::Replayed
    );
    let replacement = lock_request(107, 108, &open, 1, 10, 20, RangeLockKind::Exclusive, 80, 51)?;
    store.lock_range(replacement)?;
    Ok(())
}

#[test]
fn takeover_refences_locks_and_close_releases_them() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = publication()?;
    let open = open_request(109, 110, CreateDisposition::OpenExisting, 200)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    store.open_handle(&open)?;
    let lock = lock_request(111, 112, &open, 1, 0, 50, RangeLockKind::Exclusive, 150, 20)?;
    store.lock_range(lock)?;
    let new_gateway = NodeId::from_bytes([113; 16])?;
    store.renew_handle_lease(HandleLeaseRequest {
        operation_id: OperationId::from_bytes([114; 16])?,
        handle_id: open.handle_id,
        expected_fence: 1,
        principal_id: open.principal_id,
        authorization_revision: Revision::new(2),
        gateway_node_id: new_gateway,
        takeover: true,
        lease_expires_at: UnixMicros::new(250),
        observed_at: UnixMicros::new(30),
    })?;
    assert_eq!(
        store.lock_range(lock)?.handle_fence,
        1,
        "the immutable acquisition receipt must retain its original fence"
    );
    assert!(matches!(
        store.unlock_range(unlock_request(115, &lock, &open, 1, 40)?),
        Err(HandleError::StaleHandle)
    ));
    let mut transferred = open.clone();
    transferred.gateway_node_id = new_gateway;
    store.unlock_range(unlock_request(116, &lock, &transferred, 2, 40)?)?;

    let second_lock = lock_request(
        117,
        118,
        &transferred,
        2,
        0,
        50,
        RangeLockKind::Exclusive,
        200,
        50,
    )?;
    store.lock_range(second_lock)?;
    store.close_handle(close_request(119, &transferred, 2, 60)?)?;
    let active: i64 = store.test_connection().query_row(
        "SELECT count(*) FROM range_locks WHERE state = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(active, 0);
    Ok(())
}

#[test]
fn invalid_ranges_and_corrupt_lock_receipts_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    assert!(matches!(
        ByteRange::new(0, 0),
        Err(HandleError::InvalidInput)
    ));
    assert!(matches!(
        ByteRange::new(u64::MAX, 2),
        Err(HandleError::InvalidInput)
    ));
    assert!(matches!(
        ByteRange::new(9_223_372_036_854_775_807, 1),
        Err(HandleError::InvalidInput)
    ));

    let directory = tempdir()?;
    let file = publication()?;
    let open = open_request(120, 121, CreateDisposition::OpenExisting, 200)?;
    let lock = lock_request(122, 123, &open, 1, 0, 1, RangeLockKind::Shared, 100, 20)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    store.open_handle(&open)?;
    store.lock_range(lock)?;
    store.test_connection().execute(
        "UPDATE range_locks SET receipt_digest = zeroblob(32) WHERE lock_id = ?1",
        [lock.lock_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(store.lock_range(lock), Err(HandleError::Corrupt)));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn lock_request(
    operation: u8,
    lock: u8,
    open: &OpenHandleRequest,
    fence: u64,
    start: u64,
    length: u64,
    kind: RangeLockKind,
    expires_at: i64,
    observed_at: i64,
) -> Result<LockRangeRequest, Box<dyn std::error::Error>> {
    Ok(LockRangeRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        lock_id: LockId::from_bytes([lock; 16])?,
        handle_id: open.handle_id,
        handle_fence: fence,
        principal_id: open.principal_id,
        gateway_node_id: open.gateway_node_id,
        range: ByteRange::new(start, length)?,
        kind,
        lease_expires_at: UnixMicros::new(expires_at),
        observed_at: UnixMicros::new(observed_at),
    })
}

fn unlock_request(
    operation: u8,
    lock: &LockRangeRequest,
    open: &OpenHandleRequest,
    fence: u64,
    observed_at: i64,
) -> Result<UnlockRangeRequest, Box<dyn std::error::Error>> {
    Ok(UnlockRangeRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        lock_id: lock.lock_id,
        handle_id: open.handle_id,
        handle_fence: fence,
        principal_id: open.principal_id,
        gateway_node_id: open.gateway_node_id,
        observed_at: UnixMicros::new(observed_at),
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

fn open_request(
    operation: u8,
    handle: u8,
    create_disposition: CreateDisposition,
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
        create_disposition,
        delete_on_close: false,
        lease_expires_at: UnixMicros::new(expires_at),
        opened_at: UnixMicros::new(10),
    })
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
