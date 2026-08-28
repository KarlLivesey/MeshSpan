// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, HandleId, NamespaceCommitId, NodeId, ObjectId,
    ObjectRevisionId, OperationId, PrincipalId, Revision, UnixMicros, VolumeId,
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
