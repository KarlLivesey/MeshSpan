// SPDX-License-Identifier: GPL-2.0-only

use std::{cell::Cell, rc::Rc};

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, BranchId, ContentManifestId, FileVersionId, HandleId,
    NamespaceCommitId, NodeId, ObjectId, ObjectRevisionId, OperationId, PrincipalId, Revision,
    StageId, UnixMicros, UploadId, VolumeId,
};
use tempfile::tempdir;

use super::*;
use crate::{
    AdapterCreateDirectoryRequest, BoundFilesystemAdapter, ContentPublicationError,
    ContentPublicationRequest, ContentReadError, ContentReadRequest, CreateDisposition,
    DurableContentPublisher, DurableContentReader, FilePublication, FilesystemAdapterPolicy,
    FilesystemFileAdapter, FilesystemHandleOpenRequest, FilesystemHandleReadRequest,
    FilesystemHandleWriteRequest, HandleShare, ManifestPublication, NamespaceLimits,
    NamespaceListRequest, NamespacePath, NamespacePublicationPath, NamespaceQueryError,
    NamespaceStatRequest, OpenHandleRequest, PublicationDisposition, PublishedContentReference,
    RootFilePublication, StageWrite, StageWriteOutcome, UploadDisposition, UploadState,
    VersionPublicationStore,
};

#[test]
fn first_directory_materialises_the_committed_volume_root_without_a_fake_genesis_file()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let volume_id = VolumeId::from_bytes([12; 16])?;
    let principal_id = PrincipalId::from_bytes([18; 16])?;
    let allowed = Rc::new(Cell::new(true));
    let authority = TestAuthority::new(allowed, principal_id);
    let filesystem =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(1), UnusedPublisher)?;
    let authorised = AuthorisedFilesystemService::new(filesystem, authority);
    let branch_id = BranchId::from_bytes([11; 16])?;
    let mut adapter = BoundFilesystemAdapter::new(
        authorised,
        branch_id,
        FilesystemAdapterPolicy::new(true, 1, 1)?,
    );
    let request = AdapterCreateDirectoryRequest {
        operation_id: OperationId::from_bytes([70; 16])?,
        volume_id,
        path: NamespacePath::from_components(["first"], NamespaceLimits::PORTABLE)?,
        observed_at: UnixMicros::new(10),
    };

    let receipt = adapter.create_directory(context(request.observed_at)?, &request)?;
    assert_eq!(receipt.head_sequence, 1);
    assert_eq!(
        adapter
            .list(
                context(request.observed_at)?,
                &crate::AdapterListRequest {
                    volume_id,
                    directory_path: None,
                    cursor: None,
                    maximum_results: 10,
                    observed_at: request.observed_at,
                },
            )?
            .entries
            .len(),
        1
    );
    Ok(())
}

#[test]
fn open_authorises_the_resolved_object_and_binds_the_returned_principal()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let allowed = Rc::new(Cell::new(true));
    let authority = TestAuthority::new(Rc::clone(&allowed), PrincipalId::from_bytes([18; 16])?);
    let service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
    let mut service = AuthorisedFilesystemService::new(service, authority);
    let open = writable_open()?;

    let receipt = service.open_handle(
        context(open.opened_at)?,
        &FilesystemHandleOpenRequest {
            handle: open.clone(),
            maximum_stage_bytes: Some(1_024),
        },
    )?;

    assert_eq!(receipt.object_id, ObjectId::from_bytes([13; 16])?);
    assert_eq!(receipt.disposition, PublicationDisposition::Applied);
    let (_, authority) = service.into_parts();
    let observed = authority
        .last_request
        .get()
        .ok_or_else(|| std::io::Error::other("authority did not record the request"))?;
    assert_eq!(observed.object_id, receipt.object_id);
    assert_eq!(observed.volume_id, open.volume_id);
    assert_eq!(
        observed.requested_rights,
        Rights::READ_DATA.union(Rights::WRITE_DATA)
    );
    Ok(())
}

#[test]
fn adapter_close_completes_durable_delete_on_close_before_success()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let allowed = Rc::new(Cell::new(true));
    let authority = TestAuthority::new(allowed, PrincipalId::from_bytes([18; 16])?);
    let filesystem =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
    let authorised = AuthorisedFilesystemService::new(filesystem, authority);
    let mut adapter = BoundFilesystemAdapter::new(
        authorised,
        BranchId::from_bytes([11; 16])?,
        FilesystemAdapterPolicy::new(true, 1, 1)?,
    );
    let path = NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?;
    let open = adapter.open_existing_file(
        context(UnixMicros::new(10))?,
        &AdapterOpenFileRequest {
            operation_id: OperationId::from_bytes([70; 16])?,
            handle_id: HandleId::from_bytes([71; 16])?,
            volume_id: VolumeId::from_bytes([12; 16])?,
            path: path.clone(),
            desired_access: HandleAccess::new(true, false, true)?,
            share_access: HandleShare::new(true, true, true),
            delete_on_close: true,
            maximum_stage_bytes: None,
            lease_expires_at: UnixMicros::new(80),
            observed_at: UnixMicros::new(10),
        },
    )?;
    let closed = adapter.close_file(
        context(UnixMicros::new(20))?,
        AdapterCloseFileRequest {
            operation_id: OperationId::from_bytes([72; 16])?,
            delete_operation_id: OperationId::from_bytes([73; 16])?,
            handle_id: open.handle_id,
            handle_fence: open.handle_fence,
            flush: None,
            observed_at: UnixMicros::new(20),
        },
    )?;

    assert_eq!(closed.close.outcome, CloseHandleOutcome::DeleteReady);
    assert!(matches!(
        adapter.stat(
            context(UnixMicros::new(21))?,
            &AdapterStatRequest {
                volume_id: VolumeId::from_bytes([12; 16])?,
                path,
                observed_at: UnixMicros::new(21),
            },
        ),
        Err(AuthorisedFilesystemError::Query(
            NamespaceQueryError::NotFound
        ))
    ));
    Ok(())
}

#[test]
fn revoked_write_never_reaches_the_stage_and_restored_authority_can_resume()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let allowed = Rc::new(Cell::new(true));
    let authority = TestAuthority::new(Rc::clone(&allowed), PrincipalId::from_bytes([18; 16])?);
    let service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
    let mut service = AuthorisedFilesystemService::new(service, authority);
    let open = writable_open()?;
    service.open_handle(
        context(open.opened_at)?,
        &FilesystemHandleOpenRequest {
            handle: open.clone(),
            maximum_stage_bytes: Some(1_024),
        },
    )?;
    let write = write_request(&open)?;

    allowed.set(false);
    assert!(matches!(
        service.write_handle(context(write.observed_at)?, &write),
        Err(AuthorisedFilesystemError::Authority(TestAuthorityError))
    ));

    allowed.set(true);
    let receipt = service.write_handle(context(write.observed_at)?, &write)?;
    assert_eq!(
        receipt.admission.disposition,
        PublicationDisposition::Applied
    );
    assert_eq!(receipt.stage_outcome, StageWriteOutcome::Applied);
    assert_eq!(receipt.checkpoint.sequence, 1);
    assert_eq!(receipt.checkpoint.logical_extent, 4);
    Ok(())
}

#[test]
fn writable_handle_reads_its_private_overlay_while_another_handle_reads_published_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let published = publication()?;
    seed_publication(directory.path(), &published)?;
    let allowed = Rc::new(Cell::new(true));
    let authority = TestAuthority::new(Rc::clone(&allowed), PrincipalId::from_bytes([18; 16])?);
    let content_source = SeedPublisher {
        content: PublishedContentReference {
            publication_operation_id: published.file.operation_id,
            manifest: published.file.manifest,
        },
        bytes: b"initial".to_vec(),
    };
    let service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), content_source)?;
    let mut service = AuthorisedFilesystemService::new(service, authority);
    let writer = writable_open()?;
    let mut reader = writer.clone();
    reader.operation_id = OperationId::from_bytes([23; 16])?;
    reader.handle_id = HandleId::from_bytes([24; 16])?;
    reader.desired_access = HandleAccess::new(true, false, false)?;
    service.open_handle(
        context(writer.opened_at)?,
        &FilesystemHandleOpenRequest {
            handle: writer.clone(),
            maximum_stage_bytes: Some(1_024),
        },
    )?;
    service.open_handle(
        context(reader.opened_at)?,
        &FilesystemHandleOpenRequest {
            handle: reader.clone(),
            maximum_stage_bytes: None,
        },
    )?;
    let mut write = write_request(&writer)?;
    write.write.offset = 2;
    write.write.bytes = BoundedBytes::copy_from(b"ZZ", 2)?;
    write.write.digest = blake3::hash(b"ZZ").into();
    service.write_handle(context(write.observed_at)?, &write)?;

    let private = service.read_handle(
        context(UnixMicros::new(30))?,
        read_request(25, &writer, 0, 7)?,
    )?;
    assert_eq!(private.bytes.as_slice(), b"inZZial");
    assert_eq!(private.checkpoint_sequence, 1);
    let published = service.read_handle(
        context(UnixMicros::new(30))?,
        read_request(26, &reader, 0, 7)?,
    )?;
    assert_eq!(published.bytes.as_slice(), b"initial");
    assert_eq!(published.checkpoint_sequence, 0);

    allowed.set(false);
    assert!(matches!(
        service.read_handle(
            context(UnixMicros::new(30))?,
            read_request(27, &writer, 0, 7)?,
        ),
        Err(AuthorisedFilesystemError::Authority(TestAuthorityError))
    ));
    Ok(())
}

#[test]
fn stat_returns_verified_immutable_attributes_only_with_current_attribute_access()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let allowed = Rc::new(Cell::new(true));
    let authority = TestAuthority::new(Rc::clone(&allowed), PrincipalId::from_bytes([18; 16])?);
    let service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
    let service = AuthorisedFilesystemService::new(service, authority);
    let request = NamespaceStatRequest {
        branch_id: BranchId::from_bytes([11; 16])?,
        volume_id: VolumeId::from_bytes([12; 16])?,
        path: NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?,
        observed_at: UnixMicros::new(30),
    };

    let stat = service.stat_namespace(context(request.observed_at)?, &request)?;
    assert_eq!(stat.object_id, ObjectId::from_bytes([13; 16])?);
    assert_eq!(
        stat.file_version_id,
        Some(FileVersionId::from_bytes([14; 16])?)
    );
    assert_eq!(stat.logical_length, Some(7));
    assert_eq!(stat.name.display(), "Report");
    assert_eq!(stat.entry_generation, 1);
    let observed = service
        .authority
        .last_request
        .get()
        .ok_or_else(|| std::io::Error::other("authority did not record stat"))?;
    assert_eq!(observed.requested_rights, Rights::READ_ATTRIBUTES);

    allowed.set(false);
    assert!(matches!(
        service.stat_namespace(context(request.observed_at)?, &request),
        Err(AuthorisedFilesystemError::Authority(TestAuthorityError))
    ));
    Ok(())
}

#[test]
fn directory_pages_are_immutable_bounded_and_reauthorised_before_each_page()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    publish_additional_file(directory.path(), "Alpha", 30, 5, 35, 34)?;
    let allowed = Rc::new(Cell::new(true));
    let authority = TestAuthority::new(Rc::clone(&allowed), PrincipalId::from_bytes([18; 16])?);
    let service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), UnusedPublisher)?;
    let service = AuthorisedFilesystemService::new(service, authority);
    let mut request = NamespaceListRequest {
        branch_id: BranchId::from_bytes([11; 16])?,
        volume_id: VolumeId::from_bytes([12; 16])?,
        directory_path: None,
        cursor: None,
        maximum_results: 1,
        observed_at: UnixMicros::new(30),
    };

    let first = service.list_namespace(context(request.observed_at)?, &request)?;
    assert_eq!(first.entries.len(), 1);
    let first_cursor = first
        .next_cursor
        .clone()
        .ok_or_else(|| std::io::Error::other("first page omitted continuation"))?;
    request.cursor = Some(first_cursor.clone());
    let second = service.list_namespace(context(request.observed_at)?, &request)?;
    assert_eq!(second.entries.len(), 1);
    assert!(second.next_cursor.is_none());
    let mut names = [
        first.entries[0].name.display().to_owned(),
        second.entries[0].name.display().to_owned(),
    ];
    names.sort();
    assert_eq!(names, ["Alpha", "Report"]);
    let observed = service
        .authority
        .last_request
        .get()
        .ok_or_else(|| std::io::Error::other("authority did not record list"))?;
    assert_eq!(observed.object_id, ObjectId::from_bytes([2; 16])?);
    assert_eq!(observed.requested_rights, Rights::LIST);

    publish_additional_file(directory.path(), "Zulu", 40, 35, 45, 44)?;
    request.cursor = Some(first_cursor);
    assert!(matches!(
        service.list_namespace(context(request.observed_at)?, &request),
        Err(AuthorisedFilesystemError::Query(
            NamespaceQueryError::StaleCursor
        ))
    ));
    request.cursor = None;
    allowed.set(false);
    assert!(matches!(
        service.list_namespace(context(request.observed_at)?, &request),
        Err(AuthorisedFilesystemError::Authority(TestAuthorityError))
    ));
    Ok(())
}

#[test]
fn resumable_upload_reauthorises_the_stable_parent_before_every_range()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_file(directory.path())?;
    let allowed = Rc::new(Cell::new(true));
    let authority = TestAuthority::new(Rc::clone(&allowed), PrincipalId::from_bytes([18; 16])?);
    let service =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(2), TestPublisher)?;
    let mut service = AuthorisedFilesystemService::new(service, authority);
    let begin = AdapterUploadBeginRequest {
        operation_id: OperationId::from_bytes([70; 16])?,
        upload_id: UploadId::from_bytes([71; 16])?,
        stage_id: StageId::from_bytes([72; 16])?,
        volume_id: VolumeId::from_bytes([12; 16])?,
        path: NamespacePath::from_components(["upload.bin"], NamespaceLimits::PORTABLE)?,
        disposition: UploadDisposition::CreateNew,
        maximum_bytes: 1_024,
        expires_at: UnixMicros::new(100),
        observed_at: UnixMicros::new(30),
    };
    let receipt = service.adapter_begin_upload(
        BranchId::from_bytes([11; 16])?,
        context(begin.observed_at)?,
        &begin,
    )?;
    assert_eq!(
        receipt.session.authority_object_id,
        ObjectId::from_bytes([2; 16])?
    );
    assert_eq!(
        service
            .authority
            .last_request
            .get()
            .map(|value| value.requested_rights),
        Some(Rights::CREATE_CHILD)
    );

    let write = AdapterUploadWriteRequest {
        upload_id: begin.upload_id,
        operation_id: OperationId::from_bytes([73; 16])?,
        stage_fence: 1,
        offset: 0,
        bytes: BoundedBytes::copy_from(b"safe", 4)?,
        digest: blake3::hash(b"safe").into(),
        observed_at: UnixMicros::new(31),
    };
    allowed.set(false);
    assert!(matches!(
        service.adapter_write_upload(context(write.observed_at)?, &write),
        Err(AuthorisedFilesystemError::Authority(TestAuthorityError))
    ));
    allowed.set(true);
    assert_eq!(
        service
            .adapter_write_upload(context(write.observed_at)?, &write)?
            .checkpoint
            .logical_extent,
        4
    );
    let commit = AdapterUploadCommitRequest {
        operation_id: OperationId::from_bytes([74; 16])?,
        upload_id: begin.upload_id,
        stage_fence: 1,
        expected_sequence: 1,
        final_length: 4,
        sparse: false,
        expected_content_digest: Some(blake3::hash(b"safe").into()),
        content_deadline: UnixMicros::new(80),
        observed_at: UnixMicros::new(32),
    };
    let policy = FilesystemAdapterPolicy::new(true, 1, 1)?;
    let committed = service.adapter_commit_upload(
        BranchId::from_bytes([11; 16])?,
        context(commit.observed_at)?,
        commit,
        policy,
    )?;
    assert_eq!(committed.session.state, UploadState::Committed);
    assert_eq!(
        committed.publication.disposition,
        PublicationDisposition::Applied
    );
    let replayed = service.adapter_commit_upload(
        BranchId::from_bytes([11; 16])?,
        context(commit.observed_at)?,
        commit,
        policy,
    )?;
    assert_eq!(
        replayed.publication.disposition,
        PublicationDisposition::Replayed
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordedRequest {
    volume_id: VolumeId,
    object_id: ObjectId,
    requested_rights: Rights,
}

struct TestAuthority {
    allowed: Rc<Cell<bool>>,
    principal_id: PrincipalId,
    last_request: Cell<Option<RecordedRequest>>,
}

impl TestAuthority {
    fn new(allowed: Rc<Cell<bool>>, principal_id: PrincipalId) -> Self {
        Self {
            allowed,
            principal_id,
            last_request: Cell::new(None),
        }
    }
}

impl FilesystemAccessAuthority for TestAuthority {
    type Error = TestAuthorityError;

    fn authorise(
        &self,
        request: FilesystemAuthorityRequest,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        self.last_request.set(Some(RecordedRequest {
            volume_id: request.volume_id,
            object_id: request.object_id,
            requested_rights: request.requested_rights,
        }));
        if !self.allowed.get() {
            return Err(TestAuthorityError);
        }
        Ok(FilesystemAuthorityGrant {
            principal_id: self.principal_id,
            gateway_node_id: request.context.gateway_node_id,
            gateway_incarnation: request.context.gateway_incarnation,
            volume_id: request.volume_id,
            object_id: request.object_id,
            requested_rights: request.requested_rights,
            identity_revision: Revision::new(1),
            namespace_revision: Revision::new(1),
            object_revision: Revision::new(1),
            gateway_revision: Revision::new(1),
            expires_at: UnixMicros::new(90),
            evidence_digest: [7; 32],
        })
    }

    fn authorise_volume_root(
        &self,
        context: FilesystemAccessContext,
        volume_id: VolumeId,
        requested_rights: Rights,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        let root = ObjectId::from_bytes(volume_id.as_bytes()).map_err(|_| TestAuthorityError)?;
        self.authorise(FilesystemAuthorityRequest {
            context,
            volume_id,
            object_id: root,
            requested_rights,
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("test authority denied the operation")]
struct TestAuthorityError;

fn context(now: UnixMicros) -> Result<FilesystemAccessContext, Box<dyn std::error::Error>> {
    Ok(FilesystemAccessContext {
        authentication_service: AuthenticationService::Https,
        credential_digest: [9; 32],
        required_assurance: AssuranceLevel::SingleFactor,
        gateway_node_id: NodeId::from_bytes([19; 16])?,
        gateway_incarnation: 1,
        now,
    })
}

fn writable_open() -> Result<OpenHandleRequest, Box<dyn std::error::Error>> {
    Ok(OpenHandleRequest {
        operation_id: OperationId::from_bytes([20; 16])?,
        handle_id: HandleId::from_bytes([21; 16])?,
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
        lease_expires_at: UnixMicros::new(80),
        opened_at: UnixMicros::new(10),
    })
}

fn write_request(
    open: &OpenHandleRequest,
) -> Result<FilesystemHandleWriteRequest, Box<dyn std::error::Error>> {
    Ok(FilesystemHandleWriteRequest {
        handle_id: open.handle_id,
        principal_id: open.principal_id,
        authorization_revision: open.authorization_revision,
        gateway_node_id: open.gateway_node_id,
        write: StageWrite {
            operation_id: OperationId::from_bytes([22; 16])?,
            stage_fence: 1,
            offset: 0,
            bytes: BoundedBytes::copy_from(b"safe", 4)?,
            digest: blake3::hash(b"safe").into(),
        },
        observed_at: UnixMicros::new(25),
    })
}

fn read_request(
    operation: u8,
    open: &OpenHandleRequest,
    offset: u64,
    length: u64,
) -> Result<FilesystemHandleReadRequest, Box<dyn std::error::Error>> {
    Ok(FilesystemHandleReadRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        handle_id: open.handle_id,
        handle_fence: 1,
        principal_id: open.principal_id,
        authorization_revision: open.authorization_revision,
        gateway_node_id: open.gateway_node_id,
        offset,
        length,
        content_deadline: UnixMicros::new(70),
        observed_at: UnixMicros::new(30),
    })
}

fn seed_file(state: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    seed_publication(state, &publication()?)
}

fn seed_publication(
    state: &std::path::Path,
    publication: &RootFilePublication,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = VersionPublicationStore::open(state, UnixMicros::new(1))?;
    store.publish_root_file(publication)?;
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
                content_digest: blake3::hash(b"initial").into(),
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

fn publish_additional_file(
    state: &std::path::Path,
    name: &str,
    identity: u8,
    expected_commit: u8,
    namespace_commit: u8,
    root_revision: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = VersionPublicationStore::open(state, UnixMicros::new(2))?;
    let publication = RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([identity; 16])?,
            branch_id: BranchId::from_bytes([11; 16])?,
            volume_id: VolumeId::from_bytes([12; 16])?,
            object_id: ObjectId::from_bytes([identity + 1; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([identity + 2; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([identity + 3; 16])?,
                format_version: 1,
                logical_length: 0,
                content_digest: blake3::hash(&[]).into(),
                root_digest: [identity + 4; 32],
            },
            created_by: PrincipalId::from_bytes([18; 16])?,
            created_at: UnixMicros::new(i64::from(identity)),
        },
        root_object_id: ObjectId::from_bytes([2; 16])?,
        expected_namespace_commit_id: Some(NamespaceCommitId::from_bytes([expected_commit; 16])?),
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([identity + 5; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([root_revision; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([namespace_commit; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components([name], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    };
    let head = store.namespace_head(
        BranchId::from_bytes([11; 16])?,
        VolumeId::from_bytes([12; 16])?,
    )?;
    if head.is_none() {
        return Err(std::io::Error::other("missing seed head").into());
    }
    store.publish_root_file(&publication)?;
    Ok(())
}

struct UnusedPublisher;

struct TestPublisher;

struct SeedPublisher {
    content: PublishedContentReference,
    bytes: Vec<u8>,
}

impl DurableContentReader for SeedPublisher {
    fn stream_range(
        &mut self,
        request: ContentReadRequest,
        destination: &mut dyn std::io::Write,
    ) -> Result<(), ContentReadError> {
        let end = request
            .offset
            .checked_add(request.length)
            .ok_or(ContentReadError::InvalidInput)?;
        if request.content != self.content
            || end > self.content.manifest.logical_length
            || request.observed_at >= request.deadline
            || request.authorization_revision == Revision::ZERO
        {
            return Err(ContentReadError::InvalidInput);
        }
        let start = usize::try_from(request.offset).map_err(|_| ContentReadError::InvalidInput)?;
        let end = usize::try_from(end).map_err(|_| ContentReadError::InvalidInput)?;
        destination.write_all(&self.bytes[start..end])?;
        Ok(())
    }
}

impl DurableContentPublisher for SeedPublisher {
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

impl DurableContentReader for UnusedPublisher {
    fn stream_range(
        &mut self,
        _request: ContentReadRequest,
        _destination: &mut dyn std::io::Write,
    ) -> Result<(), ContentReadError> {
        Err(ContentReadError::Unavailable)
    }
}

impl DurableContentPublisher for TestPublisher {
    type Sink = Vec<u8>;

    fn resolve(
        &mut self,
        _request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentPublicationError> {
        Ok(None)
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
        completed: crate::CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        if sink.len() as u64 != completed.logical_length
            || blake3::hash(&sink).as_bytes() != &completed.content_digest
        {
            return Err(ContentPublicationError::Corrupt);
        }
        Ok(ManifestPublication {
            manifest_id: request.manifest_id,
            format_version: request.format_version,
            logical_length: completed.logical_length,
            content_digest: completed.content_digest,
            root_digest: blake3::hash(&sink).into(),
        })
    }
}
