// SPDX-License-Identifier: GPL-2.0-only

//! External connector-contract proof across two gateways, publication and restart.

use std::{cell::RefCell, collections::BTreeMap, io::Write, rc::Rc};

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    AssuranceLevel, BranchId, ContentManifestId, FileVersionId, HandleId, NamespaceCommitId,
    NodeId, ObjectId, ObjectRevisionId, OperationId, PrincipalId, Revision, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    AdapterFlushFileRequest, AdapterOpenFileRequest, AdapterReadFileRequest,
    AdapterWriteFileRequest, AuthorisedFilesystemError, AuthorisedFilesystemService,
    BoundFilesystemAdapter, ContentPublicationError, ContentPublicationRequest, ContentReadError,
    ContentReadRequest, DurableContentPublisher, DurableContentReader, FilePublication,
    FilesystemAccessAuthority, FilesystemAccessContext, FilesystemAdapterPolicy,
    FilesystemAuthorityGrant, FilesystemAuthorityRequest, FilesystemCommitService,
    FilesystemFileAdapter, FilesystemHandleReadReceipt, HandleAccess, HandleError, HandleIoError,
    HandleShare, ManifestPublication, NamespaceLimits, NamespacePath, NamespacePublicationPath,
    OpenHandleReceipt, PublishedContentReference, RootFilePublication, VersionPublicationStore,
};
use tempfile::tempdir;

type DurableContents = Rc<RefCell<BTreeMap<OperationId, StoredContent>>>;
type StoredContent = (ContentPublicationRequest, ManifestPublication, Vec<u8>);

#[test]
fn two_gateway_adapters_enforce_sharing_and_preserve_only_committed_bytes_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let publication = publication()?;
    seed_namespace(directory.path(), &publication)?;
    let durable = Rc::new(RefCell::new(BTreeMap::new()));
    seed_content(&durable, publication.file, b"initial");
    let principal_id = PrincipalId::from_bytes([18; 16])?;
    let gateway_a = InProcessAdapter::new(NodeId::from_bytes([19; 16])?, [40; 32]);
    let gateway_b = InProcessAdapter::new(NodeId::from_bytes([20; 16])?, [41; 32]);
    let filesystem = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(2),
        MemoryPublisher::new(Rc::clone(&durable)),
    )?;
    let service = AuthorisedFilesystemService::new(filesystem, AllowingAuthority(principal_id));
    let mut service = BoundFilesystemAdapter::new(
        service,
        BranchId::from_bytes([11; 16])?,
        FilesystemAdapterPolicy::new(true, 1, 1)?,
    );

    let rejected = open_request(35, 36, false, true, 9, 80)?;
    let missing_credential = InProcessAdapter::new(gateway_b.node_id, [0; 32]);
    assert!(matches!(
        missing_credential.open(&mut service, &rejected, None),
        Err(AuthorisedFilesystemError::InvalidInput)
    ));
    gateway_b.open(&mut service, &rejected, None)?;
    let writer = open_request(21, 22, true, false, 10, 80)?;
    let reader = open_request(23, 24, false, true, 11, 80)?;
    let conflict = open_request(25, 26, true, true, 12, 80)?;
    open_writer(&gateway_a, &mut service, &writer)?;
    assert_conflicting_open(&gateway_b, &mut service, &conflict);
    gateway_b.open(&mut service, &reader, None)?;

    write_private(&gateway_a, &mut service, &writer, 27, 2, b"ZZ", 25)?;
    assert_read(&gateway_a, &mut service, &writer, 28, b"inZZial", 30)?;
    assert_read(&gateway_b, &mut service, &reader, 29, b"initial", 30)?;
    gateway_a.flush(&mut service, flush_request(30, &writer, 1, 7, 40)?)?;
    let uncommitted = write_request(&writer, 31, 0, b"Q", 45)?;
    assert!(matches!(
        gateway_b.write(&mut service, &uncommitted),
        Err(AuthorisedFilesystemError::InvalidGrant)
    ));
    let receipt = gateway_a.write(&mut service, &uncommitted)?;
    assert_eq!(
        receipt.stage_outcome,
        meshspan_filesystem::StageWriteOutcome::Applied
    );
    drop(service);

    let filesystem = FilesystemCommitService::open(
        directory.path(),
        UnixMicros::new(100),
        MemoryPublisher::new(Rc::clone(&durable)),
    )?;
    let restarted = AuthorisedFilesystemService::new(filesystem, AllowingAuthority(principal_id));
    let mut restarted = BoundFilesystemAdapter::new(
        restarted,
        BranchId::from_bytes([11; 16])?,
        FilesystemAdapterPolicy::new(true, 1, 1)?,
    );
    let failover_reader = open_request(32, 33, false, true, 100, 180)?;
    gateway_b.open(&mut restarted, &failover_reader, None)?;
    assert_read(
        &gateway_b,
        &mut restarted,
        &failover_reader,
        34,
        b"inZZial",
        110,
    )?;
    Ok(())
}

fn open_writer<S>(
    adapter: &InProcessAdapter,
    service: &mut S,
    request: &AdapterOpenFileRequest,
) -> Result<OpenHandleReceipt, S::Error>
where
    S: FilesystemFileAdapter,
{
    adapter.open(service, request, Some(1_024))
}

fn assert_conflicting_open(
    adapter: &InProcessAdapter,
    service: &mut BoundFilesystemAdapter<MemoryPublisher, AllowingAuthority>,
    request: &AdapterOpenFileRequest,
) {
    let result = adapter.open(service, request, Some(1_024));
    assert!(matches!(
        result,
        Err(AuthorisedFilesystemError::HandleIo(HandleIoError::Handle(
            HandleError::SharingViolation
        )))
    ));
}

fn write_private<S>(
    adapter: &InProcessAdapter,
    service: &mut S,
    open: &AdapterOpenFileRequest,
    operation: u8,
    offset: u64,
    bytes: &[u8],
    observed_at: i64,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: FilesystemFileAdapter,
    S::Error: std::error::Error + 'static,
{
    let request = write_request(open, operation, offset, bytes, observed_at)?;
    let receipt = adapter.write(service, &request)?;
    assert_eq!(
        receipt.stage_outcome,
        meshspan_filesystem::StageWriteOutcome::Applied
    );
    Ok(())
}

fn assert_read<S>(
    adapter: &InProcessAdapter,
    service: &mut S,
    open: &AdapterOpenFileRequest,
    operation: u8,
    expected: &[u8],
    observed_at: i64,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: FilesystemFileAdapter,
    S::Error: std::error::Error + 'static,
{
    let receipt = adapter.read(
        service,
        read_request(operation, open, u64::try_from(expected.len())?, observed_at)?,
    )?;
    assert_eq!(receipt.bytes.as_slice(), expected);
    Ok(())
}

#[derive(Clone, Copy)]
struct InProcessAdapter {
    node_id: NodeId,
    token_digest: [u8; 32],
}

impl InProcessAdapter {
    const fn new(node_id: NodeId, token_digest: [u8; 32]) -> Self {
        Self {
            node_id,
            token_digest,
        }
    }

    fn open<S: FilesystemFileAdapter>(
        self,
        service: &mut S,
        request: &AdapterOpenFileRequest,
        maximum_stage_bytes: Option<u64>,
    ) -> Result<OpenHandleReceipt, S::Error> {
        let mut request = request.clone();
        request.maximum_stage_bytes = maximum_stage_bytes;
        service.open_existing_file(self.context(request.observed_at), &request)
    }

    fn write<S: FilesystemFileAdapter>(
        self,
        service: &mut S,
        request: &AdapterWriteFileRequest,
    ) -> Result<meshspan_filesystem::FilesystemHandleWriteReceipt, S::Error> {
        service.write_file(self.context(request.observed_at), request)
    }

    fn read<S: FilesystemFileAdapter>(
        self,
        service: &mut S,
        request: AdapterReadFileRequest,
    ) -> Result<FilesystemHandleReadReceipt, S::Error> {
        service.read_file(self.context(request.observed_at), request)
    }

    fn flush<S: FilesystemFileAdapter>(
        self,
        service: &mut S,
        request: AdapterFlushFileRequest,
    ) -> Result<meshspan_filesystem::NamespacePublicationReceipt, S::Error> {
        service.flush_file(self.context(request.observed_at), request)
    }

    const fn context(self, now: UnixMicros) -> FilesystemAccessContext {
        FilesystemAccessContext {
            token_digest: self.token_digest,
            required_assurance: AssuranceLevel::SingleFactor,
            gateway_node_id: self.node_id,
            gateway_incarnation: 1,
            now,
        }
    }
}

#[derive(Clone, Copy)]
struct AllowingAuthority(PrincipalId);

impl FilesystemAccessAuthority for AllowingAuthority {
    type Error = AuthorityError;

    fn authorise(
        &self,
        request: FilesystemAuthorityRequest,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        Ok(FilesystemAuthorityGrant {
            principal_id: self.0,
            gateway_node_id: request.context.gateway_node_id,
            gateway_incarnation: request.context.gateway_incarnation,
            volume_id: request.volume_id,
            object_id: request.object_id,
            requested_rights: request.requested_rights,
            identity_revision: Revision::new(1),
            namespace_revision: Revision::new(1),
            object_revision: Revision::new(1),
            gateway_revision: Revision::new(1),
            expires_at: UnixMicros::new(500),
            evidence_digest: [42; 32],
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("test authority rejected the request")]
struct AuthorityError;

#[derive(Clone)]
struct MemoryPublisher {
    durable: DurableContents,
}

impl MemoryPublisher {
    fn new(durable: DurableContents) -> Self {
        Self { durable }
    }
}

impl DurableContentReader for MemoryPublisher {
    fn stream_range(
        &mut self,
        request: ContentReadRequest,
        destination: &mut dyn Write,
    ) -> Result<(), ContentReadError> {
        validate_read_request(request)?;
        let durable = self.durable.borrow();
        let Some((_, manifest, bytes)) = durable.get(&request.content.publication_operation_id)
        else {
            return Err(ContentReadError::Unavailable);
        };
        validate_stored_content(request.content, *manifest, bytes)?;
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
        let durable = self.durable.borrow();
        let Some((stored, manifest, _)) = durable.get(&request.operation_id) else {
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
        if self.durable.borrow().contains_key(&request.operation_id) {
            Err(ContentPublicationError::Conflict)
        } else {
            Ok(Vec::new())
        }
    }

    fn finish(
        &mut self,
        request: ContentPublicationRequest,
        sink: Self::Sink,
        completed: meshspan_filesystem::CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        validate_completed_content(&sink, completed)?;
        let manifest = manifest_for(request, completed);
        let mut durable = self.durable.borrow_mut();
        match durable.get(&request.operation_id) {
            Some((stored, prior, bytes))
                if stored.same_intent(request) && *prior == manifest && *bytes == sink =>
            {
                Ok(*prior)
            }
            Some(_) => Err(ContentPublicationError::Conflict),
            None => {
                durable.insert(request.operation_id, (request, manifest, sink));
                Ok(manifest)
            }
        }
    }
}

fn validate_read_request(request: ContentReadRequest) -> Result<(), ContentReadError> {
    let valid = request.authorization_revision != Revision::ZERO
        && request.observed_at < request.deadline
        && request
            .offset
            .checked_add(request.length)
            .is_some_and(|end| end <= request.content.manifest.logical_length);
    if valid {
        Ok(())
    } else {
        Err(ContentReadError::InvalidInput)
    }
}

fn validate_stored_content(
    content: PublishedContentReference,
    manifest: ManifestPublication,
    bytes: &[u8],
) -> Result<(), ContentReadError> {
    let valid = content.manifest == manifest
        && u64::try_from(bytes.len()).ok() == Some(manifest.logical_length)
        && blake3::hash(bytes).as_bytes() == &manifest.content_digest;
    if valid {
        Ok(())
    } else {
        Err(ContentReadError::Corrupt)
    }
}

fn validate_completed_content(
    sink: &[u8],
    completed: meshspan_filesystem::CompletedStage,
) -> Result<(), ContentPublicationError> {
    if u64::try_from(sink.len()).ok() == Some(completed.logical_length)
        && blake3::hash(sink).as_bytes() == &completed.content_digest
    {
        Ok(())
    } else {
        Err(ContentPublicationError::Corrupt)
    }
}

fn manifest_for(
    request: ContentPublicationRequest,
    completed: meshspan_filesystem::CompletedStage,
) -> ManifestPublication {
    let mut root = blake3::Hasher::new();
    root.update(b"meshspan.test.adapter-memory.v1\0");
    root.update(&request.manifest_id.as_bytes());
    root.update(&completed.content_digest);
    ManifestPublication {
        manifest_id: request.manifest_id,
        format_version: request.format_version,
        logical_length: completed.logical_length,
        content_digest: completed.content_digest,
        root_digest: root.finalize().into(),
    }
}

fn seed_content(durable: &DurableContents, publication: FilePublication, bytes: &[u8]) {
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
    durable.borrow_mut().insert(
        publication.operation_id,
        (request, publication.manifest, bytes.to_vec()),
    );
}

fn seed_namespace(
    state: &std::path::Path,
    publication: &RootFilePublication,
) -> Result<(), Box<dyn std::error::Error>> {
    VersionPublicationStore::open(state, UnixMicros::new(1))?.publish_root_file(publication)?;
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

fn open_request(
    operation: u8,
    handle: u8,
    writable: bool,
    share_write: bool,
    opened_at: i64,
    lease_expires_at: i64,
) -> Result<AdapterOpenFileRequest, Box<dyn std::error::Error>> {
    Ok(AdapterOpenFileRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        handle_id: HandleId::from_bytes([handle; 16])?,
        volume_id: VolumeId::from_bytes([12; 16])?,
        path: NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?,
        desired_access: HandleAccess::new(true, writable, false)?,
        share_access: HandleShare::new(true, share_write, false),
        delete_on_close: false,
        maximum_stage_bytes: writable.then_some(1_024),
        lease_expires_at: UnixMicros::new(lease_expires_at),
        observed_at: UnixMicros::new(opened_at),
    })
}

fn write_request(
    open: &AdapterOpenFileRequest,
    operation: u8,
    offset: u64,
    bytes: &[u8],
    observed_at: i64,
) -> Result<AdapterWriteFileRequest, Box<dyn std::error::Error>> {
    Ok(AdapterWriteFileRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        handle_id: open.handle_id,
        handle_fence: 1,
        offset,
        bytes: BoundedBytes::copy_from(bytes, bytes.len())?,
        observed_at: UnixMicros::new(observed_at),
    })
}

fn read_request(
    operation: u8,
    open: &AdapterOpenFileRequest,
    length: u64,
    observed_at: i64,
) -> Result<AdapterReadFileRequest, Box<dyn std::error::Error>> {
    Ok(AdapterReadFileRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        handle_id: open.handle_id,
        handle_fence: 1,
        offset: 0,
        length,
        content_deadline: UnixMicros::new(200),
        observed_at: UnixMicros::new(observed_at),
    })
}

fn flush_request(
    operation: u8,
    open: &AdapterOpenFileRequest,
    sequence: u64,
    final_length: u64,
    observed_at: i64,
) -> Result<AdapterFlushFileRequest, Box<dyn std::error::Error>> {
    Ok(AdapterFlushFileRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        handle_id: open.handle_id,
        handle_fence: 1,
        expected_stage_sequence: sequence,
        final_length,
        sparse: false,
        content_deadline: UnixMicros::new(70),
        observed_at: UnixMicros::new(observed_at),
    })
}
