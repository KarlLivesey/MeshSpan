// SPDX-License-Identifier: GPL-2.0-only

use axum::http::HeaderMap;
use meshspan_api_contract::{
    BeginUploadRequest, CommitUploadRequest, NamespacePath as ApiNamespacePath,
    OperationId as ApiOperationId, UploadDisposition as ApiUploadDisposition,
    UploadState as ApiUploadState,
};
use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, BranchId, ContentManifestId, FileVersionId,
    NamespaceCommitId, NodeId, ObjectId, ObjectRevisionId, OperationId, PrincipalId, Revision,
    UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    AuthorisedFilesystemError, AuthorisedFilesystemService, BoundFilesystemAdapter, CompletedStage,
    ContentPublicationError, ContentPublicationRequest, ContentReadError, ContentReadRequest,
    DurableContentPublisher, DurableContentReader, FilePublication, FilesystemAccessAuthority,
    FilesystemAccessContext, FilesystemAdapterPolicy, FilesystemAuthorityGrant,
    FilesystemAuthorityRequest, FilesystemCommitService, ManifestPublication, NamespaceLimits,
    NamespacePath, NamespacePublicationPath, RootFilePublication, VersionPublicationStore,
};
use tempfile::tempdir;

use crate::{
    FileApiAuthenticationError, FileApiFailure, NativeFileApiAuthenticator,
    NativeFileRequestProtection, NativeUploadController, NativeUploadService,
    NativeUploadServicePolicy, UploadRangeWriteRequest,
};

#[test]
fn specialised_native_service_publishes_a_real_authorised_upload()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_namespace(directory.path())?;
    let filesystem =
        FilesystemCommitService::open(directory.path(), UnixMicros::new(1), TestPublisher)?;
    let filesystem = BoundFilesystemAdapter::new(
        AuthorisedFilesystemService::new(filesystem, TestAuthority),
        BranchId::from_bytes(versioned(11))?,
        FilesystemAdapterPolicy::new(true, 1, 1)?,
    );
    let upload_policy = NativeUploadServicePolicy::new(
        meshspan_domain::DurationMicros::new(3_600_000_000),
        meshspan_domain::DurationMicros::new(60_000_000),
    )
    .ok_or("upload policy")?;
    let mut service = NativeUploadService::new(
        TestAuthenticator,
        filesystem,
        classify_filesystem_error,
        upload_policy,
    );
    let context = service.authenticate(
        &HeaderMap::new(),
        NativeFileRequestProtection::Mutation,
        UnixMicros::new(10),
    )?;
    let begin = service.begin_upload(
        context,
        &uuid_text(versioned(12)),
        BeginUploadRequest {
            operation_id: api_operation(versioned(70))?,
            path: ApiNamespacePath::from_decoded("final.bin".to_owned()).ok_or("path")?,
            disposition: ApiUploadDisposition::CreateNew,
            maximum_bytes: 1_024,
        },
    )?;
    let upload_id = begin.upload_id.as_str().to_owned();
    let bytes = BoundedBytes::copy_from(b"meshspan", 8)?;
    let written = service.write_upload_range(
        context,
        &upload_id,
        UploadRangeWriteRequest {
            operation_id: api_operation(versioned(71))?,
            stage_fence: begin.stage_fence,
            offset: 0,
            content_blake3: blake3::hash(bytes.as_slice()).into(),
            bytes,
        },
    )?;
    assert_eq!(written.logical_extent, 8);
    let committed = service.commit_upload(
        context,
        &upload_id,
        CommitUploadRequest {
            operation_id: api_operation(versioned(72))?,
            stage_fence: written.stage_fence,
            expected_sequence: written.checkpoint_sequence,
            final_length: 8,
            sparse: false,
            expected_blake3: Some(blake3::hash(b"meshspan").to_hex().to_string()),
        },
    )?;
    assert_eq!(committed.upload.state, ApiUploadState::Committed);
    assert_eq!(committed.object.object.logical_length, Some(8));
    assert_eq!(committed.object.path.as_str(), "final.bin");
    Ok(())
}

struct TestAuthenticator;

impl NativeFileApiAuthenticator for TestAuthenticator {
    fn authenticate_file_request(
        &self,
        _headers: &HeaderMap,
        _protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError> {
        Ok(FilesystemAccessContext {
            authentication_service: AuthenticationService::HeadlessApi,
            credential_digest: [9; 32],
            required_assurance: AssuranceLevel::SingleFactor,
            gateway_node_id: NodeId::from_bytes(versioned(19))
                .map_err(|_| FileApiAuthenticationError::Rejected)?,
            gateway_incarnation: 1,
            now,
        })
    }
}

struct TestAuthority;

#[derive(Debug, thiserror::Error)]
#[error("test authority failed")]
struct TestAuthorityError;

impl FilesystemAccessAuthority for TestAuthority {
    type Error = TestAuthorityError;

    fn authorise(
        &self,
        request: FilesystemAuthorityRequest,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        Ok(FilesystemAuthorityGrant {
            principal_id: PrincipalId::from_bytes(versioned(18)).map_err(|_| TestAuthorityError)?,
            gateway_node_id: request.context.gateway_node_id,
            gateway_incarnation: request.context.gateway_incarnation,
            volume_id: request.volume_id,
            object_id: request.object_id,
            requested_rights: request.requested_rights,
            identity_revision: Revision::new(1),
            namespace_revision: Revision::new(1),
            object_revision: Revision::new(1),
            gateway_revision: Revision::new(1),
            expires_at: UnixMicros::new(1_000_000_000),
            evidence_digest: [7; 32],
        })
    }
}

fn classify_filesystem_error(
    error: &AuthorisedFilesystemError<TestAuthorityError>,
) -> FileApiFailure {
    match error {
        AuthorisedFilesystemError::InvalidInput => FileApiFailure::InvalidInput,
        AuthorisedFilesystemError::TargetUnavailable => FileApiFailure::NotFound,
        AuthorisedFilesystemError::Authority(_) => FileApiFailure::AccessDenied,
        AuthorisedFilesystemError::InvalidGrant
        | AuthorisedFilesystemError::Handle(_)
        | AuthorisedFilesystemError::HandleIo(_)
        | AuthorisedFilesystemError::Upload(_)
        | AuthorisedFilesystemError::Commit(_)
        | AuthorisedFilesystemError::Read(_)
        | AuthorisedFilesystemError::Query(_) => FileApiFailure::Failed,
    }
}

struct TestPublisher;

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
        completed: CompletedStage,
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

impl DurableContentReader for TestPublisher {
    fn stream_range(
        &mut self,
        _request: ContentReadRequest,
        _destination: &mut dyn std::io::Write,
    ) -> Result<(), ContentReadError> {
        Err(ContentReadError::Unavailable)
    }
}

fn seed_namespace(state: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = VersionPublicationStore::open(state, UnixMicros::new(1))?;
    store.publish_root_file(&RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes(versioned(1))?,
            branch_id: BranchId::from_bytes(versioned(11))?,
            volume_id: VolumeId::from_bytes(versioned(12))?,
            object_id: ObjectId::from_bytes(versioned(13))?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes(versioned(14))?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes(versioned(15))?,
                format_version: 1,
                logical_length: 0,
                content_digest: blake3::hash(&[]).into(),
                root_digest: [17; 32],
            },
            created_by: PrincipalId::from_bytes(versioned(18))?,
            created_at: UnixMicros::new(1),
        },
        root_object_id: ObjectId::from_bytes(versioned(2))?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes(versioned(3))?,
        root_object_revision_id: ObjectRevisionId::from_bytes(versioned(4))?,
        namespace_commit_id: NamespaceCommitId::from_bytes(versioned(5))?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["seed"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })?;
    Ok(())
}

fn api_operation(bytes: [u8; 16]) -> Result<ApiOperationId, Box<dyn std::error::Error>> {
    ApiOperationId::parse(&uuid_text(bytes)).ok_or_else(|| "operation".into())
}

fn uuid_text(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

const fn versioned(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
