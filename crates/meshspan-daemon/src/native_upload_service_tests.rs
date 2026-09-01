// SPDX-License-Identifier: GPL-2.0-only

use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, BeginUploadRequest, BeginUploadResponse, CommitUploadRequest,
    CreateDirectoryRequest, CreateDirectoryResponse, DeleteObjectRequest, DeleteObjectResponse,
    DeleteObjectScope, DirectoryEntryKind as ApiDirectoryEntryKind, MAX_NAMESPACE_MUTATION_BYTES,
    NamespacePath as ApiNamespacePath, OperationId as ApiOperationId, RenameObjectRequest,
    RenameObjectResponse, UploadDisposition as ApiUploadDisposition, UploadState as ApiUploadState,
};
use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, BranchId, ContentManifestId, FileVersionId,
    NamespaceCommitId, NodeId, ObjectId, ObjectRevisionId, OperationId, PrincipalId, Revision,
    Rights, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    AuthorisedFilesystemError, AuthorisedFilesystemService, BoundFilesystemAdapter, CompletedStage,
    ContentPublicationError, ContentPublicationRequest, ContentReadError, ContentReadRequest,
    DurableContentPublisher, DurableContentReader, FilePublication, FilesystemAccessAuthority,
    FilesystemAccessContext, FilesystemAdapterPolicy, FilesystemAuthorityGrant,
    FilesystemAuthorityRequest, FilesystemCommitService, HandleError, ManifestPublication,
    NamespaceLimits, NamespacePath, NamespacePublicationPath, RootFilePublication,
    VersionPublicationStore,
};
use tempfile::tempdir;
use tower::ServiceExt;

use crate::{
    FileApiAuthenticationError, FileApiFailure, NativeFileApiAuthenticator,
    NativeFileRequestProtection, NativeNamespaceMutationController, NativeNamespaceMutationService,
    NativeUploadController, NativeUploadService, NativeUploadServicePolicy,
    UploadRangeWriteRequest, native_namespace_mutation_api_router, native_upload_api_router,
};

const AUTHENTICATION_PROOF: &str = "MeshSpan native-service-proof";

#[test]
fn first_upload_materialises_a_new_volume_root_and_publishes_exact_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut service = native_upload_service(directory.path())?;
    let context = service.authenticate(
        &authenticated_headers(),
        NativeFileRequestProtection::Mutation,
        UnixMicros::new(10),
    )?;
    let begin = service.begin_upload(
        context,
        &uuid_text(versioned(12)),
        BeginUploadRequest {
            operation_id: api_operation(versioned(110))?,
            path: api_path("first.bin")?,
            disposition: ApiUploadDisposition::CreateNew,
            maximum_bytes: 64,
        },
    )?;
    let bytes = BoundedBytes::copy_from(b"first durable bytes", 19)?;
    let written = service.write_upload_range(
        context,
        begin.upload_id.as_str(),
        UploadRangeWriteRequest {
            operation_id: api_operation(versioned(111))?,
            stage_fence: begin.stage_fence,
            offset: 0,
            content_blake3: blake3::hash(bytes.as_slice()).into(),
            bytes,
        },
    )?;
    let committed = service.commit_upload(
        context,
        begin.upload_id.as_str(),
        CommitUploadRequest {
            operation_id: api_operation(versioned(112))?,
            stage_fence: written.stage_fence,
            expected_sequence: written.checkpoint_sequence,
            final_length: 19,
            sparse: false,
            expected_blake3: Some(blake3::hash(b"first durable bytes").to_hex().to_string()),
        },
    )?;
    assert_eq!(committed.upload.state, ApiUploadState::Committed);
    assert_eq!(committed.object.path.as_str(), "first.bin");
    assert_eq!(committed.object.object.logical_length, Some(19));
    Ok(())
}

#[test]
fn specialised_native_service_publishes_a_real_authorised_upload()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_namespace(directory.path())?;
    let mut service = native_upload_service(directory.path())?;
    let context = service.authenticate(
        &authenticated_headers(),
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

#[test]
fn specialised_native_service_mutates_a_real_namespace_with_exact_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_namespace(directory.path())?;
    let mut service = native_namespace_service(directory.path())?;
    let context = service.authenticate(
        &authenticated_headers(),
        NativeFileRequestProtection::Mutation,
        UnixMicros::new(10),
    )?;
    let volume_id = uuid_text(versioned(12));
    let create_request = CreateDirectoryRequest {
        operation_id: api_operation(versioned(90))?,
        path: api_path("incoming")?,
    };
    let created = service
        .create_directory(context, &volume_id, create_request.clone())
        .map_err(|error| format!("create failed: {error:?}"))?;
    assert_eq!(
        service
            .create_directory(context, &volume_id, create_request)
            .map_err(|error| format!("create replay failed: {error:?}"))?,
        created
    );

    let rename_request = RenameObjectRequest {
        operation_id: api_operation(versioned(91))?,
        source_path: api_path("incoming")?,
        target_path: api_path("ready")?,
    };
    let renamed = service
        .rename_object(context, &volume_id, rename_request.clone())
        .map_err(|error| format!("rename failed: {error:?}"))?;
    assert_eq!(renamed.object_id, created.object_id);
    assert_eq!(
        service
            .rename_object(context, &volume_id, rename_request)
            .map_err(|error| format!("rename replay failed: {error:?}"))?,
        renamed
    );

    let delete_request = DeleteObjectRequest {
        operation_id: api_operation(versioned(92))?,
        path: api_path("ready")?,
    };
    let deleted = service
        .delete_object(context, &volume_id, delete_request.clone())
        .map_err(|error| format!("delete failed: {error:?}"))?;
    assert_eq!(deleted.object_id, created.object_id);
    assert_eq!(deleted.object_kind, ApiDirectoryEntryKind::Directory);
    assert_eq!(deleted.scope, DeleteObjectScope::BranchDeleted);
    assert_eq!(
        service
            .delete_object(context, &volume_id, delete_request)
            .map_err(|error| format!("delete replay failed: {error:?}"))?,
        deleted
    );
    Ok(())
}

#[tokio::test]
async fn native_http_client_publishes_through_the_real_filesystem_service()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_namespace(directory.path())?;
    let router = native_upload_api_router(native_upload_service(directory.path())?)?;
    let volume_id = uuid_text(versioned(12));
    let begin = router
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/latest/volumes/{volume_id}/uploads"),
            &serde_json::json!({
                "disposition": { "mode": "create_new" },
                "maximum_bytes": 1_024,
                "operation_id": uuid_text(versioned(80)),
                "path": "from-client.bin"
            }),
        )?)
        .await?;
    assert_eq!(begin.status(), StatusCode::CREATED);
    let begin: BeginUploadResponse = serde_json::from_slice(&response_body(begin).await?)?;
    let upload_id = begin.upload_id.as_str();
    let content = b"external native client";
    let write = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/latest/uploads/{upload_id}/ranges/0"))
                .header(AUTHORIZATION, AUTHENTICATION_PROOF)
                .header(CONTENT_TYPE, "application/octet-stream")
                .header("MeshSpan-Operation-Id", uuid_text(versioned(81)))
                .header("MeshSpan-Stage-Fence", begin.stage_fence)
                .header(
                    "MeshSpan-Content-BLAKE3",
                    blake3::hash(content).to_hex().to_string(),
                )
                .body(Body::from(content.as_slice()))?,
        )
        .await?;
    assert_eq!(write.status(), StatusCode::OK);
    let written: meshspan_api_contract::WriteUploadRangeResponse =
        serde_json::from_slice(&response_body(write).await?)?;
    let commit = router
        .oneshot(json_request(
            "POST",
            &format!("/api/latest/uploads/{upload_id}/commits"),
            &serde_json::json!({
                "expected_blake3": blake3::hash(content).to_hex().to_string(),
                "expected_sequence": written.checkpoint_sequence,
                "final_length": content.len(),
                "operation_id": uuid_text(versioned(82)),
                "sparse": false,
                "stage_fence": written.stage_fence
            }),
        )?)
        .await?;
    let commit_status = commit.status();
    let commit_body = response_body(commit).await?;
    assert_eq!(
        commit_status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&commit_body)
    );
    let committed: meshspan_api_contract::CommitUploadResponse =
        serde_json::from_slice(&commit_body)?;
    assert_eq!(committed.upload.state, ApiUploadState::Committed);
    assert_eq!(
        committed.object.object.logical_length,
        Some(i64::try_from(content.len())?)
    );
    assert_eq!(committed.object.path.as_str(), "from-client.bin");
    Ok(())
}

#[tokio::test]
async fn native_http_client_mutates_the_real_authorised_namespace()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    seed_namespace(directory.path())?;
    let router = native_namespace_mutation_api_router(native_namespace_service(directory.path())?)?;
    let volume_id = uuid_text(versioned(12));

    let unauthenticated = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/latest/volumes/{volume_id}/directories"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b'x'; MAX_NAMESPACE_MUTATION_BYTES + 1]))?,
        )
        .await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let create = router
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/latest/volumes/{volume_id}/directories"),
            &serde_json::json!({
                "operation_id": uuid_text(versioned(100)),
                "path": "working"
            }),
        )?)
        .await?;
    assert_eq!(create.status(), StatusCode::CREATED);
    let created: CreateDirectoryResponse = serde_json::from_slice(&response_body(create).await?)?;

    let conflict = router
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/latest/volumes/{volume_id}/directories"),
            &serde_json::json!({
                "operation_id": uuid_text(versioned(100)),
                "path": "different"
            }),
        )?)
        .await?;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let conflict: ApiError = serde_json::from_slice(&response_body(conflict).await?)?;
    assert_eq!(conflict.code, ApiErrorCode::OperationConflict);

    let rename = router
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/latest/volumes/{volume_id}/renames"),
            &serde_json::json!({
                "operation_id": uuid_text(versioned(101)),
                "source_path": "working",
                "target_path": "complete"
            }),
        )?)
        .await?;
    assert_eq!(rename.status(), StatusCode::OK);
    let renamed: RenameObjectResponse = serde_json::from_slice(&response_body(rename).await?)?;
    assert_eq!(renamed.object_id, created.object_id);

    let delete = router
        .oneshot(json_request(
            "POST",
            &format!("/api/latest/volumes/{volume_id}/deletions"),
            &serde_json::json!({
                "operation_id": uuid_text(versioned(102)),
                "path": "complete"
            }),
        )?)
        .await?;
    assert_eq!(delete.status(), StatusCode::OK);
    let deleted: DeleteObjectResponse = serde_json::from_slice(&response_body(delete).await?)?;
    assert_eq!(deleted.object_id, created.object_id);
    assert_eq!(deleted.scope, DeleteObjectScope::BranchDeleted);
    Ok(())
}

struct TestAuthenticator;

impl NativeFileApiAuthenticator for TestAuthenticator {
    fn authenticate_file_request(
        &self,
        headers: &HeaderMap,
        _protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError> {
        if headers.get(AUTHORIZATION) != Some(&HeaderValue::from_static(AUTHENTICATION_PROOF)) {
            return Err(FileApiAuthenticationError::Rejected);
        }
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
            expires_at: request
                .context
                .now
                .checked_add(meshspan_domain::DurationMicros::new(60_000_000))
                .ok_or(TestAuthorityError)?,
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

type TestFilesystem = BoundFilesystemAdapter<TestPublisher, TestAuthority>;
type TestService = NativeUploadService<
    TestAuthenticator,
    TestFilesystem,
    fn(&AuthorisedFilesystemError<TestAuthorityError>) -> FileApiFailure,
>;
type TestNamespaceService = NativeNamespaceMutationService<
    TestAuthenticator,
    TestFilesystem,
    fn(&AuthorisedFilesystemError<TestAuthorityError>) -> FileApiFailure,
>;

fn native_upload_service(
    state: &std::path::Path,
) -> Result<TestService, Box<dyn std::error::Error>> {
    let filesystem = FilesystemCommitService::open(state, UnixMicros::new(1), TestPublisher)?;
    let filesystem = BoundFilesystemAdapter::new(
        AuthorisedFilesystemService::new(filesystem, TestAuthority),
        BranchId::from_bytes(versioned(11))?,
        FilesystemAdapterPolicy::new(true, 1, 1)?,
    );
    let policy = NativeUploadServicePolicy::new(
        meshspan_domain::DurationMicros::new(3_600_000_000),
        meshspan_domain::DurationMicros::new(60_000_000),
    )
    .ok_or("upload policy")?;
    Ok(NativeUploadService::new(
        TestAuthenticator,
        filesystem,
        classify_filesystem_error,
        policy,
    ))
}

fn native_namespace_service(
    state: &std::path::Path,
) -> Result<TestNamespaceService, Box<dyn std::error::Error>> {
    let filesystem = FilesystemCommitService::open(state, UnixMicros::new(1), TestPublisher)?;
    let filesystem = BoundFilesystemAdapter::new(
        AuthorisedFilesystemService::new(filesystem, TestAuthority),
        BranchId::from_bytes(versioned(11))?,
        FilesystemAdapterPolicy::new(true, 1, 1)?,
    );
    Ok(NativeNamespaceMutationService::new(
        TestAuthenticator,
        filesystem,
        classify_filesystem_error,
    ))
}

fn authenticated_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static(AUTHENTICATION_PROOF),
    );
    headers
}

fn json_request(
    method: &str,
    uri: &str,
    value: &serde_json::Value,
) -> Result<Request<Body>, axum::http::Error> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, AUTHENTICATION_PROOF)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(value.to_string()))
}

async fn response_body(
    response: axum::response::Response,
) -> Result<axum::body::Bytes, axum::Error> {
    to_bytes(response.into_body(), 256 * 1_024).await
}

fn classify_filesystem_error(
    error: &AuthorisedFilesystemError<TestAuthorityError>,
) -> FileApiFailure {
    match error {
        AuthorisedFilesystemError::InvalidInput => FileApiFailure::InvalidInput,
        AuthorisedFilesystemError::TargetUnavailable
        | AuthorisedFilesystemError::Handle(HandleError::NotFound) => FileApiFailure::NotFound,
        AuthorisedFilesystemError::Authority(_) => FileApiFailure::AccessDenied,
        AuthorisedFilesystemError::Handle(HandleError::InvalidInput) => {
            FileApiFailure::InvalidInput
        }
        AuthorisedFilesystemError::Handle(HandleError::OperationConflict) => {
            FileApiFailure::Conflict
        }
        AuthorisedFilesystemError::Handle(
            HandleError::AlreadyExists
            | HandleError::CreationRequired
            | HandleError::SharingViolation
            | HandleError::DeletePending
            | HandleError::StaleHandle
            | HandleError::GatewayMismatch
            | HandleError::LockConflict
            | HandleError::FlushInProgress
            | HandleError::DirectoryNotEmpty
            | HandleError::StaleLock,
        ) => FileApiFailure::StaleCursor,
        AuthorisedFilesystemError::InvalidGrant
        | AuthorisedFilesystemError::Handle(
            HandleError::Corrupt | HandleError::Namespace(_) | HandleError::Sqlite(_),
        )
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

fn api_path(value: &str) -> Result<ApiNamespacePath, Box<dyn std::error::Error>> {
    ApiNamespacePath::from_decoded(value.to_owned()).ok_or_else(|| "path".into())
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
