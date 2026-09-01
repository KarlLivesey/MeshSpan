// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, CreateMeshSetupRequest, CreateMeshSetupResponse, JoinMeshSetupRequest,
    JoinMeshSetupResponse, SetupState, SetupStatusResponse,
};
use meshspan_domain::{ClaimBundleError, ClaimId, NodeId, OperationId, UnixMicros};
use meshspan_metadata::{LocalDatabase, LocalSetupKind, NewLocalClaim, NewLocalSetup};
use tempfile::tempdir;
use tower::ServiceExt;

use crate::{
    CreateMeshSetupController, CreateMeshSetupError, JoinMeshSetupController, JoinMeshSetupError,
    SetupStateSnapshot, setup_api_router, setup_api_router_with_creation,
    setup_api_router_with_mutations,
};

#[tokio::test]
async fn anonymous_status_tracks_only_the_coarse_lifecycle_state()
-> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(SetupStateSnapshot::new(SetupState::ClaimRequired));
    let router = setup_api_router(Arc::clone(&state))?;
    assert_status(&router, SetupState::ClaimRequired).await?;
    state.store(SetupState::Configuring);
    assert_status(&router, SetupState::Configuring).await?;
    state.store(SetupState::Configured);
    assert_status(&router, SetupState::Configured).await
}

#[tokio::test]
async fn durable_claim_and_setup_evidence_drive_status_after_each_transition()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        NodeId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let claim_id = ClaimId::from_bytes([2; 16])?;
    database.create_local_claim(NewLocalClaim {
        claim_id,
        node_public_key_fingerprint: [3; 32],
        secret_digest: [4; 32],
        created_at: UnixMicros::new(10),
    })?;
    let snapshot = Arc::new(SetupStateSnapshot::new(SetupState::Configuring));
    let router = setup_api_router(Arc::clone(&snapshot))?;
    assert_eq!(snapshot.reconcile(&database)?, SetupState::ClaimRequired);
    assert_status(&router, SetupState::ClaimRequired).await?;

    let setup = NewLocalSetup {
        operation_id: OperationId::from_bytes([5; 16])?,
        claim_id,
        claim_secret_digest: [4; 32],
        kind: LocalSetupKind::CreateMesh,
        request_digest: [6; 32],
        created_at: UnixMicros::new(11),
    };
    database.prepare_local_setup(setup)?;
    assert_eq!(snapshot.reconcile(&database)?, SetupState::Configuring);
    database.record_local_setup_authority_commit(
        setup.operation_id,
        [7; 32],
        UnixMicros::new(20),
    )?;
    assert_eq!(snapshot.reconcile(&database)?, SetupState::Configuring);
    database.complete_local_setup(
        setup.operation_id,
        setup.claim_id,
        setup.claim_secret_digest,
        UnixMicros::new(30),
    )?;
    assert_eq!(snapshot.reconcile(&database)?, SetupState::Configured);
    assert_status(&router, SetupState::Configured).await
}

#[tokio::test]
async fn creation_boundary_rejects_unbounded_or_untyped_input_before_service_work()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = setup_api_router_with_creation(
        Arc::new(SetupStateSnapshot::new(SetupState::ClaimRequired)),
        FakeController::new(FakeOutcome::Success, Arc::clone(&calls)),
    )?;

    let missing_content_type = router
        .clone()
        .oneshot(Request::post("/api/latest/setup/meshes").body(Body::from(valid_setup_body()?))?)
        .await?;
    assert_api_error(
        missing_content_type,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ApiErrorCode::InvalidRequest,
    )
    .await?;

    let oversized = router
        .clone()
        .oneshot(
            Request::post("/api/latest/setup/meshes")
                .header("content-type", "application/json")
                .body(Body::from(vec![b' '; 2_049]))?,
        )
        .await?;
    assert_api_error(
        oversized,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
    )
    .await?;

    let malformed = router
        .oneshot(
            Request::post("/api/latest/setup/meshes")
                .header("content-type", "application/json; charset=utf-8")
                .body(Body::from("{"))?,
        )
        .await?;
    assert_api_error(
        malformed,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
    )
    .await?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn creation_boundary_validates_success_and_maps_claim_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = setup_api_router_with_creation(
        Arc::new(SetupStateSnapshot::new(SetupState::ClaimRequired)),
        FakeController::new(FakeOutcome::Success, Arc::clone(&calls)),
    )?;
    let response = router
        .oneshot(json_setup_request(valid_setup_body()?)?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get("cache-control"),
        Some(&"no-store".parse()?)
    );
    let body = to_bytes(response.into_body(), 2_048).await?;
    let created = serde_json::from_slice::<CreateMeshSetupResponse>(&body)?;
    assert_eq!(created.operation_id.as_str(), TEST_OPERATION_ID);
    assert!(created.api_key.starts_with("meshspan-key-v1."));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let rejected_calls = Arc::new(AtomicUsize::new(0));
    let rejected_router = setup_api_router_with_creation(
        Arc::new(SetupStateSnapshot::new(SetupState::ClaimRequired)),
        FakeController::new(FakeOutcome::ClaimRejected, Arc::clone(&rejected_calls)),
    )?;
    let rejected = rejected_router
        .oneshot(json_setup_request(valid_setup_body()?)?)
        .await?;
    let error = assert_api_error(
        rejected,
        StatusCode::UNAUTHORIZED,
        ApiErrorCode::Unauthenticated,
    )
    .await?;
    assert_eq!(
        error.operation_id.ok_or("operation ID missing")?.as_str(),
        TEST_OPERATION_ID
    );
    assert_eq!(rejected_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn join_boundary_returns_the_restart_safe_operation_location()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = setup_api_router_with_mutations(
        Arc::new(SetupStateSnapshot::new(SetupState::ClaimRequired)),
        FakeController::new(FakeOutcome::Success, Arc::new(AtomicUsize::new(0))),
        FakeJoinController {
            calls: Arc::clone(&calls),
        },
    )?;
    let response = router
        .oneshot(
            Request::post("/api/latest/setup/joins")
                .header("content-type", "application/json")
                .body(Body::from(valid_join_body()?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), 2_048).await?;
    let accepted = serde_json::from_slice::<JoinMeshSetupResponse>(&body)?;
    assert_eq!(accepted.operation_id.as_str(), TEST_OPERATION_ID);
    assert_eq!(
        accepted.status_url,
        format!("/api/latest/operations/{TEST_OPERATION_ID}")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

async fn assert_status(
    router: &axum::Router,
    expected: SetupState,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = router
        .clone()
        .oneshot(Request::get("/api/latest/setup/status").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("meshspan-api-version"),
        Some(&"latest".parse()?)
    );
    let schema = response
        .headers()
        .get("meshspan-api-schema")
        .ok_or("schema header missing")?
        .to_str()?;
    assert!(schema.starts_with("sha256:"));
    assert_eq!(schema.len(), 71);
    let bytes = to_bytes(response.into_body(), 1_024).await?;
    assert_eq!(
        serde_json::from_slice::<SetupStatusResponse>(&bytes)?,
        SetupStatusResponse { state: expected }
    );
    Ok(())
}

const TEST_OPERATION_ID: &str = "00000000-0000-4000-8000-000000000001";

fn valid_setup_body() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "operation_id": TEST_OPERATION_ID,
        "claim": format!("meshspan-claim-v1.{}.{}", "1".repeat(32), "2".repeat(64)),
        "mesh_name": "First mesh",
        "administrator_name": "Administrator",
        "host_name": "First host",
        "node_name": "First node"
    }))
}

fn valid_join_body() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "operation_id": TEST_OPERATION_ID,
        "claim": format!("meshspan-claim-v1.{}.{}", "1".repeat(32), "2".repeat(64)),
        "join_code": format!(
            "meshspan-join-v2.{}.{}.{}.{}.{}",
            "3".repeat(32),
            "4".repeat(32),
            "5".repeat(64),
            "6".repeat(64),
            "7".repeat(64),
        ),
        "host_name": "Shop host",
        "node_name": "Shop node"
    }))
}

fn json_setup_request(body: Vec<u8>) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/api/latest/setup/meshes")
        .header("content-type", "application/json")
        .body(Body::from(body))
}

async fn assert_api_error(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_code: ApiErrorCode,
) -> Result<ApiError, Box<dyn std::error::Error>> {
    assert_eq!(response.status(), expected_status);
    assert_eq!(
        response.headers().get("content-type"),
        Some(&"application/json".parse()?)
    );
    let body = to_bytes(response.into_body(), 2_048).await?;
    let error = serde_json::from_slice::<ApiError>(&body)?;
    assert_eq!(error.code, expected_code);
    assert_eq!(error.request_id.len(), 36);
    Ok(error)
}

#[derive(Clone, Copy)]
enum FakeOutcome {
    Success,
    ClaimRejected,
}

struct FakeController {
    outcome: FakeOutcome,
    calls: Arc<AtomicUsize>,
}

impl FakeController {
    fn new(outcome: FakeOutcome, calls: Arc<AtomicUsize>) -> Self {
        Self { outcome, calls }
    }
}

impl CreateMeshSetupController for FakeController {
    fn create_mesh(
        &mut self,
        request: &CreateMeshSetupRequest,
        _now: UnixMicros,
    ) -> Result<CreateMeshSetupResponse, CreateMeshSetupError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.outcome {
            FakeOutcome::Success => Ok(CreateMeshSetupResponse {
                operation_id: request.operation_id.clone(),
                mesh_id: "00000000-0000-4000-8000-000000000002".to_owned(),
                node_id: "00000000-0000-4000-8000-000000000003".to_owned(),
                api_key: format!("meshspan-key-v1.{}.{}", "3".repeat(32), "4".repeat(64)),
                recovery_bundle: format!("meshspan-recovery-file-v1.{}", "a5".repeat(128)),
                recovery_code: format!("meshspan-offline-v1.{}", "6".repeat(64)),
                recovery_challenge: format!("meshspan-check-v1.{}", "7".repeat(16)),
            }),
            FakeOutcome::ClaimRejected => Err(CreateMeshSetupError::Claim(
                ClaimBundleError::InvalidEncoding,
            )),
        }
    }
}

struct FakeJoinController {
    calls: Arc<AtomicUsize>,
}

impl JoinMeshSetupController for FakeJoinController {
    fn join_mesh(
        &mut self,
        request: &JoinMeshSetupRequest,
    ) -> Result<JoinMeshSetupResponse, JoinMeshSetupError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(JoinMeshSetupResponse {
            operation_id: request.operation_id.clone(),
            status_url: format!("/api/latest/operations/{}", request.operation_id.as_str()),
        })
    }
}
