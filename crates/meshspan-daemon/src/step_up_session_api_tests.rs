// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, AssuranceLevel, CreateSessionResponse, StepUpCurrentSessionRequest,
};
use meshspan_domain::{
    ApiKeyBundle, OperationId, SessionCsrfBundle, SessionTokenBundle, UnixMicros,
};
use tower::ServiceExt;

use crate::{
    CreateSessionResult, SessionAuthorityError, StepUpCurrentSessionController,
    StepUpCurrentSessionError, step_up_current_session_api_router,
};

const OPERATION: &str = "00000000-0000-4000-8000-0000000000c1";
const ROUTE: &str = "/api/latest/sessions/current/step-ups";
const API_KEY: &str = concat!(
    "meshspan-key-v1.00000000000040008000000000000031.",
    "1111111111111111111111111111111111111111111111111111111111111111"
);

#[tokio::test]
async fn boundary_returns_secure_replacement_material() -> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let response = step_up_current_session_api_router(FakeController::new(
        FakeOutcome::Success,
        Arc::clone(&calls),
    ))?
    .oneshot(json_request(valid_body()?)?)
    .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = response.headers()["set-cookie"].to_str()?;
    assert!(cookie.starts_with("meshspan_session=meshspan-session-v1."));
    assert!(cookie.contains("; Path=/; Secure; HttpOnly; SameSite=Strict"));
    assert!(response.headers().get("meshspan-csrf-token").is_some());
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = to_bytes(response.into_body(), 2_048).await?;
    let result = serde_json::from_slice::<CreateSessionResponse>(&body)?;
    assert_eq!(result.assurance, AssuranceLevel::RecentStepUp);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn boundary_rejects_untyped_or_excessive_input_before_work()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = step_up_current_session_api_router(FakeController::new(
        FakeOutcome::Success,
        Arc::clone(&calls),
    ))?;
    let missing_content_type = router
        .clone()
        .oneshot(Request::post(ROUTE).body(Body::from(valid_body()?))?)
        .await?;
    assert_error(
        missing_content_type,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ApiErrorCode::InvalidRequest,
    )
    .await?;
    let unknown = router
        .clone()
        .oneshot(json_request(serde_json::to_vec(&serde_json::json!({
            "operation_id": OPERATION,
            "additional_factor": { "method": "totp", "code": "123456" },
            "remember": true
        }))?)?)
        .await?;
    assert_error(
        unknown,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
    )
    .await?;
    let oversized = router.oneshot(json_request(vec![b' '; 513])?).await?;
    assert_error(
        oversized,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
    )
    .await?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn boundary_maps_closed_failures_without_secret_detail()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            FakeOutcome::Rejected,
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
        ),
        (
            FakeOutcome::Conflict,
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
        ),
        (
            FakeOutcome::Failed,
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
        ),
    ];
    for (outcome, status, code) in cases {
        let response = step_up_current_session_api_router(FakeController::new(
            outcome,
            Arc::new(AtomicUsize::new(0)),
        ))?
        .oneshot(json_request(valid_body()?)?)
        .await?;
        assert_error(response, status, code).await?;
    }
    Ok(())
}

async fn assert_error(
    response: axum::response::Response,
    status: StatusCode,
    code: ApiErrorCode,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), status);
    assert!(response.headers().get("set-cookie").is_none());
    assert!(response.headers().get("meshspan-csrf-token").is_none());
    let bytes = to_bytes(response.into_body(), 2_048).await?;
    let error = serde_json::from_slice::<ApiError>(&bytes)?;
    assert_eq!(error.code, code);
    assert!(!error.message.contains("123456"));
    assert!(!error.message.contains("SQLite"));
    Ok(())
}

fn valid_body() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "operation_id": OPERATION,
        "additional_factor": {
            "method": "totp",
            "code": "123456"
        }
    }))
}

fn json_request(body: Vec<u8>) -> Result<Request<Body>, axum::http::Error> {
    Request::post(ROUTE)
        .header("content-type", "application/json")
        .body(Body::from(body))
}

#[derive(Clone, Copy)]
enum FakeOutcome {
    Success,
    Rejected,
    Conflict,
    Failed,
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

impl StepUpCurrentSessionController for FakeController {
    fn step_up_current_session(
        &mut self,
        request: &StepUpCurrentSessionRequest,
        _: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, StepUpCurrentSessionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.outcome {
            FakeOutcome::Success => fake_result(request, now),
            FakeOutcome::Rejected => Err(StepUpCurrentSessionError::Rejected),
            FakeOutcome::Conflict => Err(SessionAuthorityError::Conflict.into()),
            FakeOutcome::Failed => Err(StepUpCurrentSessionError::InvalidReceipt),
        }
    }
}

fn fake_result(
    request: &StepUpCurrentSessionRequest,
    now: UnixMicros,
) -> Result<CreateSessionResult, StepUpCurrentSessionError> {
    let key =
        ApiKeyBundle::parse(API_KEY).map_err(|_| StepUpCurrentSessionError::InvalidReceipt)?;
    let operation =
        OperationId::from_bytes([7; 16]).map_err(|_| StepUpCurrentSessionError::InvalidReceipt)?;
    let bearer = SessionTokenBundle::derive(&key, operation)?;
    let csrf = SessionCsrfBundle::derive(&key, operation)?;
    let session_id =
        meshspan_api_contract::SessionId::from_uuid_bytes(bearer.session_id().as_bytes())
            .ok_or(StepUpCurrentSessionError::InvalidReceipt)?;
    Ok(CreateSessionResult {
        response: CreateSessionResponse {
            operation_id: request.operation_id.clone(),
            session_id,
            expires_at_epoch_micros: now.get().saturating_add(60_000_000),
            assurance: AssuranceLevel::RecentStepUp,
        },
        bearer,
        csrf,
        persistent_cookie: false,
    })
}
