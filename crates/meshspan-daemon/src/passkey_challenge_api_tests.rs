// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, CreatePasskeyChallengeRequest, CreatePasskeyChallengeResponse,
    PasskeyChallengeId, PasskeyUserVerification,
};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

use crate::{
    CreatePasskeyChallengeController, PasskeyChallengeError, passkey_challenge_api_router,
};

const OPERATION: &str = "00000000-0000-4000-8000-000000000081";
const ROUTE: &str = "/api/latest/sessions/passkey/challenges";

#[tokio::test]
async fn challenge_boundary_returns_only_validated_browser_options()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = passkey_challenge_api_router(FakeController::new(
        FakeOutcome::Success,
        Arc::clone(&calls),
    ))?;
    let response = router.oneshot(json_request(valid_body()?)?).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["meshspan-api-version"], "latest");
    assert!(response.headers().get("meshspan-api-schema").is_some());
    assert!(response.headers().get("set-cookie").is_none());
    let bytes = to_bytes(response.into_body(), 2_048).await?;
    let body = serde_json::from_slice::<CreatePasskeyChallengeResponse>(&bytes)?;
    assert_eq!(body.operation_id.as_str(), OPERATION);
    assert_eq!(body.challenge, "A".repeat(43));
    assert_eq!(body.relying_party_id, "files.example.test");
    assert_eq!(body.timeout_milliseconds, 120_000);
    assert_eq!(body.user_verification, PasskeyUserVerification::Required);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn challenge_boundary_rejects_untyped_or_excessive_input_before_work()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = passkey_challenge_api_router(FakeController::new(
        FakeOutcome::Success,
        Arc::clone(&calls),
    ))?;
    let missing_content_type = router
        .clone()
        .oneshot(Request::post(ROUTE).body(Body::from(valid_body()?))?)
        .await?;
    assert_eq!(
        missing_content_type.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "missing content type"
    );
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
            "user_name": "must-not-enumerate"
        }))?)?)
        .await?;
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST, "unknown field");
    assert_error(
        unknown,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
    )
    .await?;
    let oversized = router.oneshot(json_request(vec![b' '; 257])?).await?;
    assert_eq!(
        oversized.status(),
        StatusCode::BAD_REQUEST,
        "oversized body"
    );
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
async fn challenge_boundary_maps_closed_failures_without_detail()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            FakeOutcome::Error(PasskeyChallengeError::Conflict),
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
        ),
        (
            FakeOutcome::Error(PasskeyChallengeError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
        ),
        (
            FakeOutcome::Error(PasskeyChallengeError::Failed),
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
        ),
    ];
    for (outcome, status, code) in cases {
        let response = passkey_challenge_api_router(FakeController::new(
            outcome,
            Arc::new(AtomicUsize::new(0)),
        ))?
        .oneshot(json_request(valid_body()?)?)
        .await?;
        assert!(response.headers().get("set-cookie").is_none());
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
    let bytes = to_bytes(response.into_body(), 2_048).await?;
    let error = serde_json::from_slice::<ApiError>(&bytes)?;
    assert_eq!(error.code, code);
    assert!(!error.message.contains("SQLite"));
    Ok(())
}

fn valid_body() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({ "operation_id": OPERATION }))
}

fn json_request(body: Vec<u8>) -> Result<Request<Body>, axum::http::Error> {
    Request::post(ROUTE)
        .header("content-type", "application/json")
        .body(Body::from(body))
}

#[derive(Clone, Copy)]
enum FakeOutcome {
    Success,
    Error(PasskeyChallengeError),
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

impl CreatePasskeyChallengeController for FakeController {
    fn create_passkey_challenge(
        &mut self,
        request: &CreatePasskeyChallengeRequest,
        _now: UnixMicros,
    ) -> Result<CreatePasskeyChallengeResponse, PasskeyChallengeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let FakeOutcome::Error(error) = self.outcome {
            return Err(error);
        }
        Ok(CreatePasskeyChallengeResponse {
            operation_id: request.operation_id.clone(),
            challenge_id: PasskeyChallengeId::from_uuid_bytes(versioned(82))
                .ok_or(PasskeyChallengeError::Failed)?,
            challenge: "A".repeat(43),
            relying_party_id: "files.example.test".to_owned(),
            timeout_milliseconds: 120_000,
            user_verification: PasskeyUserVerification::Required,
        })
    }
}

fn versioned(value: u8) -> [u8; 16] {
    let mut bytes = [value; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
