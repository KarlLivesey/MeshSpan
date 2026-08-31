// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, AuthenticationMethodId, CreateRecoveryCodesRequest,
    CreateRecoveryCodesResponse, RecoveryCode,
};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

use crate::{
    BrowserAuthenticationError, RecoveryCodeIssuanceController, RecoveryCodeIssuanceError,
    recovery_code_issuance_api_router,
};

const OPERATION: &str = "00000000-0000-4000-8000-000000000091";
const ROUTE: &str = "/api/latest/users/current/authentication-methods/recovery-codes";

#[tokio::test]
async fn boundary_returns_exactly_ten_validated_secrets() -> Result<(), Box<dyn std::error::Error>>
{
    let calls = Arc::new(AtomicUsize::new(0));
    let response = recovery_code_issuance_api_router(FakeController::new(
        FakeOutcome::Success,
        Arc::clone(&calls),
    ))?
    .oneshot(json_request(valid_body()?)?)
    .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["meshspan-api-version"], "latest");
    assert!(response.headers().get("meshspan-api-schema").is_some());
    assert!(response.headers().get("set-cookie").is_none());
    let bytes = to_bytes(response.into_body(), 8_192).await?;
    let body = serde_json::from_slice::<CreateRecoveryCodesResponse>(&bytes)?;
    assert_eq!(body.operation_id.as_str(), OPERATION);
    assert_eq!(body.codes.len(), 10);
    assert!(body.codes.iter().all(|code| {
        code.expose_for_delivery()
            .starts_with("meshspan-recovery-v1.")
    }));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn boundary_rejects_untyped_or_excessive_input_before_work()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = recovery_code_issuance_api_router(FakeController::new(
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
            "label": "Emergency recovery",
            "count": 1
        }))?)?)
        .await?;
    assert_error(
        unknown,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
    )
    .await?;
    let oversized = router.oneshot(json_request(vec![b' '; 1_025])?).await?;
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
        let response = recovery_code_issuance_api_router(FakeController::new(
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
    let bytes = to_bytes(response.into_body(), 2_048).await?;
    let error = serde_json::from_slice::<ApiError>(&bytes)?;
    assert_eq!(error.code, code);
    assert!(!error.message.contains("meshspan-recovery"));
    assert!(!error.message.contains("SQLite"));
    Ok(())
}

fn valid_body() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "operation_id": OPERATION,
        "label": "Emergency recovery"
    }))
}

fn json_request(body: Vec<u8>) -> Result<Request<Body>, axum::http::Error> {
    Request::post(ROUTE)
        .header("content-type", "application/json")
        .header("cookie", "meshspan_session=opaque")
        .header("x-meshspan-csrf", "opaque")
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

impl RecoveryCodeIssuanceController for FakeController {
    fn issue_recovery_codes(
        &mut self,
        request: &CreateRecoveryCodesRequest,
        headers: &HeaderMap,
        _now: UnixMicros,
    ) -> Result<CreateRecoveryCodesResponse, RecoveryCodeIssuanceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if headers.get("cookie").is_none() || headers.get("x-meshspan-csrf").is_none() {
            return Err(BrowserAuthenticationError::Rejected.into());
        }
        match self.outcome {
            FakeOutcome::Success => Ok(CreateRecoveryCodesResponse {
                operation_id: request.operation_id.clone(),
                method_id: AuthenticationMethodId::from_uuid_bytes(versioned(81))
                    .ok_or(RecoveryCodeIssuanceError::InvalidReceipt)?,
                codes: fixture_codes(),
                created_at_epoch_micros: 1_700_000_000_000_000,
            }),
            FakeOutcome::Rejected => Err(BrowserAuthenticationError::Rejected.into()),
            FakeOutcome::Conflict => Err(RecoveryCodeIssuanceError::Conflict),
            FakeOutcome::Failed => Err(RecoveryCodeIssuanceError::InvalidReceipt),
        }
    }
}

fn fixture_codes() -> Vec<RecoveryCode> {
    (1..=10)
        .map(|sequence| {
            RecoveryCode::from_canonical(format!(
                "meshspan-recovery-v1.{sequence:032x}.{}",
                "5".repeat(64)
            ))
        })
        .collect()
}

fn versioned(value: u8) -> [u8; 16] {
    let mut bytes = [value; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
