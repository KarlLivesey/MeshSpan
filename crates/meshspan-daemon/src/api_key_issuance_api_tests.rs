// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, ApiKeyId, ApiKeyScope, AuthenticationMethodId, CreateApiKeyRequest,
    CreateApiKeyResponse,
};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

use crate::{ApiKeyIssuanceController, ApiKeyIssuanceError, api_key_issuance_api_router};

const OPERATION: &str = "00000000-0000-4000-8000-000000000041";
const ROUTE: &str = "/api/latest/users/current/authentication-methods/api-keys";

#[tokio::test]
async fn issuance_boundary_returns_validated_secret_once() -> Result<(), Box<dyn std::error::Error>>
{
    let calls = Arc::new(AtomicUsize::new(0));
    let response = api_key_issuance_api_router(FakeController::new(
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
    let bytes = to_bytes(response.into_body(), 4_096).await?;
    let body = serde_json::from_slice::<CreateApiKeyResponse>(&bytes)?;
    assert_eq!(body.operation_id.as_str(), OPERATION);
    assert_eq!(body.scopes, vec![ApiKeyScope::HeadlessApi]);
    assert!(body.secret.starts_with("meshspan-key-v1."));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn issuance_boundary_rejects_untyped_or_excessive_input_before_work()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = api_key_issuance_api_router(FakeController::new(
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
            "label": "Automation",
            "scopes": ["headless_api"],
            "password": "forbidden"
        }))?)?)
        .await?;
    assert_error(
        unknown,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
    )
    .await?;
    let oversized = router.oneshot(json_request(vec![b' '; 2_049])?).await?;
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
async fn issuance_boundary_maps_closed_failures_without_secret_detail()
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
        let response = api_key_issuance_api_router(FakeController::new(
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
    assert!(!error.message.contains("meshspan-key"));
    assert!(!error.message.contains("SQLite"));
    Ok(())
}

fn valid_body() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "operation_id": OPERATION,
        "label": "Automation",
        "scopes": ["headless_api"]
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

impl ApiKeyIssuanceController for FakeController {
    fn issue_api_key(
        &mut self,
        request: &CreateApiKeyRequest,
        headers: &HeaderMap,
        _now: UnixMicros,
    ) -> Result<CreateApiKeyResponse, ApiKeyIssuanceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if headers.get("cookie").is_none() || headers.get("x-meshspan-csrf").is_none() {
            return Err(ApiKeyIssuanceError::Rejected);
        }
        match self.outcome {
            FakeOutcome::Success => Ok(CreateApiKeyResponse {
                operation_id: request.operation_id.clone(),
                method_id: AuthenticationMethodId::from_uuid_bytes(versioned(81))
                    .ok_or(ApiKeyIssuanceError::InvalidReceipt)?,
                key_id: ApiKeyId::from_uuid_bytes(versioned(82))
                    .ok_or(ApiKeyIssuanceError::InvalidReceipt)?,
                secret: concat!(
                    "meshspan-key-v1.",
                    "52525252525242529252525252525252.",
                    "5353535353535353535353535353535353535353535353535353535353535353"
                )
                .to_owned(),
                scopes: vec![ApiKeyScope::HeadlessApi],
                created_at_epoch_micros: 1_700_000_000_000_000,
                valid_from_epoch_micros: 1_700_000_000_000_000,
                expires_at_epoch_micros: None,
            }),
            FakeOutcome::Rejected => Err(ApiKeyIssuanceError::Rejected),
            FakeOutcome::Conflict => Err(ApiKeyIssuanceError::Conflict),
            FakeOutcome::Failed => Err(ApiKeyIssuanceError::InvalidReceipt),
        }
    }
}

fn versioned(value: u8) -> [u8; 16] {
    let mut bytes = [value; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
