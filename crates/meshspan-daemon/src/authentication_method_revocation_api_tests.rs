// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, AuthenticationMethodId, RevokeAuthenticationMethodRequest,
    RevokeAuthenticationMethodResponse,
};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

use crate::{
    AuthenticationMethodRevocationController, AuthenticationMethodRevocationError,
    authentication_method_revocation_api_router,
};

const OPERATION: &str = "00000000-0000-4000-8000-000000000061";
const METHOD: &str = "00000000-0000-4000-8000-000000000062";
const ROUTE: &str = "/api/latest/users/current/authentication-methods/00000000-0000-4000-8000-000000000062/revocations";

#[tokio::test]
async fn revocation_boundary_returns_validated_authoritative_result()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let response = authentication_method_revocation_api_router(FakeController::new(
        FakeOutcome::Success,
        Arc::clone(&calls),
    ))?
    .oneshot(json_request(ROUTE, valid_body()?)?)
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["meshspan-api-version"], "latest");
    let bytes = to_bytes(response.into_body(), 4_096).await?;
    let body = serde_json::from_slice::<RevokeAuthenticationMethodResponse>(&bytes)?;
    assert_eq!(body.operation_id.as_str(), OPERATION);
    assert_eq!(body.method_id.as_str(), METHOD);
    assert_eq!(body.revoked_at_epoch_micros, 1_700_000_000_000_000);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn revocation_boundary_rejects_invalid_path_body_and_size_before_work()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = authentication_method_revocation_api_router(FakeController::new(
        FakeOutcome::Success,
        Arc::clone(&calls),
    ))?;
    let invalid_path = router
        .clone()
        .oneshot(json_request(
            "/api/latest/users/current/authentication-methods/not-a-uuid/revocations",
            valid_body()?,
        )?)
        .await?;
    assert_error(
        invalid_path,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
    )
    .await?;
    let unknown = router
        .clone()
        .oneshot(json_request(
            ROUTE,
            serde_json::to_vec(&serde_json::json!({
                "operation_id": OPERATION,
                "reason": "Rotation",
                "secret": "forbidden"
            }))?,
        )?)
        .await?;
    assert_error(
        unknown,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
    )
    .await?;
    let oversized = router
        .oneshot(json_request(ROUTE, vec![b' '; 1_537])?)
        .await?;
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
async fn revocation_boundary_maps_closed_failures() -> Result<(), Box<dyn std::error::Error>> {
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
        let response = authentication_method_revocation_api_router(FakeController::new(
            outcome,
            Arc::new(AtomicUsize::new(0)),
        ))?
        .oneshot(json_request(ROUTE, valid_body()?)?)
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
    assert!(!error.message.contains("SQLite"));
    Ok(())
}

fn valid_body() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "operation_id": OPERATION,
        "reason": "Rotating the automation credential"
    }))
}

fn json_request(route: &str, body: Vec<u8>) -> Result<Request<Body>, axum::http::Error> {
    Request::post(route)
        .header("content-type", "application/json")
        .header("cookie", "meshspan_session=opaque")
        .header("meshspan-csrf-token", "opaque")
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

impl AuthenticationMethodRevocationController for FakeController {
    fn revoke_authentication_method(
        &mut self,
        method_id: &AuthenticationMethodId,
        request: &RevokeAuthenticationMethodRequest,
        headers: &HeaderMap,
        _now: UnixMicros,
    ) -> Result<RevokeAuthenticationMethodResponse, AuthenticationMethodRevocationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if headers.get("cookie").is_none() || headers.get("meshspan-csrf-token").is_none() {
            return Err(AuthenticationMethodRevocationError::Rejected);
        }
        match self.outcome {
            FakeOutcome::Success => Ok(RevokeAuthenticationMethodResponse {
                operation_id: request.operation_id.clone(),
                method_id: serde_json::from_value(serde_json::json!(method_id.as_str()))
                    .map_err(|_| AuthenticationMethodRevocationError::InvalidReceipt)?,
                revoked_at_epoch_micros: 1_700_000_000_000_000,
            }),
            FakeOutcome::Rejected => Err(AuthenticationMethodRevocationError::Rejected),
            FakeOutcome::Conflict => Err(AuthenticationMethodRevocationError::Conflict),
            FakeOutcome::Failed => Err(AuthenticationMethodRevocationError::InvalidReceipt),
        }
    }
}
