// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, AssuranceLevel, CreateSessionRequest, CreateSessionResponse,
    SessionAuthentication, SessionId,
};
use meshspan_domain::{
    ApiKeyBundle, OperationId, SessionCsrfBundle, SessionTokenBundle, UnixMicros,
};
use tower::ServiceExt;

use crate::create_mesh_setup::parse_uuid;
use crate::{CreateSessionController, CreateSessionError, CreateSessionResult, session_api_router};

const OPERATION_TEXT: &str = "00000000-0000-4000-8000-000000000021";
const API_KEY: &str = concat!(
    "meshspan-key-v1.00000000000040008000000000000031.",
    "1111111111111111111111111111111111111111111111111111111111111111"
);

#[tokio::test]
async fn session_boundary_delivers_secure_cookie_csrf_and_validated_body()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = session_api_router(FakeController::new(false, Arc::clone(&calls)))?;
    let response = router.oneshot(json_request(valid_body(true)?)?).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = response
        .headers()
        .get("set-cookie")
        .ok_or("cookie missing")?
        .clone();
    assert!(cookie.is_sensitive());
    let cookie = cookie.to_str()?;
    assert!(cookie.starts_with("meshspan_session=meshspan-session-v1."));
    assert!(cookie.contains("; Path=/; Secure; HttpOnly; SameSite=Strict"));
    assert!(cookie.contains("; Max-Age="));
    let csrf = response
        .headers()
        .get("meshspan-csrf-token")
        .ok_or("CSRF header missing")?
        .clone();
    assert!(csrf.is_sensitive());
    let csrf = csrf.to_str()?;
    assert!(csrf.starts_with("meshspan-csrf-v1."));
    let bytes = to_bytes(response.into_body(), 2_048).await?;
    let body = serde_json::from_slice::<CreateSessionResponse>(&bytes)?;
    assert_eq!(body.operation_id.as_str(), OPERATION_TEXT);
    assert_eq!(body.assurance, AssuranceLevel::SingleFactor);
    let text = std::str::from_utf8(&bytes)?;
    assert!(!text.contains("meshspan-session-v1."));
    assert!(!text.contains("meshspan-csrf-v1."));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn session_boundary_rejects_before_work_and_never_sets_secrets_on_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = session_api_router(FakeController::new(false, Arc::clone(&calls)))?;
    let oversized = router
        .clone()
        .oneshot(
            Request::post("/api/latest/sessions")
                .header("content-type", "application/json")
                .body(Body::from(vec![b' '; 2_049]))?,
        )
        .await?;
    assert_error(
        oversized,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
    )
    .await?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let rejected = session_api_router(FakeController::new(true, Arc::clone(&calls)))?
        .oneshot(json_request(valid_body(false)?)?)
        .await?;
    assert!(rejected.headers().get("set-cookie").is_none());
    assert!(rejected.headers().get("meshspan-csrf-token").is_none());
    assert_error(
        rejected,
        StatusCode::UNAUTHORIZED,
        ApiErrorCode::Unauthenticated,
    )
    .await?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
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
    Ok(())
}

fn valid_body(remember: bool) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "operation_id": OPERATION_TEXT,
        "authentication": { "method": "api_key", "secret": API_KEY },
        "client_label": "office browser",
        "remember": remember
    }))
}

fn json_request(body: Vec<u8>) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/api/latest/sessions")
        .header("content-type", "application/json")
        .body(Body::from(body))
}

struct FakeController {
    reject: bool,
    calls: Arc<AtomicUsize>,
}

impl FakeController {
    fn new(reject: bool, calls: Arc<AtomicUsize>) -> Self {
        Self { reject, calls }
    }
}

impl CreateSessionController for FakeController {
    fn create_session(
        &mut self,
        request: &CreateSessionRequest,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, CreateSessionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.reject {
            return Err(CreateSessionError::Rejected);
        }
        let secret = match &request.authentication {
            SessionAuthentication::ApiKey { secret } => secret,
            SessionAuthentication::Passkey { .. } => return Err(CreateSessionError::Rejected),
        };
        let api_key = ApiKeyBundle::parse(secret)?;
        let operation = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str())
                .map_err(|_| CreateSessionError::InvalidOperation)?,
        )
        .map_err(|_| CreateSessionError::InvalidOperation)?;
        let bearer = SessionTokenBundle::derive(&api_key, operation)?;
        let csrf = SessionCsrfBundle::derive(&api_key, operation)?;
        let session_id = SessionId::from_uuid_bytes(bearer.session_id().as_bytes())
            .ok_or(CreateSessionError::InvalidReceipt)?;
        Ok(CreateSessionResult {
            response: CreateSessionResponse {
                operation_id: request.operation_id.clone(),
                session_id,
                expires_at_epoch_micros: now.get() + 60_000_000,
                assurance: AssuranceLevel::SingleFactor,
            },
            bearer,
            csrf,
            persistent_cookie: request.remember,
        })
    }
}
