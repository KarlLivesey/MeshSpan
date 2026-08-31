// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, AuthenticationMethodId, CreatePasskeyRegistrationChallengeRequest,
    CreatePasskeyRegistrationChallengeResponse, CreatePasskeyRegistrationRequest,
    CreatePasskeyRegistrationResponse, PasskeyAttestation, PasskeyChallengeId,
    PasskeyCredentialParameter, PasskeyCredentialType, PasskeyResidentKey, PasskeyUserVerification,
};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

use crate::{
    BrowserAuthenticationError, PasskeyRegistrationController, PasskeyRegistrationError,
    PasskeyRegistrationStoreError, passkey_registration_api_router,
};

const CHALLENGE_OPERATION: &str = "00000000-0000-4000-8000-000000000091";
const REGISTRATION_OPERATION: &str = "00000000-0000-4000-8000-000000000092";
const CHALLENGE_ID: &str = "93939393-9393-4393-9393-939393939393";
const METHOD_ID: &str = "94949494-9494-4494-9494-949494949494";
const CHALLENGE_ROUTE: &str =
    "/api/latest/users/current/authentication-methods/passkeys/registration-challenges";
const REGISTRATION_ROUTE: &str = "/api/latest/users/current/authentication-methods/passkeys";

#[tokio::test]
async fn registration_boundaries_return_only_validated_results()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = passkey_registration_api_router(FakeController::new(
        FakeOutcome::Success,
        Arc::clone(&calls),
    ))?;

    let challenge = router
        .clone()
        .oneshot(json_request(CHALLENGE_ROUTE, challenge_body()?)?)
        .await?;
    assert_eq!(challenge.status(), StatusCode::CREATED);
    assert_safe_headers(challenge.headers());
    let challenge_bytes = to_bytes(challenge.into_body(), 4_096).await?;
    let challenge_body =
        serde_json::from_slice::<CreatePasskeyRegistrationChallengeResponse>(&challenge_bytes)?;
    assert_eq!(challenge_body.operation_id.as_str(), CHALLENGE_OPERATION);
    assert_eq!(challenge_body.challenge_id.as_str(), CHALLENGE_ID);
    assert_eq!(challenge_body.exclude_credentials.len(), 0);

    let registration = router
        .oneshot(json_request(REGISTRATION_ROUTE, registration_body()?)?)
        .await?;
    assert_eq!(registration.status(), StatusCode::CREATED);
    assert_safe_headers(registration.headers());
    let registration_bytes = to_bytes(registration.into_body(), 2_048).await?;
    let registration_body =
        serde_json::from_slice::<CreatePasskeyRegistrationResponse>(&registration_bytes)?;
    assert_eq!(
        registration_body.operation_id.as_str(),
        REGISTRATION_OPERATION
    );
    assert_eq!(registration_body.method_id.as_str(), METHOD_ID);
    assert_eq!(
        registration_body.created_at_epoch_micros,
        1_700_000_000_000_000
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn registration_boundaries_reject_untyped_and_excessive_input_before_work()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = passkey_registration_api_router(FakeController::new(
        FakeOutcome::Success,
        Arc::clone(&calls),
    ))?;

    let missing_content_type = router
        .clone()
        .oneshot(Request::post(CHALLENGE_ROUTE).body(Body::from(challenge_body()?))?)
        .await?;
    assert_error(
        missing_content_type,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ApiErrorCode::InvalidRequest,
    )
    .await?;

    let unknown = router
        .clone()
        .oneshot(json_request(
            CHALLENGE_ROUTE,
            serde_json::to_vec(&serde_json::json!({
                "operation_id": CHALLENGE_OPERATION,
                "user_name": "must-not-enumerate"
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
        .oneshot(json_request(REGISTRATION_ROUTE, vec![b' '; 30_001])?)
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
async fn registration_boundaries_map_closed_failures_without_detail()
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
            FakeOutcome::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
        ),
        (
            FakeOutcome::Failed,
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
        ),
    ];
    for (outcome, status, code) in cases {
        let response = passkey_registration_api_router(FakeController::new(
            outcome,
            Arc::new(AtomicUsize::new(0)),
        ))?
        .oneshot(json_request(CHALLENGE_ROUTE, challenge_body()?)?)
        .await?;
        assert_error(response, status, code).await?;
    }
    Ok(())
}

fn assert_safe_headers(headers: &HeaderMap) {
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["meshspan-api-version"], "latest");
    assert!(headers.get("meshspan-api-schema").is_some());
    assert!(headers.get("set-cookie").is_none());
}

async fn assert_error(
    response: axum::response::Response,
    status: StatusCode,
    code: ApiErrorCode,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), status);
    assert!(response.headers().get("set-cookie").is_none());
    let bytes = to_bytes(response.into_body(), 2_048).await?;
    let error = serde_json::from_slice::<ApiError>(&bytes)?;
    assert_eq!(error.code, code);
    assert!(!error.message.contains("SQLite"));
    assert!(!error.message.contains("credential"));
    Ok(())
}

fn challenge_body() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({ "operation_id": CHALLENGE_OPERATION }))
}

fn registration_body() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "operation_id": REGISTRATION_OPERATION,
        "challenge_id": CHALLENGE_ID,
        "label": "Laptop passkey",
        "credential_id": "AQ",
        "client_data_json": "e30",
        "attestation_object": "oA",
        "transports": ["internal"]
    }))
}

fn json_request(route: &str, body: Vec<u8>) -> Result<Request<Body>, axum::http::Error> {
    Request::post(route)
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
    Unavailable,
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

    fn result<T>(&self, value: T) -> Result<T, PasskeyRegistrationError> {
        match self.outcome {
            FakeOutcome::Success => Ok(value),
            FakeOutcome::Rejected => Err(PasskeyRegistrationError::Authentication(
                BrowserAuthenticationError::Rejected,
            )),
            FakeOutcome::Conflict => Err(PasskeyRegistrationError::Conflict),
            FakeOutcome::Unavailable => Err(PasskeyRegistrationError::Unavailable),
            FakeOutcome::Failed => Err(PasskeyRegistrationError::Store(
                PasskeyRegistrationStoreError::Failed,
            )),
        }
    }
}

impl PasskeyRegistrationController for FakeController {
    fn create_registration_challenge(
        &mut self,
        request: &CreatePasskeyRegistrationChallengeRequest,
        headers: &HeaderMap,
        _now: UnixMicros,
    ) -> Result<CreatePasskeyRegistrationChallengeResponse, PasskeyRegistrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        require_browser_headers(headers)?;
        self.result(CreatePasskeyRegistrationChallengeResponse {
            operation_id: request.operation_id.clone(),
            challenge_id: PasskeyChallengeId::from_uuid_bytes(versioned(147))
                .ok_or(PasskeyRegistrationError::InvalidReceipt)?,
            challenge: "A".repeat(43),
            relying_party_id: "files.example.test".to_owned(),
            relying_party_name: "MeshSpan".to_owned(),
            user_id: "A".repeat(22),
            user_name: "owner@example.test".to_owned(),
            user_display_name: "Owner".to_owned(),
            timeout_milliseconds: 120_000,
            user_verification: PasskeyUserVerification::Required,
            resident_key: PasskeyResidentKey::Required,
            attestation: PasskeyAttestation::None,
            public_key_parameters: vec![PasskeyCredentialParameter {
                credential_type: PasskeyCredentialType::PublicKey,
                algorithm: -7,
            }],
            exclude_credentials: Vec::new(),
        })
    }

    fn register_passkey(
        &mut self,
        request: &CreatePasskeyRegistrationRequest,
        headers: &HeaderMap,
        _now: UnixMicros,
    ) -> Result<CreatePasskeyRegistrationResponse, PasskeyRegistrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        require_browser_headers(headers)?;
        self.result(CreatePasskeyRegistrationResponse {
            operation_id: request.operation_id.clone(),
            method_id: AuthenticationMethodId::from_uuid_bytes(versioned(148))
                .ok_or(PasskeyRegistrationError::InvalidReceipt)?,
            created_at_epoch_micros: 1_700_000_000_000_000,
        })
    }
}

fn require_browser_headers(headers: &HeaderMap) -> Result<(), PasskeyRegistrationError> {
    if headers.get("cookie").is_none() || headers.get("x-meshspan-csrf").is_none() {
        return Err(PasskeyRegistrationError::Rejected);
    }
    Ok(())
}

fn versioned(value: u8) -> [u8; 16] {
    let mut bytes = [value; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
