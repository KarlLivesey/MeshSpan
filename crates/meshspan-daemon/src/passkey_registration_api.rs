// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTPS boundary for current-user passkey registration.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, CreatePasskeyRegistrationChallengeRequest,
    CreatePasskeyRegistrationChallengeResponse, CreatePasskeyRegistrationRequest,
    CreatePasskeyRegistrationResponse, MAX_CREATE_PASSKEY_REGISTRATION_BYTES,
    MAX_CREATE_PASSKEY_REGISTRATION_CHALLENGE_BYTES,
    decode_create_passkey_registration_challenge_request,
    decode_create_passkey_registration_request,
    encode_create_passkey_registration_challenge_response,
    encode_create_passkey_registration_response, generate_openapi,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, json_response, request_identifier,
};
use crate::{
    BrowserAuthenticationError, BrowserSessionAuthorityError, PasskeyRegistrationAuthority,
    PasskeyRegistrationAuthorityError, PasskeyRegistrationError, PasskeyRegistrationService,
    PasskeyRegistrationStore, PasskeyRegistrationStoreError,
};

/// Synchronous registration boundary executed on a bounded blocking worker.
pub trait PasskeyRegistrationController: Send + 'static {
    /// Creates or exactly replays one current-user registration challenge.
    ///
    /// # Errors
    ///
    /// Returns only stable authentication, request, conflict, availability or integrity failures.
    fn create_registration_challenge(
        &mut self,
        request: &CreatePasskeyRegistrationChallengeRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreatePasskeyRegistrationChallengeResponse, PasskeyRegistrationError>;

    /// Verifies and authoritatively commits one current-user passkey.
    ///
    /// # Errors
    ///
    /// Returns only stable authentication, request, conflict, availability or integrity failures.
    fn register_passkey(
        &mut self,
        request: &CreatePasskeyRegistrationRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreatePasskeyRegistrationResponse, PasskeyRegistrationError>;
}

impl<S, A, R> PasskeyRegistrationController for PasskeyRegistrationService<S, A, R>
where
    S: PasskeyRegistrationStore + Send + 'static,
    A: PasskeyRegistrationAuthority + Send + 'static,
    R: meshspan_domain::RandomSource + Send + 'static,
{
    fn create_registration_challenge(
        &mut self,
        request: &CreatePasskeyRegistrationChallengeRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreatePasskeyRegistrationChallengeResponse, PasskeyRegistrationError> {
        self.create_challenge(request, headers, now)
    }

    fn register_passkey(
        &mut self,
        request: &CreatePasskeyRegistrationRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreatePasskeyRegistrationResponse, PasskeyRegistrationError> {
        self.register(request, headers, now)
    }
}

struct RegistrationApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for RegistrationApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds both rolling current-user passkey-registration endpoints.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn passkey_registration_api_router<C>(
    controller: C,
) -> Result<Router, PasskeyRegistrationApiError>
where
    C: PasskeyRegistrationController,
{
    let document = generate_openapi()?;
    let state = RegistrationApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/users/current/authentication-methods/passkeys/registration-challenges",
            post(post_challenge::<C>),
        )
        .route(
            "/api/latest/users/current/authentication-methods/passkeys",
            post(post_registration::<C>),
        )
        .with_state(state))
}

async fn post_challenge<C>(
    State(state): State<RegistrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: PasskeyRegistrationController,
{
    let request_id = request_identifier();
    let headers = request.headers().clone();
    let decoded = decode_request(
        request,
        MAX_CREATE_PASSKEY_REGISTRATION_CHALLENGE_BYTES,
        decode_create_passkey_registration_challenge_request,
        &request_id,
        state.schema_digest.clone(),
    )
    .await;
    let request = match decoded {
        Ok(request) => request,
        Err(response) => return *response,
    };
    execute(
        state,
        request_id,
        request.operation_id.clone(),
        move |controller, now| controller.create_registration_challenge(&request, &headers, now),
        encode_create_passkey_registration_challenge_response,
    )
    .await
}

async fn post_registration<C>(
    State(state): State<RegistrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: PasskeyRegistrationController,
{
    let request_id = request_identifier();
    let headers = request.headers().clone();
    let decoded = decode_request(
        request,
        MAX_CREATE_PASSKEY_REGISTRATION_BYTES,
        decode_create_passkey_registration_request,
        &request_id,
        state.schema_digest.clone(),
    )
    .await;
    let request = match decoded {
        Ok(request) => request,
        Err(response) => return *response,
    };
    execute(
        state,
        request_id,
        request.operation_id.clone(),
        move |controller, now| controller.register_passkey(&request, &headers, now),
        encode_create_passkey_registration_response,
    )
    .await
}

async fn decode_request<T>(
    request: Request,
    maximum_bytes: usize,
    decode: fn(&[u8]) -> Result<T, BoundaryError>,
    request_id: &str,
    schema_digest: HeaderValue,
) -> Result<T, Box<Response<Body>>> {
    if !has_json_content_type(request.headers()) {
        return Err(Box::new(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "content type must be application/json",
            request_id.to_owned(),
            None,
            vec![issue("", "content_type")],
            schema_digest,
        )));
    }
    let bytes = to_bytes(request.into_body(), maximum_bytes)
        .await
        .map_err(|_| {
            Box::new(invalid_body(
                request_id.to_owned(),
                None,
                schema_digest.clone(),
            ))
        })?;
    decode(&bytes).map_err(|error| match error {
        BoundaryError::InvalidSchema(_)
        | BoundaryError::DecodeMismatch
        | BoundaryError::EncodeMismatch => {
            Box::new(failed_closed(request_id.to_owned(), None, schema_digest))
        }
        other => Box::new(error_response(
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "request does not satisfy the public contract",
            request_id.to_owned(),
            None,
            boundary_issues(other),
            schema_digest,
        )),
    })
}

async fn execute<C, T, F>(
    state: RegistrationApiState<C>,
    request_id: String,
    operation_id: meshspan_api_contract::OperationId,
    operation: F,
    encode: fn(&T) -> Result<Vec<u8>, BoundaryError>,
) -> Response<Body>
where
    C: PasskeyRegistrationController,
    T: Send + 'static,
    F: FnOnce(&mut C, UnixMicros) -> Result<T, PasskeyRegistrationError> + Send + 'static,
{
    let Some(now) = current_time() else {
        return failed_closed(request_id, Some(operation_id), state.schema_digest);
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        let mut controller = controller
            .lock()
            .map_err(|_| RegistrationExecutionError::Unavailable)?;
        operation(&mut controller, now).map_err(RegistrationExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => failed_closed(request_id, Some(operation_id), state.schema_digest),
        },
        Ok(Err(RegistrationExecutionError::Service(error))) => {
            service_error_response(&error, request_id, Some(operation_id), state.schema_digest)
        }
        Ok(Err(RegistrationExecutionError::Unavailable)) | Err(_) => {
            failed_closed(request_id, Some(operation_id), state.schema_digest)
        }
    }
}

fn invalid_body(
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    error_response(
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
        "request does not satisfy the public contract",
        request_id,
        operation_id,
        vec![issue("", "max_bytes")],
        schema_digest,
    )
}

fn service_error_response(
    error: &PasskeyRegistrationError,
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = classify_error(error);
    error_response(
        status,
        code,
        message,
        request_id,
        operation_id,
        Vec::new(),
        schema_digest,
    )
}

fn classify_error(error: &PasskeyRegistrationError) -> (StatusCode, ApiErrorCode, &'static str) {
    match error {
        PasskeyRegistrationError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "passkey registration request is invalid",
        ),
        PasskeyRegistrationError::Rejected
        | PasskeyRegistrationError::Authentication(BrowserAuthenticationError::Rejected) => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        PasskeyRegistrationError::Conflict
        | PasskeyRegistrationError::Store(
            PasskeyRegistrationStoreError::Expired | PasskeyRegistrationStoreError::Conflict,
        )
        | PasskeyRegistrationError::Authority(PasskeyRegistrationAuthorityError::Conflict) => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "passkey registration conflicts with durable state",
        ),
        PasskeyRegistrationError::Unavailable
        | PasskeyRegistrationError::Authority(PasskeyRegistrationAuthorityError::Unavailable)
        | PasskeyRegistrationError::Authentication(BrowserAuthenticationError::Authority(
            BrowserSessionAuthorityError::Unavailable,
        )) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "passkey registration is temporarily unavailable",
        ),
        PasskeyRegistrationError::InvalidTime
        | PasskeyRegistrationError::State
        | PasskeyRegistrationError::InvalidReceipt
        | PasskeyRegistrationError::Store(PasskeyRegistrationStoreError::Failed)
        | PasskeyRegistrationError::Authority(PasskeyRegistrationAuthorityError::Failed)
        | PasskeyRegistrationError::Authentication(
            BrowserAuthenticationError::InvalidGateway
            | BrowserAuthenticationError::Authority(BrowserSessionAuthorityError::Failed),
        ) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "passkey registration failed closed",
        ),
    }
}

fn failed_closed(
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    internal_error_response(
        request_id,
        operation_id,
        schema_digest,
        "passkey registration failed closed",
    )
}

enum RegistrationExecutionError {
    Service(PasskeyRegistrationError),
    Unavailable,
}

/// Registration router construction failure.
#[derive(Debug, Error)]
pub enum PasskeyRegistrationApiError {
    /// Rust-authored API contract generation failed.
    #[error("passkey registration API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// Schema digest could not be represented as an HTTP header.
    #[error("passkey registration schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
