// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTPS boundary for current-user TOTP registration.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, CreateTotpRegistrationChallengeRequest,
    CreateTotpRegistrationChallengeResponse, CreateTotpRegistrationRequest,
    CreateTotpRegistrationResponse, MAX_CREATE_TOTP_REGISTRATION_BYTES,
    MAX_CREATE_TOTP_REGISTRATION_CHALLENGE_BYTES,
    decode_create_totp_registration_challenge_request, decode_create_totp_registration_request,
    encode_create_totp_registration_challenge_response, encode_create_totp_registration_response,
    generate_openapi,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, json_response, request_identifier,
};
use crate::{
    AuthenticationRegistrationStore, AuthenticationRegistrationStoreError,
    BrowserAuthenticationError, BrowserSessionAuthorityError, TotpRegistrationAuthority,
    TotpRegistrationAuthorityError, TotpRegistrationError, TotpRegistrationService,
};

/// Synchronous TOTP registration boundary executed on a bounded blocking worker.
pub trait TotpRegistrationController: Send + 'static {
    /// Creates or exactly replays one current-user TOTP registration challenge.
    ///
    /// # Errors
    ///
    /// Returns only stable authentication, request, conflict, availability or integrity failures.
    fn create_registration_challenge(
        &mut self,
        request: &CreateTotpRegistrationChallengeRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateTotpRegistrationChallengeResponse, TotpRegistrationError>;

    /// Verifies possession and authoritatively commits one current-user TOTP method.
    ///
    /// # Errors
    ///
    /// Returns only stable authentication, request, conflict, availability or integrity failures.
    fn register_totp(
        &mut self,
        request: &CreateTotpRegistrationRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateTotpRegistrationResponse, TotpRegistrationError>;
}

impl<S, A, R, P> TotpRegistrationController for TotpRegistrationService<S, A, R, P>
where
    S: AuthenticationRegistrationStore + Send + 'static,
    A: TotpRegistrationAuthority + Send + 'static,
    R: meshspan_domain::RandomSource + Send + 'static,
    P: crate::TotpRegistrationSecretProtector + Send + 'static,
{
    fn create_registration_challenge(
        &mut self,
        request: &CreateTotpRegistrationChallengeRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateTotpRegistrationChallengeResponse, TotpRegistrationError> {
        self.create_challenge(request, headers, now)
    }

    fn register_totp(
        &mut self,
        request: &CreateTotpRegistrationRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateTotpRegistrationResponse, TotpRegistrationError> {
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

/// Builds both rolling current-user TOTP-registration endpoints.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn totp_registration_api_router<C>(controller: C) -> Result<Router, TotpRegistrationApiError>
where
    C: TotpRegistrationController,
{
    let document = generate_openapi()?;
    let state = RegistrationApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/users/current/authentication-methods/totp/registration-challenges",
            post(post_challenge::<C>),
        )
        .route(
            "/api/latest/users/current/authentication-methods/totp",
            post(post_registration::<C>),
        )
        .with_state(state))
}

async fn post_challenge<C>(
    State(state): State<RegistrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: TotpRegistrationController,
{
    let request_id = request_identifier();
    let headers = request.headers().clone();
    let decoded = decode_request(
        request,
        MAX_CREATE_TOTP_REGISTRATION_CHALLENGE_BYTES,
        decode_create_totp_registration_challenge_request,
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
        encode_create_totp_registration_challenge_response,
    )
    .await
}

async fn post_registration<C>(
    State(state): State<RegistrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: TotpRegistrationController,
{
    let request_id = request_identifier();
    let headers = request.headers().clone();
    let decoded = decode_request(
        request,
        MAX_CREATE_TOTP_REGISTRATION_BYTES,
        decode_create_totp_registration_request,
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
        move |controller, now| controller.register_totp(&request, &headers, now),
        encode_create_totp_registration_response,
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
    C: TotpRegistrationController,
    T: Send + 'static,
    F: FnOnce(&mut C, UnixMicros) -> Result<T, TotpRegistrationError> + Send + 'static,
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
    error: &TotpRegistrationError,
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

fn classify_error(error: &TotpRegistrationError) -> (StatusCode, ApiErrorCode, &'static str) {
    match error {
        TotpRegistrationError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "TOTP registration request is invalid",
        ),
        TotpRegistrationError::Rejected
        | TotpRegistrationError::Authentication(BrowserAuthenticationError::Rejected) => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        TotpRegistrationError::Conflict
        | TotpRegistrationError::Store(
            AuthenticationRegistrationStoreError::Expired
            | AuthenticationRegistrationStoreError::Conflict,
        )
        | TotpRegistrationError::Authority(TotpRegistrationAuthorityError::Conflict) => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "TOTP registration conflicts with durable state",
        ),
        TotpRegistrationError::Unavailable
        | TotpRegistrationError::Authority(TotpRegistrationAuthorityError::Unavailable)
        | TotpRegistrationError::Authentication(BrowserAuthenticationError::Authority(
            BrowserSessionAuthorityError::Unavailable,
        )) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "TOTP registration is temporarily unavailable",
        ),
        TotpRegistrationError::InvalidTime
        | TotpRegistrationError::State
        | TotpRegistrationError::InvalidReceipt
        | TotpRegistrationError::Store(AuthenticationRegistrationStoreError::Failed)
        | TotpRegistrationError::Authority(TotpRegistrationAuthorityError::Failed)
        | TotpRegistrationError::Authentication(
            BrowserAuthenticationError::InvalidGateway
            | BrowserAuthenticationError::Authority(BrowserSessionAuthorityError::Failed),
        ) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "TOTP registration failed closed",
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
        "TOTP registration failed closed",
    )
}

enum RegistrationExecutionError {
    Service(TotpRegistrationError),
    Unavailable,
}

/// TOTP registration router construction failure.
#[derive(Debug, Error)]
pub enum TotpRegistrationApiError {
    /// Rust-authored API contract generation failed.
    #[error("TOTP registration API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// Schema digest could not be represented as an HTTP header.
    #[error("TOTP registration schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
