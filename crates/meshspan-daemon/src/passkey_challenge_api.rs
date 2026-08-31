// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTP boundary for non-enumerating passkey challenge creation.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, CreatePasskeyChallengeRequest, CreatePasskeyChallengeResponse,
    MAX_CREATE_PASSKEY_CHALLENGE_BYTES, OperationId as ApiOperationId,
    decode_create_passkey_challenge_request, encode_create_passkey_challenge_response,
    generate_openapi,
};
use meshspan_domain::{RandomSource, UnixMicros};
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, json_response, request_identifier,
};
use crate::{PasskeyCeremonyStore, PasskeyChallengeError, PasskeyChallengeService};

/// Synchronous challenge application boundary executed on a blocking worker.
pub trait CreatePasskeyChallengeController: Send + 'static {
    /// Creates or exactly resolves one validated passkey challenge request.
    ///
    /// # Errors
    ///
    /// Returns a closed service error without challenge-protection or persistence detail.
    fn create_passkey_challenge(
        &mut self,
        request: &CreatePasskeyChallengeRequest,
        now: UnixMicros,
    ) -> Result<CreatePasskeyChallengeResponse, PasskeyChallengeError>;
}

impl<S, R> CreatePasskeyChallengeController for PasskeyChallengeService<S, R>
where
    S: PasskeyCeremonyStore + Send + 'static,
    R: RandomSource + Send + 'static,
{
    fn create_passkey_challenge(
        &mut self,
        request: &CreatePasskeyChallengeRequest,
        now: UnixMicros,
    ) -> Result<CreatePasskeyChallengeResponse, PasskeyChallengeError> {
        self.create(request, now)
    }
}

struct PasskeyChallengeApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for PasskeyChallengeApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the rolling passkey challenge endpoint over one live local controller.
///
/// Synchronous cryptography and SQLite work run on Tokio's blocking pool rather than occupying an
/// asynchronous connection worker.
///
/// # Errors
///
/// Fails if the Rust-authored `OpenAPI` document or digest response header cannot be generated.
pub fn passkey_challenge_api_router<C>(controller: C) -> Result<Router, PasskeyChallengeApiError>
where
    C: CreatePasskeyChallengeController,
{
    let document = generate_openapi()?;
    let state = PasskeyChallengeApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/sessions/passkey/challenges",
            post(post_passkey_challenge::<C>),
        )
        .with_state(state))
}

async fn post_passkey_challenge<C>(
    State(state): State<PasskeyChallengeApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: CreatePasskeyChallengeController,
{
    let request_id = request_identifier();
    if !has_json_content_type(request.headers()) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "content type must be application/json",
            request_id,
            None,
            vec![issue("", "content_type")],
            state.schema_digest,
        );
    }
    let Ok(bytes) = to_bytes(request.into_body(), MAX_CREATE_PASSKEY_CHALLENGE_BYTES).await else {
        return error_response(
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "request body exceeds its byte limit",
            request_id,
            None,
            vec![issue("", "max_bytes")],
            state.schema_digest,
        );
    };
    let request = match decode_create_passkey_challenge_request(&bytes) {
        Ok(request) => request,
        Err(
            BoundaryError::InvalidSchema(_)
            | BoundaryError::DecodeMismatch
            | BoundaryError::EncodeMismatch,
        ) => {
            return internal_error_response(
                request_id,
                None,
                state.schema_digest,
                "passkey challenge creation failed closed",
            );
        }
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                "request does not satisfy the public contract",
                request_id,
                None,
                boundary_issues(error),
                state.schema_digest,
            );
        }
    };
    execute_challenge(state, request_id, request).await
}

async fn execute_challenge<C>(
    state: PasskeyChallengeApiState<C>,
    request_id: String,
    request: CreatePasskeyChallengeRequest,
) -> Response<Body>
where
    C: CreatePasskeyChallengeController,
{
    let operation_id = Some(request.operation_id.clone());
    let Some(now) = current_time() else {
        return internal_error_response(
            request_id,
            operation_id,
            state.schema_digest,
            "passkey challenge creation failed closed",
        );
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| ChallengeExecutionError::Unavailable)?
            .create_passkey_challenge(&request, now)
            .map_err(ChallengeExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_create_passkey_challenge_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => internal_error_response(
                request_id,
                operation_id,
                state.schema_digest,
                "passkey challenge creation failed closed",
            ),
        },
        Ok(Err(ChallengeExecutionError::Service(error))) => {
            service_error_response(error, request_id, operation_id, state.schema_digest)
        }
        Ok(Err(ChallengeExecutionError::Unavailable)) | Err(_) => internal_error_response(
            request_id,
            operation_id,
            state.schema_digest,
            "passkey challenge creation failed closed",
        ),
    }
}

fn service_error_response(
    error: PasskeyChallengeError,
    request_id: String,
    operation_id: Option<ApiOperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        PasskeyChallengeError::InvalidOperation => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "passkey challenge request is invalid",
        ),
        PasskeyChallengeError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "passkey challenge operation conflicts with local state",
        ),
        PasskeyChallengeError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "passkey challenge creation is temporarily unavailable",
        ),
        PasskeyChallengeError::InvalidTime | PasskeyChallengeError::Failed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "passkey challenge creation failed closed",
        ),
    };
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

enum ChallengeExecutionError {
    Service(PasskeyChallengeError),
    Unavailable,
}

/// Passkey challenge router construction failure containing no secret material.
#[derive(Debug, Error)]
pub enum PasskeyChallengeApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
