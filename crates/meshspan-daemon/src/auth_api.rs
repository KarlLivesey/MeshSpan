// SPDX-License-Identifier: GPL-2.0-only

//! Bounded session-creation HTTP boundary and secret response delivery.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, CreateSessionRequest, MAX_CREATE_SESSION_BYTES,
    OperationId as ApiOperationId, decode_create_session_request, encode_create_session_response,
    generate_openapi,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, json_response, request_identifier,
};
use crate::browser_session::{CSRF_HEADER, SESSION_COOKIE_NAME};
use crate::{
    CreateSessionError, CreateSessionResult, CreateSessionService, SessionAuthority,
    SessionAuthorityError,
};

const MICROS_PER_SECOND: i64 = 1_000_000;

/// Synchronous session application boundary executed on a blocking worker.
pub trait CreateSessionController: Send + 'static {
    /// Authenticates and commits or exactly resolves one validated session request.
    ///
    /// # Errors
    ///
    /// Returns a closed service error without exposing submitted or issued secret material.
    fn create_session(
        &mut self,
        request: &CreateSessionRequest,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, CreateSessionError>;
}

impl<A> CreateSessionController for CreateSessionService<A>
where
    A: SessionAuthority + Send + 'static,
{
    fn create_session(
        &mut self,
        request: &CreateSessionRequest,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, CreateSessionError> {
        self.create(request, now)
    }
}

struct SessionApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for SessionApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the rolling session endpoint over one live authentication controller.
///
/// The mutation runs on Tokio's blocking pool so synchronous consensus and SQLite work cannot
/// stall unrelated HTTP connections.
///
/// # Errors
///
/// Fails if the Rust-authored `OpenAPI` document or its digest header cannot be generated.
pub fn session_api_router<C>(controller: C) -> Result<Router, SessionApiError>
where
    C: CreateSessionController,
{
    let document = generate_openapi()?;
    let state = SessionApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route("/api/latest/sessions", post(post_session::<C>))
        .with_state(state))
}

async fn post_session<C>(
    State(state): State<SessionApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: CreateSessionController,
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
    let Ok(bytes) = to_bytes(request.into_body(), MAX_CREATE_SESSION_BYTES).await else {
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
    let request = match decode_create_session_request(&bytes) {
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
                "authentication failed closed",
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
    execute_session(state, request_id, request).await
}

async fn execute_session<C>(
    state: SessionApiState<C>,
    request_id: String,
    request: CreateSessionRequest,
) -> Response<Body>
where
    C: CreateSessionController,
{
    let operation_id = Some(request.operation_id.clone());
    let Some(now) = current_time() else {
        return internal_error_response(
            request_id,
            operation_id,
            state.schema_digest,
            "authentication failed closed",
        );
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| SessionExecutionError::Unavailable)?
            .create_session(&request, now)
            .map_err(SessionExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(result)) => success_response(&result, now, state.schema_digest.clone())
            .unwrap_or_else(|()| {
                internal_error_response(
                    request_id,
                    operation_id,
                    state.schema_digest,
                    "authentication failed closed",
                )
            }),
        Ok(Err(SessionExecutionError::Service(error))) => {
            service_error_response(&error, request_id, operation_id, state.schema_digest)
        }
        Ok(Err(SessionExecutionError::Unavailable)) | Err(_) => internal_error_response(
            request_id,
            operation_id,
            state.schema_digest,
            "authentication failed closed",
        ),
    }
}

fn success_response(
    result: &CreateSessionResult,
    now: UnixMicros,
    schema_digest: HeaderValue,
) -> Result<Response<Body>, ()> {
    let body = encode_create_session_response(&result.response).map_err(|_| ())?;
    let mut cookie = result.bearer.expose_encoded();
    cookie.insert(0, '=');
    cookie.insert_str(0, SESSION_COOKIE_NAME);
    cookie.push_str("; Path=/; Secure; HttpOnly; SameSite=Strict");
    if result.persistent_cookie {
        let lifetime = result
            .response
            .expires_at_epoch_micros
            .checked_sub(now.get())
            .filter(|value| *value > 0)
            .ok_or(())?;
        let seconds = lifetime / MICROS_PER_SECOND;
        if seconds == 0 {
            return Err(());
        }
        write!(cookie, "; Max-Age={seconds}").map_err(|_| ())?;
    }
    let mut cookie = HeaderValue::from_str(&cookie).map_err(|_| ())?;
    cookie.set_sensitive(true);
    let csrf = result.csrf.expose_encoded();
    let mut csrf = HeaderValue::from_str(&csrf).map_err(|_| ())?;
    csrf.set_sensitive(true);
    let mut response = json_response(StatusCode::CREATED, body, schema_digest);
    response.headers_mut().insert(SET_COOKIE, cookie);
    response.headers_mut().insert(CSRF_HEADER, csrf);
    Ok(response)
}

fn service_error_response(
    error: &CreateSessionError,
    request_id: String,
    operation_id: Option<ApiOperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        CreateSessionError::InvalidOperation | CreateSessionError::UnsupportedCeremony => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "authentication request is not supported",
        ),
        CreateSessionError::ApiKey(_)
        | CreateSessionError::Rejected
        | CreateSessionError::AdditionalFactorRequired => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        CreateSessionError::Authority(SessionAuthorityError::Conflict) => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "session operation conflicts with durable state",
        ),
        CreateSessionError::Authority(SessionAuthorityError::Unavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "authentication authority is temporarily unavailable",
        ),
        CreateSessionError::Material(_)
        | CreateSessionError::InvalidPolicy
        | CreateSessionError::InvalidReceipt
        | CreateSessionError::Authority(SessionAuthorityError::Failed) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "authentication failed closed",
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

enum SessionExecutionError {
    Service(CreateSessionError),
    Unavailable,
}

/// Session router construction failure containing no secret material.
#[derive(Debug, Error)]
pub enum SessionApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
