// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTP boundary for atomic current browser-session step-up.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, MAX_STEP_UP_CURRENT_SESSION_BYTES, OperationId as ApiOperationId,
    StepUpCurrentSessionRequest, decode_step_up_current_session_request, generate_openapi,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, request_identifier,
};
use crate::auth_api::session_success_response;
use crate::{
    BrowserAuthenticationError, BrowserSessionAuthorityError, CreateSessionResult,
    SessionAuthorityError, StepUpCurrentSessionError, StepUpCurrentSessionService,
    StepUpSessionAuthority,
};

/// Synchronous step-up boundary executed on a blocking worker.
pub trait StepUpCurrentSessionController: Send + 'static {
    /// Rotates or exactly resolves the browser session presented by this request.
    ///
    /// # Errors
    ///
    /// Returns only closed authentication, conflict, availability or integrity failures.
    fn step_up_current_session(
        &mut self,
        request: &StepUpCurrentSessionRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, StepUpCurrentSessionError>;
}

impl<A, T> StepUpCurrentSessionController for StepUpCurrentSessionService<A, T>
where
    A: StepUpSessionAuthority + Send + 'static,
    T: crate::TotpFactorVerifier + Send + 'static,
{
    fn step_up_current_session(
        &mut self,
        request: &StepUpCurrentSessionRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateSessionResult, StepUpCurrentSessionError> {
        self.step_up(request, headers, now)
    }
}

struct StepUpSessionApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for StepUpSessionApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the rolling current-session step-up endpoint.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn step_up_current_session_api_router<C>(
    controller: C,
) -> Result<Router, StepUpCurrentSessionApiError>
where
    C: StepUpCurrentSessionController,
{
    let document = generate_openapi()?;
    let state = StepUpSessionApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/sessions/current/step-ups",
            post(post_step_up::<C>),
        )
        .with_state(state))
}

async fn post_step_up<C>(
    State(state): State<StepUpSessionApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: StepUpCurrentSessionController,
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
    let headers = request.headers().clone();
    let Ok(bytes) = to_bytes(request.into_body(), MAX_STEP_UP_CURRENT_SESSION_BYTES).await else {
        return invalid_body(
            request_id,
            None,
            state.schema_digest,
            vec![issue("", "max_bytes")],
        );
    };
    let request = match decode_step_up_current_session_request(&bytes) {
        Ok(request) => request,
        Err(
            BoundaryError::InvalidSchema(_)
            | BoundaryError::DecodeMismatch
            | BoundaryError::EncodeMismatch,
        ) => return failed_closed(request_id, None, state.schema_digest),
        Err(error) => {
            return invalid_body(
                request_id,
                None,
                state.schema_digest,
                boundary_issues(error),
            );
        }
    };
    execute_step_up(state, request_id, request, headers).await
}

async fn execute_step_up<C>(
    state: StepUpSessionApiState<C>,
    request_id: String,
    request: StepUpCurrentSessionRequest,
    headers: HeaderMap,
) -> Response<Body>
where
    C: StepUpCurrentSessionController,
{
    let operation_id = Some(request.operation_id.clone());
    let Some(now) = current_time() else {
        return failed_closed(request_id, operation_id, state.schema_digest);
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| StepUpExecutionError::Unavailable)?
            .step_up_current_session(&request, &headers, now)
            .map_err(StepUpExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(result)) => session_success_response(&result, now, state.schema_digest.clone())
            .unwrap_or_else(|()| failed_closed(request_id, operation_id, state.schema_digest)),
        Ok(Err(StepUpExecutionError::Service(error))) => {
            service_error_response(&error, request_id, operation_id, state.schema_digest)
        }
        Ok(Err(StepUpExecutionError::Unavailable)) | Err(_) => {
            failed_closed(request_id, operation_id, state.schema_digest)
        }
    }
}

fn invalid_body(
    request_id: String,
    operation_id: Option<ApiOperationId>,
    schema_digest: HeaderValue,
    issues: Vec<meshspan_api_contract::ApiErrorIssue>,
) -> Response<Body> {
    error_response(
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
        "request does not satisfy the public contract",
        request_id,
        operation_id,
        issues,
        schema_digest,
    )
}

fn service_error_response(
    error: &StepUpCurrentSessionError,
    request_id: String,
    operation_id: Option<ApiOperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        StepUpCurrentSessionError::InvalidOperation
        | StepUpCurrentSessionError::Totp(crate::TotpSessionError::Unsupported) => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "session step-up request is not supported",
        ),
        StepUpCurrentSessionError::Rejected
        | StepUpCurrentSessionError::Authentication(BrowserAuthenticationError::Rejected)
        | StepUpCurrentSessionError::Totp(crate::TotpSessionError::Rejected) => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        StepUpCurrentSessionError::Authority(SessionAuthorityError::Conflict) => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "session step-up conflicts with durable state",
        ),
        StepUpCurrentSessionError::Authority(SessionAuthorityError::Unavailable)
        | StepUpCurrentSessionError::Authentication(BrowserAuthenticationError::Authority(
            BrowserSessionAuthorityError::Unavailable,
        )) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "session authority is temporarily unavailable",
        ),
        StepUpCurrentSessionError::Token(_)
        | StepUpCurrentSessionError::InvalidPolicy
        | StepUpCurrentSessionError::InvalidReceipt
        | StepUpCurrentSessionError::Totp(
            crate::TotpSessionError::InvalidEvidence | crate::TotpSessionError::InvalidTime,
        )
        | StepUpCurrentSessionError::Authority(SessionAuthorityError::Failed)
        | StepUpCurrentSessionError::Authentication(
            BrowserAuthenticationError::InvalidGateway
            | BrowserAuthenticationError::Authority(BrowserSessionAuthorityError::Failed),
        ) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "session step-up failed closed",
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

fn failed_closed(
    request_id: String,
    operation_id: Option<ApiOperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    internal_error_response(
        request_id,
        operation_id,
        schema_digest,
        "session step-up failed closed",
    )
}

enum StepUpExecutionError {
    Service(StepUpCurrentSessionError),
    Unavailable,
}

/// Current-session step-up router construction failure.
#[derive(Debug, Error)]
pub enum StepUpCurrentSessionApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
