// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTP boundary for replay-safe current browser-session revocation.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, MAX_REVOKE_CURRENT_SESSION_BYTES, OperationId as ApiOperationId,
    RevokeCurrentSessionRequest, RevokeCurrentSessionResponse,
    decode_revoke_current_session_request, encode_revoke_current_session_response,
    generate_openapi,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, json_response, request_identifier,
};
use crate::browser_session::SESSION_COOKIE_NAME;
use crate::{
    BrowserAuthenticationError, BrowserSessionAuthorityError, RevokeCurrentSessionError,
    RevokeCurrentSessionService, SessionRevocationAuthority, SessionRevocationAuthorityError,
};

/// Synchronous session-revocation boundary executed on a blocking worker.
pub trait RevokeCurrentSessionController: Send + 'static {
    /// Revokes or exactly resolves the browser session presented by this request.
    ///
    /// # Errors
    ///
    /// Returns only closed authentication, conflict, availability or integrity failures.
    fn revoke_current_session(
        &mut self,
        request: &RevokeCurrentSessionRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<RevokeCurrentSessionResponse, RevokeCurrentSessionError>;
}

impl<A> RevokeCurrentSessionController for RevokeCurrentSessionService<A>
where
    A: SessionRevocationAuthority + Send + 'static,
{
    fn revoke_current_session(
        &mut self,
        request: &RevokeCurrentSessionRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<RevokeCurrentSessionResponse, RevokeCurrentSessionError> {
        self.revoke(request, headers, now)
    }
}

struct RevokeSessionApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for RevokeSessionApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the rolling current-session revocation endpoint.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn revoke_current_session_api_router<C>(
    controller: C,
) -> Result<Router, RevokeCurrentSessionApiError>
where
    C: RevokeCurrentSessionController,
{
    let document = generate_openapi()?;
    let state = RevokeSessionApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/sessions/current/revocations",
            post(post_revocation::<C>),
        )
        .with_state(state))
}

async fn post_revocation<C>(
    State(state): State<RevokeSessionApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: RevokeCurrentSessionController,
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
    let Ok(bytes) = to_bytes(request.into_body(), MAX_REVOKE_CURRENT_SESSION_BYTES).await else {
        return invalid_body(
            request_id,
            None,
            state.schema_digest,
            vec![issue("", "max_bytes")],
        );
    };
    let request = match decode_revoke_current_session_request(&bytes) {
        Ok(request) => request,
        Err(
            BoundaryError::InvalidSchema(_)
            | BoundaryError::DecodeMismatch
            | BoundaryError::EncodeMismatch,
        ) => {
            return failed_closed(request_id, None, state.schema_digest);
        }
        Err(error) => {
            return invalid_body(
                request_id,
                None,
                state.schema_digest,
                boundary_issues(error),
            );
        }
    };
    execute_revocation(state, request_id, request, headers).await
}

async fn execute_revocation<C>(
    state: RevokeSessionApiState<C>,
    request_id: String,
    request: RevokeCurrentSessionRequest,
    headers: HeaderMap,
) -> Response<Body>
where
    C: RevokeCurrentSessionController,
{
    let operation_id = Some(request.operation_id.clone());
    let Some(now) = current_time() else {
        return failed_closed(request_id, operation_id, state.schema_digest);
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| RevocationExecutionError::Unavailable)?
            .revoke_current_session(&request, &headers, now)
            .map_err(RevocationExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(response)) => success_response(&response, state.schema_digest.clone())
            .unwrap_or_else(|()| failed_closed(request_id, operation_id, state.schema_digest)),
        Ok(Err(RevocationExecutionError::Service(error))) => {
            service_error_response(&error, request_id, operation_id, state.schema_digest)
        }
        Ok(Err(RevocationExecutionError::Unavailable)) | Err(_) => {
            failed_closed(request_id, operation_id, state.schema_digest)
        }
    }
}

fn success_response(
    result: &RevokeCurrentSessionResponse,
    schema_digest: HeaderValue,
) -> Result<Response<Body>, ()> {
    let body = encode_revoke_current_session_response(result).map_err(|_| ())?;
    let cookie =
        format!("{SESSION_COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
    let mut cookie = HeaderValue::from_str(&cookie).map_err(|_| ())?;
    cookie.set_sensitive(true);
    let mut response = json_response(StatusCode::OK, body, schema_digest);
    response.headers_mut().insert(SET_COOKIE, cookie);
    Ok(response)
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
    error: &RevokeCurrentSessionError,
    request_id: String,
    operation_id: Option<ApiOperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        RevokeCurrentSessionError::InvalidOperation => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "session revocation request is invalid",
        ),
        RevokeCurrentSessionError::Rejected
        | RevokeCurrentSessionError::Authentication(BrowserAuthenticationError::Rejected) => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        RevokeCurrentSessionError::Authority(SessionRevocationAuthorityError::Conflict) => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "session revocation conflicts with durable state",
        ),
        RevokeCurrentSessionError::Authority(SessionRevocationAuthorityError::Unavailable)
        | RevokeCurrentSessionError::Authentication(BrowserAuthenticationError::Authority(
            BrowserSessionAuthorityError::Unavailable,
        )) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "session authority is temporarily unavailable",
        ),
        RevokeCurrentSessionError::InvalidReceipt
        | RevokeCurrentSessionError::Authority(SessionRevocationAuthorityError::Failed)
        | RevokeCurrentSessionError::Authentication(
            BrowserAuthenticationError::InvalidGateway
            | BrowserAuthenticationError::Authority(BrowserSessionAuthorityError::Failed),
        ) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "session revocation failed closed",
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
        "session revocation failed closed",
    )
}

enum RevocationExecutionError {
    Service(RevokeCurrentSessionError),
    Unavailable,
}

/// Current-session revocation router construction failure.
#[derive(Debug, Error)]
pub enum RevokeCurrentSessionApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
