// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTPS boundary for current-user authentication-method revocation.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, AuthenticationMethodId, BoundaryError, MAX_REVOKE_AUTHENTICATION_METHOD_BYTES,
    RevokeAuthenticationMethodRequest, RevokeAuthenticationMethodResponse,
    decode_revoke_authentication_method_request, encode_revoke_authentication_method_response,
    generate_openapi,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, json_response, request_identifier,
};
use crate::{
    AuthenticationMethodRevocationAuthority, AuthenticationMethodRevocationAuthorityError,
    AuthenticationMethodRevocationError, AuthenticationMethodRevocationService,
    BrowserAuthenticationError, BrowserSessionAuthorityError,
};

/// Synchronous method-revocation boundary executed on a bounded blocking worker.
pub trait AuthenticationMethodRevocationController: Send + 'static {
    /// Revokes or exactly replays one current-user authentication method.
    ///
    /// # Errors
    ///
    /// Returns only stable authentication, request, conflict, availability or integrity failures.
    fn revoke_authentication_method(
        &mut self,
        method_id: &AuthenticationMethodId,
        request: &RevokeAuthenticationMethodRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<RevokeAuthenticationMethodResponse, AuthenticationMethodRevocationError>;
}

impl<A> AuthenticationMethodRevocationController for AuthenticationMethodRevocationService<A>
where
    A: AuthenticationMethodRevocationAuthority + Send + 'static,
{
    fn revoke_authentication_method(
        &mut self,
        method_id: &AuthenticationMethodId,
        request: &RevokeAuthenticationMethodRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<RevokeAuthenticationMethodResponse, AuthenticationMethodRevocationError> {
        self.revoke(method_id, request, headers, now)
    }
}

struct ApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for ApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the rolling current-user authentication-method revocation endpoint.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn authentication_method_revocation_api_router<C>(
    controller: C,
) -> Result<Router, AuthenticationMethodRevocationApiError>
where
    C: AuthenticationMethodRevocationController,
{
    let document = generate_openapi()?;
    let state = ApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/users/current/authentication-methods/{method_id}/revocations",
            post(post_revocation::<C>),
        )
        .with_state(state))
}

async fn post_revocation<C>(
    Path(method_id): Path<String>,
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: AuthenticationMethodRevocationController,
{
    let request_id = request_identifier();
    let headers = request.headers().clone();
    if !has_json_content_type(&headers) {
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
    let parsed_method = crate::create_mesh_setup::parse_uuid(&method_id);
    let Ok(parsed_method) = parsed_method else {
        return invalid_request(
            request_id,
            None,
            "method identity is invalid",
            state.schema_digest,
        );
    };
    if !(1..=8).contains(&(parsed_method[6] >> 4)) || parsed_method[8] >> 6 != 2 {
        return invalid_request(
            request_id,
            None,
            "method identity is invalid",
            state.schema_digest,
        );
    }
    let Ok(public_method_id) =
        serde_json::from_value::<AuthenticationMethodId>(serde_json::Value::String(method_id))
    else {
        return failed_closed(request_id, None, state.schema_digest);
    };
    let Ok(bytes) = to_bytes(request.into_body(), MAX_REVOKE_AUTHENTICATION_METHOD_BYTES).await
    else {
        return invalid_request(
            request_id,
            None,
            "request does not satisfy the public contract",
            state.schema_digest,
        );
    };
    let decoded = match decode_revoke_authentication_method_request(&bytes) {
        Ok(decoded) => decoded,
        Err(
            BoundaryError::InvalidSchema(_)
            | BoundaryError::DecodeMismatch
            | BoundaryError::EncodeMismatch,
        ) => return failed_closed(request_id, None, state.schema_digest),
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
    execute(state, request_id, public_method_id, headers, decoded).await
}

async fn execute<C>(
    state: ApiState<C>,
    request_id: String,
    method_id: AuthenticationMethodId,
    headers: HeaderMap,
    request: RevokeAuthenticationMethodRequest,
) -> Response<Body>
where
    C: AuthenticationMethodRevocationController,
{
    let operation_id = request.operation_id.clone();
    let Some(now) = current_time() else {
        return failed_closed(request_id, Some(operation_id), state.schema_digest);
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        let mut controller = controller
            .lock()
            .map_err(|_| RevocationExecutionError::Unavailable)?;
        controller
            .revoke_authentication_method(&method_id, &request, &headers, now)
            .map_err(RevocationExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_revoke_authentication_method_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed_closed(request_id, Some(operation_id), state.schema_digest),
        },
        Ok(Err(RevocationExecutionError::Service(error))) => {
            let (status, code, message) = classify_error(&error);
            error_response(
                status,
                code,
                message,
                request_id,
                Some(operation_id),
                Vec::new(),
                state.schema_digest,
            )
        }
        Ok(Err(RevocationExecutionError::Unavailable)) | Err(_) => {
            failed_closed(request_id, Some(operation_id), state.schema_digest)
        }
    }
}

fn classify_error(
    error: &AuthenticationMethodRevocationError,
) -> (StatusCode, ApiErrorCode, &'static str) {
    match error {
        AuthenticationMethodRevocationError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "authentication-method revocation request is invalid",
        ),
        AuthenticationMethodRevocationError::Rejected
        | AuthenticationMethodRevocationError::Authentication(
            BrowserAuthenticationError::Rejected,
        ) => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        AuthenticationMethodRevocationError::Conflict
        | AuthenticationMethodRevocationError::Authority(
            AuthenticationMethodRevocationAuthorityError::Conflict,
        ) => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "authentication-method revocation conflicts with durable state",
        ),
        AuthenticationMethodRevocationError::Authority(
            AuthenticationMethodRevocationAuthorityError::Unavailable,
        )
        | AuthenticationMethodRevocationError::Authentication(
            BrowserAuthenticationError::Authority(BrowserSessionAuthorityError::Unavailable),
        ) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "authentication-method revocation is temporarily unavailable",
        ),
        AuthenticationMethodRevocationError::InvalidReceipt
        | AuthenticationMethodRevocationError::Authority(
            AuthenticationMethodRevocationAuthorityError::Failed,
        )
        | AuthenticationMethodRevocationError::Authentication(
            BrowserAuthenticationError::InvalidGateway
            | BrowserAuthenticationError::Authority(BrowserSessionAuthorityError::Failed),
        ) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "authentication-method revocation failed closed",
        ),
    }
}

fn invalid_request(
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
    message: &'static str,
    schema_digest: HeaderValue,
) -> Response<Body> {
    error_response(
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
        message,
        request_id,
        operation_id,
        vec![issue("", "invalid")],
        schema_digest,
    )
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
        "authentication-method revocation failed closed",
    )
}

enum RevocationExecutionError {
    Service(AuthenticationMethodRevocationError),
    Unavailable,
}

/// Authentication-method revocation router construction failure.
#[derive(Debug, Error)]
pub enum AuthenticationMethodRevocationApiError {
    /// Rust-authored `OpenAPI` generation failed.
    #[error("failed to generate the public API contract")]
    Contract(#[from] serde_json::Error),
    /// Schema digest could not be represented as an HTTP header.
    #[error("failed to construct the public schema digest header")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
