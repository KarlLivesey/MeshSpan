// SPDX-License-Identifier: GPL-2.0-only

//! Bounded native HTTPS invitation and first-credential routes.

use super::{UserEnrollmentController, UserEnrollmentError};
use crate::api_http::{
    current_time, error_response, has_json_content_type, json_response, request_identifier,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode},
    routing::post,
};
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, MAX_USER_ENROLLMENT_REQUEST_BYTES, OperationId, PrincipalId,
    decode_issue_user_enrollment_request, decode_redeem_user_enrollment_api_key_request,
    decode_revoke_user_enrollment_request, encode_create_api_key_response,
    encode_issue_user_enrollment_response, encode_revoke_user_enrollment_response,
    generate_openapi,
};
use std::sync::{Arc, Mutex};
use thiserror::Error;

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

/// Builds native manager consent and explicit capability redemption endpoints.
/// # Errors
/// Rejects invalid generated contract or schema headers.
pub fn user_enrollment_api_router<C: UserEnrollmentController>(
    controller: C,
) -> Result<Router, UserEnrollmentApiError> {
    let document = generate_openapi()?;
    let state = ApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/admin/identities/users/{principal_id}/enrollments",
            post(issue::<C>),
        )
        .route(
            "/api/latest/admin/identities/user-enrollments/{enrollment_operation_id}/revocations",
            post(revoke::<C>),
        )
        .route("/api/latest/user-enrollments/api-keys", post(redeem::<C>))
        .with_state(state))
}
async fn issue<C: UserEnrollmentController>(
    State(state): State<ApiState<C>>,
    Path(target): Path<String>,
    request: Request,
) -> Response<Body> {
    handle(state, Action::Issue(target), request).await
}
async fn revoke<C: UserEnrollmentController>(
    State(state): State<ApiState<C>>,
    Path(target): Path<String>,
    request: Request,
) -> Response<Body> {
    handle(state, Action::Revoke(target), request).await
}
async fn redeem<C: UserEnrollmentController>(
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body> {
    handle(state, Action::Redeem, request).await
}

enum Action {
    Issue(String),
    Revoke(String),
    Redeem,
}
impl Action {
    const fn requires_manager(&self) -> bool {
        match self {
            Self::Issue(_) | Self::Revoke(_) => true,
            Self::Redeem => false,
        }
    }
}

async fn handle<C: UserEnrollmentController>(
    state: ApiState<C>,
    action: Action,
    request: Request,
) -> Response<Body> {
    let headers = request.headers().clone();
    if action.requires_manager() {
        if let Err(error) = authenticate(&state, headers.clone()).await {
            return failure(error, None, state.schema_digest);
        }
    }
    if request.uri().query().is_some() {
        return failure(
            UserEnrollmentError::InvalidRequest,
            None,
            state.schema_digest,
        );
    }
    if !has_json_content_type(&headers) {
        return request_failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, state.schema_digest);
    }
    let Ok(bytes) = to_bytes(request.into_body(), MAX_USER_ENROLLMENT_REQUEST_BYTES).await else {
        return request_failure(StatusCode::PAYLOAD_TOO_LARGE, state.schema_digest);
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        let mut controller = controller.lock().map_err(|_| ExecutionFailure {
            error: UserEnrollmentError::Unavailable,
            operation: None,
        })?;
        execute(&mut *controller, action, &headers, &bytes)
    })
    .await;
    match execution {
        Ok(Ok(body)) => json_response(StatusCode::OK, body, state.schema_digest),
        Ok(Err(error)) => failure(error.error, error.operation, state.schema_digest),
        Err(_) => failure(UserEnrollmentError::Unavailable, None, state.schema_digest),
    }
}
async fn authenticate<C: UserEnrollmentController>(
    state: &ApiState<C>,
    headers: HeaderMap,
) -> Result<(), UserEnrollmentError> {
    let controller = Arc::clone(&state.controller);
    tokio::task::spawn_blocking(move || {
        let now = current_time().ok_or(UserEnrollmentError::Failed)?;
        controller
            .lock()
            .map_err(|_| UserEnrollmentError::Unavailable)?
            .authenticate(&headers, now)
            .map(|_| ())
    })
    .await
    .map_err(|_| UserEnrollmentError::Unavailable)?
}

struct ExecutionFailure {
    error: UserEnrollmentError,
    operation: Option<OperationId>,
}
fn execute<C: UserEnrollmentController>(
    controller: &mut C,
    action: Action,
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<Vec<u8>, ExecutionFailure> {
    let now = current_time().ok_or_else(|| execution_failure(UserEnrollmentError::Failed, None))?;
    match action {
        Action::Issue(target) => {
            let actor = controller
                .authenticate(headers, now)
                .map_err(|error| execution_failure(error, None))?;
            let target = PrincipalId::parse(&target)
                .ok_or_else(|| execution_failure(UserEnrollmentError::InvalidRequest, None))?;
            let request = decode_issue_user_enrollment_request(bytes).map_err(boundary_failure)?;
            let operation = Some(request.operation_id.clone());
            let response = controller
                .issue(actor, &target, &request)
                .map_err(|error| execution_failure(error, operation.clone()))?;
            encode_issue_user_enrollment_response(&response)
                .map_err(|_| execution_failure(UserEnrollmentError::Failed, operation))
        }
        Action::Revoke(target) => {
            let actor = controller
                .authenticate(headers, now)
                .map_err(|error| execution_failure(error, None))?;
            let target = OperationId::parse(&target)
                .ok_or_else(|| execution_failure(UserEnrollmentError::InvalidRequest, None))?;
            let request = decode_revoke_user_enrollment_request(bytes).map_err(boundary_failure)?;
            let operation = Some(request.operation_id.clone());
            let response = controller
                .revoke(actor, &target, &request)
                .map_err(|error| execution_failure(error, operation.clone()))?;
            encode_revoke_user_enrollment_response(&response)
                .map_err(|_| execution_failure(UserEnrollmentError::Failed, operation))
        }
        Action::Redeem => {
            let request =
                decode_redeem_user_enrollment_api_key_request(bytes).map_err(boundary_failure)?;
            let operation = Some(request.operation_id.clone());
            let response = controller
                .redeem(&request, now)
                .map_err(|error| execution_failure(error, operation.clone()))?;
            encode_create_api_key_response(&response)
                .map_err(|_| execution_failure(UserEnrollmentError::Failed, operation))
        }
    }
}
fn execution_failure(
    error: UserEnrollmentError,
    operation: Option<OperationId>,
) -> ExecutionFailure {
    ExecutionFailure { error, operation }
}
fn boundary_failure(error: BoundaryError) -> ExecutionFailure {
    let error = match error {
        BoundaryError::InvalidSchema(_) | BoundaryError::EncodeMismatch => {
            UserEnrollmentError::Failed
        }
        BoundaryError::DecodeMismatch
        | BoundaryError::MalformedJson
        | BoundaryError::BodyTooLarge { .. }
        | BoundaryError::Invalid { .. } => UserEnrollmentError::InvalidRequest,
    };
    execution_failure(error, None)
}
fn failure(
    error: UserEnrollmentError,
    operation: Option<OperationId>,
    digest: HeaderValue,
) -> Response<Body> {
    let (status, code) = match error {
        UserEnrollmentError::InvalidRequest => {
            (StatusCode::BAD_REQUEST, ApiErrorCode::InvalidRequest)
        }
        UserEnrollmentError::Rejected => (StatusCode::FORBIDDEN, ApiErrorCode::Forbidden),
        UserEnrollmentError::Conflict => (StatusCode::CONFLICT, ApiErrorCode::OperationConflict),
        UserEnrollmentError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, ApiErrorCode::Busy),
        UserEnrollmentError::Failed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
        ),
    };
    error_response(
        status,
        code,
        "user enrollment could not return a verified result",
        request_identifier(),
        operation,
        Vec::new(),
        digest,
    )
}
fn request_failure(status: StatusCode, digest: HeaderValue) -> Response<Body> {
    error_response(
        status,
        ApiErrorCode::InvalidRequest,
        "user enrollment request does not satisfy the public contract",
        request_identifier(),
        None,
        Vec::new(),
        digest,
    )
}

/// Router construction failure, without credential or session material.
#[derive(Debug, Error)]
pub enum UserEnrollmentApiError {
    /// Rust-authored contract generation failed.
    #[error("user enrollment contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// Schema digest header is invalid.
    #[error("user enrollment schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
