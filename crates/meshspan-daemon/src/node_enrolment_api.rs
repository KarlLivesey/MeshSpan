// SPDX-License-Identifier: GPL-2.0-only

//! Bounded anonymous HTTPS boundary for pre-authorised node enrolment.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, MAX_ENROL_NODE_BYTES, decode_enrol_node_request,
    encode_enrol_node_response, generate_openapi,
};
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    json_response, request_identifier,
};
use crate::{NodeEnrolmentController, NodeEnrolmentError};

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

/// Builds the rolling anonymous pre-authorised node-enrolment route.
///
/// The join grant is the route's authentication material. The bounded public contract is
/// validated before any authority, certificate or consensus work begins.
///
/// # Errors
///
/// Fails when the Rust-authored contract or its schema digest is invalid.
pub fn node_enrolment_api_router<C>(controller: C) -> Result<Router, NodeEnrolmentApiError>
where
    C: NodeEnrolmentController,
{
    let document = generate_openapi()?;
    Ok(Router::new()
        .route("/api/latest/setup/enrolments", post(enrol_node::<C>))
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn enrol_node<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: NodeEnrolmentController,
{
    let request_id = request_identifier();
    if !has_json_content_type(request.headers()) {
        return public_error(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "node enrolment requires application/json",
            request_id,
            Vec::new(),
        );
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_ENROL_NODE_BYTES).await else {
        return public_error(
            &state,
            StatusCode::PAYLOAD_TOO_LARGE,
            "node enrolment body exceeds its bound",
            request_id,
            Vec::new(),
        );
    };
    let decoded = match decode_enrol_node_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    let operation_id = Some(decoded.operation_id.clone());
    let Some(now) = current_time() else {
        return failed(&state, request_id, operation_id);
    };
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| NodeEnrolmentError::Unavailable)?
            .enrol(decoded, now)
    })
    .await
    {
        Ok(Ok(response)) => match encode_enrol_node_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => failed(&state, request_id, operation_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id, operation_id),
        Err(_) => failed(&state, request_id, operation_id),
    }
}

fn boundary_error<C>(
    state: &ApiState<C>,
    error: BoundaryError,
    request_id: String,
) -> Response<Body> {
    let status = if matches!(error, BoundaryError::BodyTooLarge { .. }) {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    };
    public_error(
        state,
        status,
        "node enrolment request is invalid",
        request_id,
        boundary_issues(error),
    )
}

fn service_error<C>(
    state: &ApiState<C>,
    error: NodeEnrolmentError,
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
) -> Response<Body> {
    let (status, code, message) = match error {
        NodeEnrolmentError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "node enrolment values are invalid",
        ),
        NodeEnrolmentError::Rejected => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "node enrolment was rejected",
        ),
        NodeEnrolmentError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "node enrolment conflicts with committed state",
        ),
        NodeEnrolmentError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "node enrolment authority is temporarily unavailable",
        ),
        NodeEnrolmentError::Failed => return failed(state, request_id, operation_id),
    };
    error_response(
        status,
        code,
        message,
        request_id,
        operation_id,
        Vec::new(),
        state.schema_digest.clone(),
    )
}

fn public_error<C>(
    state: &ApiState<C>,
    status: StatusCode,
    message: &str,
    request_id: String,
    issues: Vec<meshspan_api_contract::ApiErrorIssue>,
) -> Response<Body> {
    error_response(
        status,
        ApiErrorCode::InvalidRequest,
        message,
        request_id,
        None,
        issues,
        state.schema_digest.clone(),
    )
}

fn failed<C>(
    state: &ApiState<C>,
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
) -> Response<Body> {
    internal_error_response(
        request_id,
        operation_id,
        state.schema_digest.clone(),
        "node enrolment failed closed",
    )
}

/// Node-enrolment API construction failure.
#[derive(Debug, Error)]
pub enum NodeEnrolmentApiError {
    /// Rust-authored `OpenAPI` generation failed.
    #[error("node enrolment API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// Generated schema digest was not a valid header value.
    #[error("node enrolment API schema header is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
