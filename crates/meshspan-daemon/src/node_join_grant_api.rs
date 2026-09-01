// SPDX-License-Identifier: GPL-2.0-only

//! Bounded authenticate-before-body HTTP boundary for node join-grant issuance.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, MAX_CREATE_NODE_JOIN_GRANT_BYTES,
    decode_create_node_join_grant_request, encode_create_node_join_grant_response,
    generate_openapi,
};
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    json_response, request_identifier,
};
use crate::{NodeJoinGrantIssuanceController, NodeJoinGrantIssuanceError};

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

/// Builds the rolling system-manager node join-grant route.
///
/// # Errors
///
/// Fails when the Rust-authored contract or its schema digest is invalid.
pub fn node_join_grant_api_router<C>(controller: C) -> Result<Router, NodeJoinGrantIssuanceApiError>
where
    C: NodeJoinGrantIssuanceController,
{
    let document = generate_openapi()?;
    Ok(Router::new()
        .route(
            "/api/latest/admin/node-join-grants",
            post(issue_join_grant::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn issue_join_grant<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: NodeJoinGrantIssuanceController,
{
    let request_id = request_identifier();
    let Some(now) = current_time() else {
        return failed(&state, request_id);
    };
    let controller = Arc::clone(&state.controller);
    let headers = request.headers().clone();
    let administrator = match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| NodeJoinGrantIssuanceError::Unavailable)?
            .authenticate(&headers, now)
    })
    .await
    {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return service_error(&state, error, request_id),
        Err(_) => return failed(&state, request_id),
    };
    if !has_json_content_type(request.headers()) {
        return public_error(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "node join-grant issuance requires application/json",
            request_id,
            Vec::new(),
        );
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_CREATE_NODE_JOIN_GRANT_BYTES).await else {
        return public_error(
            &state,
            StatusCode::PAYLOAD_TOO_LARGE,
            ApiErrorCode::InvalidRequest,
            "node join-grant body exceeds its bound",
            request_id,
            Vec::new(),
        );
    };
    let decoded = match decode_create_node_join_grant_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| NodeJoinGrantIssuanceError::Unavailable)?
            .issue(administrator, decoded)
    })
    .await
    {
        Ok(Ok(response)) => match encode_create_node_join_grant_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => failed(&state, request_id),
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
        ApiErrorCode::InvalidRequest,
        "node join-grant request is invalid",
        request_id,
        boundary_issues(error),
    )
}

fn service_error<C>(
    state: &ApiState<C>,
    error: NodeJoinGrantIssuanceError,
    request_id: String,
) -> Response<Body> {
    let (status, code, message) = match error {
        NodeJoinGrantIssuanceError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "node join-grant policy is invalid",
        ),
        NodeJoinGrantIssuanceError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        NodeJoinGrantIssuanceError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        NodeJoinGrantIssuanceError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "node join-grant operation conflicts with committed state",
        ),
        NodeJoinGrantIssuanceError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "node join-grant authority is temporarily unavailable",
        ),
        NodeJoinGrantIssuanceError::Failed => return failed(state, request_id),
    };
    public_error(state, status, code, message, request_id, Vec::new())
}

fn public_error<C>(
    state: &ApiState<C>,
    status: StatusCode,
    code: ApiErrorCode,
    message: &str,
    request_id: String,
    issues: Vec<meshspan_api_contract::ApiErrorIssue>,
) -> Response<Body> {
    error_response(
        status,
        code,
        message,
        request_id,
        None,
        issues,
        state.schema_digest.clone(),
    )
}

fn failed<C>(state: &ApiState<C>, request_id: String) -> Response<Body> {
    internal_error_response(
        request_id,
        None,
        state.schema_digest.clone(),
        "node join-grant issuance failed closed",
    )
}

/// Node join-grant API construction failure.
#[derive(Debug, Error)]
pub enum NodeJoinGrantIssuanceApiError {
    /// Rust-authored `OpenAPI` generation failed.
    #[error("node join-grant API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// Generated schema digest was not a valid header value.
    #[error("node join-grant API schema header is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
