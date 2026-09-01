// SPDX-License-Identifier: GPL-2.0-only

//! Bounded authenticated HTTP boundary for durable-operation polling.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{
    ApiErrorCode, OperationId, encode_operation_status_response, generate_openapi,
};
use thiserror::Error;

use crate::api_http::{
    current_time, error_response, internal_error_response, json_response, request_identifier,
};
use crate::{OperationStatusController, OperationStatusError};

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

/// Builds the rolling authenticated operation-status route.
pub fn operation_status_api_router<C>(controller: C) -> Result<Router, OperationStatusApiError>
where
    C: OperationStatusController,
{
    let document = generate_openapi()?;
    Ok(Router::new()
        .route(
            "/api/latest/operations/{operation_id}",
            get(get_operation::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn get_operation<C>(
    Path(raw_operation_id): Path<String>,
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: OperationStatusController,
{
    let request_id = request_identifier();
    let Some(now) = current_time() else {
        return failed(&state, request_id);
    };
    let headers = request.headers().clone();
    let controller = Arc::clone(&state.controller);
    let authentication = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| OperationStatusError::Unavailable)?
            .authenticate(&headers, now)
    })
    .await;
    let viewer = match authentication {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return service_error(&state, error, request_id),
        Err(_) => return failed(&state, request_id),
    };
    let Some(operation_id) = OperationId::parse(&raw_operation_id) else {
        return service_error(&state, OperationStatusError::InvalidInput, request_id);
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| OperationStatusError::Unavailable)?
            .get_operation_status(viewer, &operation_id)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_operation_status_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => failed(&state, request_id),
    }
}

fn service_error<C>(
    state: &ApiState<C>,
    error: OperationStatusError,
    request_id: String,
) -> Response<Body> {
    let (status, code, message) = match error {
        OperationStatusError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "operation identifier is invalid",
        ),
        OperationStatusError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        OperationStatusError::NotFound => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::NotFound,
            "operation was not found",
        ),
        OperationStatusError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "operation authority is temporarily unavailable",
        ),
        OperationStatusError::Failed => return failed(state, request_id),
    };
    error_response(
        status,
        code,
        message,
        request_id,
        None,
        Vec::new(),
        state.schema_digest.clone(),
    )
}

fn failed<C>(state: &ApiState<C>, request_id: String) -> Response<Body> {
    internal_error_response(
        request_id,
        None,
        state.schema_digest.clone(),
        "operation status failed closed",
    )
}

/// Router-construction failure.
#[derive(Debug, Error)]
pub enum OperationStatusApiError {
    /// The authoritative public contract could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
