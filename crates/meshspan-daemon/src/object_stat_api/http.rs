// SPDX-License-Identifier: GPL-2.0-only

//! Native object-metadata HTTP execution and stable public error mapping.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{ApiErrorCode, encode_get_object_response, generate_openapi};
use thiserror::Error;

use super::codec::parse_object_query;
use super::service::{ObjectStatController, ObjectStatError};
use crate::FileApiAuthenticationError;
use crate::api_http::{
    boundary_issues, current_time, error_response, internal_error_response, json_response,
    request_identifier,
};

struct ObjectStatApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for ObjectStatApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the rolling native object-metadata route.
///
/// # Errors
///
/// Fails if the Rust-authored contract or schema-digest header cannot be generated.
pub fn object_stat_api_router<C>(controller: C) -> Result<Router, ObjectStatApiError>
where
    C: ObjectStatController,
{
    let document = generate_openapi()?;
    let state = ObjectStatApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/volumes/{volume_id}/objects",
            get(get_object::<C>),
        )
        .with_state(state))
}

async fn get_object<C>(
    State(state): State<ObjectStatApiState<C>>,
    Path(volume_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: ObjectStatController,
{
    let request_id = request_identifier();
    let Ok(query) = parse_object_query(request.uri().query()) else {
        return invalid_request(request_id, state.schema_digest);
    };
    let Some(now) = current_time() else {
        return failed_closed(request_id, state.schema_digest);
    };
    let headers = request.headers().clone();
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| ObjectStatExecutionError::Unavailable)?
            .get_object(&headers, &volume_id, query, now)
            .map_err(ObjectStatExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_get_object_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed_closed(request_id, state.schema_digest),
        },
        Ok(Err(ObjectStatExecutionError::Service(error))) => {
            service_error_response(error, request_id, state.schema_digest)
        }
        Ok(Err(ObjectStatExecutionError::Unavailable)) | Err(_) => {
            failed_closed(request_id, state.schema_digest)
        }
    }
}

fn service_error_response(
    error: ObjectStatError,
    request_id: String,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        ObjectStatError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "object query is invalid",
        ),
        ObjectStatError::Authentication(FileApiAuthenticationError::Rejected)
        | ObjectStatError::AccessDenied => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication or access was rejected",
        ),
        ObjectStatError::NotFound => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::NotFound,
            "volume or object was not found",
        ),
        ObjectStatError::Unavailable
        | ObjectStatError::Authentication(FileApiAuthenticationError::AuthorityUnavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "file authority is temporarily unavailable",
        ),
        ObjectStatError::Failed
        | ObjectStatError::Authentication(
            FileApiAuthenticationError::InvalidGateway
            | FileApiAuthenticationError::AuthorityFailed,
        ) => return failed_closed(request_id, schema_digest),
    };
    error_response(
        status,
        code,
        message,
        request_id,
        None,
        Vec::new(),
        schema_digest,
    )
}

fn invalid_request(request_id: String, schema_digest: HeaderValue) -> Response<Body> {
    error_response(
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
        "object query does not satisfy the public contract",
        request_id,
        None,
        boundary_issues(meshspan_api_contract::BoundaryError::DecodeMismatch),
        schema_digest,
    )
}

fn failed_closed(request_id: String, schema_digest: HeaderValue) -> Response<Body> {
    internal_error_response(
        request_id,
        None,
        schema_digest,
        "native object metadata API failed closed",
    )
}

enum ObjectStatExecutionError {
    Service(ObjectStatError),
    Unavailable,
}

/// Object-metadata router construction failure.
#[derive(Debug, Error)]
pub enum ObjectStatApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
