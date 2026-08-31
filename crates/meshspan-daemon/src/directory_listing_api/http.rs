// SPDX-License-Identifier: GPL-2.0-only

//! Native file-API HTTP execution and stable public error mapping.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{ApiErrorCode, encode_list_directory_response, generate_openapi};
use thiserror::Error;

use super::codec::parse_directory_query;
use super::service::{DirectoryListingController, DirectoryListingError};
use crate::FileApiAuthenticationError;
use crate::api_http::{
    boundary_issues, current_time, error_response, internal_error_response, json_response,
    request_identifier,
};

struct DirectoryListingApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for DirectoryListingApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the rolling native directory-listing route.
///
/// # Errors
///
/// Fails if the Rust-authored contract or schema-digest header cannot be generated.
pub fn directory_listing_api_router<C>(controller: C) -> Result<Router, DirectoryListingApiError>
where
    C: DirectoryListingController,
{
    let document = generate_openapi()?;
    let state = DirectoryListingApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/volumes/{volume_id}/directory-entries",
            get(get_directory::<C>),
        )
        .with_state(state))
}

async fn get_directory<C>(
    State(state): State<DirectoryListingApiState<C>>,
    Path(volume_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: DirectoryListingController,
{
    let request_id = request_identifier();
    let Ok(query) = parse_directory_query(request.uri().query()) else {
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
            .map_err(|_| DirectoryListingExecutionError::Unavailable)?
            .list_directory(&headers, &volume_id, &query, now)
            .map_err(DirectoryListingExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_list_directory_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed_closed(request_id, state.schema_digest),
        },
        Ok(Err(DirectoryListingExecutionError::Service(error))) => {
            service_error_response(error, request_id, state.schema_digest)
        }
        Ok(Err(DirectoryListingExecutionError::Unavailable)) | Err(_) => {
            failed_closed(request_id, state.schema_digest)
        }
    }
}

fn service_error_response(
    error: DirectoryListingError,
    request_id: String,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        DirectoryListingError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "directory query is invalid",
        ),
        DirectoryListingError::Authentication(FileApiAuthenticationError::Rejected)
        | DirectoryListingError::AccessDenied => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication or access was rejected",
        ),
        DirectoryListingError::NotFound => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::NotFound,
            "volume or directory was not found",
        ),
        DirectoryListingError::StaleCursor => (
            StatusCode::CONFLICT,
            ApiErrorCode::StateConflict,
            "directory continuation is stale",
        ),
        DirectoryListingError::Unavailable
        | DirectoryListingError::Authentication(FileApiAuthenticationError::AuthorityUnavailable) => {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                ApiErrorCode::Busy,
                "file authority is temporarily unavailable",
            )
        }
        DirectoryListingError::Failed
        | DirectoryListingError::Authentication(
            FileApiAuthenticationError::InvalidGateway
            | FileApiAuthenticationError::AuthorityFailed,
        ) => {
            return failed_closed(request_id, schema_digest);
        }
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
        "directory query does not satisfy the public contract",
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
        "native file API failed closed",
    )
}

enum DirectoryListingExecutionError {
    Service(DirectoryListingError),
    Unavailable,
}

/// Directory-listing router construction failure.
#[derive(Debug, Error)]
pub enum DirectoryListingApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
