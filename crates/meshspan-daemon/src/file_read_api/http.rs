// SPDX-License-Identifier: GPL-2.0-only

//! Native bounded-file HTTP execution and stable public error mapping.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderName, HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{ApiErrorCode, generate_openapi};
use thiserror::Error;

use super::codec::parse_file_read_query;
use super::service::{FileReadController, FileReadError, FileReadResult};
use crate::FileApiAuthenticationError;
use crate::api_http::{
    API_SCHEMA_HEADER, API_VERSION_HEADER, boundary_issues, current_time, error_response,
    internal_error_response, request_identifier,
};
use crate::create_mesh_setup::format_uuid;

const FILE_VERSION_HEADER: HeaderName = HeaderName::from_static("meshspan-file-version");
const READ_OFFSET_HEADER: HeaderName = HeaderName::from_static("meshspan-read-offset");

struct FileReadApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for FileReadApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the rolling native bounded-file route.
///
/// # Errors
///
/// Fails if the Rust-authored contract or schema-digest header cannot be generated.
pub fn file_read_api_router<C>(controller: C) -> Result<Router, FileReadApiError>
where
    C: FileReadController,
{
    let document = generate_openapi()?;
    let state = FileReadApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/volumes/{volume_id}/file-content",
            get(read_file::<C>),
        )
        .with_state(state))
}

async fn read_file<C>(
    State(state): State<FileReadApiState<C>>,
    Path(volume_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: FileReadController,
{
    let request_id = request_identifier();
    let Ok(query) = parse_file_read_query(request.uri().query()) else {
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
            .map_err(|_| FileReadExecutionError::Unavailable)?
            .read_file(&headers, &volume_id, query, now)
            .map_err(FileReadExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(result)) => file_response(result, state.schema_digest.clone())
            .unwrap_or_else(|_| failed_closed(request_id, state.schema_digest)),
        Ok(Err(FileReadExecutionError::Service(error))) => {
            service_error_response(error, request_id, state.schema_digest)
        }
        Ok(Err(FileReadExecutionError::Unavailable)) | Err(_) => {
            failed_closed(request_id, state.schema_digest)
        }
    }
}

fn file_response(
    result: FileReadResult,
    schema_digest: HeaderValue,
) -> Result<Response<Body>, axum::http::header::InvalidHeaderValue> {
    let version = HeaderValue::from_str(&format_uuid(result.file_version_id.as_bytes()))?;
    let offset = HeaderValue::from_str(&result.offset.to_string())?;
    let mut response = Response::new(Body::from(result.bytes.into_vec()));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    headers.insert(API_VERSION_HEADER, HeaderValue::from_static("latest"));
    headers.insert(API_SCHEMA_HEADER, schema_digest);
    headers.insert(FILE_VERSION_HEADER, version);
    headers.insert(READ_OFFSET_HEADER, offset);
    Ok(response)
}

fn service_error_response(
    error: FileReadError,
    request_id: String,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        FileReadError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "file read query is invalid",
        ),
        FileReadError::Authentication(FileApiAuthenticationError::Rejected)
        | FileReadError::AccessDenied => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication or access was rejected",
        ),
        FileReadError::NotFound => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::NotFound,
            "volume or regular file was not found",
        ),
        FileReadError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::StateConflict,
            "a live file handle currently prevents this read",
        ),
        FileReadError::Unavailable
        | FileReadError::Authentication(FileApiAuthenticationError::AuthorityUnavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "file authority or content is temporarily unavailable",
        ),
        FileReadError::Failed
        | FileReadError::Authentication(
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
        "file read query does not satisfy the public contract",
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
        "native file-content API failed closed",
    )
}

enum FileReadExecutionError {
    Service(FileReadError),
    Unavailable,
}

/// Bounded-file router construction failure.
#[derive(Debug, Error)]
pub enum FileReadApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
