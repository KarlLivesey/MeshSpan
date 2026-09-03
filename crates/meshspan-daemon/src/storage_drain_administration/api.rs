// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTP boundary for manager-only storage-drain administration.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, ListStorageDrainsQuery, MAX_BEGIN_STORAGE_DRAIN_BYTES,
    StorageDrainCursor, decode_begin_storage_drain_request, encode_begin_storage_drain_response,
    encode_list_storage_drains_response, encode_storage_drain_summary, generate_openapi,
};
use thiserror::Error;

use super::{StorageDrainAdministrationController, StorageDrainAdministrationError};
use crate::BrowserRequestProtection;
use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    json_response, request_identifier,
};
use crate::native_query::has_valid_percent_encoding;

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

/// Builds the rolling manager-only storage-drain routes.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn storage_drain_administration_api_router<C>(
    controller: C,
) -> Result<Router, StorageDrainAdministrationApiError>
where
    C: StorageDrainAdministrationController,
{
    let document = generate_openapi()?;
    Ok(Router::new()
        .route(
            "/api/latest/admin/storage-drains",
            get(list::<C>).post(begin::<C>),
        )
        .route(
            "/api/latest/admin/storage-drains/{drain_id}",
            get(get_one::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn begin<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: StorageDrainAdministrationController,
{
    let request_id = request_identifier();
    let Some(now) = current_time() else {
        return failed(&state, request_id);
    };
    let administrator = match authenticate(
        &state,
        request.headers().clone(),
        BrowserRequestProtection::Mutation,
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return service_error(&state, error, request_id),
    };
    if !has_json_content_type(request.headers()) {
        return public_error(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "storage-drain admission requires application/json",
            request_id,
            Vec::new(),
        );
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_BEGIN_STORAGE_DRAIN_BYTES).await else {
        return public_error(
            &state,
            StatusCode::PAYLOAD_TOO_LARGE,
            ApiErrorCode::InvalidRequest,
            "storage-drain request body exceeds its bound",
            request_id,
            Vec::new(),
        );
    };
    let decoded = match decode_begin_storage_drain_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| StorageDrainAdministrationError::Unavailable)?
            .begin_storage_drain(administrator, decoded)
    })
    .await
    {
        Ok(Ok(response)) => match encode_begin_storage_drain_response(&response) {
            Ok(body) => json_response(StatusCode::ACCEPTED, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => failed(&state, request_id),
    }
}

async fn list<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: StorageDrainAdministrationController,
{
    let request_id = request_identifier();
    let Some(now) = current_time() else {
        return failed(&state, request_id);
    };
    let administrator = match authenticate(
        &state,
        request.headers().clone(),
        BrowserRequestProtection::Read,
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return service_error(&state, error, request_id),
    };
    let Ok(query) = parse_query(request.uri().query()) else {
        return service_error(
            &state,
            StorageDrainAdministrationError::InvalidInput,
            request_id,
        );
    };
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| StorageDrainAdministrationError::Unavailable)?
            .list_storage_drains(administrator, query)
    })
    .await
    {
        Ok(Ok(response)) => match encode_list_storage_drains_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => failed(&state, request_id),
    }
}

async fn get_one<C>(
    Path(drain_id): Path<String>,
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: StorageDrainAdministrationController,
{
    let request_id = request_identifier();
    let Some(now) = current_time() else {
        return failed(&state, request_id);
    };
    let administrator = match authenticate(
        &state,
        request.headers().clone(),
        BrowserRequestProtection::Read,
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return service_error(&state, error, request_id),
    };
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| StorageDrainAdministrationError::Unavailable)?
            .get_storage_drain(administrator, &drain_id)
    })
    .await
    {
        Ok(Ok(response)) => match encode_storage_drain_summary(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => failed(&state, request_id),
    }
}

async fn authenticate<C>(
    state: &ApiState<C>,
    headers: axum::http::HeaderMap,
    protection: BrowserRequestProtection,
    now: meshspan_domain::UnixMicros,
) -> Result<crate::IdentityAdministrator, StorageDrainAdministrationError>
where
    C: StorageDrainAdministrationController,
{
    let controller = Arc::clone(&state.controller);
    tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| StorageDrainAdministrationError::Unavailable)?
            .authenticate(&headers, protection, now)
    })
    .await
    .map_err(|_| StorageDrainAdministrationError::Failed)?
}

fn parse_query(raw_query: Option<&str>) -> Result<ListStorageDrainsQuery, ()> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(ListStorageDrainsQuery::default());
    };
    if raw_query.len() > 4_096 || !has_valid_percent_encoding(raw_query.as_bytes()) {
        return Err(());
    }
    let mut query = ListStorageDrainsQuery::default();
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor =
                    Some(StorageDrainCursor::from_encoded(value.into_owned()).ok_or(())?);
            }
            "limit" if !limit_seen => {
                limit_seen = true;
                query.limit = Some(value.parse::<u16>().map_err(|_| ())?);
            }
            _ => return Err(()),
        }
    }
    Ok(query)
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
        "storage-drain request body is invalid",
        request_id,
        boundary_issues(error),
    )
}

fn service_error<C>(
    state: &ApiState<C>,
    error: StorageDrainAdministrationError,
    request_id: String,
) -> Response<Body> {
    let (status, code, message) = match error {
        StorageDrainAdministrationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "storage-drain input is invalid",
        ),
        StorageDrainAdministrationError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        StorageDrainAdministrationError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        StorageDrainAdministrationError::NotFound => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::NotFound,
            "storage drain was not found",
        ),
        StorageDrainAdministrationError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "storage-drain request conflicts with durable state",
        ),
        StorageDrainAdministrationError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "storage-drain authority is temporarily unavailable",
        ),
        StorageDrainAdministrationError::Failed => return failed(state, request_id),
    };
    public_error(state, status, code, message, request_id, Vec::new())
}

fn public_error<C>(
    state: &ApiState<C>,
    status: StatusCode,
    code: ApiErrorCode,
    message: &'static str,
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
        "storage-drain administration failed closed",
    )
}

/// Router-construction failure.
#[derive(Debug, Error)]
pub enum StorageDrainAdministrationApiError {
    /// The Rust-authored public contract could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
