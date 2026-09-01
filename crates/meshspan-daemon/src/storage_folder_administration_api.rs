// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTP boundary for manager-only local storage-folder administration.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, ListStorageFoldersQuery, MAX_REGISTER_STORAGE_FOLDER_BYTES,
    StorageFolderCursor, decode_register_storage_folder_request,
    encode_list_storage_folders_response, encode_register_storage_folder_response,
    generate_openapi,
};
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    json_response, request_identifier,
};
use crate::native_query::has_valid_percent_encoding;
use crate::{
    BrowserRequestProtection, StorageFolderAdministrationController,
    StorageFolderAdministrationError,
};

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

/// Builds the rolling manager-only storage-folder inventory and registration route.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn storage_folder_administration_api_router<C>(
    controller: C,
) -> Result<Router, StorageFolderAdministrationApiError>
where
    C: StorageFolderAdministrationController,
{
    let document = generate_openapi()?;
    Ok(Router::new()
        .route(
            "/api/latest/admin/storage-folders",
            get(list::<C>).post(register::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn list<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: StorageFolderAdministrationController,
{
    let request_id = request_identifier();
    let Some(now) = current_time() else {
        return failed(&state, request_id);
    };
    let controller = Arc::clone(&state.controller);
    let headers = request.headers().clone();
    let authentication = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| StorageFolderAdministrationError::Unavailable)?
            .authenticate(&headers, BrowserRequestProtection::Read, now)
    })
    .await;
    let administrator = match authentication {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return service_error(&state, error, request_id),
        Err(_) => return failed(&state, request_id),
    };
    let Ok(query) = parse_query(request.uri().query()) else {
        return service_error(
            &state,
            StorageFolderAdministrationError::InvalidInput,
            request_id,
        );
    };
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| StorageFolderAdministrationError::Unavailable)?
            .list_storage_folders(administrator, query)
    })
    .await
    {
        Ok(Ok(response)) => match encode_list_storage_folders_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => failed(&state, request_id),
    }
}

async fn register<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: StorageFolderAdministrationController,
{
    let request_id = request_identifier();
    let Some(now) = current_time() else {
        return failed(&state, request_id);
    };
    let controller = Arc::clone(&state.controller);
    let headers = request.headers().clone();
    let authentication = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| StorageFolderAdministrationError::Unavailable)?
            .authenticate(&headers, BrowserRequestProtection::Mutation, now)
    })
    .await;
    let administrator = match authentication {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return service_error(&state, error, request_id),
        Err(_) => return failed(&state, request_id),
    };
    if !has_json_content_type(request.headers()) {
        return public_error(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "storage-folder registration requires application/json",
            request_id,
            Vec::new(),
        );
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_REGISTER_STORAGE_FOLDER_BYTES).await else {
        return public_error(
            &state,
            StatusCode::PAYLOAD_TOO_LARGE,
            ApiErrorCode::InvalidRequest,
            "storage-folder registration body exceeds its bound",
            request_id,
            Vec::new(),
        );
    };
    let decoded = match decode_register_storage_folder_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| StorageFolderAdministrationError::Unavailable)?
            .register_storage_folder(administrator, decoded)
    })
    .await
    {
        Ok(Ok(response)) => match encode_register_storage_folder_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => failed(&state, request_id),
    }
}

fn parse_query(raw_query: Option<&str>) -> Result<ListStorageFoldersQuery, ()> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(ListStorageFoldersQuery::default());
    };
    if raw_query.len() > 4_096 || !has_valid_percent_encoding(raw_query.as_bytes()) {
        return Err(());
    }
    let mut query = ListStorageFoldersQuery::default();
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor =
                    Some(StorageFolderCursor::from_encoded(value.into_owned()).ok_or(())?);
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
        "storage-folder registration body is invalid",
        request_id,
        boundary_issues(error),
    )
}

fn service_error<C>(
    state: &ApiState<C>,
    error: StorageFolderAdministrationError,
    request_id: String,
) -> Response<Body> {
    let (status, code, message) = match error {
        StorageFolderAdministrationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "storage-folder administration input is invalid",
        ),
        StorageFolderAdministrationError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        StorageFolderAdministrationError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        StorageFolderAdministrationError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "storage-folder registration conflicts with durable state",
        ),
        StorageFolderAdministrationError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "storage-folder administration is temporarily unavailable",
        ),
        StorageFolderAdministrationError::Failed => return failed(state, request_id),
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
        "storage-folder administration failed closed",
    )
}

/// Router-construction failure.
#[derive(Debug, Error)]
pub enum StorageFolderAdministrationApiError {
    /// The authoritative public contract could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
