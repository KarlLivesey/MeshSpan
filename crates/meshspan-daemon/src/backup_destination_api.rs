// SPDX-License-Identifier: GPL-2.0-only

//! Bounded authenticated HTTP access to metadata-backup destinations.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Response, StatusCode},
    routing::get,
};
use meshspan_api_contract::{
    ApiErrorCode, MAX_CONFIGURE_BACKUP_DESTINATION_BYTES,
    decode_configure_backup_destination_request, encode_configure_backup_destination_response,
    encode_list_backup_destinations_response, generate_openapi,
};
use thiserror::Error;

use crate::api_http::{
    current_time, error_response, has_json_content_type, internal_error_response, json_response,
    request_identifier,
};
use crate::backup_destination_administration::{
    BackupDestinationController, BackupDestinationError,
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

/// Builds current destination inventory and exact-retry configuration.
///
/// # Errors
/// Rejects invalid generated contracts or schema-digest headers.
pub fn backup_destination_api_router<C: BackupDestinationController>(
    controller: C,
) -> Result<Router, BackupDestinationApiError> {
    let document = generate_openapi()?;
    Ok(Router::new()
        .route(
            "/api/latest/admin/backups/destinations",
            get(read::<C>).put(configure::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn read<C: BackupDestinationController>(
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body> {
    let controller = Arc::clone(&state.controller);
    let headers = request.headers().clone();
    let raw_query = request.uri().query().map(str::to_owned);
    let result = tokio::task::spawn_blocking(move || {
        let controller = controller
            .lock()
            .map_err(|_| BackupDestinationError::Failed)?;
        let now = current_time().ok_or(BackupDestinationError::Unavailable)?;
        controller.authenticate(&headers, false, now)?;
        let query =
            crate::backup_destination_administration::inventory::parse_query(raw_query.as_deref())?;
        let response = controller.list(&headers, now, query)?;
        encode_list_backup_destinations_response(&response)
            .map_err(|_| BackupDestinationError::Failed)
    })
    .await;
    finish(&state, result)
}

async fn configure<C: BackupDestinationController>(
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body> {
    let headers = request.headers().clone();
    let controller = Arc::clone(&state.controller);
    let authentication_headers = headers.clone();
    let authenticated = tokio::task::spawn_blocking(move || {
        let controller = controller
            .lock()
            .map_err(|_| BackupDestinationError::Failed)?;
        let now = current_time().ok_or(BackupDestinationError::Unavailable)?;
        controller.authenticate(&authentication_headers, true, now)
    })
    .await;
    match authenticated {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return service_error(&state, error),
        Err(_) => return service_error(&state, BackupDestinationError::Failed),
    }
    if !has_json_content_type(&headers) {
        return invalid_body(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "backup destination requires application/json",
        );
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_CONFIGURE_BACKUP_DESTINATION_BYTES).await
    else {
        return invalid_body(
            &state,
            StatusCode::PAYLOAD_TOO_LARGE,
            "backup destination body exceeds its bound",
        );
    };
    let Ok(decoded) = decode_configure_backup_destination_request(&body) else {
        return invalid_body(
            &state,
            StatusCode::BAD_REQUEST,
            "backup destination body is invalid",
        );
    };
    let controller = Arc::clone(&state.controller);
    let result = tokio::task::spawn_blocking(move || {
        // Time and credentials are checked again after the potentially slow body transfer.
        let mut controller = controller
            .lock()
            .map_err(|_| BackupDestinationError::Failed)?;
        let now = current_time().ok_or(BackupDestinationError::Unavailable)?;
        let response = controller.configure(&headers, now, decoded)?;
        encode_configure_backup_destination_response(&response)
            .map_err(|_| BackupDestinationError::Failed)
    })
    .await;
    finish(&state, result)
}

fn finish<C>(
    state: &ApiState<C>,
    result: Result<Result<Vec<u8>, BackupDestinationError>, tokio::task::JoinError>,
) -> Response<Body> {
    match result {
        Ok(Ok(body)) => json_response(StatusCode::OK, body, state.schema_digest.clone()),
        Ok(Err(error)) => service_error(state, error),
        Err(_) => service_error(state, BackupDestinationError::Failed),
    }
}

fn invalid_body<C>(state: &ApiState<C>, status: StatusCode, message: &str) -> Response<Body> {
    error_response(
        status,
        ApiErrorCode::InvalidRequest,
        message,
        request_identifier(),
        None,
        Vec::new(),
        state.schema_digest.clone(),
    )
}

fn service_error<C>(state: &ApiState<C>, error: BackupDestinationError) -> Response<Body> {
    let (status, code, message) = match error {
        BackupDestinationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "backup destination is invalid",
        ),
        BackupDestinationError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        BackupDestinationError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        BackupDestinationError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "backup destination conflicts with committed state",
        ),
        BackupDestinationError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "backup destination authority is temporarily unavailable",
        ),
        BackupDestinationError::Failed => {
            return internal_error_response(
                request_identifier(),
                None,
                state.schema_digest.clone(),
                "backup destination failed closed",
            );
        }
    };
    error_response(
        status,
        code,
        message,
        request_identifier(),
        None,
        Vec::new(),
        state.schema_digest.clone(),
    )
}

/// Failure to construct the public destination routes.
#[derive(Debug, Error)]
pub enum BackupDestinationApiError {
    /// Rust-authored contract generation failed.
    #[error("backup destination contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// Schema digest could not be encoded in a header.
    #[error("backup destination schema header is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
