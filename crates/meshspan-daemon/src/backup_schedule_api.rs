// SPDX-License-Identifier: GPL-2.0-only

//! Bounded authenticated HTTP access to automatic metadata-backup policy.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Response, StatusCode},
    routing::get,
};
use meshspan_api_contract::{
    ApiErrorCode, MAX_CONFIGURE_BACKUP_SCHEDULE_BYTES, decode_configure_backup_schedule_request,
    encode_backup_schedule_response, encode_configure_backup_schedule_response, generate_openapi,
};
use thiserror::Error;

use crate::api_http::{
    current_time, error_response, has_json_content_type, internal_error_response, json_response,
    request_identifier,
};
use crate::backup_schedule_administration::{BackupScheduleController, BackupScheduleError};

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

/// Builds current-policy reads and exact-retry policy replacement.
///
/// # Errors
/// Rejects invalid generated contracts or schema-digest headers.
pub fn backup_schedule_api_router<C: BackupScheduleController>(
    controller: C,
) -> Result<Router, BackupScheduleApiError> {
    let document = generate_openapi()?;
    Ok(Router::new()
        .route(
            "/api/latest/admin/backups/schedule",
            get(read::<C>).put(configure::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn read<C: BackupScheduleController>(
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body> {
    let controller = Arc::clone(&state.controller);
    let headers = request.headers().clone();
    let result = tokio::task::spawn_blocking(move || {
        let now = current_time().ok_or(BackupScheduleError::Unavailable)?;
        let response = controller
            .lock()
            .map_err(|_| BackupScheduleError::Failed)?
            .read(&headers, now)?;
        encode_backup_schedule_response(&response).map_err(|_| BackupScheduleError::Failed)
    })
    .await;
    finish(&state, result)
}

async fn configure<C: BackupScheduleController>(
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body> {
    let headers = request.headers().clone();
    let controller = Arc::clone(&state.controller);
    let authentication_headers = headers.clone();
    let authenticated = tokio::task::spawn_blocking(move || {
        let now = current_time().ok_or(BackupScheduleError::Unavailable)?;
        controller
            .lock()
            .map_err(|_| BackupScheduleError::Failed)?
            .authenticate(&authentication_headers, now)
    })
    .await;
    match authenticated {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return service_error(&state, error),
        Err(_) => return service_error(&state, BackupScheduleError::Failed),
    }
    if !has_json_content_type(&headers) {
        return invalid_body(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "backup policy requires application/json",
        );
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_CONFIGURE_BACKUP_SCHEDULE_BYTES).await else {
        return invalid_body(
            &state,
            StatusCode::PAYLOAD_TOO_LARGE,
            "backup policy body exceeds its bound",
        );
    };
    let Ok(decoded) = decode_configure_backup_schedule_request(&body) else {
        return invalid_body(
            &state,
            StatusCode::BAD_REQUEST,
            "backup policy body is invalid",
        );
    };
    let controller = Arc::clone(&state.controller);
    let result = tokio::task::spawn_blocking(move || {
        // Time and credentials are checked again after the potentially slow body transfer.
        let now = current_time().ok_or(BackupScheduleError::Unavailable)?;
        let response = controller
            .lock()
            .map_err(|_| BackupScheduleError::Failed)?
            .configure(&headers, now, decoded)?;
        encode_configure_backup_schedule_response(&response)
            .map_err(|_| BackupScheduleError::Failed)
    })
    .await;
    finish(&state, result)
}

fn finish<C>(
    state: &ApiState<C>,
    result: Result<Result<Vec<u8>, BackupScheduleError>, tokio::task::JoinError>,
) -> Response<Body> {
    match result {
        Ok(Ok(body)) => json_response(StatusCode::OK, body, state.schema_digest.clone()),
        Ok(Err(error)) => service_error(state, error),
        Err(_) => service_error(state, BackupScheduleError::Failed),
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

fn service_error<C>(state: &ApiState<C>, error: BackupScheduleError) -> Response<Body> {
    let (status, code, message) = match error {
        BackupScheduleError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "backup policy is invalid",
        ),
        BackupScheduleError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        BackupScheduleError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        BackupScheduleError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "backup policy conflicts with committed state",
        ),
        BackupScheduleError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "backup policy authority is temporarily unavailable",
        ),
        BackupScheduleError::Failed => {
            return internal_error_response(
                request_identifier(),
                None,
                state.schema_digest.clone(),
                "backup policy failed closed",
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

/// Failure to construct the public policy routes.
#[derive(Debug, Error)]
pub enum BackupScheduleApiError {
    /// Rust-authored contract generation failed.
    #[error("backup policy contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// Schema digest could not be encoded in a header.
    #[error("backup policy schema header is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
