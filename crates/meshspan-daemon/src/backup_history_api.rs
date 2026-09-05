// SPDX-License-Identifier: GPL-2.0-only

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Response, StatusCode},
    routing::get,
};
use meshspan_api_contract::{ApiErrorCode, encode_list_backup_runs_response, generate_openapi};
use std::sync::{Arc, Mutex};

use crate::api_http::{current_time, error_response, json_response, request_identifier};
use crate::{BackupHistoryController, BackupScheduleApiError, BackupScheduleError};

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

/// Builds a current-authority, bounded backup history endpoint.
///
/// # Errors
/// Rejects invalid generated contracts or schema-digest headers.
pub fn backup_history_api_router<C: BackupHistoryController>(
    controller: C,
) -> Result<Router, BackupScheduleApiError> {
    let document = generate_openapi()?;
    Ok(Router::new()
        .route("/api/latest/admin/backups/runs", get(read::<C>))
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn read<C: BackupHistoryController>(
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body> {
    let controller = Arc::clone(&state.controller);
    let headers = request.headers().clone();
    let query = request.uri().query().map(str::to_owned);
    let result = tokio::task::spawn_blocking(move || {
        let controller = controller.lock().map_err(|_| BackupScheduleError::Failed)?;
        let now = current_time().ok_or(BackupScheduleError::Unavailable)?;
        controller.authenticate(&headers, now)?;
        let query = crate::backup_history::inventory::parse_query(query.as_deref())?;
        let response = controller.list(&headers, now, &query)?;
        encode_list_backup_runs_response(&response).map_err(|_| BackupScheduleError::Failed)
    })
    .await;
    match result {
        Ok(Ok(bytes)) => json_response(StatusCode::OK, bytes, state.schema_digest),
        Ok(Err(error)) => failure(error, state.schema_digest),
        Err(_) => failure(BackupScheduleError::Failed, state.schema_digest),
    }
}

fn failure(error: BackupScheduleError, digest: HeaderValue) -> Response<Body> {
    let (status, code, message) = match error {
        BackupScheduleError::InvalidInput | BackupScheduleError::Conflict => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "backup history query is invalid",
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
        BackupScheduleError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "backup history authority is unavailable",
        ),
        BackupScheduleError::Failed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "backup history failed closed",
        ),
    };
    error_response(
        status,
        code,
        message,
        request_identifier(),
        None,
        Vec::new(),
        digest,
    )
}
