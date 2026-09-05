// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, manager-only, non-destructive restore checks.

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode, Uri},
    routing::get,
};
use meshspan_api_contract::{
    ApiErrorCode, BackupExportPath, encode_backup_readiness_response, generate_openapi,
    validate_backup_export_path,
};
use meshspan_domain::{BackupId, DurationMicros, OperationId};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::{
    sync::{Semaphore, oneshot},
    task::JoinSet,
};

use crate::api_http::{current_time, error_response, json_response, request_identifier};
use crate::backup_readiness_service::{
    BackupReadinessRequest, BackupReadinessService, ReadinessBudget,
};
use crate::{BackupExportApiError, BackupExportController, BackupExportError};

struct ReadinessApi<C> {
    service: Arc<BackupReadinessService<C>>,
    admission: Arc<Semaphore>,
    // Own cancelled clients' jobs too. Completed results are observed before new admission;
    // at most the worker capacity remains retained while idle. Drop aborts queued work.
    jobs: Mutex<JoinSet<()>>,
    timeout: Duration,
    digest: HeaderValue,
}

pub(crate) fn router<C: BackupExportController>(
    service: BackupReadinessService<C>,
    timeout: Duration,
) -> Result<Router, BackupExportApiError> {
    if timeout.as_micros() == 0
        || timeout.as_micros() > i64::MAX as u128
        || Instant::now().checked_add(timeout).is_none()
    {
        return Err(BackupExportApiError::Limits);
    }
    Ok(Router::new()
        .route(
            "/api/latest/admin/backups/{backup_id}/restore-readiness",
            get(check::<C>),
        )
        .with_state(Arc::new(ReadinessApi {
            service: Arc::new(service),
            // Restore uses three disk-backed files. One active check avoids multiplying that
            // demand; ordinary exports, file traffic and other administration stay independent.
            admission: Arc::new(Semaphore::new(1)),
            jobs: Mutex::new(JoinSet::new()),
            timeout,
            digest: HeaderValue::from_str(generate_openapi()?.digest())?,
        })))
}

async fn check<C: BackupExportController>(
    State(state): State<Arc<ReadinessApi<C>>>,
    request: Request,
) -> Response<Body> {
    let Ok(permit) = Arc::clone(&state.admission).try_acquire_owned() else {
        return failure(BackupExportError::Unavailable, state.digest.clone());
    };
    let Some(deadline) = Instant::now().checked_add(state.timeout) else {
        return failure(BackupExportError::Failed, state.digest.clone());
    };
    let budget = ReadinessBudget {
        cancelled: Arc::new(AtomicBool::new(false)),
        deadline,
    };
    let _cancellation = CancelCheck(Arc::clone(&budget.cancelled));
    let service = Arc::clone(&state.service);
    let headers = request.headers().clone();
    let uri = request.uri().clone();
    let timeout = state.timeout;
    let (sender, receiver) = oneshot::channel();
    {
        let Ok(mut jobs) = state.jobs.lock() else {
            return failure(BackupExportError::Failed, state.digest.clone());
        };
        while let Some(completed) = jobs.try_join_next() {
            if completed.is_err() {
                return failure(BackupExportError::Failed, state.digest.clone());
            }
        }
        jobs.spawn_blocking(move || {
            let _permit = permit;
            let result = execute(&service, headers, &uri, timeout, &budget);
            // A cancelled request deliberately has no recipient. Its workspace has still
            // been cleaned before this job terminates and releases admission.
            let _cancelled_client = sender.send(result);
        });
    }
    match receiver.await {
        Ok(Ok(bytes)) => json_response(StatusCode::OK, bytes, state.digest.clone()),
        Ok(Err(error)) => failure(error, state.digest.clone()),
        Err(_) => failure(BackupExportError::Failed, state.digest.clone()),
    }
}

fn execute<C: BackupExportController>(
    service: &BackupReadinessService<C>,
    headers: HeaderMap,
    uri: &Uri,
    timeout: Duration,
    budget: &ReadinessBudget,
) -> Result<Vec<u8>, BackupExportError> {
    budget.check()?;
    let now = current_time().ok_or(BackupExportError::Unavailable)?;
    service.export.authenticate(&headers, now)?;
    if uri.query().is_some()
        || headers.contains_key("transfer-encoding")
        || headers
            .get("content-length")
            .is_some_and(|value| value != "0")
    {
        return Err(BackupExportError::InvalidInput);
    }
    let selected = uri
        .path()
        .strip_prefix("/api/latest/admin/backups/")
        .and_then(|value| value.strip_suffix("/restore-readiness"))
        .ok_or(BackupExportError::InvalidInput)?;
    validate_backup_export_path(&BackupExportPath {
        backup_id: selected.to_owned(),
    })
    .map_err(|_| BackupExportError::InvalidInput)?;
    let backup_id = BackupId::from_bytes(
        crate::create_mesh_setup::parse_uuid(selected)
            .map_err(|_| BackupExportError::InvalidInput)?,
    )
    .map_err(|_| BackupExportError::InvalidInput)?;
    let operation_id = OperationId::from_bytes(
        crate::create_mesh_setup::parse_uuid(&request_identifier())
            .map_err(|_| BackupExportError::Failed)?,
    )
    .map_err(|_| BackupExportError::Failed)?;
    let deadline = now
        .checked_add(DurationMicros::new(
            u64::try_from(timeout.as_micros()).map_err(|_| BackupExportError::Failed)?,
        ))
        .ok_or(BackupExportError::Failed)?;
    let response = service.check(&BackupReadinessRequest {
        headers,
        backup_id,
        operation_id,
        deadline,
        budget: budget.clone(),
    })?;
    budget.check()?;
    encode_backup_readiness_response(&response).map_err(|_| BackupExportError::Failed)
}

struct CancelCheck(Arc<AtomicBool>);
impl Drop for CancelCheck {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn failure(error: BackupExportError, digest: HeaderValue) -> Response<Body> {
    let (status, code, message) = match error {
        BackupExportError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "Restore check input is invalid",
        ),
        BackupExportError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "Authentication is required",
        ),
        BackupExportError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "System-manager authority is required",
        ),
        BackupExportError::NotReady => (
            StatusCode::CONFLICT,
            ApiErrorCode::StateConflict,
            "This gateway could not verify an isolated restore of the selected backup",
        ),
        BackupExportError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "Restore check capacity, authority or a required provider is unavailable",
        ),
        BackupExportError::Failed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "Restore check did not complete safely",
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
