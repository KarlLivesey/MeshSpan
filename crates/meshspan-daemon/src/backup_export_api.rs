// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated native encrypted-byte downloads; no recovery secret is accepted.

use crate::api_http::{
    API_SCHEMA_HEADER, API_VERSION_HEADER, current_time, error_response, request_identifier,
};
use crate::create_mesh_setup::{format_uuid, parse_uuid};
use crate::{BackupExportController, BackupExportError, BackupExportRequest};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode},
    routing::get,
};
use meshspan_api_contract::{
    ApiErrorCode, BackupExportHeaders, BackupExportPath, generate_openapi,
    validate_backup_export_headers, validate_backup_export_path,
};
use meshspan_backup::{BackupExportEvidence, VerifiedBackupExport};
use meshspan_domain::{BackupId, DurationMicros, OperationId};
use std::{io, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

struct ApiState<C> {
    controller: Arc<C>,
    admission: Arc<Semaphore>,
    timeout: Duration,
    digest: HeaderValue,
}
impl<C> Clone for ApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            admission: Arc::clone(&self.admission),
            timeout: self.timeout,
            digest: self.digest.clone(),
        }
    }
}

/// Builds bounded export routes. Capacity covers authentication, lookup and the full stream.
///
/// # Errors
/// Rejects zero/overflowing deadlines, unsupported semaphore capacity or contract headers.
pub fn backup_export_api_router<C: BackupExportController>(
    controller: C,
    workers: NonZeroUsize,
    timeout: Duration,
) -> Result<Router, BackupExportApiError> {
    if workers.get() > Semaphore::MAX_PERMITS
        || timeout.as_micros() == 0
        || timeout.as_micros() > i64::MAX as u128
        || tokio::time::Instant::now().checked_add(timeout).is_none()
    {
        return Err(BackupExportApiError::Limits);
    }
    Ok(Router::new()
        .route(
            "/api/latest/admin/backups/{backup_id}/export",
            get(export::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(controller),
            admission: Arc::new(Semaphore::new(workers.get())),
            timeout,
            digest: HeaderValue::from_str(generate_openapi()?.digest())?,
        }))
}

async fn export<C: BackupExportController>(
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body> {
    let Ok(permit) = Arc::clone(&state.admission).try_acquire_owned() else {
        return failure(BackupExportError::Unavailable, state.digest);
    };
    let controller = Arc::clone(&state.controller);
    let timeout = state.timeout;
    let prepared = tokio::task::spawn_blocking(move || {
        let prepared = prepare(&*controller, &request, timeout)?;
        Ok::<_, BackupExportError>((prepared, permit))
    })
    .await;
    let ((input, headers), permit) = match prepared {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(error)) => return failure(error, state.digest),
        Err(_) => return failure(BackupExportError::Failed, state.digest),
    };
    let controller = Arc::clone(&state.controller);
    let body = crate::backup_export_body::body(
        move |sink| {
            let _permit = permit;
            let mut verified = VerifiedBackupExport::from_evidence(
                sink,
                BackupExportEvidence {
                    operation_id: input.operation_id,
                    byte_length: input.evidence.byte_length,
                    digest: input.evidence.digest,
                },
            )
            .map_err(|_| incomplete())?;
            let receipt = controller
                .stream(&input, &mut verified)
                .map_err(|_| incomplete())?;
            let now = current_time()
                .filter(|now| *now < input.deadline)
                .ok_or_else(incomplete)?;
            controller
                .authenticate(&input.headers, now)
                .map_err(|_| incomplete())?;
            verified.finish(receipt).map(|_| ())
        },
        timeout,
    );
    let mut response = Response::new(body);
    *response.headers_mut() = headers;
    response
        .headers_mut()
        .insert(API_SCHEMA_HEADER, state.digest);
    response
}

fn prepare<C: BackupExportController>(
    controller: &C,
    request: &Request,
    timeout: Duration,
) -> Result<(BackupExportRequest, HeaderMap), BackupExportError> {
    let now = current_time().ok_or(BackupExportError::Unavailable)?;
    controller.authenticate(request.headers(), now)?;
    if request.uri().query().is_some() {
        return Err(BackupExportError::InvalidInput);
    }
    let selected = request
        .uri()
        .path()
        .strip_prefix("/api/latest/admin/backups/")
        .and_then(|value| value.strip_suffix("/export"))
        .ok_or(BackupExportError::InvalidInput)?;
    validate_backup_export_path(&BackupExportPath {
        backup_id: selected.to_owned(),
    })
    .map_err(|_| BackupExportError::InvalidInput)?;
    let backup_id =
        BackupId::from_bytes(parse_uuid(selected).map_err(|_| BackupExportError::InvalidInput)?)
            .map_err(|_| BackupExportError::InvalidInput)?;
    let evidence = controller.prepare(request.headers(), backup_id, now)?;
    if evidence.source.backup_id != backup_id {
        return Err(BackupExportError::Failed);
    }
    evidence
        .source
        .validate()
        .map_err(|_| BackupExportError::Failed)?;
    let headers = response_headers(&evidence)?;
    let deadline = now
        .checked_add(DurationMicros::new(
            u64::try_from(timeout.as_micros()).map_err(|_| BackupExportError::Failed)?,
        ))
        .ok_or(BackupExportError::Failed)?;
    let operation_id = OperationId::from_bytes(
        parse_uuid(&request_identifier()).map_err(|_| BackupExportError::Failed)?,
    )
    .map_err(|_| BackupExportError::Failed)?;
    Ok((
        BackupExportRequest {
            headers: request.headers().clone(),
            evidence,
            operation_id,
            deadline,
        },
        headers,
    ))
}

fn response_headers(
    evidence: &meshspan_backup::BackupFileEvidence,
) -> Result<HeaderMap, BackupExportError> {
    use std::fmt::Write;
    if evidence.digest == [0; 32] || evidence.byte_length > i64::MAX.unsigned_abs() {
        return Err(BackupExportError::Failed);
    }
    let mut digest = String::from("sha256:");
    for byte in evidence.digest {
        write!(&mut digest, "{byte:02x}").map_err(|_| BackupExportError::Failed)?;
    }
    let boundary = BackupExportHeaders {
        backup_id: format_uuid(evidence.source.backup_id.as_bytes()),
        byte_length: evidence.byte_length.to_string(),
        digest,
    };
    validate_backup_export_headers(&boundary).map_err(|_| BackupExportError::Failed)?;
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("meshspan-backup-id", boundary.backup_id.clone()),
        ("meshspan-backup-digest", boundary.digest),
        ("content-length", boundary.byte_length),
        (
            "content-disposition",
            format!(
                "attachment; filename=\"meshspan-backup-{}.msb\"",
                boundary.backup_id
            ),
        ),
    ] {
        headers.insert(
            name,
            HeaderValue::from_str(&value).map_err(|_| BackupExportError::Failed)?,
        );
    }
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(API_VERSION_HEADER, HeaderValue::from_static("latest"));
    Ok(headers)
}

fn incomplete() -> io::Error {
    io::Error::other("backup export did not complete")
}

fn failure(error: BackupExportError, digest: HeaderValue) -> Response<Body> {
    let (status, code) = match error {
        BackupExportError::InvalidInput => (StatusCode::BAD_REQUEST, ApiErrorCode::InvalidRequest),
        BackupExportError::Unauthenticated => {
            (StatusCode::UNAUTHORIZED, ApiErrorCode::Unauthenticated)
        }
        BackupExportError::Forbidden => (StatusCode::FORBIDDEN, ApiErrorCode::Forbidden),
        BackupExportError::NotReady => (StatusCode::CONFLICT, ApiErrorCode::StateConflict),
        BackupExportError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, ApiErrorCode::Busy),
        BackupExportError::Failed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
        ),
    };
    error_response(
        status,
        code,
        &error.to_string(),
        request_identifier(),
        None,
        Vec::new(),
        digest,
    )
}

/// Failure to construct encrypted backup export routes.
#[derive(Debug, thiserror::Error)]
pub enum BackupExportApiError {
    /// Contract generation failed.
    #[error("backup export contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// Schema digest could not be encoded.
    #[error("backup export header is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
    /// Invalid worker capacity or transfer deadline.
    #[error("backup export limits are invalid")]
    Limits,
}
