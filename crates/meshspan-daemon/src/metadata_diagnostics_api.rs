// SPDX-License-Identifier: GPL-2.0-only

//! Owned, bounded diagnostic collection, independent of foreground data work.

use axum::{
    Router,
    body::{Body, HttpBody},
    extract::{Request, State},
    http::{HeaderValue, Response, StatusCode},
    routing::get,
};
use meshspan_api_contract::{ApiErrorCode, encode_metadata_diagnostics_response, generate_openapi};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::{
    sync::{Semaphore, oneshot},
    task::JoinSet,
};

use crate::PublicContractApiError;
use crate::api_http::{current_time, error_response, json_response, request_identifier};
use crate::metadata_diagnostics::{DiagnosticsError as Error, MetadataDiagnosticsController};

const COLLECTION_DEADLINE: Duration = Duration::from_secs(5);

struct DiagnosticsApi<C> {
    controller: Arc<Mutex<C>>,
    admission: Arc<Semaphore>,
    jobs: Mutex<JoinSet<()>>,
    digest: HeaderValue,
}

pub(crate) fn router<C: MetadataDiagnosticsController>(
    controller: C,
) -> Result<Router, PublicContractApiError> {
    let document = generate_openapi().map_err(PublicContractApiError::Contract)?;
    let digest =
        HeaderValue::from_str(document.digest()).map_err(PublicContractApiError::SchemaDigest)?;
    Ok(Router::new()
        .route("/api/latest/admin/diagnostics/metadata", get(read::<C>))
        .with_state(Arc::new(DiagnosticsApi {
            controller: Arc::new(Mutex::new(controller)),
            // This limits diagnostic jobs, not users, connections or foreground IO.
            admission: Arc::new(Semaphore::new(1)),
            jobs: Mutex::new(JoinSet::new()),
            digest,
        })))
}

async fn read<C: MetadataDiagnosticsController>(
    State(state): State<Arc<DiagnosticsApi<C>>>,
    request: Request,
) -> Response<Body> {
    let Ok(permit) = Arc::clone(&state.admission).try_acquire_owned() else {
        return failure(Error::Unavailable, state.digest.clone());
    };
    let controller = Arc::clone(&state.controller);
    let deadline = Instant::now() + COLLECTION_DEADLINE;
    let (respond, response) = oneshot::channel();
    {
        let Ok(mut jobs) = state.jobs.lock() else {
            return failure(Error::Failed, state.digest.clone());
        };
        while let Some(completed) = jobs.try_join_next() {
            if completed.is_err() {
                return failure(Error::Failed, state.digest.clone());
            }
        }
        jobs.spawn_blocking(move || {
            // Retain admission even when the HTTP request is cancelled. Blocking SQLite IO
            // cannot be forcibly aborted, but no subsequent section runs after cancellation.
            let _permit = permit;
            let check = || {
                if respond.is_closed() || Instant::now() >= deadline {
                    Err(Error::Unavailable)
                } else {
                    Ok(())
                }
            };
            let outcome = execute(&controller, &request, &check);
            let _cancelled = respond.send(outcome);
        });
    }
    match tokio::time::timeout(COLLECTION_DEADLINE, response).await {
        Ok(Ok(Ok(bytes))) => {
            let mut response = json_response(StatusCode::OK, bytes, state.digest.clone());
            response.headers_mut().insert(
                "content-disposition",
                HeaderValue::from_static(
                    "attachment; filename=\"meshspan-metadata-diagnostics.json\"",
                ),
            );
            response.headers_mut().insert(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
            );
            response
        }
        Ok(Ok(Err(error))) => failure(error, state.digest.clone()),
        Ok(Err(_)) => failure(Error::Failed, state.digest.clone()),
        Err(_) => failure(Error::Unavailable, state.digest.clone()),
    }
}

fn execute<C: MetadataDiagnosticsController>(
    controller: &Mutex<C>,
    request: &Request,
    check: &dyn Fn() -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    check()?;
    let controller = controller.try_lock().map_err(|_| Error::Unavailable)?;
    let now = current_time().ok_or(Error::Unavailable)?;
    controller.authenticate(request.headers(), now)?;
    if request.uri().query().is_some()
        || !request.body().is_end_stream()
        || request.headers().contains_key("transfer-encoding")
        || request
            .headers()
            .get_all("content-length")
            .iter()
            .any(|value| value != "0")
    {
        return Err(Error::InvalidInput);
    }
    let value = controller.collect(now, check)?;
    check()?;
    let bytes = encode_metadata_diagnostics_response(&value).map_err(|_| Error::Failed)?;
    if bytes.len() > meshspan_api_contract::MAX_METADATA_DIAGNOSTICS_BYTES {
        return Err(Error::Failed);
    }
    controller.authenticate(request.headers(), current_time().ok_or(Error::Unavailable)?)?;
    check()?;
    Ok(bytes)
}

fn failure(error: Error, digest: HeaderValue) -> Response<Body> {
    let (status, code, message) = match error {
        Error::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "Diagnostic query or body is not supported",
        ),
        Error::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "Authentication is required",
        ),
        Error::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "System-manager authority is required",
        ),
        Error::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "Diagnostic collection is unavailable",
        ),
        Error::Failed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "Diagnostic evidence failed validation",
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
