// SPDX-License-Identifier: GPL-2.0-only

//! Owned bounded configuration/scrape work, independent of foreground filesystem service.

use axum::{
    Router,
    body::{Body, HttpBody, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Response, StatusCode},
    routing::get,
};
use meshspan_api_contract::{
    ApiErrorCode, MAX_CONFIGURE_METRICS_EXPORTER_BYTES, decode_configure_metrics_exporter_request,
    encode_configure_metrics_exporter_response, encode_metrics_exporter_response, generate_openapi,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinSet,
};

use crate::PublicContractApiError;
use crate::api_http::{
    current_time, error_response, has_json_content_type, json_response, request_identifier,
};
use crate::metrics_exporter_service::{
    MetricsAccess, MetricsError as Error, MetricsExporterController,
};

const JOB_DEADLINE: Duration = Duration::from_secs(5);

struct MetricsApi<C> {
    controller: Arc<Mutex<C>>,
    admission: Arc<Semaphore>,
    jobs: Mutex<JoinSet<()>>,
    digest: HeaderValue,
}

pub(crate) fn router<C: MetricsExporterController>(
    controller: C,
) -> Result<Router, PublicContractApiError> {
    let document = generate_openapi().map_err(PublicContractApiError::Contract)?;
    let digest =
        HeaderValue::from_str(document.digest()).map_err(PublicContractApiError::SchemaDigest)?;
    Ok(Router::new()
        .route(
            "/api/latest/admin/metrics/exporter",
            get(read::<C, false>).put(configure::<C>),
        )
        .route("/api/latest/metrics", get(read::<C, true>))
        .with_state(Arc::new(MetricsApi {
            controller: Arc::new(Mutex::new(controller)),
            // A single owned SQL reader/collector job, not a cap on ordinary connections.
            admission: Arc::new(Semaphore::new(1)),
            jobs: Mutex::new(JoinSet::new()),
            digest,
        })))
}

impl<C: MetricsExporterController> MetricsApi<C> {
    fn admit(&self) -> Result<Arc<OwnedSemaphorePermit>, Error> {
        Arc::clone(&self.admission)
            .try_acquire_owned()
            .map(Arc::new)
            .map_err(|_| Error::Unavailable)
    }

    async fn job<T: Send + 'static>(
        &self,
        permit: Arc<OwnedSemaphorePermit>,
        work: impl FnOnce(&C, &dyn Fn() -> Result<(), Error>) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        let controller = Arc::clone(&self.controller);
        let deadline = Instant::now() + JOB_DEADLINE;
        let (send, receive) = oneshot::channel();
        {
            let mut jobs = self.jobs.lock().map_err(|_| Error::Failed)?;
            while let Some(result) = jobs.try_join_next() {
                result.map_err(|_| Error::Failed)?;
            }
            jobs.spawn_blocking(move || {
                // Cancellation cannot release admission while blocking work still owns it.
                let _permit = permit;
                let check = || {
                    if send.is_closed() || Instant::now() >= deadline {
                        Err(Error::Unavailable)
                    } else {
                        Ok(())
                    }
                };
                let result = (|| {
                    check()?;
                    let controller = controller.try_lock().map_err(|_| Error::Unavailable)?;
                    let result = work(&controller, &check)?;
                    check()?;
                    Ok(result)
                })();
                let _cancelled = send.send(result);
            });
        }
        tokio::time::timeout(JOB_DEADLINE, receive)
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Failed)?
    }
}

async fn read<C: MetricsExporterController, const SCRAPE: bool>(
    State(state): State<Arc<MetricsApi<C>>>,
    request: Request,
) -> Response<Body> {
    let Ok(permit) = state.admit() else {
        return failure(Error::Unavailable, &state.digest);
    };
    let result = state
        .job(permit, move |controller, check| {
            let access = if SCRAPE {
                MetricsAccess::Scrape
            } else {
                MetricsAccess::ReadConfiguration
            };
            controller.authenticate(
                request.headers(),
                current_time().ok_or(Error::Unavailable)?,
                access,
            )?;
            require_empty_read(&request)?;
            check()?;
            let bytes = if SCRAPE {
                crate::encode_openmetrics(&controller.collect()?).map_err(|_| Error::Failed)?
            } else {
                encode_metrics_exporter_response(&controller.configuration()?)
                    .map_err(|_| Error::Failed)?
            };
            check()?;
            controller.authenticate(
                request.headers(),
                current_time().ok_or(Error::Unavailable)?,
                access,
            )?;
            Ok(bytes)
        })
        .await;
    match result {
        Ok(bytes) => {
            let mut response = json_response(StatusCode::OK, bytes, state.digest.clone());
            if SCRAPE {
                response.headers_mut().insert(
                    "content-type",
                    HeaderValue::from_static(crate::OPENMETRICS_CONTENT_TYPE),
                );
            }
            response.headers_mut().insert(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
            );
            response
        }
        Err(error) => failure(error, &state.digest),
    }
}

async fn configure<C: MetricsExporterController>(
    State(state): State<Arc<MetricsApi<C>>>,
    request: Request,
) -> Response<Body> {
    let result = configure_request(&state, request).await;
    match result {
        Ok(bytes) => json_response(StatusCode::OK, bytes, state.digest.clone()),
        Err(error) => failure(error, &state.digest),
    }
}

async fn configure_request<C: MetricsExporterController>(
    state: &MetricsApi<C>,
    request: Request,
) -> Result<Vec<u8>, Error> {
    let permit = state.admit()?;
    let headers = request.headers().clone();
    let authentication_headers = headers.clone();
    state
        .job(Arc::clone(&permit), move |controller, _check| {
            controller.authenticate(
                &authentication_headers,
                current_time().ok_or(Error::Unavailable)?,
                MetricsAccess::Configure,
            )
        })
        .await?;
    if request.uri().query().is_some() {
        return Err(Error::InvalidInput);
    }
    if !has_json_content_type(&headers) {
        return Err(Error::UnsupportedMediaType);
    }
    let bytes = tokio::time::timeout(
        JOB_DEADLINE,
        to_bytes(request.into_body(), MAX_CONFIGURE_METRICS_EXPORTER_BYTES),
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(|_| Error::BodyTooLarge)?;
    let request =
        decode_configure_metrics_exporter_request(&bytes).map_err(|_| Error::InvalidInput)?;
    state
        .job(permit, move |controller, check| {
            check()?;
            let response = controller.configure(
                &headers,
                current_time().ok_or(Error::Unavailable)?,
                request,
            )?;
            check()?;
            // Successful receipts are durable; cancelling HTTP cannot roll a committed policy back.
            controller.authenticate(
                &headers,
                current_time().ok_or(Error::Unavailable)?,
                MetricsAccess::Configure,
            )?;
            encode_configure_metrics_exporter_response(&response).map_err(|_| Error::Failed)
        })
        .await
}

fn require_empty_read(request: &Request) -> Result<(), Error> {
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
    Ok(())
}

fn failure(error: Error, digest: &HeaderValue) -> Response<Body> {
    let (status, code, message) = match error {
        Error::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "Metrics request is invalid",
        ),
        Error::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "Current API-key or administrator authentication is required",
        ),
        Error::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "Metrics access is not granted",
        ),
        Error::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "Metrics configuration conflicts with committed state",
        ),
        Error::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "Metrics authority or collection is unavailable",
        ),
        Error::Failed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "Metrics evidence failed validation",
        ),
        Error::BodyTooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            ApiErrorCode::InvalidRequest,
            "Metrics policy body exceeds its bound",
        ),
        Error::UnsupportedMediaType => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "Metrics policy requires application/json",
        ),
    };
    error_response(
        status,
        code,
        message,
        request_identifier(),
        None,
        Vec::new(),
        digest.clone(),
    )
}
