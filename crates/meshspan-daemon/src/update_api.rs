// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authenticated, bounded update configuration jobs.

#[path = "update_artifact_api.rs"]
mod artifact;

use crate::{
    PublicContractApiError,
    api_http::{
        current_time, error_response, has_json_content_type, json_response, request_identifier,
    },
    update_service::{UpdateError as Error, UpdateService},
};
use axum::{
    Router,
    body::{Body, HttpBody, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Response, StatusCode},
    routing::get,
};
use meshspan_api_contract::{
    ApiErrorCode, MAX_MANAGE_UPDATE_BYTES, decode_manage_update_request,
    encode_manage_update_response, encode_updates_response, generate_openapi,
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinSet,
};

const DEADLINE: Duration = Duration::from_secs(5);

struct UpdateApi {
    service: Arc<Mutex<UpdateService>>,
    admission: Arc<Semaphore>,
    jobs: Mutex<JoinSet<()>>,
    digest: HeaderValue,
    artifact_admission: Arc<Semaphore>,
    state_directory: std::path::PathBuf,
}

pub(crate) fn router(
    service: UpdateService,
    state_directory: &std::path::Path,
) -> Result<Router, PublicContractApiError> {
    let document = generate_openapi().map_err(PublicContractApiError::Contract)?;
    let digest =
        HeaderValue::from_str(document.digest()).map_err(PublicContractApiError::SchemaDigest)?;
    Ok(Router::new()
        .route("/api/latest/admin/updates", get(read).put(configure))
        .route(
            "/api/latest/admin/updates/{rollout_id}/artifacts/{target}",
            axum::routing::put(artifact::upload),
        )
        .with_state(Arc::new(UpdateApi {
            service: Arc::new(Mutex::new(service)),
            admission: Arc::new(Semaphore::new(1)),
            jobs: Mutex::new(JoinSet::new()),
            digest,
            artifact_admission: Arc::new(Semaphore::new(2)),
            state_directory: state_directory.to_path_buf(),
        })))
}

impl UpdateApi {
    fn admit(&self) -> Result<Arc<OwnedSemaphorePermit>, Error> {
        self.admission
            .clone()
            .try_acquire_owned()
            .map(Arc::new)
            .map_err(|_| Error::Unavailable)
    }

    async fn job<T: Send + 'static>(
        &self,
        permit: Arc<OwnedSemaphorePermit>,
        work: impl FnOnce(&UpdateService) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        let service = self.service.clone();
        let deadline = Instant::now() + DEADLINE;
        let (send, receive) = oneshot::channel();
        {
            let mut jobs = self.jobs.lock().map_err(|_| Error::Failed)?;
            while let Some(result) = jobs.try_join_next() {
                result.map_err(|_| Error::Failed)?;
            }
            jobs.spawn_blocking(move || {
                let _permit = permit;
                let result = (|| {
                    if send.is_closed() || Instant::now() >= deadline {
                        return Err(Error::Unavailable);
                    }
                    let service = service.try_lock().map_err(|_| Error::Unavailable)?;
                    work(&service)
                })();
                // A dropped receiver cannot undo a committed operation. The stable ID resolves it.
                let _cancelled = send.send(result);
            });
        }
        tokio::time::timeout(DEADLINE, receive)
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Failed)?
    }
}

async fn read(State(state): State<Arc<UpdateApi>>, request: Request) -> Response<Body> {
    let result = async {
        let permit = state.admit()?;
        state
            .job(permit, move |service| {
                service.authenticate(request.headers(), now()?, false)?;
                if !request.body().is_end_stream()
                    || request.headers().contains_key("transfer-encoding")
                    || request
                        .headers()
                        .get_all("content-length")
                        .iter()
                        .any(|value| value != "0")
                {
                    return Err(Error::Invalid);
                }
                let rollout = match request.uri().query() {
                    None => None,
                    Some(query) => {
                        let value = query.strip_prefix("rollout_id=").ok_or(Error::Invalid)?;
                        Some(
                            meshspan_domain::WorkId::from_bytes(crate::update_service::parse(
                                value,
                            )?)
                            .map_err(|_| Error::Invalid)?,
                        )
                    }
                };
                let response = service.status(rollout)?;
                service.authenticate(request.headers(), now()?, false)?;
                encode_updates_response(&response).map_err(|_| Error::Failed)
            })
            .await
    }
    .await;
    respond(result, &state.digest)
}

async fn configure(State(state): State<Arc<UpdateApi>>, request: Request) -> Response<Body> {
    respond(configure_request(&state, request).await, &state.digest)
}

async fn configure_request(state: &UpdateApi, request: Request) -> Result<Vec<u8>, Error> {
    let permit = state.admit()?;
    let headers = request.headers().clone();
    let authentication = headers.clone();
    state
        .job(permit.clone(), move |service| {
            service
                .authenticate(&authentication, now()?, true)
                .map(|_| ())
        })
        .await?;
    if request.uri().query().is_some() {
        return Err(Error::Invalid);
    }
    if !has_json_content_type(&headers) {
        return Err(Error::MediaType);
    }
    let bytes = tokio::time::timeout(
        DEADLINE,
        to_bytes(request.into_body(), MAX_MANAGE_UPDATE_BYTES),
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(|_| Error::BodyTooLarge)?;
    let request = decode_manage_update_request(&bytes).map_err(|_| Error::Invalid)?;
    state
        .job(permit, move |service| {
            let administrator = service.authenticate(&headers, now()?, true)?;
            let receipt = service.manage(administrator, &request)?;
            service.authenticate(&headers, now()?, true)?;
            encode_manage_update_response(&receipt).map_err(|_| Error::Failed)
        })
        .await
}

fn now() -> Result<meshspan_domain::UnixMicros, Error> {
    current_time().ok_or(Error::Unavailable)
}

fn respond(result: Result<Vec<u8>, Error>, digest: &HeaderValue) -> Response<Body> {
    let error = match result {
        Ok(bytes) => return json_response(StatusCode::OK, bytes, digest.clone()),
        Err(error) => error,
    };
    let (status, code) = match error {
        Error::Invalid => (StatusCode::BAD_REQUEST, ApiErrorCode::InvalidRequest),
        Error::Unauthenticated => (StatusCode::UNAUTHORIZED, ApiErrorCode::Unauthenticated),
        Error::Forbidden => (StatusCode::FORBIDDEN, ApiErrorCode::Forbidden),
        Error::Conflict => (StatusCode::CONFLICT, ApiErrorCode::OperationConflict),
        Error::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, ApiErrorCode::Busy),
        Error::Failed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
        ),
        Error::BodyTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, ApiErrorCode::InvalidRequest),
        Error::MediaType => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
        ),
    };
    error_response(
        status,
        code,
        &error.to_string(),
        request_identifier(),
        None,
        Vec::new(),
        digest.clone(),
    )
}
