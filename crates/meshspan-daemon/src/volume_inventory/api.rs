// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTP boundary for permission-filtered logical volumes.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{
    ApiErrorCode, ListVolumesQuery, ListVolumesResponse, VolumeCursor,
    encode_list_volumes_response, generate_openapi,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use super::{VolumeInventoryAuthority, VolumeInventoryError, VolumeInventoryService};
use crate::api_http::{
    current_time, error_response, internal_error_response, issue, json_response, request_identifier,
};
use crate::{NativeFileApiAuthenticator, native_query::has_valid_percent_encoding};

/// Synchronous inventory boundary executed on a blocking worker.
pub trait VolumeInventoryController: Send + 'static {
    /// Returns one bounded permission-filtered logical-volume page.
    ///
    /// # Errors
    ///
    /// Returns only stable request, authentication, availability or integrity failures.
    fn list_volumes(
        &mut self,
        headers: &HeaderMap,
        query: ListVolumesQuery,
        now: UnixMicros,
    ) -> Result<ListVolumesResponse, VolumeInventoryError>;
}

impl<A, V> VolumeInventoryController for VolumeInventoryService<A, V>
where
    A: NativeFileApiAuthenticator,
    V: VolumeInventoryAuthority,
{
    fn list_volumes(
        &mut self,
        headers: &HeaderMap,
        query: ListVolumesQuery,
        now: UnixMicros,
    ) -> Result<ListVolumesResponse, VolumeInventoryError> {
        self.list(headers, &query, now)
    }
}

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

/// Builds the rolling permission-filtered volume inventory endpoint.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn volume_inventory_api_router<C>(controller: C) -> Result<Router, VolumeInventoryApiError>
where
    C: VolumeInventoryController,
{
    let document = generate_openapi()?;
    let state = ApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route("/api/latest/volumes", get(list::<C>))
        .with_state(state))
}

async fn list<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: VolumeInventoryController,
{
    let request_id = request_identifier();
    let Ok(query) = parse_query(request.uri().query()) else {
        return invalid_query(request_id, state.schema_digest);
    };
    let Some(now) = current_time() else {
        return failed_closed(request_id, state.schema_digest);
    };
    execute(state, request_id, request.headers().clone(), query, now).await
}

async fn execute<C>(
    state: ApiState<C>,
    request_id: String,
    headers: HeaderMap,
    query: ListVolumesQuery,
    now: UnixMicros,
) -> Response<Body>
where
    C: VolumeInventoryController,
{
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| VolumeInventoryError::Unavailable)?
            .list_volumes(&headers, query, now)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_list_volumes_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed_closed(request_id, state.schema_digest),
        },
        Ok(Err(error)) => service_error(error, request_id, state.schema_digest),
        Err(_) => failed_closed(request_id, state.schema_digest),
    }
}

fn parse_query(raw_query: Option<&str>) -> Result<ListVolumesQuery, ()> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(ListVolumesQuery::default());
    };
    if raw_query.len() > 4_096 || !has_valid_percent_encoding(raw_query.as_bytes()) {
        return Err(());
    }
    let mut query = ListVolumesQuery::default();
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor = Some(VolumeCursor::from_encoded(value.into_owned()).ok_or(())?);
            }
            "limit" if !limit_seen => {
                limit_seen = true;
                query.limit = Some(parse_limit(&value)?);
            }
            _ => return Err(()),
        }
    }
    Ok(query)
}

fn parse_limit(value: &str) -> Result<u16, ()> {
    value
        .parse::<u16>()
        .ok()
        .filter(|limit| (1..=256).contains(limit))
        .ok_or(())
}

fn service_error(
    error: VolumeInventoryError,
    request_id: String,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        VolumeInventoryError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "volume query is invalid",
        ),
        VolumeInventoryError::Rejected => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        VolumeInventoryError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "volume authority is temporarily unavailable",
        ),
        VolumeInventoryError::Failed => {
            return failed_closed(request_id, schema_digest);
        }
    };
    error_response(
        status,
        code,
        message,
        request_id,
        None,
        Vec::new(),
        schema_digest,
    )
}

fn invalid_query(request_id: String, schema_digest: HeaderValue) -> Response<Body> {
    error_response(
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
        "volume query is invalid",
        request_id,
        None,
        vec![issue("", "query")],
        schema_digest,
    )
}

fn failed_closed(request_id: String, schema_digest: HeaderValue) -> Response<Body> {
    internal_error_response(
        request_id,
        None,
        schema_digest,
        "volume inventory failed closed",
    )
}

/// Router construction failure.
#[derive(Debug, Error)]
pub enum VolumeInventoryApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
