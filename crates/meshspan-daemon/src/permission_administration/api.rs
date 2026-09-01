// SPDX-License-Identifier: GPL-2.0-only

//! Bounded public routes for manager-only permission administration.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, ListVolumePermissionGrantsQuery,
    MAX_PERMISSION_GRANT_MUTATION_BYTES, PermissionGrantCursor, PermissionGrantId, VolumeId,
    decode_create_volume_permission_grant_request, decode_revoke_permission_grant_request,
    encode_create_volume_permission_grant_response, encode_list_volume_permission_grants_response,
    encode_revoke_permission_grant_response, generate_openapi,
    validate_list_volume_permission_grants_query,
};
use thiserror::Error;

use super::{PermissionAdministrationController, PermissionAdministrationError};
use crate::BrowserRequestProtection;
use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, json_response, request_identifier,
};
use crate::native_query::has_valid_percent_encoding;

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

/// Builds manager-only volume permission-grant routes.
///
/// # Errors
///
/// Fails if the Rust-authored contract or schema header cannot be generated.
pub fn permission_administration_api_router<C>(
    controller: C,
) -> Result<Router, PermissionAdministrationApiError>
where
    C: PermissionAdministrationController,
{
    let document = generate_openapi()?;
    Ok(Router::new()
        .route(
            "/api/latest/admin/volumes/{volume_id}/permission-grants",
            get(list::<C>).post(create::<C>),
        )
        .route(
            "/api/latest/admin/volumes/{volume_id}/permission-grants/{grant_id}/revocations",
            axum::routing::post(revoke::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn list<C>(
    Path(volume_id): Path<String>,
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: PermissionAdministrationController,
{
    let request_id = request_identifier();
    let administrator = match authenticate(
        &state,
        request.headers(),
        BrowserRequestProtection::Read,
        request_id.clone(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let (Some(volume_id), Ok(query)) = (
        VolumeId::parse(&volume_id),
        parse_query(request.uri().query()),
    ) else {
        return invalid_path_or_query(&state, request_id);
    };
    if validate_list_volume_permission_grants_query(&query).is_err() {
        return invalid_path_or_query(&state, request_id);
    }
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| PermissionAdministrationError::Unavailable)?
            .list_volume_grants(administrator, &volume_id, query)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_list_volume_permission_grants_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed(&state, request_id, None),
        },
        Ok(Err(error)) => service_error(&state, error, request_id, None),
        Err(_) => service_error(
            &state,
            PermissionAdministrationError::Unavailable,
            request_id,
            None,
        ),
    }
}

async fn create<C>(
    Path(volume_id): Path<String>,
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: PermissionAdministrationController,
{
    let request_id = request_identifier();
    let (administrator, body) = match authenticated_body(&state, request, request_id.clone()).await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let Some(volume_id) = VolumeId::parse(&volume_id) else {
        return invalid_path_or_query(&state, request_id);
    };
    let decoded = match decode_create_volume_permission_grant_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    let operation_id = decoded.operation_id.clone();
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| PermissionAdministrationError::Unavailable)?
            .create_volume_grant(administrator, &volume_id, decoded)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_create_volume_permission_grant_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => failed(&state, request_id, Some(operation_id)),
        },
        Ok(Err(error)) => service_error(&state, error, request_id, Some(operation_id)),
        Err(_) => service_error(
            &state,
            PermissionAdministrationError::Unavailable,
            request_id,
            Some(operation_id),
        ),
    }
}

async fn revoke<C>(
    Path((volume_id, grant_id)): Path<(String, String)>,
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: PermissionAdministrationController,
{
    let request_id = request_identifier();
    let (administrator, body) = match authenticated_body(&state, request, request_id.clone()).await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let (Some(volume_id), Some(grant_id)) = (
        VolumeId::parse(&volume_id),
        PermissionGrantId::parse(&grant_id),
    ) else {
        return invalid_path_or_query(&state, request_id);
    };
    let decoded = match decode_revoke_permission_grant_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    let operation_id = decoded.operation_id.clone();
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| PermissionAdministrationError::Unavailable)?
            .revoke_grant(administrator, &volume_id, &grant_id, decoded)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_revoke_permission_grant_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed(&state, request_id, Some(operation_id)),
        },
        Ok(Err(error)) => service_error(&state, error, request_id, Some(operation_id)),
        Err(_) => service_error(
            &state,
            PermissionAdministrationError::Unavailable,
            request_id,
            Some(operation_id),
        ),
    }
}

async fn authenticated_body<C>(
    state: &ApiState<C>,
    request: Request,
    request_id: String,
) -> Result<(crate::IdentityAdministrator, Bytes), Box<Response<Body>>>
where
    C: PermissionAdministrationController,
{
    if !has_json_content_type(request.headers()) {
        return Err(Box::new(public_error(
            state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "permission mutation requires application/json",
            request_id,
            vec![issue("", "content_type")],
        )));
    }
    let administrator = authenticate(
        state,
        request.headers(),
        BrowserRequestProtection::Mutation,
        request_id.clone(),
    )
    .await?;
    to_bytes(request.into_body(), MAX_PERMISSION_GRANT_MUTATION_BYTES)
        .await
        .map(|body| (administrator, body))
        .map_err(|_| {
            Box::new(public_error(
                state,
                StatusCode::PAYLOAD_TOO_LARGE,
                ApiErrorCode::InvalidRequest,
                "permission mutation body exceeds its bound",
                request_id,
                vec![issue("", "max_bytes")],
            ))
        })
}

async fn authenticate<C>(
    state: &ApiState<C>,
    headers: &HeaderMap,
    protection: BrowserRequestProtection,
    request_id: String,
) -> Result<crate::IdentityAdministrator, Box<Response<Body>>>
where
    C: PermissionAdministrationController,
{
    let Some(now) = current_time() else {
        return Err(Box::new(failed(state, request_id, None)));
    };
    let headers = headers.clone();
    let controller = Arc::clone(&state.controller);
    tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| PermissionAdministrationError::Unavailable)?
            .authenticate(&headers, protection, now)
    })
    .await
    .map_err(|_| PermissionAdministrationError::Unavailable)
    .and_then(|result| result)
    .map_err(|error| Box::new(service_error(state, error, request_id, None)))
}

fn parse_query(raw_query: Option<&str>) -> Result<ListVolumePermissionGrantsQuery, ()> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(ListVolumePermissionGrantsQuery::default());
    };
    if raw_query.len() > 4_096 || !has_valid_percent_encoding(raw_query.as_bytes()) {
        return Err(());
    }
    let mut query = ListVolumePermissionGrantsQuery::default();
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor =
                    Some(PermissionGrantCursor::from_encoded(value.into_owned()).ok_or(())?);
            }
            "limit" if !limit_seen => {
                limit_seen = true;
                query.limit = Some(
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|value| *value > 0)
                        .ok_or(())?,
                );
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
        "permission-administration request is invalid",
        request_id,
        boundary_issues(error),
    )
}

fn invalid_path_or_query<C>(state: &ApiState<C>, request_id: String) -> Response<Body> {
    public_error(
        state,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
        "permission-administration path or query is invalid",
        request_id,
        vec![issue("", "path_or_query")],
    )
}

fn service_error<C>(
    state: &ApiState<C>,
    error: PermissionAdministrationError,
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
) -> Response<Body> {
    let (status, code, message) = match error {
        PermissionAdministrationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "permission-administration input is invalid",
        ),
        PermissionAdministrationError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        PermissionAdministrationError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        PermissionAdministrationError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "permission mutation conflicts with committed state",
        ),
        PermissionAdministrationError::NotFound => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::NotFound,
            "permission resource was not found",
        ),
        PermissionAdministrationError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "permission authority is temporarily unavailable",
        ),
        PermissionAdministrationError::Failed => return failed(state, request_id, operation_id),
    };
    error_response(
        status,
        code,
        message,
        request_id,
        operation_id,
        Vec::new(),
        state.schema_digest.clone(),
    )
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

fn failed<C>(
    state: &ApiState<C>,
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
) -> Response<Body> {
    internal_error_response(
        request_id,
        operation_id,
        state.schema_digest.clone(),
        "permission administration failed closed",
    )
}

/// Router-construction failure.
#[derive(Debug, Error)]
pub enum PermissionAdministrationApiError {
    /// The authoritative public contract could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
