// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTPS boundary for explicit SMB-export publication and withdrawal.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, MAX_PUBLISH_SMB_EXPORT_BYTES, MAX_WITHDRAW_SMB_EXPORT_BYTES,
    decode_publish_smb_export_request, decode_withdraw_smb_export_request,
    encode_publish_smb_export_response, encode_withdraw_smb_export_response, generate_openapi,
};
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    json_response, request_identifier,
};
use crate::{SmbExportAdministrationController, SmbExportAdministrationError};

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

/// Builds the explicit SMB-export mutation routes.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn smb_export_administration_api_router<C>(
    controller: C,
) -> Result<Router, SmbExportAdministrationApiError>
where
    C: SmbExportAdministrationController,
{
    let document = generate_openapi()?;
    Ok(Router::new()
        .route(
            "/api/latest/admin/volumes/{volume_id}/smb-exports",
            post(publish::<C>),
        )
        .route(
            "/api/latest/admin/smb-exports/{export_id}/withdrawals",
            post(withdraw::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn publish<C>(
    State(state): State<ApiState<C>>,
    Path(volume_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: SmbExportAdministrationController,
{
    let request_id = request_identifier();
    let administrator = match authenticate(&state, request.headers().clone()).await {
        Ok(administrator) => administrator,
        Err(error) => return service_error(&state, error, request_id),
    };
    if !has_json_content_type(request.headers()) {
        return public_error(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "SMB export publication requires application/json",
            request_id,
            Vec::new(),
        );
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_PUBLISH_SMB_EXPORT_BYTES).await else {
        return oversized(&state, request_id);
    };
    let decoded = match decode_publish_smb_export_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| SmbExportAdministrationError::Unavailable)?
            .publish(administrator, &volume_id, decoded)
    })
    .await
    {
        Ok(Ok(response)) => match encode_publish_smb_export_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => failed(&state, request_id),
    }
}

async fn withdraw<C>(
    State(state): State<ApiState<C>>,
    Path(export_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: SmbExportAdministrationController,
{
    let request_id = request_identifier();
    let administrator = match authenticate(&state, request.headers().clone()).await {
        Ok(administrator) => administrator,
        Err(error) => return service_error(&state, error, request_id),
    };
    if !has_json_content_type(request.headers()) {
        return public_error(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "SMB export withdrawal requires application/json",
            request_id,
            Vec::new(),
        );
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_WITHDRAW_SMB_EXPORT_BYTES).await else {
        return oversized(&state, request_id);
    };
    let decoded = match decode_withdraw_smb_export_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| SmbExportAdministrationError::Unavailable)?
            .withdraw(administrator, &export_id, decoded)
    })
    .await
    {
        Ok(Ok(response)) => match encode_withdraw_smb_export_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => failed(&state, request_id),
    }
}

async fn authenticate<C>(
    state: &ApiState<C>,
    headers: axum::http::HeaderMap,
) -> Result<crate::IdentityAdministrator, SmbExportAdministrationError>
where
    C: SmbExportAdministrationController,
{
    let now = current_time().ok_or(SmbExportAdministrationError::Failed)?;
    let controller = Arc::clone(&state.controller);
    tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| SmbExportAdministrationError::Unavailable)?
            .authenticate(&headers, now)
    })
    .await
    .map_err(|_| SmbExportAdministrationError::Failed)?
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
        "SMB export request is invalid",
        request_id,
        boundary_issues(error),
    )
}

fn oversized<C>(state: &ApiState<C>, request_id: String) -> Response<Body> {
    public_error(
        state,
        StatusCode::PAYLOAD_TOO_LARGE,
        ApiErrorCode::InvalidRequest,
        "SMB export request exceeds its bound",
        request_id,
        Vec::new(),
    )
}

fn service_error<C>(
    state: &ApiState<C>,
    error: SmbExportAdministrationError,
    request_id: String,
) -> Response<Body> {
    let (status, code, message) = match error {
        SmbExportAdministrationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "SMB export input is invalid",
        ),
        SmbExportAdministrationError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        SmbExportAdministrationError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        SmbExportAdministrationError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "SMB export operation conflicts with committed state",
        ),
        SmbExportAdministrationError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "SMB export authority is temporarily unavailable",
        ),
        SmbExportAdministrationError::Failed => return failed(state, request_id),
    };
    public_error(state, status, code, message, request_id, Vec::new())
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

fn failed<C>(state: &ApiState<C>, request_id: String) -> Response<Body> {
    internal_error_response(
        request_id,
        None,
        state.schema_digest.clone(),
        "SMB export administration failed closed",
    )
}

/// Router-construction failure.
#[derive(Debug, Error)]
pub enum SmbExportAdministrationApiError {
    /// Authoritative public contract generation failed.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// Contract digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
