// SPDX-License-Identifier: GPL-2.0-only

//! Authenticate before reading pairing material; recheck authority before committing it.

#[path = "federation_connection_api.rs"]
mod connection;
#[path = "federation_storage_grant_api.rs"]
mod storage;

use std::sync::{Arc, Mutex};

use crate::api_http::{
    current_time, error_response, has_json_content_type, json_response, request_identifier,
};
use crate::federation_pairing_service::{FederationPairingService, PairingError};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Response, StatusCode},
    routing::post,
};
use meshspan_api_contract::{
    ApiErrorCode, MAX_CREATE_FEDERATION_PAIRING_BYTES, decode_cancel_federation_pairing_request,
    decode_create_federation_pairing_request, encode_cancel_federation_pairing_response,
    encode_create_federation_pairing_response, generate_openapi,
};

#[derive(Clone)]
struct ApiState {
    service: Arc<Mutex<FederationPairingService>>,
    schema_digest: HeaderValue,
}

pub(crate) fn federation_pairing_api_router(
    service: FederationPairingService,
) -> Result<Router, FederationPairingApiError> {
    Ok(Router::new()
        .route("/api/latest/admin/federation/invitations", post(issue))
        .route(
            "/api/latest/admin/federation/invitations/cancel",
            post(cancel),
        )
        .route("/api/latest/federation/pairings/accept", post(accept))
        .route(
            "/api/latest/admin/federation/storage-grants",
            axum::routing::get(storage::read).post(storage::configure),
        )
        .route(
            "/api/latest/admin/federation/connections",
            post(connection::connect),
        )
        .with_state(ApiState {
            service: Arc::new(Mutex::new(service)),
            schema_digest: HeaderValue::from_str(generate_openapi()?.digest())?,
        }))
}

async fn issue(State(state): State<ApiState>, request: Request) -> Response<Body> {
    mutate(state, request, PairingOperation::Issue).await
}

async fn cancel(State(state): State<ApiState>, request: Request) -> Response<Body> {
    mutate(state, request, PairingOperation::Cancel).await
}

async fn accept(State(state): State<ApiState>, request: Request) -> Response<Body> {
    mutate(state, request, PairingOperation::Accept).await
}

#[derive(Clone, Copy)]
enum PairingOperation {
    Issue,
    Cancel,
    Accept,
}

async fn mutate(state: ApiState, request: Request, operation: PairingOperation) -> Response<Body> {
    let request_id = request_identifier();
    let Some(now) = current_time() else {
        return service_error(&state, PairingError::Failed, request_id);
    };
    let service = Arc::clone(&state.service);
    let headers = request.headers().clone();
    let early_headers = headers.clone();
    match tokio::task::spawn_blocking(move || {
        let service = service.lock().map_err(|_| PairingError::Unavailable)?;
        match operation {
            PairingOperation::Issue | PairingOperation::Cancel => {
                service.authenticate(&early_headers, now)
            }
            PairingOperation::Accept => service.authenticate_invitation(&early_headers, now),
        }
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return service_error(&state, error, request_id),
        Err(_) => return service_error(&state, PairingError::Failed, request_id),
    }
    if !has_json_content_type(request.headers()) {
        return invalid(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json is required",
            request_id,
        );
    }
    let maximum = match operation {
        PairingOperation::Issue | PairingOperation::Cancel => MAX_CREATE_FEDERATION_PAIRING_BYTES,
        PairingOperation::Accept => meshspan_api_contract::MAX_FEDERATION_CONNECTION_BYTES,
    };
    let Ok(body) = to_bytes(request.into_body(), maximum).await else {
        return invalid(
            &state,
            StatusCode::PAYLOAD_TOO_LARGE,
            "pairing request exceeds its bound",
            request_id,
        );
    };
    let service = Arc::clone(&state.service);
    match tokio::task::spawn_blocking(move || {
        let now = current_time().ok_or(PairingError::Failed)?;
        let service = service.lock().map_err(|_| PairingError::Unavailable)?;
        match operation {
            PairingOperation::Accept => {
                let request =
                    meshspan_api_contract::decode_accept_federation_pairing_request(&body)
                        .map_err(|_| PairingError::Invalid)?;
                let response = service.accept(&headers, now, &request)?;
                Ok((
                    StatusCode::CREATED,
                    meshspan_api_contract::encode_accept_federation_pairing_response(&response)
                        .map_err(|_| PairingError::Failed)?,
                ))
            }
            PairingOperation::Issue => {
                let request = decode_create_federation_pairing_request(&body)
                    .map_err(|_| PairingError::Invalid)?;
                let response = service.issue(&headers, now, &request)?;
                Ok((
                    StatusCode::CREATED,
                    encode_create_federation_pairing_response(&response)
                        .map_err(|_| PairingError::Failed)?,
                ))
            }
            PairingOperation::Cancel => {
                let request = decode_cancel_federation_pairing_request(&body)
                    .map_err(|_| PairingError::Invalid)?;
                let response = service.cancel(&headers, now, &request)?;
                Ok((
                    StatusCode::OK,
                    encode_cancel_federation_pairing_response(&response)
                        .map_err(|_| PairingError::Failed)?,
                ))
            }
        }
    })
    .await
    {
        Ok(Ok((status, body))) => json_response(status, body, state.schema_digest),
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => service_error(&state, PairingError::Failed, request_id),
    }
}

fn invalid(
    state: &ApiState,
    code: StatusCode,
    message: &str,
    request_id: String,
) -> Response<Body> {
    error_response(
        code,
        ApiErrorCode::InvalidRequest,
        message,
        request_id,
        None,
        Vec::new(),
        state.schema_digest.clone(),
    )
}

fn service_error(state: &ApiState, error: PairingError, request_id: String) -> Response<Body> {
    let (status, code, message) = match error {
        PairingError::Invalid => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "federation input is invalid",
        ),
        PairingError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        PairingError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        PairingError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "federation operation conflicts with committed state",
        ),
        PairingError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "federation authority is temporarily unavailable",
        ),
        PairingError::Failed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "federation operation failed closed",
        ),
    };
    error_response(
        status,
        code,
        message,
        request_id,
        None,
        Vec::new(),
        state.schema_digest.clone(),
    )
}

/// Federation API construction failed before requests could be accepted.
#[derive(Debug, thiserror::Error)]
pub enum FederationPairingApiError {
    /// The Rust-authored contract could not be generated.
    #[error("federation API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest is not a valid HTTP header.
    #[error("federation API schema header is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
