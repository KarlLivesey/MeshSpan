// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated bounded HTTP adapter for provider capacity offers.

use super::{ApiState, PairingError, invalid, service_error};
use crate::api_http::{current_time, has_json_content_type, json_response, request_identifier};
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{Response, StatusCode},
};
use meshspan_api_contract::{
    FederationStorageGrantQuery, MAX_FEDERATION_STORAGE_GRANT_BYTES,
    decode_federation_storage_grant_query, decode_federation_storage_grant_request,
    encode_federation_storage_grant_receipt, encode_federation_storage_grant_response,
};
use std::sync::Arc;

pub(super) async fn read(State(state): State<ApiState>, request: Request) -> Response<Body> {
    let service = Arc::clone(&state.service);
    let headers = request.headers().clone();
    let uri = request.uri().clone();
    let result = tokio::task::spawn_blocking(move || {
        let service = service.lock().map_err(|_| PairingError::Unavailable)?;
        let now = current_time().ok_or(PairingError::Unavailable)?;
        service.authenticate_storage_read(&headers, now)?;
        if uri
            .query()
            .is_none_or(|query| query.len() > MAX_FEDERATION_STORAGE_GRANT_BYTES)
        {
            return Err(PairingError::Invalid);
        }
        let query = parse_query(uri.query().ok_or(PairingError::Invalid)?)?;
        let response = service.storage_grant(&headers, now, &query)?;
        encode_federation_storage_grant_response(&response).map_err(|_| PairingError::Failed)
    })
    .await;
    finish(&state, result)
}

pub(super) async fn configure(State(state): State<ApiState>, request: Request) -> Response<Body> {
    let service = Arc::clone(&state.service);
    let headers = request.headers().clone();
    let early_headers = headers.clone();
    let authentication = tokio::task::spawn_blocking(move || {
        let service = service.lock().map_err(|_| PairingError::Unavailable)?;
        service.authenticate(
            &early_headers,
            current_time().ok_or(PairingError::Unavailable)?,
        )
    })
    .await;
    match authentication {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return service_error(&state, error, request_identifier()),
        Err(_) => return service_error(&state, PairingError::Failed, request_identifier()),
    }
    if !has_json_content_type(&headers) {
        return invalid(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json is required",
            request_identifier(),
        );
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_FEDERATION_STORAGE_GRANT_BYTES).await else {
        return invalid(
            &state,
            StatusCode::PAYLOAD_TOO_LARGE,
            "storage grant request exceeds its bound",
            request_identifier(),
        );
    };
    let service = Arc::clone(&state.service);
    let result = tokio::task::spawn_blocking(move || {
        let service = service.lock().map_err(|_| PairingError::Unavailable)?;
        let now = current_time().ok_or(PairingError::Unavailable)?;
        service.authenticate(&headers, now)?;
        let request =
            decode_federation_storage_grant_request(&body).map_err(|_| PairingError::Invalid)?;
        let response = service.configure_storage_grant(&headers, now, &request)?;
        encode_federation_storage_grant_receipt(&response).map_err(|_| PairingError::Failed)
    })
    .await;
    finish(&state, result)
}

fn finish(
    state: &ApiState,
    result: Result<Result<Vec<u8>, PairingError>, tokio::task::JoinError>,
) -> Response<Body> {
    match result {
        Ok(Ok(body)) => json_response(StatusCode::OK, body, state.schema_digest.clone()),
        Ok(Err(error)) => service_error(state, error, request_identifier()),
        Err(_) => service_error(state, PairingError::Failed, request_identifier()),
    }
}

fn parse_query(raw: &str) -> Result<FederationStorageGrantQuery, PairingError> {
    let mut fields = serde_json::Map::new();
    for (name, value) in form_urlencoded::parse(raw.as_bytes()) {
        if fields
            .insert(
                name.into_owned(),
                serde_json::Value::String(value.into_owned()),
            )
            .is_some()
        {
            return Err(PairingError::Invalid);
        }
    }
    let bytes = serde_json::to_vec(&fields).map_err(|_| PairingError::Invalid)?;
    decode_federation_storage_grant_query(&bytes).map_err(|_| PairingError::Invalid)
}
