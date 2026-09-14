// SPDX-License-Identifier: GPL-2.0-only

//! Bounded pinned peer exchange without holding a service lock across network IO.

use super::{
    ApiState, PairingError, current_time, invalid, json_response, request_identifier, service_error,
};
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, Response, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use meshspan_api_contract::{ConnectFederationRequest, MAX_FEDERATION_CONNECTION_BYTES};
use meshspan_metadata::FederationConnectionIntentRecord;
use std::sync::Arc;

pub(super) async fn connect(State(state): State<ApiState>, request: Request) -> Response<Body> {
    let request_id = request_identifier();
    let headers = request.headers().clone();
    if let Err(error) = admit(&state, headers.clone()).await {
        return service_error(&state, error, request_id);
    }
    if !crate::api_http::has_json_content_type(&headers) {
        return invalid(
            &state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json is required",
            request_id,
        );
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_FEDERATION_CONNECTION_BYTES).await else {
        return invalid(
            &state,
            StatusCode::PAYLOAD_TOO_LARGE,
            "connection request exceeds its bound",
            request_id,
        );
    };
    let Ok(request) = meshspan_api_contract::decode_connect_federation_request(&body) else {
        return service_error(&state, PairingError::Invalid, request_id);
    };
    match exchange(&state, headers, request).await {
        Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
        Err(error) => service_error(&state, error, request_id),
    }
}

async fn admit(state: &ApiState, headers: HeaderMap) -> Result<(), PairingError> {
    let service = Arc::clone(&state.service);
    tokio::task::spawn_blocking(move || {
        service
            .lock()
            .map_err(|_| PairingError::Unavailable)?
            .authenticate(&headers, current_time().ok_or(PairingError::Failed)?)
    })
    .await
    .map_err(|_| PairingError::Failed)?
}

async fn prepare(
    state: &ApiState,
    headers: HeaderMap,
    request: ConnectFederationRequest,
) -> Result<(ConnectFederationRequest, FederationConnectionIntentRecord), PairingError> {
    let service = Arc::clone(&state.service);
    tokio::task::spawn_blocking(move || {
        let record = service
            .lock()
            .map_err(|_| PairingError::Unavailable)?
            .begin_connection(
                &headers,
                current_time().ok_or(PairingError::Failed)?,
                &request,
            )?;
        Ok((request, record))
    })
    .await
    .map_err(|_| PairingError::Failed)?
}

async fn exchange(
    state: &ApiState,
    headers: HeaderMap,
    request: ConnectFederationRequest,
) -> Result<Vec<u8>, PairingError> {
    let (request, record) = prepare(state, headers.clone(), request).await?;
    let payload = meshspan_api_contract::AcceptFederationPairingRequest {
        operation_id: request.operation_id.clone(),
        peer_record: URL_SAFE_NO_PAD.encode(
            meshspan_metadata::encode_federation_pairing_peer(&record.intent.local)
                .map_err(|_| PairingError::Failed)?,
        ),
    };
    let body = serde_json::to_vec(&payload).map_err(|_| PairingError::Failed)?;
    meshspan_api_contract::decode_accept_federation_pairing_request(&body)
        .map_err(|_| PairingError::Failed)?;
    let authorization =
        zeroize::Zeroizing::new(format!("MeshSpan-Pairing {}", request.connection_code));
    let response = crate::pinned_https_client::post_pinned_json_authorised(
        &record.intent.remote_endpoint,
        "/api/latest/federation/pairings/accept",
        record.intent.certificate_fingerprint,
        crate::pinned_https_client::PinnedJsonPayload {
            body: &body,
            maximum_response_bytes: MAX_FEDERATION_CONNECTION_BYTES,
            authorization: Some(&authorization),
        },
    )
    .await
    .map_err(|_| PairingError::Unavailable)?;
    let response = meshspan_api_contract::decode_accept_federation_pairing_response(&response)
        .map_err(|_| PairingError::Invalid)?;
    let service = Arc::clone(&state.service);
    tokio::task::spawn_blocking(move || {
        let response = service
            .lock()
            .map_err(|_| PairingError::Unavailable)?
            .finish_connection(
                &headers,
                current_time().ok_or(PairingError::Failed)?,
                &request,
                &response,
            )?;
        meshspan_api_contract::encode_connect_federation_response(&response)
            .map_err(|_| PairingError::Failed)
    })
    .await
    .map_err(|_| PairingError::Failed)?
}
