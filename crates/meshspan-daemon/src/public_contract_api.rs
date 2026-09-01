// SPDX-License-Identifier: GPL-2.0-only

//! Anonymous bounded health and exact public-contract routes.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{HealthResponse, HealthStatus, generate_openapi};
use thiserror::Error;

use crate::api_http::{
    API_SCHEMA_HEADER, API_VERSION_HEADER, internal_error_response, json_response,
    request_identifier,
};

/// Supplies the cheap current process readiness projected by the public health route.
pub trait ReadinessSource: Send + Sync + 'static {
    /// Returns the current bounded readiness state without exposing topology or failure detail.
    fn status(&self) -> HealthStatus;
}

#[derive(Clone)]
struct PublicContractState {
    openapi: Arc<Vec<u8>>,
    readiness: Arc<dyn ReadinessSource>,
    schema_digest: HeaderValue,
    schema_digest_text: Arc<str>,
}

/// Creates the anonymous health and exact `OpenAPI` router.
///
/// # Errors
///
/// Returns an error when the Rust-authored contract cannot be serialized or its digest cannot be
/// represented as an HTTP header.
pub fn public_contract_api_router(
    readiness: Arc<dyn ReadinessSource>,
) -> Result<Router, PublicContractApiError> {
    let contract = generate_openapi().map_err(PublicContractApiError::Contract)?;
    let schema_digest =
        HeaderValue::from_str(contract.digest()).map_err(PublicContractApiError::SchemaDigest)?;
    let state = PublicContractState {
        openapi: Arc::new(
            contract
                .to_pretty_bytes()
                .map_err(PublicContractApiError::Contract)?,
        ),
        readiness,
        schema_digest,
        schema_digest_text: Arc::from(contract.digest()),
    };
    Ok(Router::new()
        .route("/api/latest/health", get(health))
        .route("/api/latest/openapi.json", get(openapi))
        .with_state(state))
}

async fn health(State(state): State<PublicContractState>) -> Response<Body> {
    let response = HealthResponse {
        status: state.readiness.status(),
        api_version: "latest".to_owned(),
        schema_digest: state.schema_digest_text.to_string(),
    };
    match serde_json::to_vec(&response) {
        Ok(body) => json_response(StatusCode::OK, body, state.schema_digest.clone()),
        Err(_) => internal_error_response(
            request_identifier(),
            None,
            state.schema_digest.clone(),
            "MeshSpan could not encode its health contract",
        ),
    }
}

async fn openapi(State(state): State<PublicContractState>) -> Response<Body> {
    let mut response = Response::new(Body::from(state.openapi.as_ref().clone()));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(API_VERSION_HEADER, HeaderValue::from_static("latest"));
    response
        .headers_mut()
        .insert(API_SCHEMA_HEADER, state.schema_digest);
    response
}

/// Public contract router construction failure.
#[derive(Debug, Error)]
pub enum PublicContractApiError {
    /// The Rust-authored contract could not be serialized.
    #[error("could not generate the public API contract: {0}")]
    Contract(#[source] serde_json::Error),
    /// The generated digest was not a valid HTTP header value.
    #[error("the public API schema digest is not a valid HTTP header: {0}")]
    SchemaDigest(#[source] axum::http::header::InvalidHeaderValue),
}
