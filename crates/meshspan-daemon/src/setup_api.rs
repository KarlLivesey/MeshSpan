// SPDX-License-Identifier: GPL-2.0-only

//! Cheap anonymous first-start status over the public HTTP contract.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderName, HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{
    SetupState, SetupStatusResponse, encode_setup_status_response, generate_openapi,
};
use thiserror::Error;

const CLAIM_REQUIRED: u8 = 1;
const CONFIGURING: u8 = 2;
const CONFIGURED: u8 = 3;
const API_VERSION_HEADER: HeaderName = HeaderName::from_static("meshspan-api-version");
const API_SCHEMA_HEADER: HeaderName = HeaderName::from_static("meshspan-api-schema");

/// Read boundary for one already-reconciled daemon setup state.
pub trait SetupStatusSource: Send + Sync + 'static {
    /// Returns the current coarse state without performing remote or expensive work.
    fn setup_state(&self) -> SetupState;
}

/// Lock-free state snapshot updated by daemon lifecycle transitions.
pub struct SetupStateSnapshot {
    state: AtomicU8,
}

impl SetupStateSnapshot {
    /// Creates a snapshot at one valid closed setup state.
    #[must_use]
    pub const fn new(state: SetupState) -> Self {
        Self {
            state: AtomicU8::new(encode_state(state)),
        }
    }

    /// Publishes one lifecycle transition for subsequent API reads.
    pub fn store(&self, state: SetupState) {
        self.state.store(encode_state(state), Ordering::Release);
    }
}

impl SetupStatusSource for SetupStateSnapshot {
    fn setup_state(&self) -> SetupState {
        decode_state(self.state.load(Ordering::Acquire))
    }
}

struct SetupApiState<S> {
    source: Arc<S>,
    schema_digest: HeaderValue,
}

impl<S> Clone for SetupApiState<S> {
    fn clone(&self) -> Self {
        Self {
            source: Arc::clone(&self.source),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the public rolling setup route with its exact generated contract headers.
///
/// # Errors
///
/// Fails if the Rust-authored `OpenAPI` document or its header value cannot be generated.
pub fn setup_api_router<S>(source: Arc<S>) -> Result<Router, SetupApiError>
where
    S: SetupStatusSource,
{
    let document = generate_openapi()?;
    let state = SetupApiState {
        source,
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route("/api/latest/setup/status", get(get_setup_status::<S>))
        .with_state(state))
}

async fn get_setup_status<S>(State(state): State<SetupApiState<S>>) -> Response<Body>
where
    S: SetupStatusSource,
{
    let response = SetupStatusResponse {
        state: state.source.setup_state(),
    };
    let Ok(body) = encode_setup_status_response(&response) else {
        let mut failure = Response::new(Body::empty());
        *failure.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return failure;
    };
    let mut response = Response::new(Body::from(body));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(API_VERSION_HEADER, HeaderValue::from_static("latest"));
    response
        .headers_mut()
        .insert(API_SCHEMA_HEADER, state.schema_digest);
    response
}

const fn encode_state(state: SetupState) -> u8 {
    match state {
        SetupState::ClaimRequired => CLAIM_REQUIRED,
        SetupState::Configuring => CONFIGURING,
        SetupState::Configured => CONFIGURED,
    }
}

const fn decode_state(state: u8) -> SetupState {
    match state {
        CONFIGURING => SetupState::Configuring,
        CONFIGURED => SetupState::Configured,
        CLAIM_REQUIRED | 0 | 4..=u8::MAX => SetupState::ClaimRequired,
    }
}

/// Setup router construction failures which contain no secret material.
#[derive(Debug, Error)]
pub enum SetupApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
