// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated current-session resource over the public HTTP contract.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{
    ApiErrorCode, CurrentSessionResponse, PrincipalId as ApiPrincipalId, SessionId as ApiSessionId,
    encode_current_session_response, generate_openapi,
};
use meshspan_domain::{AssuranceLevel, UnixMicros};
use thiserror::Error;

use crate::api_http::{
    current_time, error_response, internal_error_response, json_response, request_identifier,
};
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    BrowserSessionAuthority, BrowserSessionAuthorityError,
};

/// Synchronous authenticated-session read executed on a blocking worker.
pub trait CurrentSessionController: Send + 'static {
    /// Returns the current authenticated caller and coarse administration visibility.
    ///
    /// # Errors
    ///
    /// Returns a closed authentication or authority failure without credential details.
    fn current_session(
        &mut self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CurrentSessionResponse, CurrentSessionError>;
}

impl<A> CurrentSessionController for BrowserSessionAuthenticator<A>
where
    A: BrowserSessionAuthority + Send + 'static,
{
    fn current_session(
        &mut self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CurrentSessionResponse, CurrentSessionError> {
        let capability = self.authenticate(
            headers,
            BrowserRequestProtection::Read,
            AssuranceLevel::SingleFactor,
            now,
        )?;
        let session_id = ApiSessionId::from_uuid_bytes(capability.session_id.as_bytes())
            .ok_or(CurrentSessionError::InvalidEvidence)?;
        let principal_id = ApiPrincipalId::from_uuid_bytes(capability.principal_id.as_bytes())
            .ok_or(CurrentSessionError::InvalidEvidence)?;
        Ok(CurrentSessionResponse {
            session_id,
            principal_id,
            expires_at_epoch_micros: capability.expires_at.get(),
            administration_available: capability.is_system_manager(),
        })
    }
}

struct CurrentSessionApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for CurrentSessionApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the authenticated rolling current-session route.
///
/// # Errors
///
/// Fails if the Rust-authored contract or schema-digest header cannot be generated.
pub fn current_session_api_router<C>(controller: C) -> Result<Router, CurrentSessionApiError>
where
    C: CurrentSessionController,
{
    let document = generate_openapi()?;
    let state = CurrentSessionApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/sessions/current",
            get(get_current_session::<C>),
        )
        .with_state(state))
}

async fn get_current_session<C>(
    State(state): State<CurrentSessionApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: CurrentSessionController,
{
    let request_id = request_identifier();
    let Some(now) = current_time() else {
        return failed_closed(request_id, state.schema_digest);
    };
    let headers = request.headers().clone();
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| CurrentSessionExecutionError::Unavailable)?
            .current_session(&headers, now)
            .map_err(CurrentSessionExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_current_session_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed_closed(request_id, state.schema_digest),
        },
        Ok(Err(CurrentSessionExecutionError::Service(error))) => {
            service_error_response(error, request_id, state.schema_digest)
        }
        Ok(Err(CurrentSessionExecutionError::Unavailable)) | Err(_) => {
            failed_closed(request_id, state.schema_digest)
        }
    }
}

fn service_error_response(
    error: CurrentSessionError,
    request_id: String,
    schema_digest: HeaderValue,
) -> Response<Body> {
    match error {
        CurrentSessionError::Authentication(BrowserAuthenticationError::Rejected) => {
            error_response(
                StatusCode::UNAUTHORIZED,
                ApiErrorCode::Unauthenticated,
                "authentication was rejected",
                request_id,
                None,
                Vec::new(),
                schema_digest,
            )
        }
        CurrentSessionError::Authentication(BrowserAuthenticationError::Authority(
            BrowserSessionAuthorityError::Unavailable,
        )) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "authentication authority is temporarily unavailable",
            request_id,
            None,
            Vec::new(),
            schema_digest,
        ),
        CurrentSessionError::InvalidEvidence
        | CurrentSessionError::Authentication(
            BrowserAuthenticationError::InvalidGateway
            | BrowserAuthenticationError::Authority(BrowserSessionAuthorityError::Failed),
        ) => failed_closed(request_id, schema_digest),
    }
}

fn failed_closed(request_id: String, schema_digest: HeaderValue) -> Response<Body> {
    internal_error_response(
        request_id,
        None,
        schema_digest,
        "authentication failed closed",
    )
}

enum CurrentSessionExecutionError {
    Service(CurrentSessionError),
    Unavailable,
}

/// Current-session application failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CurrentSessionError {
    /// Authentication was rejected or its authority failed.
    #[error("current session authentication failed")]
    Authentication(#[from] BrowserAuthenticationError),
    /// Capability identifiers cannot satisfy the public contract.
    #[error("current session evidence is invalid")]
    InvalidEvidence,
}

/// Current-session router construction failure.
#[derive(Debug, Error)]
pub enum CurrentSessionApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
