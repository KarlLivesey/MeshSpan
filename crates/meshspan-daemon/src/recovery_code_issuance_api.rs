// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTPS boundary for current-user recovery-code issuance.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, CreateRecoveryCodesRequest, CreateRecoveryCodesResponse,
    MAX_CREATE_RECOVERY_CODES_BYTES, decode_create_recovery_codes_request,
    encode_create_recovery_codes_response, generate_openapi,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, json_response, request_identifier,
};
use crate::{
    BrowserAuthenticationError, BrowserSessionAuthorityError, RecoveryCodeIssuanceAuthority,
    RecoveryCodeIssuanceAuthorityError, RecoveryCodeIssuanceError, RecoveryCodeIssuanceService,
};

/// Synchronous issuance boundary executed on a bounded blocking worker.
pub trait RecoveryCodeIssuanceController: Send + 'static {
    /// Issues or exactly replays one current-user recovery-code set.
    ///
    /// # Errors
    ///
    /// Returns only stable authentication, request, conflict, availability or integrity failures.
    fn issue_recovery_codes(
        &mut self,
        request: &CreateRecoveryCodesRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateRecoveryCodesResponse, RecoveryCodeIssuanceError>;
}

impl<A> RecoveryCodeIssuanceController for RecoveryCodeIssuanceService<A>
where
    A: RecoveryCodeIssuanceAuthority + Send + 'static,
{
    fn issue_recovery_codes(
        &mut self,
        request: &CreateRecoveryCodesRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateRecoveryCodesResponse, RecoveryCodeIssuanceError> {
        self.issue(request, headers, now)
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

/// Builds the rolling current-user recovery-code issuance endpoint.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn recovery_code_issuance_api_router<C>(
    controller: C,
) -> Result<Router, RecoveryCodeIssuanceApiError>
where
    C: RecoveryCodeIssuanceController,
{
    let document = generate_openapi()?;
    let state = ApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/users/current/authentication-methods/recovery-codes",
            post(post_recovery_codes::<C>),
        )
        .with_state(state))
}

async fn post_recovery_codes<C>(
    State(state): State<ApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: RecoveryCodeIssuanceController,
{
    let request_id = request_identifier();
    let headers = request.headers().clone();
    if !has_json_content_type(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "content type must be application/json",
            request_id,
            None,
            vec![issue("", "content_type")],
            state.schema_digest,
        );
    }
    let Ok(bytes) = to_bytes(request.into_body(), MAX_CREATE_RECOVERY_CODES_BYTES).await else {
        return invalid_body(request_id, state.schema_digest);
    };
    let decoded = match decode_create_recovery_codes_request(&bytes) {
        Ok(decoded) => decoded,
        Err(
            BoundaryError::InvalidSchema(_)
            | BoundaryError::DecodeMismatch
            | BoundaryError::EncodeMismatch,
        ) => return failed_closed(request_id, None, state.schema_digest),
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                "request does not satisfy the public contract",
                request_id,
                None,
                boundary_issues(error),
                state.schema_digest,
            );
        }
    };
    execute(state, request_id, headers, decoded).await
}

async fn execute<C>(
    state: ApiState<C>,
    request_id: String,
    headers: HeaderMap,
    request: CreateRecoveryCodesRequest,
) -> Response<Body>
where
    C: RecoveryCodeIssuanceController,
{
    let operation_id = request.operation_id.clone();
    let Some(now) = current_time() else {
        return failed_closed(request_id, Some(operation_id), state.schema_digest);
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        let mut controller = controller
            .lock()
            .map_err(|_| IssuanceExecutionError::Unavailable)?;
        controller
            .issue_recovery_codes(&request, &headers, now)
            .map_err(IssuanceExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_create_recovery_codes_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => failed_closed(request_id, Some(operation_id), state.schema_digest),
        },
        Ok(Err(IssuanceExecutionError::Service(error))) => {
            let (status, code, message) = classify_error(&error);
            error_response(
                status,
                code,
                message,
                request_id,
                Some(operation_id),
                Vec::new(),
                state.schema_digest,
            )
        }
        Ok(Err(IssuanceExecutionError::Unavailable)) | Err(_) => {
            failed_closed(request_id, Some(operation_id), state.schema_digest)
        }
    }
}

fn classify_error(error: &RecoveryCodeIssuanceError) -> (StatusCode, ApiErrorCode, &'static str) {
    match error {
        RecoveryCodeIssuanceError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "recovery-code issuance request is invalid",
        ),
        RecoveryCodeIssuanceError::Authentication(BrowserAuthenticationError::Rejected) => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        RecoveryCodeIssuanceError::Conflict
        | RecoveryCodeIssuanceError::Authority(RecoveryCodeIssuanceAuthorityError::Conflict) => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "recovery-code issuance conflicts with durable state",
        ),
        RecoveryCodeIssuanceError::Authority(RecoveryCodeIssuanceAuthorityError::Unavailable)
        | RecoveryCodeIssuanceError::Authentication(BrowserAuthenticationError::Authority(
            BrowserSessionAuthorityError::Unavailable,
        )) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "recovery-code issuance is temporarily unavailable",
        ),
        RecoveryCodeIssuanceError::Material
        | RecoveryCodeIssuanceError::InvalidReceipt
        | RecoveryCodeIssuanceError::Authority(RecoveryCodeIssuanceAuthorityError::Failed)
        | RecoveryCodeIssuanceError::Authentication(
            BrowserAuthenticationError::InvalidGateway
            | BrowserAuthenticationError::Authority(BrowserSessionAuthorityError::Failed),
        ) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "recovery-code issuance failed closed",
        ),
    }
}

fn invalid_body(request_id: String, schema_digest: HeaderValue) -> Response<Body> {
    error_response(
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
        "request does not satisfy the public contract",
        request_id,
        None,
        vec![issue("", "max_bytes")],
        schema_digest,
    )
}

fn failed_closed(
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    internal_error_response(
        request_id,
        operation_id,
        schema_digest,
        "recovery-code issuance failed closed",
    )
}

enum IssuanceExecutionError {
    Service(RecoveryCodeIssuanceError),
    Unavailable,
}

/// Recovery-code issuance router construction failure.
#[derive(Debug, Error)]
pub enum RecoveryCodeIssuanceApiError {
    /// Rust-authored contract generation failed.
    #[error("recovery-code issuance contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// Schema digest could not be represented as an HTTP header.
    #[error("recovery-code issuance schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
