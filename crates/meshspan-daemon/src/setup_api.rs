// SPDX-License-Identifier: GPL-2.0-only

//! Bounded public first-start HTTP routes over the generated contract.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::{get, post};
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, CreateMeshSetupRequest, CreateMeshSetupResponse,
    MAX_CREATE_MESH_SETUP_BYTES, OperationId as ApiOperationId, SetupState, SetupStatusResponse,
    decode_create_mesh_setup_request, encode_create_mesh_setup_response,
    encode_setup_status_response, generate_openapi,
};
use meshspan_domain::UnixMicros;
use meshspan_metadata::{
    LocalClaimError, LocalClaimState, LocalDatabase, LocalSetupError, LocalSetupState,
};
use thiserror::Error;

use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type,
    internal_error_response as shared_internal_error_response, issue, json_response,
    request_identifier,
};
use crate::{
    BootstrapAuthority, BootstrapAuthorityError, CreateMeshSetupError, CreateMeshSetupService,
};

const CLAIM_REQUIRED: u8 = 1;
const CONFIGURING: u8 = 2;
const CONFIGURED: u8 = 3;

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

    /// Verifies durable claim/setup evidence and publishes the resulting lifecycle state.
    ///
    /// # Errors
    ///
    /// Fails closed if local evidence is unreadable or its claim and setup states disagree.
    pub fn reconcile(&self, database: &LocalDatabase) -> Result<SetupState, SetupLifecycleError> {
        let setup = database.local_setup()?;
        let next = if let Some(setup) = setup {
            let claim = database
                .local_claim_record(setup.claim_id)?
                .ok_or(SetupLifecycleError::Inconsistent)?;
            match setup.state {
                LocalSetupState::Prepared | LocalSetupState::AuthorityCommitted
                    if claim.state == LocalClaimState::Active =>
                {
                    SetupState::Configuring
                }
                LocalSetupState::Configured if claim.state == LocalClaimState::Consumed => {
                    SetupState::Configured
                }
                LocalSetupState::Prepared
                | LocalSetupState::AuthorityCommitted
                | LocalSetupState::Configured => return Err(SetupLifecycleError::Inconsistent),
            }
        } else if database.active_local_claim()?.is_some() {
            SetupState::ClaimRequired
        } else {
            return Err(SetupLifecycleError::Inconsistent);
        };
        self.store(next);
        Ok(next)
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

/// Synchronous first-mesh application boundary executed on a blocking worker.
pub trait CreateMeshSetupController: Send + 'static {
    /// Commits or exactly resolves one validated first-mesh request.
    ///
    /// # Errors
    ///
    /// Returns a closed service error without exposing submitted secret material.
    fn create_mesh(
        &mut self,
        request: &CreateMeshSetupRequest,
        now: UnixMicros,
    ) -> Result<CreateMeshSetupResponse, CreateMeshSetupError>;
}

impl<A, R> CreateMeshSetupController for CreateMeshSetupService<A, R>
where
    A: BootstrapAuthority + Send + 'static,
    R: meshspan_domain::RandomSource + Send + 'static,
{
    fn create_mesh(
        &mut self,
        request: &CreateMeshSetupRequest,
        now: UnixMicros,
    ) -> Result<CreateMeshSetupResponse, CreateMeshSetupError> {
        self.create(request, now)
    }
}

struct SetupMutationApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for SetupMutationApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the complete first-start API, including bounded first-mesh creation.
///
/// The mutation runs on Tokio's blocking pool so synchronous durable SQLite work cannot
/// stall unrelated HTTP connections.
///
/// # Errors
///
/// Fails if the Rust-authored `OpenAPI` document or its header value cannot be generated.
pub fn setup_api_router_with_creation<S, C>(
    source: Arc<S>,
    controller: C,
) -> Result<Router, SetupApiError>
where
    S: SetupStatusSource,
    C: CreateMeshSetupController,
{
    let status_router = setup_api_router(source)?;
    let document = generate_openapi()?;
    let mutation_state = SetupMutationApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    let mutation_router = Router::new()
        .route("/api/latest/setup/meshes", post(post_create_mesh::<C>))
        .with_state(mutation_state);
    Ok(status_router.merge(mutation_router))
}

async fn post_create_mesh<C>(
    State(state): State<SetupMutationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: CreateMeshSetupController,
{
    let request_id = request_identifier();
    if !has_json_content_type(request.headers()) {
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
    let Ok(bytes) = to_bytes(request.into_body(), MAX_CREATE_MESH_SETUP_BYTES).await else {
        return error_response(
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "request body exceeds its byte limit",
            request_id,
            None,
            vec![issue("", "max_bytes")],
            state.schema_digest,
        );
    };
    let request = match decode_create_mesh_setup_request(&bytes) {
        Ok(request) => request,
        Err(
            BoundaryError::InvalidSchema(_)
            | BoundaryError::DecodeMismatch
            | BoundaryError::EncodeMismatch,
        ) => {
            return internal_error_response(request_id, None, state.schema_digest);
        }
        Err(error) => {
            let issues = boundary_issues(error);
            return error_response(
                StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                "request does not satisfy the public contract",
                request_id,
                None,
                issues,
                state.schema_digest,
            );
        }
    };
    let operation_id = Some(request.operation_id.clone());
    let Some(now) = current_time() else {
        return internal_error_response(request_id, operation_id, state.schema_digest);
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| CreateExecutionError::Unavailable)?
            .create_mesh(&request, now)
            .map_err(CreateExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_create_mesh_setup_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => internal_error_response(request_id, operation_id, state.schema_digest),
        },
        Ok(Err(CreateExecutionError::Service(error))) => {
            service_error_response(&error, request_id, operation_id, state.schema_digest)
        }
        Ok(Err(CreateExecutionError::Unavailable)) | Err(_) => {
            internal_error_response(request_id, operation_id, state.schema_digest)
        }
    }
}

async fn get_setup_status<S>(State(state): State<SetupApiState<S>>) -> Response<Body>
where
    S: SetupStatusSource,
{
    let response = SetupStatusResponse {
        state: state.source.setup_state(),
    };
    let Ok(body) = encode_setup_status_response(&response) else {
        return internal_error_response(request_identifier(), None, state.schema_digest);
    };
    json_response(StatusCode::OK, body, state.schema_digest)
}

fn service_error_response(
    error: &CreateMeshSetupError,
    request_id: String,
    operation_id: Option<ApiOperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        CreateMeshSetupError::InvalidUuid
        | CreateMeshSetupError::Identifier(_)
        | CreateMeshSetupError::Name(_) => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "request contains an invalid domain value",
        ),
        CreateMeshSetupError::Claim(_)
        | CreateMeshSetupError::Local(LocalSetupError::ClaimRejected) => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "first-boot claim was not accepted",
        ),
        CreateMeshSetupError::Local(LocalSetupError::Conflict)
        | CreateMeshSetupError::Authority(BootstrapAuthorityError::Conflict) => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "setup operation conflicts with durable state",
        ),
        CreateMeshSetupError::Authority(BootstrapAuthorityError::Unavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "bootstrap authority is temporarily unavailable",
        ),
        CreateMeshSetupError::Material(_)
        | CreateMeshSetupError::Certificate
        | CreateMeshSetupError::InitialSecretEnvelope(_)
        | CreateMeshSetupError::RecoveryCode(_)
        | CreateMeshSetupError::RecoveryBundle(_)
        | CreateMeshSetupError::Local(LocalSetupError::Store | LocalSetupError::Invalid)
        | CreateMeshSetupError::Authority(BootstrapAuthorityError::Failed)
        | CreateMeshSetupError::ClaimFile(_)
        | CreateMeshSetupError::Lifecycle(_)
        | CreateMeshSetupError::Inconsistent => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalContract,
            "setup failed closed",
        ),
    };
    error_response(
        status,
        code,
        message,
        request_id,
        operation_id,
        Vec::new(),
        schema_digest,
    )
}

fn internal_error_response(
    request_id: String,
    operation_id: Option<ApiOperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    shared_internal_error_response(
        request_id,
        operation_id,
        schema_digest,
        "setup failed closed",
    )
}

enum CreateExecutionError {
    Service(CreateMeshSetupError),
    Unavailable,
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

/// Failure to derive public setup state from durable local evidence.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SetupLifecycleError {
    /// Setup journal persistence or validation failed.
    #[error("local setup state is unavailable")]
    Setup(#[from] LocalSetupError),
    /// Claim persistence or validation failed.
    #[error("local claim state is unavailable")]
    Claim(#[from] LocalClaimError),
    /// Individually valid claim and setup records disagree.
    #[error("local claim and setup state are inconsistent")]
    Inconsistent,
}
