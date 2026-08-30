// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative public API models, schemas, and trust-boundary validation.

mod model;
mod openapi;
mod schema;
mod validation;

pub use model::{
    ApiError, ApiErrorCode, ApiErrorIssue, AssuranceLevel, CreateMeshSetupRequest,
    CreateMeshSetupResponse, CreateSessionRequest, CreateSessionResponse, CurrentSessionResponse,
    HealthResponse, HealthStatus, NullableField, OperationId, PrincipalId, SessionAdditionalFactor,
    SessionAuthentication, SessionId, SetupClaim, SetupName, SetupState, SetupStatusResponse,
};
pub use openapi::{OPENAPI_PATH, OpenApiDocument, generate_openapi};
pub use validation::{
    BoundaryError, MAX_CREATE_MESH_SETUP_BYTES, MAX_CREATE_SESSION_BYTES, ValidationIssue,
    decode_create_mesh_setup_request, decode_create_session_request, encode_api_error,
    encode_create_mesh_setup_response, encode_create_session_response,
    encode_current_session_response, encode_setup_status_response, validate_api_error_value,
    validate_create_mesh_setup_request_value, validate_create_mesh_setup_response_value,
    validate_create_session_request_value, validate_create_session_response_value,
    validate_setup_status_response_value,
};
