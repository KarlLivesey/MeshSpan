// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative public API models, schemas, and trust-boundary validation.

mod model;
mod openapi;
mod schema;
mod validation;

pub use model::{
    ApiError, ApiErrorCode, AssuranceLevel, CreateMeshSetupRequest, CreateMeshSetupResponse,
    CreateSessionRequest, CreateSessionResponse, HealthResponse, HealthStatus, NullableField,
    OperationId, SessionAdditionalFactor, SessionAuthentication, SessionId, SetupClaim, SetupName,
    SetupState, SetupStatusResponse,
};
pub use openapi::{OPENAPI_PATH, OpenApiDocument, generate_openapi};
pub use validation::{
    BoundaryError, ValidationIssue, decode_create_mesh_setup_request,
    decode_create_session_request, encode_create_mesh_setup_response,
    encode_create_session_response, encode_setup_status_response,
    validate_create_mesh_setup_request_value, validate_create_mesh_setup_response_value,
    validate_create_session_request_value, validate_create_session_response_value,
    validate_setup_status_response_value,
};
