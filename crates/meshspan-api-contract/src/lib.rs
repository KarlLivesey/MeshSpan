// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative public API models, schemas, and trust-boundary validation.

mod model;
mod openapi;
mod schema;
mod validation;

pub use model::{
    ApiError, ApiErrorCode, ApiErrorIssue, AssuranceLevel, CreateMeshSetupRequest,
    CreateMeshSetupResponse, CreatePasskeyChallengeRequest, CreatePasskeyChallengeResponse,
    CreateSessionRequest, CreateSessionResponse, CurrentSessionResponse, HealthResponse,
    HealthStatus, NullableField, OperationId, PasskeyChallengeId, PasskeyUserVerification,
    PrincipalId, RevokeCurrentSessionRequest, RevokeCurrentSessionResponse,
    SessionAdditionalFactor, SessionAuthentication, SessionId, SetupClaim, SetupName, SetupState,
    SetupStatusResponse,
};
pub use openapi::{OPENAPI_PATH, OpenApiDocument, generate_openapi};
pub use validation::{
    BoundaryError, MAX_CREATE_MESH_SETUP_BYTES, MAX_CREATE_PASSKEY_CHALLENGE_BYTES,
    MAX_CREATE_SESSION_BYTES, MAX_REVOKE_CURRENT_SESSION_BYTES, ValidationIssue,
    decode_create_mesh_setup_request, decode_create_passkey_challenge_request,
    decode_create_session_request, decode_revoke_current_session_request, encode_api_error,
    encode_create_mesh_setup_response, encode_create_passkey_challenge_response,
    encode_create_session_response, encode_current_session_response,
    encode_revoke_current_session_response, encode_setup_status_response, validate_api_error_value,
    validate_create_mesh_setup_request_value, validate_create_mesh_setup_response_value,
    validate_create_passkey_challenge_request_value,
    validate_create_passkey_challenge_response_value, validate_create_session_request_value,
    validate_create_session_response_value, validate_revoke_current_session_request_value,
    validate_revoke_current_session_response_value, validate_setup_status_response_value,
};
