// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative public API models, schemas, and trust-boundary validation.

mod api_key_management;
mod api_key_validation;
mod model;
mod openapi;
mod passkey_registration;
mod passkey_validation;
mod schema;
mod validation;

pub use api_key_management::{
    ApiKeyExpiry, ApiKeyId, ApiKeyScope, CreateApiKeyRequest, CreateApiKeyResponse,
};
pub use api_key_validation::{
    MAX_CREATE_API_KEY_BYTES, decode_create_api_key_request, encode_create_api_key_response,
    validate_create_api_key_request_value, validate_create_api_key_response_value,
};
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
pub use passkey_registration::{
    AuthenticationMethodId, AuthenticationMethodLabel, CreatePasskeyRegistrationChallengeRequest,
    CreatePasskeyRegistrationChallengeResponse, CreatePasskeyRegistrationRequest,
    CreatePasskeyRegistrationResponse, PasskeyAttestation, PasskeyCredentialDescriptor,
    PasskeyCredentialParameter, PasskeyCredentialType, PasskeyResidentKey, PasskeyTransport,
};
pub use passkey_validation::{
    MAX_CREATE_PASSKEY_CHALLENGE_BYTES, MAX_CREATE_PASSKEY_REGISTRATION_BYTES,
    MAX_CREATE_PASSKEY_REGISTRATION_CHALLENGE_BYTES, decode_create_passkey_challenge_request,
    decode_create_passkey_registration_challenge_request,
    decode_create_passkey_registration_request, encode_create_passkey_challenge_response,
    encode_create_passkey_registration_challenge_response,
    encode_create_passkey_registration_response, validate_create_passkey_challenge_request_value,
    validate_create_passkey_challenge_response_value,
    validate_create_passkey_registration_challenge_request_value,
    validate_create_passkey_registration_challenge_response_value,
    validate_create_passkey_registration_request_value,
    validate_create_passkey_registration_response_value,
};
pub use validation::{
    BoundaryError, MAX_CREATE_MESH_SETUP_BYTES, MAX_CREATE_SESSION_BYTES,
    MAX_REVOKE_CURRENT_SESSION_BYTES, ValidationIssue, decode_create_mesh_setup_request,
    decode_create_session_request, decode_revoke_current_session_request, encode_api_error,
    encode_create_mesh_setup_response, encode_create_session_response,
    encode_current_session_response, encode_revoke_current_session_response,
    encode_setup_status_response, validate_api_error_value,
    validate_create_mesh_setup_request_value, validate_create_mesh_setup_response_value,
    validate_create_session_request_value, validate_create_session_response_value,
    validate_revoke_current_session_request_value, validate_revoke_current_session_response_value,
    validate_setup_status_response_value,
};
