// SPDX-License-Identifier: GPL-2.0-only

//! Bounded request decoding and outgoing-response validation.

use std::sync::OnceLock;

use boon::{Compiler, Draft, SchemaIndex, Schemas, ValidationError};
use serde_json::Value;
use thiserror::Error;

use crate::{
    ApiError, CreateMeshSetupRequest, CreateMeshSetupResponse, CreatePasskeyChallengeRequest,
    CreatePasskeyChallengeResponse, CreateSessionRequest, CreateSessionResponse,
    CurrentSessionResponse, RevokeCurrentSessionRequest, RevokeCurrentSessionResponse,
    SetupStatusResponse, model::MAX_ERROR_ISSUES, schema,
};

/// Maximum accepted body size for one session-creation request.
pub const MAX_CREATE_SESSION_BYTES: usize = 2_048;
/// Maximum accepted body size for one first-mesh setup request.
pub const MAX_CREATE_MESH_SETUP_BYTES: usize = 2_048;
/// Maximum accepted body size for creating a passkey challenge.
pub const MAX_CREATE_PASSKEY_CHALLENGE_BYTES: usize = 256;
/// Maximum accepted body size for one current-session revocation request.
pub const MAX_REVOKE_CURRENT_SESSION_BYTES: usize = 256;

static API_ERROR_VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CREATE_MESH_SETUP_REQUEST_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static CREATE_MESH_SETUP_RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static CREATE_PASSKEY_CHALLENGE_REQUEST_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static CREATE_PASSKEY_CHALLENGE_RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static CREATE_SESSION_REQUEST_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static CREATE_SESSION_RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static CURRENT_SESSION_RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static REVOKE_CURRENT_SESSION_REQUEST_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static REVOKE_CURRENT_SESSION_RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static SETUP_STATUS_RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();

struct CompiledValidator {
    schemas: Schemas,
    schema: SchemaIndex,
}

/// Validates and encodes a public error before transmission.
///
/// # Errors
///
/// Returns an encoding or outgoing-contract error instead of emitting an invalid envelope.
pub fn encode_api_error(response: &ApiError) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_api_error_value(&value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates a raw public error against the Rust-authored response schema.
///
/// # Errors
///
/// Returns every discovered issue up to the public issue limit.
pub fn validate_api_error_value(value: &Value) -> Result<(), BoundaryError> {
    validate(api_error_validator()?, value)
}

/// Validates and decodes a first-mesh setup request without coercion.
///
/// # Errors
///
/// Returns a bounded boundary error before domain or persistence work begins.
pub fn decode_create_mesh_setup_request(
    bytes: &[u8],
) -> Result<CreateMeshSetupRequest, BoundaryError> {
    if bytes.len() > MAX_CREATE_MESH_SETUP_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CREATE_MESH_SETUP_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate_create_mesh_setup_request_value(&value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validates raw first-mesh setup input against the Rust-authored request schema.
///
/// # Errors
///
/// Returns every discovered issue up to the public issue limit.
pub fn validate_create_mesh_setup_request_value(value: &Value) -> Result<(), BoundaryError> {
    validate(create_mesh_setup_request_validator()?, value)
}

/// Validates and encodes a committed first-mesh setup response before transmission.
///
/// # Errors
///
/// Returns an encoding or outgoing-contract error instead of leaking invalid output.
pub fn encode_create_mesh_setup_response(
    response: &CreateMeshSetupResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_create_mesh_setup_response_value(&value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates raw first-mesh setup output against the Rust-authored response schema.
///
/// # Errors
///
/// Returns every discovered issue up to the public issue limit.
pub fn validate_create_mesh_setup_response_value(value: &Value) -> Result<(), BoundaryError> {
    validate(create_mesh_setup_response_validator()?, value)
}

/// Validates and decodes one bounded passkey challenge-creation request.
///
/// # Errors
///
/// Returns before ceremony work for oversized, malformed or schema-invalid input.
pub fn decode_create_passkey_challenge_request(
    bytes: &[u8],
) -> Result<CreatePasskeyChallengeRequest, BoundaryError> {
    if bytes.len() > MAX_CREATE_PASSKEY_CHALLENGE_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CREATE_PASSKEY_CHALLENGE_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate_create_passkey_challenge_request_value(&value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validates raw passkey challenge input against the Rust-authored schema.
///
/// # Errors
///
/// Returns all discovered issues up to the public issue limit.
pub fn validate_create_passkey_challenge_request_value(value: &Value) -> Result<(), BoundaryError> {
    validate(create_passkey_challenge_request_validator()?, value)
}

/// Validates and encodes one browser-ready passkey challenge response.
///
/// # Errors
///
/// Returns an outgoing-contract error instead of emitting malformed options.
pub fn encode_create_passkey_challenge_response(
    response: &CreatePasskeyChallengeResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_create_passkey_challenge_response_value(&value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates raw passkey challenge output against the Rust-authored schema.
///
/// # Errors
///
/// Returns all discovered issues up to the public issue limit.
pub fn validate_create_passkey_challenge_response_value(
    value: &Value,
) -> Result<(), BoundaryError> {
    validate(create_passkey_challenge_response_validator()?, value)
}

/// One safe, bounded description of a structural contract violation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationIssue {
    /// JSON Pointer to the rejected value.
    pub path: String,
    /// JSON Schema keyword that rejected the value.
    pub constraint: String,
}

/// Failure at a public JSON trust boundary.
#[derive(Debug, Error)]
pub enum BoundaryError {
    /// The declared byte limit was exceeded before JSON parsing.
    #[error("request body exceeds the {limit}-byte limit")]
    BodyTooLarge {
        /// Maximum accepted body size in bytes.
        limit: usize,
    },
    /// The bytes were not one complete JSON value.
    #[error("request body is not valid JSON")]
    MalformedJson,
    /// JSON was well formed but violated the authoritative schema.
    #[error("message violates its public schema")]
    Invalid {
        /// Bounded structural issues with no raw input values.
        issues: Vec<ValidationIssue>,
    },
    /// A schema compiled from Rust constraints was itself invalid.
    #[error("authoritative schema could not be compiled: {0}")]
    InvalidSchema(String),
    /// A validated value could not be converted to its Rust boundary type.
    #[error("validated message could not be decoded")]
    DecodeMismatch,
    /// A Rust response could not be encoded as JSON.
    #[error("response could not be encoded")]
    EncodeMismatch,
}

/// Validates and decodes a create-session request without coercion.
///
/// # Errors
///
/// Returns a bounded boundary error for an oversized, malformed, schema-invalid,
/// or unexpectedly undecodable request.
pub fn decode_create_session_request(bytes: &[u8]) -> Result<CreateSessionRequest, BoundaryError> {
    if bytes.len() > MAX_CREATE_SESSION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CREATE_SESSION_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate_create_session_request_value(&value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validates a raw create-session request against the Rust-authored schema.
///
/// # Errors
///
/// Returns all discovered issues up to the public issue limit.
pub fn validate_create_session_request_value(value: &Value) -> Result<(), BoundaryError> {
    validate(request_validator()?, value)
}

/// Validates and encodes a create-session response before transmission.
///
/// # Errors
///
/// Returns an encoding or outgoing-contract error instead of emitting an invalid body.
pub fn encode_create_session_response(
    response: &CreateSessionResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_create_session_response_value(&value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates a raw create-session response against the Rust-authored schema.
///
/// # Errors
///
/// Returns all discovered issues up to the public issue limit.
pub fn validate_create_session_response_value(value: &Value) -> Result<(), BoundaryError> {
    validate(response_validator()?, value)
}

/// Validates and encodes the current authenticated-session response before transmission.
///
/// # Errors
///
/// Returns an encoding or outgoing-contract error instead of emitting an invalid body.
pub fn encode_current_session_response(
    response: &CurrentSessionResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(current_session_response_validator()?, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates and decodes an idempotent current-session revocation request.
///
/// # Errors
///
/// Rejects oversized, malformed, schema-invalid or unexpectedly undecodable input.
pub fn decode_revoke_current_session_request(
    bytes: &[u8],
) -> Result<RevokeCurrentSessionRequest, BoundaryError> {
    if bytes.len() > MAX_REVOKE_CURRENT_SESSION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_REVOKE_CURRENT_SESSION_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate_revoke_current_session_request_value(&value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validates raw current-session revocation input against the Rust-authored schema.
///
/// # Errors
///
/// Returns all discovered issues up to the public issue limit.
pub fn validate_revoke_current_session_request_value(value: &Value) -> Result<(), BoundaryError> {
    validate(revoke_current_session_request_validator()?, value)
}

/// Validates and encodes an authoritative current-session revocation result.
///
/// # Errors
///
/// Suppresses an invalid outgoing body.
pub fn encode_revoke_current_session_response(
    response: &RevokeCurrentSessionResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_revoke_current_session_response_value(&value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates raw current-session revocation output against the Rust-authored schema.
///
/// # Errors
///
/// Returns all discovered issues up to the public issue limit.
pub fn validate_revoke_current_session_response_value(value: &Value) -> Result<(), BoundaryError> {
    validate(revoke_current_session_response_validator()?, value)
}

/// Validates and encodes anonymous setup status before transmission.
///
/// # Errors
///
/// Returns an encoding or outgoing-contract error instead of emitting an invalid body.
pub fn encode_setup_status_response(
    response: &SetupStatusResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_setup_status_response_value(&value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates raw setup status against the Rust-authored response schema.
///
/// # Errors
///
/// Returns every discovered issue up to the public issue limit.
pub fn validate_setup_status_response_value(value: &Value) -> Result<(), BoundaryError> {
    validate(setup_status_response_validator()?, value)
}

fn request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        CREATE_SESSION_REQUEST_VALIDATOR
            .get_or_init(|| compile(&schema::request_schema::<CreateSessionRequest>())),
    )
}

fn api_error_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        API_ERROR_VALIDATOR.get_or_init(|| compile(&schema::response_schema::<ApiError>())),
    )
}

fn create_mesh_setup_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        CREATE_MESH_SETUP_REQUEST_VALIDATOR
            .get_or_init(|| compile(&schema::request_schema::<CreateMeshSetupRequest>())),
    )
}

fn create_mesh_setup_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        CREATE_MESH_SETUP_RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<CreateMeshSetupResponse>())),
    )
}

fn create_passkey_challenge_request_validator() -> Result<&'static CompiledValidator, BoundaryError>
{
    validator_from(
        CREATE_PASSKEY_CHALLENGE_REQUEST_VALIDATOR
            .get_or_init(|| compile(&schema::request_schema::<CreatePasskeyChallengeRequest>())),
    )
}

fn create_passkey_challenge_response_validator() -> Result<&'static CompiledValidator, BoundaryError>
{
    validator_from(
        CREATE_PASSKEY_CHALLENGE_RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<CreatePasskeyChallengeResponse>())),
    )
}

fn response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        CREATE_SESSION_RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<CreateSessionResponse>())),
    )
}

fn current_session_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        CURRENT_SESSION_RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<CurrentSessionResponse>())),
    )
}

fn revoke_current_session_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        REVOKE_CURRENT_SESSION_REQUEST_VALIDATOR
            .get_or_init(|| compile(&schema::request_schema::<RevokeCurrentSessionRequest>())),
    )
}

fn revoke_current_session_response_validator() -> Result<&'static CompiledValidator, BoundaryError>
{
    validator_from(
        REVOKE_CURRENT_SESSION_RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<RevokeCurrentSessionResponse>())),
    )
}

fn setup_status_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        SETUP_STATUS_RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<SetupStatusResponse>())),
    )
}

fn compile(schema: &schemars::Schema) -> Result<CompiledValidator, String> {
    const SCHEMA_LOCATION: &str = "https://schemas.meshspan.invalid/public-api.json";

    let mut compiler = Compiler::new();
    compiler.set_default_draft(Draft::V2020_12);
    compiler
        .add_resource(SCHEMA_LOCATION, schema.as_value().clone())
        .map_err(|error| error.to_string())?;
    let mut schemas = Schemas::new();
    let schema = compiler
        .compile(SCHEMA_LOCATION, &mut schemas)
        .map_err(|error| error.to_string())?;
    Ok(CompiledValidator { schemas, schema })
}

fn validator_from(
    result: &'static Result<CompiledValidator, String>,
) -> Result<&'static CompiledValidator, BoundaryError> {
    result
        .as_ref()
        .map_err(|message| BoundaryError::InvalidSchema(message.clone()))
}

fn validate(validator: &CompiledValidator, value: &Value) -> Result<(), BoundaryError> {
    match validator.schemas.validate(value, validator.schema) {
        Ok(()) => Ok(()),
        Err(error) => {
            let mut issues = Vec::new();
            collect_issues(&error, &mut issues);
            if issues.is_empty() {
                issues.push(ValidationIssue {
                    path: error.instance_location.to_string(),
                    constraint: constraint(&error),
                });
            }
            Err(BoundaryError::Invalid { issues })
        }
    }
}

fn collect_issues(error: &ValidationError<'_, '_>, issues: &mut Vec<ValidationIssue>) {
    if issues.len() >= MAX_ERROR_ISSUES {
        return;
    }
    if error.causes.is_empty() {
        issues.push(ValidationIssue {
            path: error.instance_location.to_string(),
            constraint: constraint(error),
        });
        return;
    }
    for cause in &error.causes {
        collect_issues(cause, issues);
        if issues.len() >= MAX_ERROR_ISSUES {
            break;
        }
    }
}

fn constraint(error: &ValidationError<'_, '_>) -> String {
    error.kind.keyword_path().map_or_else(
        || "schema".to_owned(),
        |path| public_constraint(path.keyword),
    )
}

fn public_constraint(keyword: &str) -> String {
    let mut output = String::with_capacity(keyword.len().min(64));
    for character in keyword.chars() {
        if output.len() >= 64 {
            break;
        }
        if character.is_ascii_uppercase() {
            if !output.is_empty() && !output.ends_with('_') {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
        } else if character.is_ascii_lowercase() || character.is_ascii_digit() {
            output.push(character);
        } else if !output.is_empty() && !output.ends_with('_') {
            output.push('_');
        }
    }
    while output.ends_with('_') {
        output.pop();
    }
    if output
        .as_bytes()
        .first()
        .is_none_or(|character| !character.is_ascii_lowercase())
    {
        "schema".to_owned()
    } else {
        output
    }
}
