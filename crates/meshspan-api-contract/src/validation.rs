// SPDX-License-Identifier: GPL-2.0-only

//! Bounded request decoding and outgoing-response validation.

use std::sync::OnceLock;

use jsonschema::Validator;
use serde_json::Value;
use thiserror::Error;

use crate::{
    CreateMeshSetupRequest, CreateMeshSetupResponse, CreateSessionRequest, CreateSessionResponse,
    SetupStatusResponse, model::MAX_ERROR_ISSUES, schema,
};

const MAX_CREATE_SESSION_BYTES: usize = 2_048;
const MAX_CREATE_MESH_SETUP_BYTES: usize = 2_048;

static CREATE_MESH_SETUP_REQUEST_VALIDATOR: OnceLock<Result<Validator, String>> = OnceLock::new();
static CREATE_MESH_SETUP_RESPONSE_VALIDATOR: OnceLock<Result<Validator, String>> = OnceLock::new();
static CREATE_SESSION_REQUEST_VALIDATOR: OnceLock<Result<Validator, String>> = OnceLock::new();
static CREATE_SESSION_RESPONSE_VALIDATOR: OnceLock<Result<Validator, String>> = OnceLock::new();
static SETUP_STATUS_RESPONSE_VALIDATOR: OnceLock<Result<Validator, String>> = OnceLock::new();

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

fn request_validator() -> Result<&'static Validator, BoundaryError> {
    validator_from(
        CREATE_SESSION_REQUEST_VALIDATOR
            .get_or_init(|| compile(&schema::request_schema::<CreateSessionRequest>())),
    )
}

fn create_mesh_setup_request_validator() -> Result<&'static Validator, BoundaryError> {
    validator_from(
        CREATE_MESH_SETUP_REQUEST_VALIDATOR
            .get_or_init(|| compile(&schema::request_schema::<CreateMeshSetupRequest>())),
    )
}

fn create_mesh_setup_response_validator() -> Result<&'static Validator, BoundaryError> {
    validator_from(
        CREATE_MESH_SETUP_RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<CreateMeshSetupResponse>())),
    )
}

fn response_validator() -> Result<&'static Validator, BoundaryError> {
    validator_from(
        CREATE_SESSION_RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<CreateSessionResponse>())),
    )
}

fn setup_status_response_validator() -> Result<&'static Validator, BoundaryError> {
    validator_from(
        SETUP_STATUS_RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<SetupStatusResponse>())),
    )
}

fn compile(schema: &schemars::Schema) -> Result<Validator, String> {
    jsonschema::draft202012::new(schema.as_value()).map_err(|error| error.to_string())
}

fn validator_from(
    result: &'static Result<Validator, String>,
) -> Result<&'static Validator, BoundaryError> {
    result
        .as_ref()
        .map_err(|message| BoundaryError::InvalidSchema(message.clone()))
}

fn validate(validator: &Validator, value: &Value) -> Result<(), BoundaryError> {
    let issues = validator
        .iter_errors(value)
        .take(MAX_ERROR_ISSUES)
        .map(|error| ValidationIssue {
            path: error.instance_path().to_string(),
            constraint: constraint_name(error.schema_path().to_string().as_str()),
        })
        .collect::<Vec<_>>();

    if issues.is_empty() {
        Ok(())
    } else {
        Err(BoundaryError::Invalid { issues })
    }
}

fn constraint_name(schema_path: &str) -> String {
    schema_path
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("schema")
        .replace(['~', '-'], "_")
}
