// SPDX-License-Identifier: GPL-2.0-only

//! Bounded passkey request decoding and response validation.

use std::sync::OnceLock;

use serde_json::Value;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, CreatePasskeyChallengeRequest, CreatePasskeyChallengeResponse,
    CreatePasskeyRegistrationChallengeRequest, CreatePasskeyRegistrationChallengeResponse,
    CreatePasskeyRegistrationRequest, CreatePasskeyRegistrationResponse, schema,
};

/// Maximum accepted body size for creating a passkey authentication challenge.
pub const MAX_CREATE_PASSKEY_CHALLENGE_BYTES: usize = 256;
/// Maximum accepted body size for creating a passkey registration challenge.
pub const MAX_CREATE_PASSKEY_REGISTRATION_CHALLENGE_BYTES: usize = 256;
/// Maximum accepted body size for completing passkey registration.
pub const MAX_CREATE_PASSKEY_REGISTRATION_BYTES: usize = 30_000;

static CHALLENGE_REQUEST_VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CHALLENGE_RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REGISTRATION_CHALLENGE_REQUEST_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static REGISTRATION_CHALLENGE_RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static REGISTRATION_REQUEST_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();
static REGISTRATION_RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> =
    OnceLock::new();

/// Validates and decodes one bounded passkey authentication challenge request.
///
/// # Errors
///
/// Returns before ceremony work for oversized, malformed or schema-invalid input.
pub fn decode_create_passkey_challenge_request(
    bytes: &[u8],
) -> Result<CreatePasskeyChallengeRequest, BoundaryError> {
    decode_request(
        bytes,
        MAX_CREATE_PASSKEY_CHALLENGE_BYTES,
        challenge_request_validator()?,
    )
}

/// Validates raw passkey authentication challenge input.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_create_passkey_challenge_request_value(value: &Value) -> Result<(), BoundaryError> {
    validate(challenge_request_validator()?, value)
}

/// Validates and encodes browser-ready passkey authentication options.
///
/// # Errors
///
/// Returns an encoding or outgoing-contract failure.
pub fn encode_create_passkey_challenge_response(
    response: &CreatePasskeyChallengeResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response, challenge_response_validator()?)
}

/// Validates raw passkey authentication challenge output.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_create_passkey_challenge_response_value(
    value: &Value,
) -> Result<(), BoundaryError> {
    validate(challenge_response_validator()?, value)
}

/// Validates and decodes one current-user registration challenge request.
///
/// # Errors
///
/// Rejects excessive, malformed, schema-invalid or unexpectedly undecodable input.
pub fn decode_create_passkey_registration_challenge_request(
    bytes: &[u8],
) -> Result<CreatePasskeyRegistrationChallengeRequest, BoundaryError> {
    decode_request(
        bytes,
        MAX_CREATE_PASSKEY_REGISTRATION_CHALLENGE_BYTES,
        registration_challenge_request_validator()?,
    )
}

/// Validates raw current-user registration challenge input.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_create_passkey_registration_challenge_request_value(
    value: &Value,
) -> Result<(), BoundaryError> {
    validate(registration_challenge_request_validator()?, value)
}

/// Validates and encodes browser-ready current-user registration options.
///
/// # Errors
///
/// Returns an encoding or outgoing-contract failure.
pub fn encode_create_passkey_registration_challenge_response(
    response: &CreatePasskeyRegistrationChallengeResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response, registration_challenge_response_validator()?)
}

/// Validates raw current-user registration challenge output.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_create_passkey_registration_challenge_response_value(
    value: &Value,
) -> Result<(), BoundaryError> {
    validate(registration_challenge_response_validator()?, value)
}

/// Validates and decodes one bounded passkey registration response.
///
/// # Errors
///
/// Rejects excessive, malformed, schema-invalid or unexpectedly undecodable input.
pub fn decode_create_passkey_registration_request(
    bytes: &[u8],
) -> Result<CreatePasskeyRegistrationRequest, BoundaryError> {
    decode_request(
        bytes,
        MAX_CREATE_PASSKEY_REGISTRATION_BYTES,
        registration_request_validator()?,
    )
}

/// Validates raw passkey registration input.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_create_passkey_registration_request_value(
    value: &Value,
) -> Result<(), BoundaryError> {
    validate(registration_request_validator()?, value)
}

/// Validates and encodes one committed passkey registration result.
///
/// # Errors
///
/// Returns an encoding or outgoing-contract failure.
pub fn encode_create_passkey_registration_response(
    response: &CreatePasskeyRegistrationResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response, registration_response_validator()?)
}

/// Validates raw committed passkey registration output.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_create_passkey_registration_response_value(
    value: &Value,
) -> Result<(), BoundaryError> {
    validate(registration_response_validator()?, value)
}

fn decode_request<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
    validator: &CompiledValidator,
) -> Result<T, BoundaryError> {
    if bytes.len() > limit {
        return Err(BoundaryError::BodyTooLarge { limit });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(validator, &value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

fn encode_response<T: serde::Serialize>(
    response: &T,
    validator: &CompiledValidator,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(validator, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn challenge_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        CHALLENGE_REQUEST_VALIDATOR
            .get_or_init(|| compile(&schema::request_schema::<CreatePasskeyChallengeRequest>())),
    )
}

fn challenge_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        CHALLENGE_RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<CreatePasskeyChallengeResponse>())),
    )
}

fn registration_challenge_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(REGISTRATION_CHALLENGE_REQUEST_VALIDATOR.get_or_init(|| {
        compile(&schema::request_schema::<
            CreatePasskeyRegistrationChallengeRequest,
        >())
    }))
}

fn registration_challenge_response_validator() -> Result<&'static CompiledValidator, BoundaryError>
{
    validator_from(REGISTRATION_CHALLENGE_RESPONSE_VALIDATOR.get_or_init(|| {
        compile(&schema::response_schema::<
            CreatePasskeyRegistrationChallengeResponse,
        >())
    }))
}

fn registration_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        REGISTRATION_REQUEST_VALIDATOR
            .get_or_init(|| compile(&schema::request_schema::<CreatePasskeyRegistrationRequest>())),
    )
}

fn registration_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        REGISTRATION_RESPONSE_VALIDATOR.get_or_init(|| {
            compile(&schema::response_schema::<CreatePasskeyRegistrationResponse>())
        }),
    )
}
