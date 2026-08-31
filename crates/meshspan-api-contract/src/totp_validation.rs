// SPDX-License-Identifier: GPL-2.0-only

//! Bounded current-user TOTP registration request and response validation.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, CreateTotpRegistrationChallengeRequest, CreateTotpRegistrationChallengeResponse,
    CreateTotpRegistrationRequest, CreateTotpRegistrationResponse, schema,
};

/// Maximum accepted body size for TOTP registration-material creation.
pub const MAX_CREATE_TOTP_REGISTRATION_CHALLENGE_BYTES: usize = 512;
/// Maximum accepted body size for TOTP registration confirmation.
pub const MAX_CREATE_TOTP_REGISTRATION_BYTES: usize = 512;

static CHALLENGE_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CHALLENGE_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REGISTRATION_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REGISTRATION_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Validates and decodes one bounded registration-material request.
///
/// # Errors
///
/// Returns a boundary error when the body is oversized, malformed, structurally invalid, or
/// cannot be decoded into the schema-backed request model.
pub fn decode_create_totp_registration_challenge_request(
    bytes: &[u8],
) -> Result<CreateTotpRegistrationChallengeRequest, BoundaryError> {
    decode(
        bytes,
        MAX_CREATE_TOTP_REGISTRATION_CHALLENGE_BYTES,
        challenge_request()?,
    )
}

/// Validates and encodes one secret-bearing registration-material response.
///
/// # Errors
///
/// Returns a boundary error when the response cannot be encoded or violates its public schema.
pub fn encode_create_totp_registration_challenge_response(
    response: &CreateTotpRegistrationChallengeResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(response, challenge_response()?)
}

/// Validates and decodes one bounded TOTP confirmation request.
///
/// # Errors
///
/// Returns a boundary error when the body is oversized, malformed, structurally invalid, or
/// cannot be decoded into the schema-backed request model.
pub fn decode_create_totp_registration_request(
    bytes: &[u8],
) -> Result<CreateTotpRegistrationRequest, BoundaryError> {
    decode(
        bytes,
        MAX_CREATE_TOTP_REGISTRATION_BYTES,
        registration_request()?,
    )
}

/// Validates and encodes one committed TOTP registration response.
///
/// # Errors
///
/// Returns a boundary error when the response cannot be encoded or violates its public schema.
pub fn encode_create_totp_registration_response(
    response: &CreateTotpRegistrationResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(response, registration_response()?)
}

fn decode<T: serde::de::DeserializeOwned>(
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

fn encode<T: serde::Serialize>(
    response: &T,
    validator: &CompiledValidator,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(validator, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn challenge_request() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(CHALLENGE_REQUEST.get_or_init(|| {
        compile(&schema::request_schema::<
            CreateTotpRegistrationChallengeRequest,
        >())
    }))
}

fn challenge_response() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(CHALLENGE_RESPONSE.get_or_init(|| {
        compile(&schema::response_schema::<
            CreateTotpRegistrationChallengeResponse,
        >())
    }))
}

fn registration_request() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        REGISTRATION_REQUEST
            .get_or_init(|| compile(&schema::request_schema::<CreateTotpRegistrationRequest>())),
    )
}

fn registration_response() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        REGISTRATION_RESPONSE
            .get_or_init(|| compile(&schema::response_schema::<CreateTotpRegistrationResponse>())),
    )
}
