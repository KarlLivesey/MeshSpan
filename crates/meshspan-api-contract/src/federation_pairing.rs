// SPDX-License-Identifier: GPL-2.0-only

//! Native administrator API for short-lived federation connection material.

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, OperationId, schema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[cfg(test)]
#[path = "federation_pairing_tests.rs"]
mod tests;

/// Administrator request to approve one connection attempt by another autonomous swarm.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFederationPairingInvitationRequest {
    /// Stable retry identity.
    pub operation_id: OperationId,
    /// HTTPS origin of this gateway, normally supplied from the panel's current origin.
    #[schemars(length(min = 9, max = 512), pattern(r"^https://[a-z0-9.\-\[\]:]+$"))]
    pub pairing_endpoint: String,
    /// Short-lived validity; the simple panel uses 900 seconds.
    #[schemars(range(min = 60, max = 3600))]
    pub valid_for_seconds: u32,
}

/// Secret-bearing original receipt. This does not mean a peer relationship is active.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFederationPairingInvitationResponse {
    /// Exact committed issuance operation.
    pub operation_id: OperationId,
    /// Reserved relationship identity used to inspect or cancel this material.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub invitation_id: String,
    /// Share only with the intended other swarm's administrator. Never a node join code.
    #[schemars(length(min = 260, max = 763), pattern(r"^meshspan-federate-v1\.[0-9a-f]{32}\|[0-9a-f]{32}\|[0-9a-f]{16}\|[0-9a-f]{16}\|[0-9a-f]{64}\|[0-9a-f]{64}\|https://[a-z0-9.\-\[\]:]+$"))]
    pub connection_code: String,
    /// Exclusive original expiry, not extended by retry.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub expires_at_epoch_micros: i64,
    /// Original committed metadata revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}

/// Maximum administrator issuance body, checked before JSON parsing.
pub const MAX_CREATE_FEDERATION_PAIRING_BYTES: usize = 2048;
/// Cancels unused material without affecting an established relationship.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelFederationPairingInvitationRequest {
    /// Stable retry identity, distinct from issuance.
    pub operation_id: OperationId,
    /// Exact reserved relationship to withdraw.
    pub invitation_id: OperationId,
    /// Revision observed when issuing the material.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub expected_invitation_revision: u64,
    /// Administrator's non-secret audit explanation.
    #[schemars(length(min = 1, max = 512))]
    pub reason: String,
}

/// Durable cancellation receipt; no connection secret is returned.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelFederationPairingInvitationResponse {
    /// Exact committed cancellation operation.
    pub operation_id: OperationId,
    /// Withdrawn reserved relationship.
    pub invitation_id: OperationId,
    /// Original cancellation revision, preserved on retry.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}

static CANCEL_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CANCEL_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes untrusted issuance input without coercion or unknown fields.
///
/// # Errors
/// Rejects malformed, oversized and schema-invalid requests.
pub fn decode_create_federation_pairing_request(
    bytes: &[u8],
) -> Result<CreateFederationPairingInvitationRequest, BoundaryError> {
    if bytes.len() > MAX_CREATE_FEDERATION_PAIRING_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CREATE_FEDERATION_PAIRING_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(REQUEST.get_or_init(|| {
            compile(&schema::request_schema::<
                CreateFederationPairingInvitationRequest,
            >())
        }))?,
        &value,
    )?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validates outgoing connection material before sending a secret-bearing response.
///
/// # Errors
/// Rejects invalid response fields or encoding failure.
pub fn encode_create_federation_pairing_response(
    value: &CreateFederationPairingInvitationResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(value).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(RESPONSE.get_or_init(|| {
            compile(&schema::response_schema::<
                CreateFederationPairingInvitationResponse,
            >())
        }))?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates bounded cancellation input without trusting the calling client.
///
/// # Errors
/// Rejects oversized, malformed or schema-invalid input.
pub fn decode_cancel_federation_pairing_request(
    bytes: &[u8],
) -> Result<CancelFederationPairingInvitationRequest, BoundaryError> {
    if bytes.len() > MAX_CREATE_FEDERATION_PAIRING_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CREATE_FEDERATION_PAIRING_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(CANCEL_REQUEST.get_or_init(|| {
            compile(&schema::request_schema::<
                CancelFederationPairingInvitationRequest,
            >())
        }))?,
        &value,
    )?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validates the outgoing cancellation receipt.
///
/// # Errors
/// Rejects invalid evidence or encoding failure.
pub fn encode_cancel_federation_pairing_response(
    value: &CancelFederationPairingInvitationResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(value).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(CANCEL_RESPONSE.get_or_init(|| {
            compile(&schema::response_schema::<
                CancelFederationPairingInvitationResponse,
            >())
        }))?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}
