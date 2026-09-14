// SPDX-License-Identifier: GPL-2.0-only

//! Native two-swarm pairing operations. Peer records are canonical signed public bytes.

use crate::{
    BoundaryError, OperationId, schema,
    validation::{CompiledValidator, compile, validate, validator_from},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::OnceLock;

/// Local manager intent to connect to the swarm that issued the secret invitation.
#[derive(Clone, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectFederationRequest {
    /// Stable retry identity for the whole connection attempt.
    pub operation_id: OperationId,
    /// Secret invitation supplied by the other administrator; never a node join grant.
    #[schemars(length(min = 260, max = 763), pattern(r"^meshspan-federate-v1\."))]
    pub connection_code: String,
    /// This gateway's reachable HTTPS origin and corresponding federation UDP endpoint.
    #[schemars(length(min = 9, max = 512), pattern(r"^https://[a-z0-9.\-\[\]:]+$"))]
    pub local_endpoint: String,
}

/// Connection attempt sent through TLS pinned by the invitation; the code is in Authorization.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptFederationPairingRequest {
    /// Original accepting administrator's operation identity.
    pub operation_id: OperationId,
    /// Unpadded base64url of a canonical MSFP-v1 signed public peer record.
    #[schemars(length(min = 172, max = 24576), pattern(r"^[A-Za-z0-9_-]+$"))]
    pub peer_record: String,
}

/// Issuing swarm's durable approval and signed public identity, not user/file access.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptFederationPairingResponse {
    /// Original accepting administrator's operation identity.
    pub operation_id: OperationId,
    /// Shared relationship identity.
    pub relationship_id: OperationId,
    /// Inviter's exact signed public peer record.
    #[schemars(length(min = 172, max = 24576), pattern(r"^[A-Za-z0-9_-]+$"))]
    pub peer_record: String,
    /// Original approval revision in the issuing swarm's consensus.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}

/// Both swarms have committed relationship approval; live transport health is separate.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectFederationResponse {
    /// Exact local operation, resolved to a durable approval receipt.
    pub operation_id: OperationId,
    /// Shared relationship identity.
    pub relationship_id: OperationId,
    /// Original local approval revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}

/// Maximum signed peer JSON body/response, before base64 or record decoding.
pub const MAX_FEDERATION_CONNECTION_BYTES: usize = 26 * 1024;
static CONNECT: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CONNECT_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static ACCEPT: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static ACCEPT_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes bounded manager connection input.
/// # Errors
/// Rejects malformed, unknown, coerced or out-of-bounds fields.
pub fn decode_connect_federation_request(
    bytes: &[u8],
) -> Result<ConnectFederationRequest, BoundaryError> {
    decode(bytes, &CONNECT, true)
}
/// Decodes bounded pinned-HTTPS peer input.
/// # Errors
/// Rejects malformed, unknown, coerced or out-of-bounds fields.
pub fn decode_accept_federation_pairing_request(
    bytes: &[u8],
) -> Result<AcceptFederationPairingRequest, BoundaryError> {
    decode(bytes, &ACCEPT, true)
}
/// Validates a received peer approval before it influences local metadata.
/// # Errors
/// Rejects malformed, unknown or out-of-bounds response fields.
pub fn decode_accept_federation_pairing_response(
    bytes: &[u8],
) -> Result<AcceptFederationPairingResponse, BoundaryError> {
    decode(bytes, &ACCEPT_RESPONSE, false)
}
/// Validates a peer approval before transmission.
/// # Errors
/// Rejects invalid public material or receipt fields.
pub fn encode_accept_federation_pairing_response(
    value: &AcceptFederationPairingResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(value, &ACCEPT_RESPONSE)
}
/// Validates the local durable connection receipt before transmission.
/// # Errors
/// Rejects invalid operation/relationship identifiers or revision.
pub fn encode_connect_federation_response(
    value: &ConnectFederationResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(value, &CONNECT_RESPONSE)
}

fn decode<T: DeserializeOwned + JsonSchema>(
    bytes: &[u8],
    validator: &'static OnceLock<Result<CompiledValidator, String>>,
    request: bool,
) -> Result<T, BoundaryError> {
    if bytes.len() > MAX_FEDERATION_CONNECTION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_FEDERATION_CONNECTION_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(validator.get_or_init(|| {
            compile(&if request {
                schema::request_schema::<T>()
            } else {
                schema::response_schema::<T>()
            })
        }))?,
        &value,
    )?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

fn encode<T: Serialize + JsonSchema>(
    value: &T,
    validator: &'static OnceLock<Result<CompiledValidator, String>>,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(value).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(validator.get_or_init(|| compile(&schema::response_schema::<T>())))?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}
