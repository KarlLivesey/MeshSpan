// SPDX-License-Identifier: GPL-2.0-only

//! Runtime validation for hostile SMB-export administration messages.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, PublishSmbExportRequest, PublishSmbExportResponse, SmbExportGatewaySelection,
    WithdrawSmbExportRequest, WithdrawSmbExportResponse, schema,
};

/// Maximum accepted publication request bytes.
pub const MAX_PUBLISH_SMB_EXPORT_BYTES: usize = 64 * 1_024;
/// Maximum accepted withdrawal request bytes.
pub const MAX_WITHDRAW_SMB_EXPORT_BYTES: usize = 8 * 1_024;

static PUBLISH_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static PUBLISH_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static WITHDRAW_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static WITHDRAW_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes one bounded structurally validated publication request.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, schema-invalid or noncanonical input.
pub fn decode_publish_smb_export_request(
    bytes: &[u8],
) -> Result<PublishSmbExportRequest, BoundaryError> {
    let request = decode(bytes, MAX_PUBLISH_SMB_EXPORT_BYTES, publish_request()?)?;
    let request: PublishSmbExportRequest =
        serde_json::from_value(request).map_err(|_| BoundaryError::DecodeMismatch)?;
    validate_gateway_selection(&request.gateways)?;
    Ok(request)
}

/// Encodes one validated authoritative publication response.
///
/// # Errors
///
/// Refuses to emit schema-invalid or noncanonical authoritative output.
pub fn encode_publish_smb_export_response(
    response: &PublishSmbExportResponse,
) -> Result<Vec<u8>, BoundaryError> {
    validate_gateway_selection(&response.gateways)?;
    encode(response, publish_response()?)
}

/// Decodes one bounded structurally validated withdrawal request.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, schema-invalid or blank audit input.
pub fn decode_withdraw_smb_export_request(
    bytes: &[u8],
) -> Result<WithdrawSmbExportRequest, BoundaryError> {
    let value = decode(bytes, MAX_WITHDRAW_SMB_EXPORT_BYTES, withdraw_request()?)?;
    let request: WithdrawSmbExportRequest =
        serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)?;
    if request.reason.trim().is_empty() {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(request)
}

/// Encodes one validated authoritative withdrawal response.
///
/// # Errors
///
/// Refuses to emit schema-invalid authoritative output.
pub fn encode_withdraw_smb_export_response(
    response: &WithdrawSmbExportResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(response, withdraw_response()?)
}

fn decode(
    bytes: &[u8],
    limit: usize,
    validator: &CompiledValidator,
) -> Result<serde_json::Value, BoundaryError> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(BoundaryError::BodyTooLarge { limit });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(validator, &value)?;
    Ok(value)
}

fn encode<T: serde::Serialize>(
    response: &T,
    validator: &CompiledValidator,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(validator, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn validate_gateway_selection(selection: &SmbExportGatewaySelection) -> Result<(), BoundaryError> {
    let Some(nodes) = selection.selected_node_ids() else {
        return Ok(());
    };
    if nodes.windows(2).any(|pair| pair[0] >= pair[1])
        || nodes.iter().any(|node| !is_canonical_uuid(node))
    {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(())
}

fn is_canonical_uuid(value: &str) -> bool {
    super::directory_listing::parse_public_uuid(value).is_some()
}

fn publish_request() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        PUBLISH_REQUEST
            .get_or_init(|| compile(&schema::request_schema::<PublishSmbExportRequest>())),
    )
}

fn publish_response() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        PUBLISH_RESPONSE
            .get_or_init(|| compile(&schema::response_schema::<PublishSmbExportResponse>())),
    )
}

fn withdraw_request() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        WITHDRAW_REQUEST
            .get_or_init(|| compile(&schema::request_schema::<WithdrawSmbExportRequest>())),
    )
}

fn withdraw_response() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        WITHDRAW_RESPONSE
            .get_or_init(|| compile(&schema::response_schema::<WithdrawSmbExportResponse>())),
    )
}
