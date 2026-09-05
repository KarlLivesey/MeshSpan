// SPDX-License-Identifier: GPL-2.0-only

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, ConfigureMetricsExporterRequest, ConfigureMetricsExporterResponse,
    MetricsExporterPolicy, MetricsExporterResponse, schema,
};
use std::sync::OnceLock;

static REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static STATUS: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RECEIPT: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Maximum JSON policy body, checked before parsing.
pub const MAX_CONFIGURE_METRICS_EXPORTER_BYTES: usize = 8 * 1024;

/// Validates a complete bounded policy without coercion or undeclared fields.
///
/// # Errors
/// Rejects malformed JSON, excessive consumers, duplicates and enabled empty policies.
pub fn decode_configure_metrics_exporter_request(
    bytes: &[u8],
) -> Result<ConfigureMetricsExporterRequest, BoundaryError> {
    if bytes.len() > MAX_CONFIGURE_METRICS_EXPORTER_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CONFIGURE_METRICS_EXPORTER_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(REQUEST.get_or_init(|| {
            compile(&schema::request_schema::<ConfigureMetricsExporterRequest>())
        }))?,
        &value,
    )?;
    let request: ConfigureMetricsExporterRequest =
        serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)?;
    valid_policy(&request.policy)
        .then_some(request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Independently validates configuration output before transmission.
///
/// # Errors
/// Rejects unknown variants, malformed identities/counters or inconsistent policy.
pub fn encode_metrics_exporter_response(
    response: &MetricsExporterResponse,
) -> Result<Vec<u8>, BoundaryError> {
    if response
        .configuration
        .as_ref()
        .is_some_and(|value| !valid_policy(&value.policy))
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            STATUS.get_or_init(|| compile(&schema::response_schema::<MetricsExporterResponse>())),
        )?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Independently validates an original durable configuration receipt.
///
/// # Errors
/// Rejects invalid identities, zero counters or non-representable output.
pub fn encode_configure_metrics_exporter_response(
    response: &ConfigureMetricsExporterResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(RECEIPT.get_or_init(|| {
            compile(&schema::response_schema::<ConfigureMetricsExporterResponse>())
        }))?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn valid_policy(policy: &MetricsExporterPolicy) -> bool {
    let distinct = policy
        .allowed_principals
        .iter()
        .map(crate::PrincipalId::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    (!policy.enabled || !policy.allowed_principals.is_empty())
        && distinct.len() == policy.allowed_principals.len()
}
