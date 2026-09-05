// SPDX-License-Identifier: GPL-2.0-only

//! Independent Rust validation of incoming and outgoing backup policy messages.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BackupSchedulePolicy, BackupScheduleResponse, BoundaryError, ConfigureBackupScheduleRequest,
    ConfigureBackupScheduleResponse, schema,
};

static REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static STATUS: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RECEIPT: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Maximum encoded policy request, checked before parsing.
pub const MAX_CONFIGURE_BACKUP_SCHEDULE_BYTES: usize = 2_048;

/// Decodes a complete bounded policy without coercion or unknown fields.
///
/// # Errors
///
/// Rejects invalid JSON, structure, bounds and contradictory protection thresholds.
pub fn decode_configure_backup_schedule_request(
    bytes: &[u8],
) -> Result<ConfigureBackupScheduleRequest, BoundaryError> {
    if bytes.len() > MAX_CONFIGURE_BACKUP_SCHEDULE_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CONFIGURE_BACKUP_SCHEDULE_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(
            REQUEST.get_or_init(|| {
                compile(&schema::request_schema::<ConfigureBackupScheduleRequest>())
            }),
        )?,
        &value,
    )?;
    let request: ConfigureBackupScheduleRequest =
        serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)?;
    valid_policy(&request.policy)
        .then_some(request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Validates the current policy before emitting it to any client.
///
/// # Errors
///
/// Rejects malformed output and contradictory protection thresholds.
pub fn encode_backup_schedule_response(
    response: &BackupScheduleResponse,
) -> Result<Vec<u8>, BoundaryError> {
    if response
        .schedule
        .as_ref()
        .is_some_and(|schedule| !valid_policy(&schedule.policy))
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            STATUS.get_or_init(|| compile(&schema::response_schema::<BackupScheduleResponse>())),
        )?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates the original committed receipt before transmission.
///
/// # Errors
///
/// Rejects unrepresentable, zero or malformed receipt fields.
pub fn encode_configure_backup_schedule_response(
    response: &ConfigureBackupScheduleResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(RECEIPT.get_or_init(|| {
            compile(&schema::response_schema::<ConfigureBackupScheduleResponse>())
        }))?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn valid_policy(policy: &BackupSchedulePolicy) -> bool {
    policy.interval_seconds > 0
        && policy.retained_generations > 0
        && policy.minimum_verified_copies > 0
        && policy.minimum_independent_copies <= policy.minimum_verified_copies
}
