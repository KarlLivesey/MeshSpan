// SPDX-License-Identifier: GPL-2.0-only

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, ConfigureNotificationRequest, ConfigureNotificationResponse,
    NotificationSettingsUpdate, NotificationsResponse, schema,
};
use std::sync::OnceLock;

/// Configuration JSON limit, including bounded encrypted destination input.
pub const MAX_CONFIGURE_NOTIFICATION_BYTES: usize = 20 * 1024;

/// Validates the original JSON bytes, including duplicate fields and destination constraints.
///
/// # Errors
/// Rejects excessive, malformed or ambiguous input; never coerces a field.
pub fn decode_configure_notification_request(
    bytes: &[u8],
) -> Result<ConfigureNotificationRequest, BoundaryError> {
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    if bytes.len() > MAX_CONFIGURE_NOTIFICATION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CONFIGURE_NOTIFICATION_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(
            VALIDATOR
                .get_or_init(|| compile(&schema::request_schema::<ConfigureNotificationRequest>())),
        )?,
        &value,
    )?;
    let request: ConfigureNotificationRequest =
        serde_json::from_slice(bytes).map_err(|_| BoundaryError::DecodeMismatch)?;
    if let NotificationSettingsUpdate::Replace { destination } = &request.settings {
        let bytes = serde_json::to_vec(destination).map_err(|_| BoundaryError::DecodeMismatch)?;
        crate::decode_notification_destination(&bytes)?;
    }
    Ok(request)
}

/// Validates redacted outgoing status independently of the caller.
///
/// # Errors
/// Rejects invalid identities, configuration bounds or response structure.
pub fn encode_notifications_response(
    response: &NotificationsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            VALIDATOR.get_or_init(|| compile(&schema::response_schema::<NotificationsResponse>())),
        )?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates the original committed configuration receipt before transmission.
///
/// # Errors
/// Rejects zero or non-representable counters and malformed operation identity.
pub fn encode_configure_notification_response(
    response: &ConfigureNotificationResponse,
) -> Result<Vec<u8>, BoundaryError> {
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            VALIDATOR.get_or_init(|| {
                compile(&schema::response_schema::<ConfigureNotificationResponse>())
            }),
        )?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}
