// SPDX-License-Identifier: GPL-2.0-only

//! Explicit notification destinations. These values contain secrets and are never status output.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Administrator-selected encrypted delivery settings, not an address supplied by an event.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NotificationDestination {
    /// POST redacted events to this exact authenticated HTTPS endpoint; redirects are forbidden.
    Webhook {
        /// Exact allow-listed HTTPS URL, without credentials or fragment.
        #[schemars(length(min = 9, max = 2048), pattern(r"^https://[^\s#@]+$"))]
        endpoint: String,
        /// Bearer credential for this destination alone.
        #[schemars(length(min = 16, max = 2048), pattern(r"^[A-Za-z0-9._~+/-]+=*$"))]
        bearer_token: String,
    },
    /// Send a redacted message to these mailboxes through one authenticated TLS relay.
    Email {
        /// Explicit relay DNS name or address; no URL, automatic MX discovery or redirect.
        #[schemars(length(min = 1, max = 253), pattern(r"^[A-Za-z0-9.:-]+$"))]
        host: String,
        /// Explicit relay port, normally 465 for implicit TLS or 587 for required STARTTLS.
        #[schemars(range(min = 1))]
        port: u16,
        /// Encryption starts before any credentials or mail content is sent.
        tls: NotificationSmtpTls,
        /// SASL PLAIN authentication identity. ASCII initially; no implicit Unicode mapping.
        #[schemars(length(min = 1, max = 128), pattern(r"^[\x21-\x7e]+$"))]
        username: String,
        /// Relay credential, never a `MeshSpan` user password or a diagnostic field.
        #[schemars(length(min = 1, max = 128), pattern(r"^[\x20-\x7e]+$"))]
        password: String,
        /// Explicit envelope sender and From mailbox.
        #[schemars(
            length(min = 3, max = 254),
            pattern(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+$")
        )]
        sender: String,
        /// Exact recipient allow-list. BCC/forwarding destinations cannot come from an event.
        #[schemars(length(min = 1, max = 32))]
        recipients: Vec<NotificationMailbox>,
    },
}

/// Explicit ASCII mailbox accepted by the initial notification sender.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NotificationMailbox(
    #[schemars(
        length(min = 3, max = 254),
        pattern(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+$")
    )]
    pub String,
);

/// Supported encrypted SMTP submission modes; there is no opportunistic plaintext fallback.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationSmtpTls {
    /// Establish TLS before reading the SMTP greeting.
    Implicit,
    /// Require advertised STARTTLS and issue a fresh EHLO after the TLS handshake.
    Starttls,
}

/// Validates an encrypted-settings plaintext before transport use or before encrypting a change.
///
/// # Errors
/// Rejects unknown properties, malformed values and bodies beyond 16 KiB.
pub fn decode_notification_destination(
    bytes: &[u8],
) -> Result<NotificationDestination, crate::BoundaryError> {
    use crate::validation::{CompiledValidator, compile, validate, validator_from};
    use std::sync::OnceLock;
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    if bytes.len() > 16 * 1024 {
        return Err(crate::BoundaryError::BodyTooLarge { limit: 16 * 1024 });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| crate::BoundaryError::MalformedJson)?;
    validate(
        validator_from(
            VALIDATOR.get_or_init(|| {
                compile(&crate::schema::request_schema::<NotificationDestination>())
            }),
        )?,
        &value,
    )?;
    // Decode the original bytes, not the intermediate JSON value, so duplicate typed fields
    // cannot be silently collapsed before Serde's duplicate-field rejection.
    let destination: NotificationDestination =
        serde_json::from_slice(bytes).map_err(|_| crate::BoundaryError::DecodeMismatch)?;
    if let NotificationDestination::Email { recipients, .. } = &destination {
        let distinct = recipients
            .iter()
            .map(|mailbox| mailbox.0.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if distinct.len() != recipients.len() {
            return Err(crate::BoundaryError::DecodeMismatch);
        }
    }
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::decode_notification_destination;

    #[test]
    fn notification_settings_reject_plaintext_injection_duplicates_and_undeclared_fields() {
        assert!(decode_notification_destination(br#"{"kind":"webhook","endpoint":"https://localhost/notify","bearer_token":"local-notification-token"}"#).is_ok());
        for bytes in [
            br#"{"kind":"webhook","endpoint":"http://localhost/notify","bearer_token":"local-notification-token"}"#.as_slice(),
            br#"{"kind":"webhook","endpoint":"https://localhost/notify","bearer_token":"token\r\nInjected: value"}"#,
            br#"{"kind":"webhook","endpoint":"https://user@localhost/notify","bearer_token":"local-notification-token"}"#,
            br#"{"kind":"webhook","endpoint":"https://localhost/notify","bearer_token":"local-notification-token","extra":true}"#,
            br#"{"kind":"webhook","endpoint":"https://localhost/a","endpoint":"https://localhost/b","bearer_token":"local-notification-token"}"#,
        ] { assert!(decode_notification_destination(bytes).is_err()); }
    }
}
