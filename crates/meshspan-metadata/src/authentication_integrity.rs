// SPDX-License-Identifier: GPL-2.0-only

//! Cross-table integrity checks for typed authentication methods.

use rusqlite::Connection;

use crate::MetadataStoreError;

/// Proves each common method has only its required typed credential rows.
pub(crate) fn check_method_shapes(connection: &Connection) -> Result<(), MetadataStoreError> {
    let invalid_subtype: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM authentication_methods AS method
            WHERE NOT (
                (method.method_kind = 1
                    AND EXISTS(SELECT 1 FROM webauthn_credentials
                               WHERE method_id = method.method_id)
                    AND NOT EXISTS(SELECT 1 FROM totp_credentials
                                   WHERE method_id = method.method_id)
                    AND NOT EXISTS(SELECT 1 FROM recovery_codes
                                   WHERE method_id = method.method_id)
                    AND NOT EXISTS(SELECT 1 FROM api_keys
                                   WHERE method_id = method.method_id))
                OR (method.method_kind = 2
                    AND NOT EXISTS(SELECT 1 FROM webauthn_credentials
                                   WHERE method_id = method.method_id)
                    AND EXISTS(SELECT 1 FROM totp_credentials
                               WHERE method_id = method.method_id)
                    AND NOT EXISTS(SELECT 1 FROM recovery_codes
                                   WHERE method_id = method.method_id)
                    AND NOT EXISTS(SELECT 1 FROM api_keys
                                   WHERE method_id = method.method_id))
                OR (method.method_kind = 3
                    AND NOT EXISTS(SELECT 1 FROM webauthn_credentials
                                   WHERE method_id = method.method_id)
                    AND NOT EXISTS(SELECT 1 FROM totp_credentials
                                   WHERE method_id = method.method_id)
                    AND EXISTS(SELECT 1 FROM recovery_codes
                               WHERE method_id = method.method_id)
                    AND NOT EXISTS(SELECT 1 FROM api_keys
                                   WHERE method_id = method.method_id))
                OR (method.method_kind = 4
                    AND NOT EXISTS(SELECT 1 FROM webauthn_credentials
                                   WHERE method_id = method.method_id)
                    AND NOT EXISTS(SELECT 1 FROM totp_credentials
                                   WHERE method_id = method.method_id)
                    AND NOT EXISTS(SELECT 1 FROM recovery_codes
                                   WHERE method_id = method.method_id)
                    AND EXISTS(SELECT 1 FROM api_keys
                               WHERE method_id = method.method_id))
            )
         )",
        [],
        |row| row.get(0),
    )?;
    let invalid_lifecycle: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM authentication_methods AS method
            WHERE NOT EXISTS(
                SELECT 1 FROM authentication_method_events AS event
                WHERE event.method_id = method.method_id
                    AND event.event_sequence = 1
                    AND event.event_kind = 1
                    AND event.resulting_state = 1
            )
            OR (method.state IN (1, 2) AND EXISTS(
                SELECT 1 FROM authentication_method_events
                WHERE method_id = method.method_id AND event_sequence = 2
            ))
            OR (method.state = 3 AND NOT EXISTS(
                SELECT 1 FROM authentication_method_events AS event
                WHERE event.method_id = method.method_id
                    AND event.event_sequence = 2
                    AND event.event_kind = 2
                    AND event.resulting_state = 3
            ))
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_subtype == 0 && invalid_lifecycle == 0 {
        Ok(())
    } else {
        Err(MetadataStoreError::IntegrityFailed)
    }
}
