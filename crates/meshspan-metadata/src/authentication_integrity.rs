// SPDX-License-Identifier: GPL-2.0-only

//! Cross-table integrity checks for typed authentication methods.

use rusqlite::Connection;

use crate::MetadataStoreError;

/// Proves each common method has only its required typed credential rows.
pub(crate) fn check_method_shapes(connection: &Connection) -> Result<(), MetadataStoreError> {
    let invalid: i64 = connection.query_row(
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
    if invalid == 0 {
        Ok(())
    } else {
        Err(MetadataStoreError::IntegrityFailed)
    }
}
