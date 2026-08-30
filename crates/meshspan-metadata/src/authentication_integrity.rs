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
    let invalid_session = invalid_session_shape(connection)?;
    let invalid_factor = invalid_session_factor(connection)?;
    let invalid_policy = invalid_authentication_policy(connection)?;
    if invalid_subtype == 0
        && invalid_lifecycle == 0
        && invalid_session == 0
        && invalid_factor == 0
        && invalid_policy == 0
    {
        Ok(())
    } else {
        Err(MetadataStoreError::IntegrityFailed)
    }
}

fn invalid_authentication_policy(connection: &Connection) -> Result<i64, rusqlite::Error> {
    connection.query_row(
        "SELECT
            CASE
                WHEN (SELECT count(*) FROM meshes) = 0 THEN
                    (SELECT count(*) FROM authentication_policy_revisions) <> 0
                WHEN (SELECT count(*) FROM meshes) <> 1 THEN 1
                WHEN (SELECT count(*) FROM (
                    SELECT service, operation_class
                    FROM authentication_policy_revisions
                    GROUP BY service, operation_class
                )) <> 12 THEN 1
                WHEN EXISTS(
                    SELECT 1
                    FROM authentication_policy_revisions AS policy
                    WHERE policy.allowed_factor_classes < 1
                       OR policy.allowed_factor_classes > 15
                       OR (policy.allowed_factor_classes & 9) = 0
                       OR policy.minimum_factor_count NOT BETWEEN 1 AND 8
                       OR policy.maximum_session_duration_micros <= 0
                       OR (
                           policy.operation_class IN (1, 2)
                           AND policy.maximum_step_up_age_micros IS NOT NULL
                       )
                       OR (
                           policy.operation_class IN (3, 4)
                           AND (
                               policy.maximum_step_up_age_micros IS NULL
                               OR policy.maximum_step_up_age_micros <= 0
                               OR policy.maximum_step_up_age_micros
                                  > policy.maximum_session_duration_micros
                           )
                       )
                ) THEN 1
                WHEN EXISTS(
                    SELECT 1 FROM (
                        SELECT service, operation_class,
                               min(policy_sequence) AS first_sequence,
                               max(policy_sequence) AS last_sequence,
                               count(*) AS revision_count
                        FROM authentication_policy_revisions
                        GROUP BY service, operation_class
                    )
                    WHERE first_sequence <> 1 OR last_sequence <> revision_count
                ) THEN 1
                ELSE 0
            END",
        [],
        |row| row.get(0),
    )
}

fn invalid_session_shape(connection: &Connection) -> Result<i64, rusqlite::Error> {
    connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM authentication_sessions AS session
            WHERE (SELECT count(*) FROM authentication_session_factors
                   WHERE session_id = session.session_id) NOT BETWEEN 1 AND 8
               OR (SELECT min(factor_sequence) FROM authentication_session_factors
                   WHERE session_id = session.session_id) <> 1
               OR (SELECT max(factor_sequence) FROM authentication_session_factors
                   WHERE session_id = session.session_id) <>
                  (SELECT count(*) FROM authentication_session_factors
                   WHERE session_id = session.session_id)
               OR NOT EXISTS(
                   SELECT 1 FROM authentication_session_factors
                   WHERE session_id = session.session_id AND method_kind IN (1, 4)
               )
               OR session.assurance <> CASE WHEN EXISTS(
                   SELECT 1 FROM authentication_session_factors
                   WHERE session_id = session.session_id AND method_kind IN (2, 3)
               ) THEN 2 ELSE 1 END
         )",
        [],
        |row| row.get(0),
    )
}

fn invalid_session_factor(connection: &Connection) -> Result<i64, rusqlite::Error> {
    connection.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM authentication_session_factors AS factor
            JOIN authentication_sessions AS session USING(session_id)
            JOIN authentication_methods AS method USING(method_id)
            WHERE factor.method_kind <> method.method_kind
               OR factor.authenticated_at <> session.issued_at
               OR method.user_principal_id <> session.user_principal_id
               OR (method.service_scope & session.service) <> session.service
               OR factor.credential_generation > method.credential_generation
               OR factor.method_revision > method.revision
               OR (factor.method_kind = 1 AND NOT EXISTS(
                   SELECT 1 FROM webauthn_credentials
                   WHERE method_id = factor.method_id
                     AND credential_id = factor.credential_reference
               ))
               OR (factor.method_kind = 2
                   AND (factor.credential_reference <> factor.method_id OR NOT EXISTS(
                       SELECT 1 FROM totp_credentials WHERE method_id = factor.method_id
                   )))
               OR (factor.method_kind = 3 AND NOT EXISTS(
                   SELECT 1 FROM recovery_codes
                   WHERE method_id = factor.method_id
                     AND code_id = factor.credential_reference
                     AND used_at IS NOT NULL
               ))
               OR (factor.method_kind = 4 AND NOT EXISTS(
                   SELECT 1 FROM api_keys
                   WHERE method_id = factor.method_id
                     AND key_id = factor.credential_reference
               ))
         )",
        [],
        |row| row.get(0),
    )
}
