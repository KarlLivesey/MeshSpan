-- SPDX-License-Identifier: GPL-2.0-only

-- Retain an accepted TOTP step in each immutable session factor so exact retries can be
-- authenticated after the original wall-clock window without admitting a new use of that step.
-- Legacy TOTP session evidence only retained the method identifier. It cannot prove which step
-- was accepted, so fail closed by removing those ephemeral sessions during the migration.

DROP TRIGGER authentication_session_factors_require_current_method;
DROP TRIGGER authentication_session_factors_immutable;

DELETE FROM authentication_sessions
WHERE EXISTS (
    SELECT 1
    FROM authentication_session_factors AS factor
    WHERE factor.session_id = authentication_sessions.session_id
      AND factor.method_kind = 2
);

CREATE TABLE authentication_session_factors_next (
    session_id BLOB NOT NULL
        REFERENCES authentication_sessions(session_id) ON DELETE CASCADE,
    factor_sequence INTEGER NOT NULL CHECK (factor_sequence BETWEEN 1 AND 8),
    method_id BLOB NOT NULL
        REFERENCES authentication_methods(method_id) ON DELETE RESTRICT,
    method_kind INTEGER NOT NULL CHECK (method_kind BETWEEN 1 AND 4),
    credential_reference BLOB NOT NULL CHECK (
        (method_kind = 1 AND length(credential_reference) BETWEEN 1 AND 1024)
        OR (method_kind = 2 AND length(credential_reference) = 8)
        OR (method_kind IN (3, 4) AND length(credential_reference) = 16)
    ),
    credential_generation INTEGER NOT NULL CHECK (credential_generation > 0),
    method_revision INTEGER NOT NULL CHECK (method_revision > 0),
    authenticated_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (session_id, factor_sequence),
    UNIQUE (session_id, method_id)
) STRICT;

INSERT INTO authentication_session_factors_next(
    session_id, factor_sequence, method_id, method_kind, credential_reference,
    credential_generation, method_revision, authenticated_at, revision
)
SELECT
    session_id, factor_sequence, method_id, method_kind, credential_reference,
    credential_generation, method_revision, authenticated_at, revision
FROM authentication_session_factors;

DROP TABLE authentication_session_factors;
ALTER TABLE authentication_session_factors_next RENAME TO authentication_session_factors;

CREATE INDEX authentication_session_factors_by_method
ON authentication_session_factors(method_id, session_id);

CREATE TRIGGER authentication_session_factors_require_current_method
BEFORE INSERT ON authentication_session_factors
WHEN NOT EXISTS (
    SELECT 1
    FROM authentication_sessions AS session
    JOIN authentication_methods AS method
      ON method.method_id = NEW.method_id
     AND method.user_principal_id = session.user_principal_id
    WHERE session.session_id = NEW.session_id
      AND method.state = 1
      AND (method.service_scope & session.service) = session.service
      AND method.created_at <= session.issued_at
      AND (method.expires_at IS NULL OR method.expires_at > session.issued_at)
      AND method.credential_generation = NEW.credential_generation
      AND method.revision = NEW.method_revision
      AND method.method_kind = NEW.method_kind
      AND NEW.authenticated_at = session.issued_at
      AND (
          (method.method_kind = 1 AND EXISTS (
              SELECT 1 FROM webauthn_credentials AS passkey
              WHERE passkey.method_id = method.method_id
                AND passkey.credential_id = NEW.credential_reference
          ))
          OR (method.method_kind = 2
              AND length(NEW.credential_reference) = 8
              AND EXISTS (
                  SELECT 1 FROM totp_credentials AS totp
                  WHERE totp.method_id = method.method_id
              ))
          OR (method.method_kind = 3 AND EXISTS (
              SELECT 1 FROM recovery_codes AS recovery
              WHERE recovery.method_id = method.method_id
                AND recovery.code_id = NEW.credential_reference
                AND recovery.used_at IS NULL
          ))
          OR (method.method_kind = 4 AND EXISTS (
              SELECT 1 FROM api_keys AS key
              WHERE key.method_id = method.method_id
                AND key.key_id = NEW.credential_reference
                AND key.valid_from <= session.issued_at
                AND (key.valid_until IS NULL OR key.valid_until > session.issued_at)
          ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'session factor is not current authentication evidence');
END;

CREATE TRIGGER authentication_session_factors_immutable
BEFORE UPDATE ON authentication_session_factors
BEGIN
    SELECT RAISE(ABORT, 'authentication session factors are immutable');
END;
