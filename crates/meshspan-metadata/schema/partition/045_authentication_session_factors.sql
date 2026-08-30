-- SPDX-License-Identifier: GPL-2.0-only

-- Sessions are intentionally ephemeral authority. The superseded shape let a
-- caller assert an assurance level without retaining the methods that proved
-- it, so upgrading revokes those sessions rather than guessing their evidence.
DROP TABLE authentication_sessions;

-- Reject replay of an already accepted TOTP step even after its derived session
-- is revoked or expires.
ALTER TABLE totp_credentials
ADD COLUMN last_accepted_step INTEGER CHECK (
    last_accepted_step IS NULL OR last_accepted_step >= 0
);

-- service is one exact connector family: HTTPS 1, headless API 2 or SMB 4.
-- assurance is derived from admitted factor classes: 1 single, 2 multiple.
CREATE TABLE authentication_sessions (
    session_id BLOB PRIMARY KEY CHECK (length(session_id) = 16),
    token_digest BLOB NOT NULL UNIQUE CHECK (length(token_digest) = 32),
    user_principal_id BLOB NOT NULL REFERENCES users(principal_id) ON DELETE CASCADE,
    service INTEGER NOT NULL CHECK (service IN (1, 2, 4)),
    assurance INTEGER NOT NULL CHECK (assurance IN (1, 2)),
    identity_revision INTEGER NOT NULL CHECK (identity_revision > 0),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    revoked_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
) STRICT;

CREATE INDEX authentication_sessions_active
ON authentication_sessions(user_principal_id, service, expires_at, revoked_at);

CREATE TABLE authentication_session_factors (
    session_id BLOB NOT NULL
        REFERENCES authentication_sessions(session_id) ON DELETE CASCADE,
    factor_sequence INTEGER NOT NULL CHECK (factor_sequence BETWEEN 1 AND 8),
    method_id BLOB NOT NULL
        REFERENCES authentication_methods(method_id) ON DELETE RESTRICT,
    method_kind INTEGER NOT NULL CHECK (method_kind BETWEEN 1 AND 4),
    credential_reference BLOB NOT NULL CHECK (
        length(credential_reference) BETWEEN 1 AND 1024
        AND (method_kind = 1 OR length(credential_reference) = 16)
    ),
    credential_generation INTEGER NOT NULL CHECK (credential_generation > 0),
    method_revision INTEGER NOT NULL CHECK (method_revision > 0),
    authenticated_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (session_id, factor_sequence),
    UNIQUE (session_id, method_id)
) STRICT;

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
          OR (method.method_kind = 2 AND NEW.credential_reference = method.method_id)
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

CREATE TRIGGER authentication_session_evidence_immutable
BEFORE UPDATE OF
    session_id, token_digest, user_principal_id, service, assurance,
    identity_revision, issued_at, expires_at
ON authentication_sessions
BEGIN
    SELECT RAISE(ABORT, 'authentication session evidence is immutable');
END;

CREATE TRIGGER authentication_session_factors_immutable
BEFORE UPDATE ON authentication_session_factors
BEGIN
    SELECT RAISE(ABORT, 'authentication session factors are immutable');
END;
