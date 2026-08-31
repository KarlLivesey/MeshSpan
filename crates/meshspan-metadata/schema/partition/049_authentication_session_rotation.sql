-- SPDX-License-Identifier: GPL-2.0-only

-- A step-up replacement retains one current primary proof from its source session, accepts one
-- fresh additional factor, and revokes the source in the same authoritative transaction.
ALTER TABLE authentication_sessions
ADD COLUMN source_session_id BLOB REFERENCES authentication_sessions(session_id)
CHECK (source_session_id IS NULL OR length(source_session_id) = 16);

CREATE UNIQUE INDEX authentication_sessions_one_replacement
ON authentication_sessions(source_session_id)
WHERE source_session_id IS NOT NULL;

DROP TRIGGER authentication_session_evidence_immutable;
CREATE TRIGGER authentication_session_evidence_immutable
BEFORE UPDATE OF
    session_id, token_digest, csrf_digest, client_label_state, client_label,
    persistent_cookie, user_principal_id, service, assurance, identity_revision,
    issued_at, expires_at, source_session_id
ON authentication_sessions
BEGIN
    SELECT RAISE(ABORT, 'authentication session evidence is immutable');
END;

DROP TRIGGER authentication_session_factors_require_current_method;
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
      AND method.created_at <= NEW.authenticated_at
      AND (method.expires_at IS NULL OR method.expires_at > session.issued_at)
      AND method.credential_generation = NEW.credential_generation
      AND method.revision = NEW.method_revision
      AND method.method_kind = NEW.method_kind
      AND (
          (session.source_session_id IS NULL AND NEW.authenticated_at = session.issued_at)
          OR (
              session.source_session_id IS NOT NULL
              AND NEW.authenticated_at <= session.issued_at
          )
      )
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
                AND key.valid_from <= NEW.authenticated_at
                AND (key.valid_until IS NULL OR key.valid_until > session.issued_at)
          ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'session factor is not current authentication evidence');
END;
