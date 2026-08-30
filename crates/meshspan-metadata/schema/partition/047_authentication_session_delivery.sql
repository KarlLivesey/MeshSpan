-- SPDX-License-Identifier: GPL-2.0-only

-- Authentication sessions are ephemeral authority. Incomplete pre-release
-- sessions are revoked during this migration rather than inventing CSRF or
-- cookie-persistence evidence which was never committed.
DELETE FROM authentication_session_factors;
DELETE FROM authentication_sessions;

ALTER TABLE authentication_sessions
ADD COLUMN csrf_digest BLOB NOT NULL
    DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK (
        length(csrf_digest) = 32
        AND csrf_digest <> X'0000000000000000000000000000000000000000000000000000000000000000'
    );

ALTER TABLE authentication_sessions
ADD COLUMN client_label_state INTEGER NOT NULL DEFAULT 1
    CHECK (client_label_state BETWEEN 1 AND 3);

ALTER TABLE authentication_sessions
ADD COLUMN client_label TEXT CHECK (
    (client_label_state IN (1, 2) AND client_label IS NULL)
    OR (client_label_state = 3
        AND length(client_label) BETWEEN 1 AND 80
        AND client_label = trim(client_label))
);

ALTER TABLE authentication_sessions
ADD COLUMN persistent_cookie INTEGER NOT NULL DEFAULT 0
    CHECK (persistent_cookie IN (0, 1));

CREATE UNIQUE INDEX authentication_sessions_csrf_digest
ON authentication_sessions(csrf_digest);

DROP TRIGGER authentication_session_evidence_immutable;

CREATE TRIGGER authentication_session_evidence_immutable
BEFORE UPDATE OF
    session_id, token_digest, csrf_digest, client_label_state, client_label, persistent_cookie,
    user_principal_id, service, assurance, identity_revision, issued_at, expires_at
ON authentication_sessions
BEGIN
    SELECT RAISE(ABORT, 'authentication session evidence is immutable');
END;
