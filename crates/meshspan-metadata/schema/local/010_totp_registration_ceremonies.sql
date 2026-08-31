-- SPDX-License-Identifier: GPL-2.0-only

-- TOTP enrolment uses the same crash-safe reservation/authority/consumption
-- lifecycle as passkey ceremonies, but has its own exact adapter kind.
ALTER TABLE local_authentication_ceremonies
RENAME TO local_authentication_ceremonies_v9;

CREATE TABLE local_authentication_ceremonies (
    challenge_id BLOB PRIMARY KEY CHECK (length(challenge_id) = 16),
    creation_operation_id BLOB NOT NULL UNIQUE CHECK (length(creation_operation_id) = 16),
    ceremony_kind INTEGER NOT NULL CHECK (ceremony_kind BETWEEN 1 AND 4),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    protected_state BLOB NOT NULL CHECK (length(protected_state) BETWEEN 1 AND 65536),
    protected_state_digest BLOB NOT NULL UNIQUE CHECK (length(protected_state_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    completion_operation_id BLOB UNIQUE
        CHECK (completion_operation_id IS NULL OR length(completion_operation_id) = 16),
    assertion_digest BLOB
        CHECK (assertion_digest IS NULL OR length(assertion_digest) = 32),
    authority_result_digest BLOB
        CHECK (authority_result_digest IS NULL OR length(authority_result_digest) = 32),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    verification_started_at INTEGER,
    authority_committed_at INTEGER,
    consumed_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (state = 1 AND completion_operation_id IS NULL AND assertion_digest IS NULL
            AND authority_result_digest IS NULL AND verification_started_at IS NULL
            AND authority_committed_at IS NULL AND consumed_at IS NULL)
        OR (state = 2 AND completion_operation_id IS NOT NULL AND assertion_digest IS NOT NULL
            AND authority_result_digest IS NULL AND verification_started_at IS NOT NULL
            AND verification_started_at >= created_at AND verification_started_at < expires_at
            AND authority_committed_at IS NULL AND consumed_at IS NULL)
        OR (state = 3 AND completion_operation_id IS NOT NULL AND assertion_digest IS NOT NULL
            AND authority_result_digest IS NOT NULL AND verification_started_at IS NOT NULL
            AND authority_committed_at IS NOT NULL
            AND authority_committed_at >= verification_started_at AND consumed_at IS NULL)
        OR (state = 4 AND completion_operation_id IS NOT NULL AND assertion_digest IS NOT NULL
            AND authority_result_digest IS NOT NULL AND verification_started_at IS NOT NULL
            AND authority_committed_at IS NOT NULL AND consumed_at IS NOT NULL
            AND consumed_at >= authority_committed_at)
    )
) STRICT;

INSERT INTO local_authentication_ceremonies(
    challenge_id, creation_operation_id, ceremony_kind, request_digest,
    protected_state, protected_state_digest, state, completion_operation_id,
    assertion_digest, authority_result_digest, created_at, expires_at,
    verification_started_at, authority_committed_at, consumed_at, revision
)
SELECT
    challenge_id, creation_operation_id, ceremony_kind, request_digest,
    protected_state, protected_state_digest, state, completion_operation_id,
    assertion_digest, authority_result_digest, created_at, expires_at,
    verification_started_at, authority_committed_at, consumed_at, revision
FROM local_authentication_ceremonies_v9;

DROP TABLE local_authentication_ceremonies_v9;

CREATE INDEX local_authentication_ceremonies_expiry
ON local_authentication_ceremonies(state, expires_at, challenge_id);
