-- SPDX-License-Identifier: GPL-2.0-only

-- Invitation consent and first-method publication share one authority transaction.
CREATE TABLE user_enrollments (
    issuance_operation_id BLOB PRIMARY KEY CHECK (length(issuance_operation_id) = 16)
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED,
    principal_id BLOB NOT NULL REFERENCES users(principal_id),
    principal_revision INTEGER NOT NULL CHECK (principal_revision > 0),
    issued_by BLOB NOT NULL REFERENCES users(principal_id),
    token_digest BLOB NOT NULL UNIQUE CHECK (length(token_digest) = 32),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    redeemed_operation_id BLOB UNIQUE CHECK (redeemed_operation_id IS NULL OR length(redeemed_operation_id) = 16)
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED,
    redeemed_request_digest BLOB CHECK (redeemed_request_digest IS NULL OR length(redeemed_request_digest) = 32),
    method_id BLOB REFERENCES authentication_methods(method_id),
    redeemed_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK ((redeemed_operation_id IS NULL) = (method_id IS NULL)),
    CHECK ((redeemed_operation_id IS NULL) = (redeemed_request_digest IS NULL)),
    CHECK ((redeemed_operation_id IS NULL) = (redeemed_at IS NULL)),
    CHECK (state != 1 OR redeemed_operation_id IS NULL),
    CHECK (state != 2 OR redeemed_operation_id IS NOT NULL),
    CHECK (redeemed_at IS NULL OR (redeemed_at >= issued_at AND redeemed_at < expires_at))
) STRICT;
CREATE UNIQUE INDEX user_enrollments_one_issued_per_user ON user_enrollments(principal_id) WHERE state = 1;
