-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE join_grants (
    join_grant_id BLOB PRIMARY KEY CHECK (length(join_grant_id) = 16),
    secret_digest BLOB NOT NULL UNIQUE CHECK (length(secret_digest) = 32),
    issued_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    allowed_roles INTEGER NOT NULL CHECK (allowed_roles BETWEEN 1 AND 7),
    maximum_uses INTEGER NOT NULL CHECK (maximum_uses BETWEEN 1 AND 1000),
    used_count INTEGER NOT NULL DEFAULT 0 CHECK (used_count BETWEEN 0 AND maximum_uses),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    revoked_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
) STRICT;

CREATE INDEX join_grants_active
ON join_grants(expires_at, revoked_at, used_count, maximum_uses);

CREATE TABLE node_certificates (
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation > 0),
    certificate_der BLOB NOT NULL CHECK (length(certificate_der) BETWEEN 1 AND 65536),
    certificate_fingerprint BLOB NOT NULL UNIQUE CHECK (length(certificate_fingerprint) = 32),
    valid_from INTEGER NOT NULL,
    valid_until INTEGER NOT NULL CHECK (valid_until > valid_from),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (node_id, generation)
) STRICT;

CREATE INDEX node_certificates_active
ON node_certificates(node_id, state, valid_until, generation);

CREATE TABLE node_roles (
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    role_code INTEGER NOT NULL CHECK (role_code BETWEEN 1 AND 3),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (node_id, role_code)
) STRICT;

CREATE TABLE join_grant_consumptions (
    join_grant_id BLOB NOT NULL REFERENCES join_grants(join_grant_id) ON DELETE RESTRICT,
    node_id BLOB NOT NULL UNIQUE REFERENCES nodes(node_id) ON DELETE RESTRICT,
    certificate_fingerprint BLOB NOT NULL REFERENCES node_certificates(certificate_fingerprint)
        ON DELETE RESTRICT,
    consumed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (join_grant_id, node_id)
) STRICT;
