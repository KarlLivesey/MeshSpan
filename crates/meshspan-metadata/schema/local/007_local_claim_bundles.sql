-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE local_claim_bundles (
    claim_id BLOB PRIMARY KEY CHECK (length(claim_id) = 16),
    node_public_key_fingerprint BLOB NOT NULL
        CHECK (length(node_public_key_fingerprint) = 32),
    secret_digest BLOB NOT NULL UNIQUE CHECK (length(secret_digest) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    created_at INTEGER NOT NULL,
    consumed_at INTEGER,
    rotated_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (state = 1 AND consumed_at IS NULL AND rotated_at IS NULL)
        OR (state = 2 AND consumed_at IS NOT NULL AND consumed_at >= created_at
            AND rotated_at IS NULL)
        OR (state = 3 AND consumed_at IS NULL AND rotated_at IS NOT NULL
            AND rotated_at >= created_at)
    )
) STRICT;

CREATE UNIQUE INDEX local_claim_bundles_one_active
ON local_claim_bundles(state)
WHERE state = 1;

CREATE INDEX local_claim_bundles_by_revision
ON local_claim_bundles(revision, claim_id);
