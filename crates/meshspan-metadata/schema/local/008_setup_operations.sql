-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE local_setup_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    claim_id BLOB NOT NULL UNIQUE
        REFERENCES local_claim_bundles(claim_id),
    operation_kind INTEGER NOT NULL CHECK (operation_kind IN (1, 2)),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    authority_result_digest BLOB
        CHECK (authority_result_digest IS NULL OR length(authority_result_digest) = 32),
    created_at INTEGER NOT NULL,
    authority_committed_at INTEGER,
    completed_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (state = 1 AND authority_result_digest IS NULL
            AND authority_committed_at IS NULL AND completed_at IS NULL)
        OR (state = 2 AND authority_result_digest IS NOT NULL
            AND authority_committed_at IS NOT NULL
            AND authority_committed_at >= created_at AND completed_at IS NULL)
        OR (state = 3 AND authority_result_digest IS NOT NULL
            AND authority_committed_at IS NOT NULL
            AND authority_committed_at >= created_at
            AND completed_at IS NOT NULL
            AND completed_at >= authority_committed_at)
    )
) STRICT;

CREATE UNIQUE INDEX local_setup_operations_singleton
ON local_setup_operations((1));
