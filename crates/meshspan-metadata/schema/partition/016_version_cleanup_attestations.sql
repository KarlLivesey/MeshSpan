-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE version_cleanup_intents
ADD COLUMN required_attestation_count INTEGER CHECK (
    required_attestation_count IS NULL OR required_attestation_count > 0
);

ALTER TABLE version_cleanup_intents
ADD COLUMN reachability_subject_digest BLOB CHECK (
    reachability_subject_digest IS NULL OR length(reachability_subject_digest) = 32
);

CREATE TABLE cleanup_attestation_keys (
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(node_id) = 16),
    generation INTEGER NOT NULL CHECK (generation > 0),
    verifying_key BLOB NOT NULL CHECK (length(verifying_key) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    created_at INTEGER NOT NULL,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (node_id, generation),
    UNIQUE (node_id, verifying_key),
    CHECK ((state = 1) = (retired_at IS NULL))
) STRICT;

CREATE UNIQUE INDEX cleanup_attestation_keys_active
ON cleanup_attestation_keys(node_id) WHERE state = 1;

CREATE TABLE version_cleanup_participants (
    cleanup_operation_id BLOB NOT NULL
        REFERENCES version_cleanup_intents(cleanup_operation_id) ON DELETE CASCADE
        CHECK (length(cleanup_operation_id) = 16),
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(node_id) = 16),
    node_incarnation INTEGER NOT NULL CHECK (node_incarnation > 0),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    attestation_operation_id BLOB UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (attestation_operation_id IS NULL OR length(attestation_operation_id) = 16),
    key_generation INTEGER,
    scan_operation_id BLOB
        CHECK (scan_operation_id IS NULL OR length(scan_operation_id) = 16),
    scan_request_digest BLOB
        CHECK (scan_request_digest IS NULL OR length(scan_request_digest) = 32),
    reachability_subject_digest BLOB
        CHECK (reachability_subject_digest IS NULL OR length(reachability_subject_digest) = 32),
    local_roots_digest BLOB
        CHECK (local_roots_digest IS NULL OR length(local_roots_digest) = 32),
    scan_result_digest BLOB
        CHECK (scan_result_digest IS NULL OR length(scan_result_digest) = 32),
    signature BLOB CHECK (signature IS NULL OR length(signature) = 64),
    attested_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (cleanup_operation_id, node_id),
    FOREIGN KEY (node_id, key_generation)
        REFERENCES cleanup_attestation_keys(node_id, generation) ON DELETE RESTRICT,
    CHECK (
        (state = 1 AND attestation_operation_id IS NULL AND key_generation IS NULL
            AND scan_operation_id IS NULL AND scan_request_digest IS NULL
            AND reachability_subject_digest IS NULL
            AND local_roots_digest IS NULL AND scan_result_digest IS NULL
            AND signature IS NULL AND attested_at IS NULL)
        OR
        (state = 2 AND attestation_operation_id IS NOT NULL AND key_generation IS NOT NULL
            AND scan_operation_id IS NOT NULL AND scan_request_digest IS NOT NULL
            AND reachability_subject_digest IS NOT NULL
            AND local_roots_digest IS NOT NULL AND scan_result_digest IS NOT NULL
            AND signature IS NOT NULL AND attested_at IS NOT NULL)
    )
) STRICT;

CREATE INDEX version_cleanup_participants_pending
ON version_cleanup_participants(cleanup_operation_id, state, node_id);
