-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE version_cleanup_intents (
    cleanup_operation_id BLOB PRIMARY KEY
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(cleanup_operation_id) = 16),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE RESTRICT
        CHECK (length(volume_id) = 16),
    version_id BLOB NOT NULL UNIQUE CHECK (length(version_id) = 16),
    manifest_id BLOB NOT NULL CHECK (length(manifest_id) = 16),
    source_scan_operation_id BLOB NOT NULL UNIQUE CHECK (length(source_scan_operation_id) = 16),
    scan_request_digest BLOB NOT NULL CHECK (length(scan_request_digest) = 32),
    retention_policy_sequence INTEGER NOT NULL CHECK (retention_policy_sequence > 0),
    reachability_revision INTEGER NOT NULL CHECK (reachability_revision > 0),
    retained_root_count INTEGER NOT NULL CHECK (retained_root_count > 0),
    retained_root_digest BLOB NOT NULL CHECK (length(retained_root_digest) = 32),
    local_roots_digest BLOB NOT NULL CHECK (length(local_roots_digest) = 32),
    proof_result_digest BLOB NOT NULL UNIQUE CHECK (length(proof_result_digest) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    proposed_at INTEGER NOT NULL,
    completed_at INTEGER,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    CHECK ((state = 2) = (completed_at IS NOT NULL))
) STRICT;

CREATE INDEX version_cleanup_intents_manifest
ON version_cleanup_intents(manifest_id, state, cleanup_operation_id);
