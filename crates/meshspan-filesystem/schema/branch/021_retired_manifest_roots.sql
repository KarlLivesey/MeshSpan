-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE retired_manifest_roots (
    retirement_operation_id BLOB PRIMARY KEY CHECK (length(retirement_operation_id) = 16),
    request_digest BLOB NOT NULL UNIQUE CHECK (length(request_digest) = 32),
    cleanup_operation_id BLOB NOT NULL UNIQUE CHECK (length(cleanup_operation_id) = 16),
    source_scan_operation_id BLOB NOT NULL UNIQUE
        REFERENCES version_cleanup_reference_fences(operation_id) ON DELETE RESTRICT
        CHECK (length(source_scan_operation_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    version_id BLOB NOT NULL CHECK (length(version_id) = 16),
    manifest_id BLOB NOT NULL CHECK (length(manifest_id) = 16),
    manifest_root_digest BLOB NOT NULL UNIQUE CHECK (length(manifest_root_digest) = 32),
    reachability_subject_digest BLOB NOT NULL CHECK (length(reachability_subject_digest) = 32),
    completed_item_count INTEGER NOT NULL CHECK (completed_item_count > 0),
    completion_digest BLOB NOT NULL UNIQUE CHECK (length(completion_digest) = 32),
    completion_operation_id BLOB NOT NULL UNIQUE CHECK (length(completion_operation_id) = 16),
    completion_revision INTEGER NOT NULL CHECK (completion_revision > 0),
    completed_at INTEGER NOT NULL,
    retired_at INTEGER NOT NULL CHECK (retired_at >= completed_at),
    retirement_digest BLOB NOT NULL UNIQUE CHECK (length(retirement_digest) = 32)
) STRICT;

CREATE INDEX retired_manifest_roots_manifest
ON retired_manifest_roots(manifest_id, manifest_root_digest);

CREATE INDEX retired_manifest_roots_volume
ON retired_manifest_roots(volume_id, manifest_root_digest);
