-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE cancelled_cleanup_releases (
    release_operation_id BLOB PRIMARY KEY CHECK (length(release_operation_id) = 16),
    request_digest BLOB NOT NULL UNIQUE CHECK (length(request_digest) = 32),
    cleanup_operation_id BLOB NOT NULL UNIQUE CHECK (length(cleanup_operation_id) = 16),
    source_scan_operation_id BLOB NOT NULL UNIQUE
        REFERENCES version_cleanup_reference_fences(operation_id) ON DELETE RESTRICT
        CHECK (length(source_scan_operation_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    version_id BLOB NOT NULL CHECK (length(version_id) = 16),
    manifest_id BLOB NOT NULL CHECK (length(manifest_id) = 16),
    manifest_root_digest BLOB NOT NULL CHECK (length(manifest_root_digest) = 32),
    reachability_subject_digest BLOB NOT NULL CHECK (length(reachability_subject_digest) = 32),
    cancellation_operation_id BLOB NOT NULL UNIQUE
        CHECK (length(cancellation_operation_id) = 16),
    cancellation_revision INTEGER NOT NULL CHECK (cancellation_revision > 0),
    cancelled_at INTEGER NOT NULL,
    released_at INTEGER NOT NULL CHECK (released_at >= cancelled_at),
    release_digest BLOB NOT NULL UNIQUE CHECK (length(release_digest) = 32)
) STRICT;

CREATE INDEX cancelled_cleanup_releases_manifest
ON cancelled_cleanup_releases(manifest_id, manifest_root_digest);
