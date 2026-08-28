-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE version_cleanup_reference_fences (
    operation_id BLOB PRIMARY KEY
        REFERENCES version_reachability_scans(operation_id) ON DELETE CASCADE
        CHECK (length(operation_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    version_id BLOB NOT NULL REFERENCES file_versions(version_id)
        CHECK (length(version_id) = 16),
    manifest_id BLOB NOT NULL REFERENCES content_manifests(manifest_id)
        CHECK (length(manifest_id) = 16),
    manifest_root_digest BLOB NOT NULL CHECK (length(manifest_root_digest) = 32),
    subject_digest BLOB NOT NULL CHECK (length(subject_digest) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    installed_at INTEGER NOT NULL,
    released_at INTEGER,
    CHECK ((state = 1) = (released_at IS NULL))
) STRICT;

CREATE UNIQUE INDEX version_cleanup_reference_fences_active_manifest
ON version_cleanup_reference_fences(manifest_root_digest) WHERE state = 1;

CREATE INDEX version_cleanup_reference_fences_active_manifest_id
ON version_cleanup_reference_fences(manifest_id) WHERE state = 1;
