-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE version_reachability_scans (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    version_id BLOB NOT NULL REFERENCES file_versions(version_id)
        CHECK (length(version_id) = 16),
    manifest_id BLOB NOT NULL REFERENCES content_manifests(manifest_id)
        CHECK (length(manifest_id) = 16),
    metadata_revision INTEGER NOT NULL CHECK (metadata_revision > 0),
    expected_root_count INTEGER NOT NULL CHECK (expected_root_count > 0),
    expected_root_digest BLOB NOT NULL CHECK (length(expected_root_digest) = 32),
    roots_received INTEGER NOT NULL DEFAULT 0 CHECK (
        roots_received >= 0 AND roots_received <= expected_root_count
    ),
    local_roots_digest BLOB CHECK (
        local_roots_digest IS NULL OR length(local_roots_digest) = 32
    ),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    result_digest BLOB CHECK (result_digest IS NULL OR length(result_digest) = 32),
    CHECK ((state >= 3) = (completed_at IS NOT NULL)),
    CHECK ((state >= 3) = (result_digest IS NOT NULL)),
    UNIQUE (version_id, metadata_revision, operation_id)
) STRICT;

CREATE TABLE version_reachability_roots (
    operation_id BLOB NOT NULL REFERENCES version_reachability_scans(operation_id) ON DELETE CASCADE,
    root_ordinal INTEGER NOT NULL CHECK (root_ordinal >= 0),
    source_kind INTEGER NOT NULL CHECK (source_kind IN (1, 2)),
    source_id BLOB NOT NULL CHECK (length(source_id) = 16),
    namespace_commit_id BLOB NOT NULL CHECK (length(namespace_commit_id) = 16),
    root_object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(root_object_revision_id) = 16),
    record_digest BLOB NOT NULL CHECK (length(record_digest) = 32),
    PRIMARY KEY (operation_id, root_ordinal),
    UNIQUE (operation_id, source_kind, source_id)
) STRICT;

CREATE TABLE version_reachability_work (
    operation_id BLOB NOT NULL REFERENCES version_reachability_scans(operation_id) ON DELETE CASCADE,
    work_kind INTEGER NOT NULL CHECK (work_kind IN (1, 2)),
    identity BLOB NOT NULL CHECK (
        (work_kind = 1 AND length(identity) = 16)
        OR (work_kind = 2 AND length(identity) = 32)
    ),
    processed INTEGER NOT NULL DEFAULT 0 CHECK (processed IN (0, 1)),
    PRIMARY KEY (operation_id, work_kind, identity)
) STRICT;

CREATE INDEX version_reachability_pending
ON version_reachability_work(operation_id, processed, work_kind, identity);
