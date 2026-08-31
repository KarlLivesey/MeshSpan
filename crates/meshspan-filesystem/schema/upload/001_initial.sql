-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    migration_digest BLOB NOT NULL UNIQUE CHECK (length(migration_digest) = 32),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE upload_sessions (
    upload_id BLOB PRIMARY KEY CHECK (length(upload_id) = 16),
    begin_operation_id BLOB NOT NULL UNIQUE CHECK (length(begin_operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    stage_id BLOB NOT NULL UNIQUE CHECK (length(stage_id) = 16),
    stage_fence INTEGER NOT NULL CHECK (stage_fence > 0),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    principal_id BLOB NOT NULL CHECK (length(principal_id) = 16),
    authorization_revision INTEGER NOT NULL CHECK (authorization_revision > 0),
    disposition INTEGER NOT NULL CHECK (disposition BETWEEN 1 AND 3),
    expected_version_id BLOB CHECK (
        expected_version_id IS NULL OR length(expected_version_id) = 16
    ),
    maximum_bytes INTEGER NOT NULL CHECK (maximum_bytes > 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 6),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    path_depth INTEGER NOT NULL CHECK (path_depth BETWEEN 1 AND 1024),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    abort_operation_id BLOB UNIQUE CHECK (
        abort_operation_id IS NULL OR length(abort_operation_id) = 16
    ),
    abort_request_digest BLOB CHECK (
        abort_request_digest IS NULL OR length(abort_request_digest) = 32
    ),
    aborted_at INTEGER,
    CHECK ((disposition = 2) = (expected_version_id IS NOT NULL)),
    CHECK ((abort_operation_id IS NULL) = (abort_request_digest IS NULL)),
    CHECK ((state IN (3, 4)) = (aborted_at IS NOT NULL)),
    CHECK (state < 3 OR abort_operation_id IS NOT NULL OR state > 4)
) STRICT;

CREATE TABLE upload_path_components (
    upload_id BLOB NOT NULL REFERENCES upload_sessions(upload_id) ON DELETE CASCADE,
    component_ordinal INTEGER NOT NULL CHECK (component_ordinal BETWEEN 0 AND 1023),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 16384),
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 16384),
    PRIMARY KEY (upload_id, component_ordinal)
) STRICT;

CREATE INDEX uploads_by_principal
ON upload_sessions(principal_id, state, expires_at, upload_id);
