-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    migration_digest BLOB NOT NULL UNIQUE CHECK (length(migration_digest) = 32),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE branch_files (
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    current_version_id BLOB NULL CHECK (
        current_version_id IS NULL OR length(current_version_id) = 16
    ),
    head_sequence INTEGER NOT NULL CHECK (head_sequence >= 0),
    PRIMARY KEY (branch_id, object_id)
) STRICT;

CREATE TABLE content_manifests (
    manifest_id BLOB PRIMARY KEY CHECK (length(manifest_id) = 16),
    format_version INTEGER NOT NULL CHECK (format_version > 0),
    logical_length INTEGER NOT NULL CHECK (logical_length >= 0),
    content_digest BLOB NOT NULL CHECK (length(content_digest) = 32),
    root_digest BLOB NOT NULL CHECK (length(root_digest) = 32),
    state INTEGER NOT NULL CHECK (state = 1)
) STRICT;

CREATE TABLE file_versions (
    version_id BLOB PRIMARY KEY CHECK (length(version_id) = 16),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    parent_version_id BLOB NULL REFERENCES file_versions(version_id) CHECK (
        parent_version_id IS NULL OR length(parent_version_id) = 16
    ),
    manifest_id BLOB NOT NULL REFERENCES content_manifests(manifest_id),
    logical_length INTEGER NOT NULL CHECK (logical_length >= 0),
    content_digest BLOB NOT NULL CHECK (length(content_digest) = 32),
    created_by BLOB NOT NULL CHECK (length(created_by) = 16),
    created_at INTEGER NOT NULL,
    publication_operation_id BLOB NOT NULL UNIQUE CHECK (
        length(publication_operation_id) = 16
    ),
    FOREIGN KEY (branch_id, object_id) REFERENCES branch_files(branch_id, object_id)
) STRICT;

CREATE INDEX file_versions_by_object
ON file_versions(branch_id, object_id, created_at, version_id);

CREATE TABLE publication_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    version_id BLOB NOT NULL REFERENCES file_versions(version_id),
    head_sequence INTEGER NOT NULL CHECK (head_sequence > 0),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    committed_at INTEGER NOT NULL
) STRICT;
