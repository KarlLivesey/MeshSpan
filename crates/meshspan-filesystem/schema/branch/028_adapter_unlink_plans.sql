-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE adapter_unlink_plans (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    root_object_id BLOB NOT NULL CHECK (length(root_object_id) = 16),
    expected_namespace_commit_id BLOB NOT NULL CHECK (
        length(expected_namespace_commit_id) = 16
    ),
    expected_object_id BLOB NOT NULL CHECK (length(expected_object_id) = 16),
    expected_object_revision_id BLOB NOT NULL CHECK (
        length(expected_object_revision_id) = 16
    ),
    expected_kind INTEGER NOT NULL CHECK (expected_kind IN (1, 2)),
    expected_file_version_id BLOB NULL CHECK (
        expected_file_version_id IS NULL OR length(expected_file_version_id) = 16
    ),
    expected_entry_generation INTEGER NOT NULL CHECK (expected_entry_generation > 0),
    root_object_revision_id BLOB NOT NULL CHECK (length(root_object_revision_id) = 16),
    namespace_commit_id BLOB NOT NULL CHECK (length(namespace_commit_id) = 16),
    requesting_handle_id BLOB NULL CHECK (
        requesting_handle_id IS NULL OR length(requesting_handle_id) = 16
    ),
    created_by BLOB NOT NULL CHECK (length(created_by) = 16),
    created_at INTEGER NOT NULL,
    path_depth INTEGER NOT NULL CHECK (path_depth BETWEEN 1 AND 1024),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    CHECK (
        (expected_kind = 1 AND expected_file_version_id IS NULL)
        OR (expected_kind = 2 AND expected_file_version_id IS NOT NULL)
    )
) STRICT;

CREATE TABLE adapter_unlink_plan_ancestors (
    operation_id BLOB NOT NULL REFERENCES adapter_unlink_plans(operation_id),
    ancestor_ordinal INTEGER NOT NULL CHECK (ancestor_ordinal BETWEEN 0 AND 1022),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    expected_revision_id BLOB NOT NULL CHECK (length(expected_revision_id) = 16),
    new_revision_id BLOB NOT NULL CHECK (length(new_revision_id) = 16),
    PRIMARY KEY (operation_id, ancestor_ordinal),
    UNIQUE (operation_id, object_id),
    CHECK (expected_revision_id != new_revision_id)
) STRICT;
