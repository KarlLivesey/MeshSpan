-- SPDX-License-Identifier: GPL-2.0-only

-- A semantic connector request is planned once against one exact namespace head.  The plan is
-- durable before publication so a crash or lost response cannot make a retry silently rebase.
CREATE TABLE adapter_directory_plans (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    root_object_id BLOB NOT NULL CHECK (length(root_object_id) = 16),
    expected_namespace_commit_id BLOB NOT NULL CHECK (
        length(expected_namespace_commit_id) = 16
    ),
    directory_object_id BLOB NOT NULL CHECK (length(directory_object_id) = 16),
    directory_object_revision_id BLOB NOT NULL CHECK (
        length(directory_object_revision_id) = 16
    ),
    root_object_revision_id BLOB NOT NULL CHECK (length(root_object_revision_id) = 16),
    namespace_commit_id BLOB NOT NULL CHECK (length(namespace_commit_id) = 16),
    entry_generation INTEGER NOT NULL CHECK (entry_generation > 0),
    parent_object_id BLOB NOT NULL CHECK (length(parent_object_id) = 16),
    created_by BLOB NOT NULL CHECK (length(created_by) = 16),
    created_at INTEGER NOT NULL,
    path_depth INTEGER NOT NULL CHECK (path_depth BETWEEN 1 AND 1024),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32)
) STRICT;

CREATE TABLE adapter_directory_plan_ancestors (
    operation_id BLOB NOT NULL REFERENCES adapter_directory_plans(operation_id),
    ancestor_ordinal INTEGER NOT NULL CHECK (ancestor_ordinal BETWEEN 0 AND 1022),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    expected_revision_id BLOB NOT NULL CHECK (length(expected_revision_id) = 16),
    new_revision_id BLOB NOT NULL CHECK (length(new_revision_id) = 16),
    PRIMARY KEY (operation_id, ancestor_ordinal),
    UNIQUE (operation_id, object_id),
    CHECK (expected_revision_id != new_revision_id)
) STRICT;
