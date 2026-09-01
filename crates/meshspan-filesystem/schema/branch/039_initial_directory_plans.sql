-- SPDX-License-Identifier: GPL-2.0-only

-- A new volume has no namespace commit until its first visible mutation. Preserve the same durable
-- planning contract while allowing that exact initial transition to carry no expected head.
CREATE TABLE adapter_directory_plans_v39 (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    root_object_id BLOB NOT NULL CHECK (length(root_object_id) = 16),
    expected_namespace_commit_id BLOB NULL CHECK (
        expected_namespace_commit_id IS NULL OR length(expected_namespace_commit_id) = 16
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

CREATE TABLE adapter_directory_plan_ancestors_v39 (
    operation_id BLOB NOT NULL REFERENCES adapter_directory_plans_v39(operation_id),
    ancestor_ordinal INTEGER NOT NULL CHECK (ancestor_ordinal BETWEEN 0 AND 1022),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    expected_revision_id BLOB NOT NULL CHECK (length(expected_revision_id) = 16),
    new_revision_id BLOB NOT NULL CHECK (length(new_revision_id) = 16),
    PRIMARY KEY (operation_id, ancestor_ordinal),
    UNIQUE (operation_id, object_id),
    CHECK (expected_revision_id != new_revision_id)
) STRICT;

INSERT INTO adapter_directory_plans_v39 SELECT * FROM adapter_directory_plans;
INSERT INTO adapter_directory_plan_ancestors_v39 SELECT * FROM adapter_directory_plan_ancestors;

DROP TABLE adapter_directory_plan_ancestors;
DROP TABLE adapter_directory_plans;

ALTER TABLE adapter_directory_plans_v39 RENAME TO adapter_directory_plans;
ALTER TABLE adapter_directory_plan_ancestors_v39 RENAME TO adapter_directory_plan_ancestors;
