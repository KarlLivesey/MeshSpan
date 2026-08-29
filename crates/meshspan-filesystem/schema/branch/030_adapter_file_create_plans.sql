-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE adapter_file_create_plans (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    handle_id BLOB NOT NULL CHECK (length(handle_id) = 16),
    principal_id BLOB NOT NULL CHECK (length(principal_id) = 16),
    authorization_revision INTEGER NOT NULL CHECK (authorization_revision > 0),
    gateway_node_id BLOB NOT NULL CHECK (length(gateway_node_id) = 16),
    gateway_incarnation INTEGER NOT NULL CHECK (gateway_incarnation > 0),
    retain_superseded_history INTEGER NOT NULL CHECK (retain_superseded_history IN (0, 1)),
    retention_policy_sequence INTEGER NOT NULL CHECK (retention_policy_sequence > 0),
    manifest_format_version INTEGER NOT NULL CHECK (
        manifest_format_version BETWEEN 1 AND 65535
    ),
    creation_operation_id BLOB NOT NULL UNIQUE CHECK (length(creation_operation_id) = 16),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    version_id BLOB NOT NULL CHECK (length(version_id) = 16),
    manifest_id BLOB NOT NULL CHECK (length(manifest_id) = 16),
    root_object_id BLOB NOT NULL CHECK (length(root_object_id) = 16),
    expected_namespace_commit_id BLOB NOT NULL CHECK (
        length(expected_namespace_commit_id) = 16
    ),
    file_object_revision_id BLOB NOT NULL CHECK (length(file_object_revision_id) = 16),
    root_object_revision_id BLOB NOT NULL CHECK (length(root_object_revision_id) = 16),
    namespace_commit_id BLOB NOT NULL CHECK (length(namespace_commit_id) = 16),
    entry_generation INTEGER NOT NULL CHECK (entry_generation > 0),
    parent_object_id BLOB NOT NULL CHECK (length(parent_object_id) = 16),
    created_at INTEGER NOT NULL,
    path_depth INTEGER NOT NULL CHECK (path_depth BETWEEN 1 AND 1024),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32)
) STRICT;

CREATE TABLE adapter_file_create_plan_ancestors (
    operation_id BLOB NOT NULL REFERENCES adapter_file_create_plans(operation_id),
    ancestor_ordinal INTEGER NOT NULL CHECK (ancestor_ordinal BETWEEN 0 AND 1022),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    expected_revision_id BLOB NOT NULL CHECK (length(expected_revision_id) = 16),
    new_revision_id BLOB NOT NULL CHECK (length(new_revision_id) = 16),
    PRIMARY KEY (operation_id, ancestor_ordinal),
    UNIQUE (operation_id, object_id),
    CHECK (expected_revision_id != new_revision_id)
) STRICT;
