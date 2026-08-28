-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE handle_flush_plans (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    handle_id BLOB NOT NULL REFERENCES open_handles(handle_id) CHECK (length(handle_id) = 16),
    handle_fence INTEGER NOT NULL CHECK (handle_fence > 0),
    principal_id BLOB NOT NULL CHECK (length(principal_id) = 16),
    authorization_revision INTEGER NOT NULL CHECK (authorization_revision > 0),
    gateway_node_id BLOB NOT NULL CHECK (length(gateway_node_id) = 16),
    stage_sequence INTEGER NOT NULL CHECK (stage_sequence > 0),
    final_length INTEGER NOT NULL CHECK (final_length >= 0),
    sparse INTEGER NOT NULL CHECK (sparse IN (0, 1)),
    retain_superseded_history INTEGER NOT NULL CHECK (retain_superseded_history IN (0, 1)),
    retention_policy_sequence INTEGER NOT NULL CHECK (retention_policy_sequence > 0),
    manifest_format_version INTEGER NOT NULL CHECK (manifest_format_version > 0),
    content_authorization_revision INTEGER NOT NULL CHECK (content_authorization_revision > 0),
    content_deadline INTEGER NOT NULL,
    planned_at INTEGER NOT NULL,
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    expected_version_id BLOB NOT NULL REFERENCES file_versions(version_id)
        CHECK (length(expected_version_id) = 16),
    version_id BLOB NOT NULL UNIQUE CHECK (length(version_id) = 16),
    manifest_id BLOB NOT NULL UNIQUE CHECK (length(manifest_id) = 16),
    expected_namespace_commit_id BLOB NOT NULL REFERENCES namespace_commits(namespace_commit_id)
        CHECK (length(expected_namespace_commit_id) = 16),
    expected_file_object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(expected_file_object_revision_id) = 16),
    file_object_revision_id BLOB NOT NULL UNIQUE CHECK (length(file_object_revision_id) = 16),
    root_object_id BLOB NOT NULL CHECK (length(root_object_id) = 16),
    expected_root_object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(expected_root_object_revision_id) = 16),
    root_object_revision_id BLOB NOT NULL UNIQUE CHECK (length(root_object_revision_id) = 16),
    namespace_commit_id BLOB NOT NULL UNIQUE CHECK (length(namespace_commit_id) = 16),
    entry_generation INTEGER NOT NULL CHECK (entry_generation > 0),
    path_depth INTEGER NOT NULL CHECK (path_depth BETWEEN 1 AND 1024),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    CHECK (content_deadline > planned_at)
) STRICT;

CREATE TABLE handle_flush_plan_path_components (
    operation_id BLOB NOT NULL REFERENCES handle_flush_plans(operation_id),
    component_ordinal INTEGER NOT NULL CHECK (component_ordinal BETWEEN 0 AND 1023),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 16384),
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 16384),
    PRIMARY KEY (operation_id, component_ordinal)
) STRICT;

CREATE TABLE handle_flush_plan_ancestors (
    operation_id BLOB NOT NULL REFERENCES handle_flush_plans(operation_id),
    ancestor_ordinal INTEGER NOT NULL CHECK (ancestor_ordinal BETWEEN 0 AND 1022),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    expected_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(expected_revision_id) = 16),
    new_revision_id BLOB NOT NULL UNIQUE CHECK (length(new_revision_id) = 16),
    PRIMARY KEY (operation_id, ancestor_ordinal)
) STRICT;

CREATE TABLE handle_flush_progress (
    handle_id BLOB PRIMARY KEY REFERENCES open_handles(handle_id) CHECK (length(handle_id) = 16),
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commits(namespace_commit_id)
        CHECK (length(namespace_commit_id) = 16),
    object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(object_revision_id) = 16),
    version_id BLOB NOT NULL REFERENCES file_versions(version_id) CHECK (length(version_id) = 16),
    committed_stage_sequence INTEGER NOT NULL CHECK (committed_stage_sequence > 0),
    flush_operation_id BLOB NOT NULL UNIQUE REFERENCES handle_flush_plans(operation_id)
        CHECK (length(flush_operation_id) = 16)
) STRICT;

CREATE INDEX handle_flush_plans_by_handle
ON handle_flush_plans(handle_id, handle_fence, stage_sequence, planned_at, operation_id);
