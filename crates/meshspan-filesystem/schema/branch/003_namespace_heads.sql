-- SPDX-License-Identifier: GPL-2.0-only

DROP TABLE publication_operations;

CREATE TABLE object_revisions (
    object_revision_id BLOB PRIMARY KEY CHECK (length(object_revision_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    object_kind INTEGER NOT NULL CHECK (object_kind BETWEEN 1 AND 2),
    prior_revision_id BLOB NULL REFERENCES object_revisions(object_revision_id) CHECK (
        prior_revision_id IS NULL OR length(prior_revision_id) = 16
    ),
    directory_root_digest BLOB NULL REFERENCES directory_nodes(node_digest) CHECK (
        directory_root_digest IS NULL OR length(directory_root_digest) = 32
    ),
    file_version_id BLOB NULL REFERENCES file_versions(version_id) CHECK (
        file_version_id IS NULL OR length(file_version_id) = 16
    ),
    revision_digest BLOB NOT NULL UNIQUE CHECK (length(revision_digest) = 32),
    created_by BLOB NOT NULL CHECK (length(created_by) = 16),
    created_at INTEGER NOT NULL,
    CHECK (
        (object_kind = 1 AND directory_root_digest IS NOT NULL AND file_version_id IS NULL)
        OR
        (object_kind = 2 AND directory_root_digest IS NULL AND file_version_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX object_revisions_by_object
ON object_revisions(volume_id, object_id, created_at, object_revision_id);

CREATE TABLE namespace_commits (
    namespace_commit_id BLOB PRIMARY KEY CHECK (length(namespace_commit_id) = 16),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    root_object_id BLOB NOT NULL CHECK (length(root_object_id) = 16),
    root_object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id),
    created_by BLOB NOT NULL CHECK (length(created_by) = 16),
    publication_operation_id BLOB NOT NULL UNIQUE CHECK (
        length(publication_operation_id) = 16
    ),
    created_at INTEGER NOT NULL,
    commit_digest BLOB NOT NULL UNIQUE CHECK (length(commit_digest) = 32)
) STRICT;

CREATE TABLE namespace_commit_parents (
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commits(namespace_commit_id),
    parent_ordinal INTEGER NOT NULL CHECK (parent_ordinal >= 0),
    parent_commit_id BLOB NOT NULL REFERENCES namespace_commits(namespace_commit_id) CHECK (
        length(parent_commit_id) = 16
    ),
    PRIMARY KEY (namespace_commit_id, parent_ordinal),
    UNIQUE (namespace_commit_id, parent_commit_id)
) STRICT;

CREATE TABLE branch_namespace_heads (
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commits(namespace_commit_id),
    head_sequence INTEGER NOT NULL CHECK (head_sequence > 0),
    PRIMARY KEY (branch_id, volume_id)
) STRICT;

CREATE TABLE namespace_publication_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commits(namespace_commit_id),
    file_version_id BLOB NOT NULL REFERENCES file_versions(version_id),
    head_sequence INTEGER NOT NULL CHECK (head_sequence > 0),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    committed_at INTEGER NOT NULL
) STRICT;
