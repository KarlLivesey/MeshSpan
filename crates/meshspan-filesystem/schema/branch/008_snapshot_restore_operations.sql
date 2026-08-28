-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE namespace_snapshot_restore_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    snapshot_id BLOB NOT NULL CHECK (length(snapshot_id) = 16),
    snapshot_namespace_commit_id BLOB NOT NULL
        REFERENCES namespace_commits(namespace_commit_id)
        CHECK (length(snapshot_namespace_commit_id) = 16),
    expected_namespace_commit_id BLOB NOT NULL
        REFERENCES namespace_commits(namespace_commit_id)
        CHECK (length(expected_namespace_commit_id) = 16),
    namespace_commit_id BLOB NOT NULL UNIQUE
        REFERENCES namespace_commits(namespace_commit_id)
        CHECK (length(namespace_commit_id) = 16),
    root_object_revision_id BLOB NOT NULL
        REFERENCES object_revisions(object_revision_id)
        CHECK (length(root_object_revision_id) = 16),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    prepared_at INTEGER NOT NULL,
    activated_at INTEGER,
    CHECK (snapshot_namespace_commit_id <> namespace_commit_id),
    CHECK (expected_namespace_commit_id <> namespace_commit_id)
) STRICT;
