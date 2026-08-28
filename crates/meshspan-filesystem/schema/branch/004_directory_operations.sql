-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE directory_publication_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commits(namespace_commit_id),
    directory_object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id),
    head_sequence INTEGER NOT NULL CHECK (head_sequence > 0),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    committed_at INTEGER NOT NULL
) STRICT;
