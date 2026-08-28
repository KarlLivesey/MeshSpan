-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE namespace_reconciliation_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    causal_plan_digest BLOB NOT NULL CHECK (length(causal_plan_digest) = 32),
    replay_plan_digest BLOB NOT NULL CHECK (length(replay_plan_digest) = 32),
    namespace_commit_id BLOB NOT NULL UNIQUE REFERENCES namespace_commits(namespace_commit_id),
    root_object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    committed_at INTEGER NOT NULL
) STRICT;
