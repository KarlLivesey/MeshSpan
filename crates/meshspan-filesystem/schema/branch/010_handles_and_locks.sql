-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE open_handles (
    handle_id BLOB PRIMARY KEY CHECK (length(handle_id) = 16),
    open_operation_id BLOB NOT NULL UNIQUE CHECK (length(open_operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    opened_namespace_commit_id BLOB NOT NULL REFERENCES namespace_commits(namespace_commit_id)
        CHECK (length(opened_namespace_commit_id) = 16),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(object_revision_id) = 16),
    opened_version_id BLOB NOT NULL REFERENCES file_versions(version_id)
        CHECK (length(opened_version_id) = 16),
    principal_id BLOB NOT NULL CHECK (length(principal_id) = 16),
    authorization_revision INTEGER NOT NULL CHECK (authorization_revision > 0),
    gateway_node_id BLOB NOT NULL CHECK (length(gateway_node_id) = 16),
    opened_fence INTEGER NOT NULL CHECK (opened_fence = 1),
    handle_fence INTEGER NOT NULL CHECK (handle_fence >= opened_fence),
    desired_access INTEGER NOT NULL CHECK (desired_access BETWEEN 1 AND 7),
    share_access INTEGER NOT NULL CHECK (share_access BETWEEN 0 AND 7),
    create_disposition INTEGER NOT NULL CHECK (create_disposition BETWEEN 1 AND 5),
    delete_on_close INTEGER NOT NULL CHECK (delete_on_close IN (0, 1)),
    lease_expires_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    opened_at INTEGER NOT NULL,
    closed_at INTEGER,
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32),
    FOREIGN KEY (branch_id, object_id) REFERENCES branch_files(branch_id, object_id),
    CHECK (lease_expires_at > opened_at),
    CHECK ((state = 1) = (closed_at IS NULL))
) STRICT;

CREATE INDEX open_handles_by_object
ON open_handles(branch_id, volume_id, object_id, state, lease_expires_at, handle_id);

CREATE TABLE range_locks (
    lock_id BLOB PRIMARY KEY CHECK (length(lock_id) = 16),
    operation_id BLOB NOT NULL UNIQUE CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    handle_id BLOB NOT NULL REFERENCES open_handles(handle_id),
    handle_fence INTEGER NOT NULL CHECK (handle_fence > 0),
    byte_start INTEGER NOT NULL CHECK (byte_start >= 0),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    lock_kind INTEGER NOT NULL CHECK (lock_kind IN (1, 2)),
    lease_expires_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_at INTEGER NOT NULL,
    released_at INTEGER,
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32),
    CHECK (byte_start <= 9223372036854775807 - byte_length),
    CHECK (lease_expires_at > created_at),
    CHECK ((state = 1) = (released_at IS NULL))
) STRICT;

CREATE INDEX range_locks_by_object_range
ON range_locks(handle_id, state, lease_expires_at, byte_start, byte_length, lock_id);

CREATE TABLE handle_mutation_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    operation_kind INTEGER NOT NULL CHECK (operation_kind BETWEEN 1 AND 3),
    handle_id BLOB NOT NULL REFERENCES open_handles(handle_id),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    resulting_fence INTEGER NOT NULL CHECK (resulting_fence > 0),
    result_code INTEGER NOT NULL CHECK (result_code BETWEEN 1 AND 3),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    committed_at INTEGER NOT NULL
) STRICT;
