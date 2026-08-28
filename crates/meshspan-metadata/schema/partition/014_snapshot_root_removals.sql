-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE snapshot_root_removals (
    snapshot_id BLOB PRIMARY KEY
        REFERENCES volume_snapshots(snapshot_id) ON DELETE RESTRICT
        CHECK (length(snapshot_id) = 16),
    operation_id BLOB NOT NULL UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(operation_id) = 16),
    expiry_operation_id BLOB NOT NULL UNIQUE
        REFERENCES snapshot_expiry_requests(operation_id) ON DELETE RESTRICT
        CHECK (length(expiry_operation_id) = 16),
    namespace_commit_id BLOB NOT NULL CHECK (length(namespace_commit_id) = 16),
    root_object_revision_id BLOB NOT NULL CHECK (length(root_object_revision_id) = 16),
    removed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0)
) STRICT;
