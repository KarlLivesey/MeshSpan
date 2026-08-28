-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE volume_snapshot_restores (
    metadata_operation_id BLOB PRIMARY KEY
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(metadata_operation_id) = 16),
    snapshot_id BLOB NOT NULL REFERENCES volume_snapshots(snapshot_id)
        CHECK (length(snapshot_id) = 16),
    snapshot_revision INTEGER NOT NULL CHECK (snapshot_revision > 0),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE CASCADE
        CHECK (length(volume_id) = 16),
    previous_namespace_commit_id BLOB NOT NULL CHECK (
        length(previous_namespace_commit_id) = 16
    ),
    namespace_commit_id BLOB NOT NULL UNIQUE
        REFERENCES volume_head_transitions(namespace_commit_id)
        CHECK (length(namespace_commit_id) = 16),
    source_operation_id BLOB NOT NULL UNIQUE CHECK (length(source_operation_id) = 16),
    restored_by BLOB NOT NULL REFERENCES principals(principal_id)
        CHECK (length(restored_by) = 16),
    restored_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    CHECK (previous_namespace_commit_id <> namespace_commit_id)
) STRICT;

CREATE INDEX volume_snapshot_restores_by_snapshot
ON volume_snapshot_restores(snapshot_id, restored_at DESC, metadata_operation_id);
