-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE volume_snapshots (
    snapshot_id BLOB PRIMARY KEY CHECK (length(snapshot_id) = 16),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE CASCADE,
    namespace_commit_id BLOB NOT NULL CHECK (length(namespace_commit_id) = 16),
    root_object_revision_id BLOB NOT NULL CHECK (length(root_object_revision_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    protected_from_expiry INTEGER NOT NULL CHECK (protected_from_expiry IN (0, 1)),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    removed_at INTEGER,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    UNIQUE (volume_id, canonical_name),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK ((state = 3) = (removed_at IS NOT NULL))
) STRICT;

CREATE INDEX volume_snapshots_by_volume
ON volume_snapshots(volume_id, canonical_name, snapshot_id);

CREATE INDEX volume_snapshots_due
ON volume_snapshots(state, protected_from_expiry, expires_at, snapshot_id);
