-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE handle_mutation_operations
ADD COLUMN result_value INTEGER;

ALTER TABLE handle_mutation_operations
ADD COLUMN result_identity BLOB CHECK (
    result_identity IS NULL OR length(result_identity) = 16
);

-- A gateway takeover advances the live lock fence without rewriting the immutable acquisition
-- receipt. Existing v10 rows were acquired under their then-current live fence.
ALTER TABLE range_locks
ADD COLUMN acquired_handle_fence INTEGER NOT NULL DEFAULT 1
    CHECK (acquired_handle_fence > 0);

UPDATE range_locks
SET acquired_handle_fence = handle_fence;

CREATE TABLE pending_object_deletes (
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    requesting_handle_id BLOB NOT NULL REFERENCES open_handles(handle_id),
    object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(object_revision_id) = 16),
    version_id BLOB NOT NULL REFERENCES file_versions(version_id)
        CHECK (length(version_id) = 16),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    requested_at INTEGER NOT NULL,
    ready_at INTEGER,
    PRIMARY KEY (branch_id, object_id),
    FOREIGN KEY (branch_id, object_id) REFERENCES branch_files(branch_id, object_id),
    CHECK ((state = 2) = (ready_at IS NOT NULL))
) STRICT;

CREATE INDEX pending_object_deletes_by_state
ON pending_object_deletes(state, branch_id, volume_id, object_id);
