-- SPDX-License-Identifier: GPL-2.0-only

-- One target drain is authority, not a UI flag. The work row owns resumable evacuation while
-- this record retains the requested safety mode and terminal safe-to-detach proof.
CREATE TABLE storage_target_drains (
    work_id BLOB PRIMARY KEY REFERENCES maintenance_work_jobs(work_id) ON DELETE RESTRICT
        CHECK (length(work_id) = 16),
    target_id BLOB NOT NULL REFERENCES storage_targets(target_id) ON DELETE RESTRICT
        CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    allow_temporary_degraded INTEGER NOT NULL CHECK (allow_temporary_degraded IN (0, 1)),
    cleanup_requested INTEGER NOT NULL CHECK (cleanup_requested IN (0, 1)),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    requested_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT
        CHECK (length(requested_by) = 16),
    requested_at INTEGER NOT NULL,
    safe_at INTEGER,
    completed_at INTEGER,
    safety_evidence_digest BLOB
        CHECK (safety_evidence_digest IS NULL OR length(safety_evidence_digest) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (target_id, target_generation),
    CHECK ((state >= 2) = (safe_at IS NOT NULL)),
    CHECK ((state >= 2) = (safety_evidence_digest IS NOT NULL)),
    CHECK ((state = 3) = (completed_at IS NOT NULL))
) STRICT;

CREATE INDEX storage_target_drains_by_state
ON storage_target_drains(state, requested_at, target_id);
