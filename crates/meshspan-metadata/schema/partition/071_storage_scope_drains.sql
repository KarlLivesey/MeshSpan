-- SPDX-License-Identifier: GPL-2.0-only

-- Node and fault-group drains are authoritative fences composed from ordinary target drains.
-- The target set stays derivable because registration and group-membership mutation are rejected
-- while the scope is live. Terminal evidence binds every child target proof and, for a node,
-- exclusion from the active consensus membership.
CREATE TABLE storage_scope_drains (
    drain_id BLOB PRIMARY KEY CHECK (length(drain_id) = 16),
    scope_kind INTEGER NOT NULL CHECK (scope_kind IN (1, 2)),
    scope_id BLOB NOT NULL CHECK (length(scope_id) = 16),
    scope_incarnation INTEGER CHECK (scope_incarnation IS NULL OR scope_incarnation > 0),
    allow_temporary_degraded INTEGER NOT NULL CHECK (allow_temporary_degraded IN (0, 1)),
    cleanup_requested INTEGER NOT NULL CHECK (cleanup_requested IN (0, 1)),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    requested_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT
        CHECK (length(requested_by) = 16),
    requested_at INTEGER NOT NULL,
    membership_fenced_at INTEGER,
    safe_at INTEGER,
    safety_evidence_digest BLOB
        CHECK (safety_evidence_digest IS NULL OR length(safety_evidence_digest) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (scope_kind, scope_id),
    CHECK ((scope_kind = 1) = (scope_incarnation IS NOT NULL)),
    CHECK (scope_kind = 2 OR (state >= 2) = (membership_fenced_at IS NOT NULL)),
    CHECK (scope_kind = 1 OR membership_fenced_at IS NULL),
    CHECK ((state = 3) = (safe_at IS NOT NULL)),
    CHECK ((state = 3) = (safety_evidence_digest IS NOT NULL))
) STRICT;

CREATE INDEX storage_scope_drains_by_state
ON storage_scope_drains(state, requested_at, drain_id);
