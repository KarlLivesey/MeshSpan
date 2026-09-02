-- SPDX-License-Identifier: GPL-2.0-only

-- A storage-target scrub is local physical work. This restart journal retains the exact page
-- continuation and rolling evidence until its authoritative complete-pass effect commits.
CREATE TABLE local_maintenance_scrub_progress (
    work_id BLOB PRIMARY KEY CHECK (length(work_id) = 16),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    next_cursor BLOB,
    page_index INTEGER NOT NULL CHECK (page_index >= 0),
    observation_count INTEGER NOT NULL CHECK (observation_count >= 0),
    verified_bytes INTEGER NOT NULL CHECK (verified_bytes >= 0),
    healthy_count INTEGER NOT NULL CHECK (healthy_count >= 0),
    missing_count INTEGER NOT NULL CHECK (missing_count >= 0),
    corrupt_count INTEGER NOT NULL CHECK (corrupt_count >= 0),
    unreadable_count INTEGER NOT NULL CHECK (unreadable_count >= 0),
    unexpected_count INTEGER NOT NULL CHECK (unexpected_count >= 0),
    deferred_count INTEGER NOT NULL CHECK (deferred_count >= 0),
    rolling_evidence_digest BLOB NOT NULL CHECK (length(rolling_evidence_digest) = 32),
    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
    completed_at INTEGER,
    updated_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (next_cursor IS NULL OR length(next_cursor) BETWEEN 1 AND 512),
    CHECK (observation_count = healthy_count + missing_count + corrupt_count
        + unreadable_count + unexpected_count + deferred_count),
    CHECK ((complete = 1 AND next_cursor IS NULL AND completed_at IS NOT NULL)
        OR (complete = 0 AND completed_at IS NULL))
) STRICT;

