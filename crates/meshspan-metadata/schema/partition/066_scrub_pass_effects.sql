-- SPDX-License-Identifier: GPL-2.0-only

-- A scrub completes only after every bounded page has been consumed. This immutable summary
-- retains exact classified totals and a canonical digest of the ordered observation stream.
CREATE TABLE maintenance_scrub_effects (
    effect_operation_id BLOB PRIMARY KEY
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(effect_operation_id) = 16),
    work_id BLOB NOT NULL UNIQUE REFERENCES maintenance_work_jobs(work_id) ON DELETE RESTRICT,
    claim_generation INTEGER NOT NULL CHECK (claim_generation > 0),
    worker_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(worker_node_id) = 16),
    worker_incarnation INTEGER NOT NULL CHECK (worker_incarnation > 0),
    fence INTEGER NOT NULL CHECK (fence > 0),
    target_id BLOB NOT NULL REFERENCES storage_targets(target_id) ON DELETE RESTRICT
        CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    observation_count INTEGER NOT NULL CHECK (observation_count >= 0),
    verified_bytes INTEGER NOT NULL CHECK (verified_bytes >= 0),
    healthy_count INTEGER NOT NULL CHECK (healthy_count >= 0),
    missing_count INTEGER NOT NULL CHECK (missing_count >= 0),
    corrupt_count INTEGER NOT NULL CHECK (corrupt_count >= 0),
    unreadable_count INTEGER NOT NULL CHECK (unreadable_count >= 0),
    unexpected_count INTEGER NOT NULL CHECK (unexpected_count >= 0),
    deferred_count INTEGER NOT NULL CHECK (deferred_count >= 0),
    evidence_digest BLOB NOT NULL CHECK (length(evidence_digest) = 32),
    committed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (observation_count = healthy_count + missing_count + corrupt_count
        + unreadable_count + unexpected_count + deferred_count)
) STRICT;

CREATE INDEX maintenance_scrub_effects_by_target
ON maintenance_scrub_effects(target_id, target_generation, committed_at);
