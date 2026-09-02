-- SPDX-License-Identifier: GPL-2.0-only

-- Slow work remains durable authority while short-lived claims merely fence execution. The
-- subject payload is a closed, versioned MeshSpan encoding decoded and revalidated on every read.
CREATE TABLE maintenance_work_jobs (
    work_id BLOB PRIMARY KEY CHECK (length(work_id) = 16),
    deduplication_key BLOB NOT NULL UNIQUE CHECK (length(deduplication_key) = 32),
    work_kind INTEGER NOT NULL CHECK (work_kind BETWEEN 1 AND 5),
    subject_payload BLOB NOT NULL CHECK (length(subject_payload) BETWEEN 2 AND 128),
    data_unavailable INTEGER NOT NULL CHECK (data_unavailable IN (0, 1)),
    remaining_recovery_margin INTEGER NOT NULL
        CHECK (remaining_recovery_margin BETWEEN 0 AND 65535),
    protection_debt INTEGER NOT NULL CHECK (protection_debt BETWEEN 0 AND 65535),
    locality_debt INTEGER NOT NULL CHECK (locality_debt BETWEEN 0 AND 65535),
    instability INTEGER NOT NULL CHECK (instability BETWEEN 0 AND 65535),
    access_heat INTEGER NOT NULL CHECK (access_heat BETWEEN 0 AND 65535),
    due_at INTEGER,
    priority INTEGER NOT NULL CHECK (priority > 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    next_attempt_at INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    created_at INTEGER NOT NULL,
    completed_at INTEGER,
    result_digest BLOB CHECK (result_digest IS NULL OR length(result_digest) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK ((state = 3) = (completed_at IS NOT NULL)),
    CHECK ((state = 3) = (result_digest IS NOT NULL))
) STRICT;

CREATE INDEX maintenance_work_jobs_ready
ON maintenance_work_jobs(state, next_attempt_at, priority DESC, created_at, work_id);

CREATE TABLE maintenance_work_claims (
    work_id BLOB NOT NULL REFERENCES maintenance_work_jobs(work_id) ON DELETE RESTRICT,
    claim_generation INTEGER NOT NULL CHECK (claim_generation > 0),
    worker_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(worker_node_id) = 16),
    worker_incarnation INTEGER NOT NULL CHECK (worker_incarnation > 0),
    fence INTEGER NOT NULL CHECK (fence > 0),
    claimed_at INTEGER NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    completed_at INTEGER,
    result_digest BLOB CHECK (result_digest IS NULL OR length(result_digest) = 32),
    retry_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (work_id, claim_generation),
    UNIQUE (work_id, fence),
    CHECK (lease_expires_at > claimed_at),
    CHECK ((state = 3) = (completed_at IS NOT NULL)),
    CHECK ((state = 3) = (result_digest IS NOT NULL)),
    CHECK (retry_at IS NULL OR state = 3)
) STRICT;

CREATE UNIQUE INDEX one_active_maintenance_work_claim
ON maintenance_work_claims(work_id)
WHERE state = 1;

CREATE INDEX maintenance_work_claims_by_worker
ON maintenance_work_claims(worker_node_id, worker_incarnation, state, lease_expires_at, work_id);
