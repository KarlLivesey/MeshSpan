-- SPDX-License-Identifier: GPL-2.0-only

-- Every expensive snapshot/encryption attempt is owned by one incarnation and
-- unpredictable fence at a time. Expired attempts remain durable evidence and
-- cannot publish after a replacement claim exists.
CREATE TABLE metadata_backup_run_claims (
    backup_id BLOB NOT NULL REFERENCES metadata_backup_runs(backup_id) ON DELETE RESTRICT
        CHECK (length(backup_id) = 16),
    claim_generation INTEGER NOT NULL CHECK (claim_generation > 0),
    worker_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(worker_node_id) = 16),
    worker_incarnation INTEGER NOT NULL CHECK (worker_incarnation > 0),
    fence INTEGER NOT NULL CHECK (fence > 0),
    claimed_at INTEGER NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    finished_at INTEGER,
    result_digest BLOB CHECK (result_digest IS NULL OR length(result_digest) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (backup_id, claim_generation),
    UNIQUE (backup_id, fence),
    CHECK (lease_expires_at > claimed_at),
    CHECK ((state = 1) = (finished_at IS NULL AND result_digest IS NULL))
) WITHOUT ROWID, STRICT;

CREATE UNIQUE INDEX one_active_metadata_backup_run_claim
ON metadata_backup_run_claims(backup_id)
WHERE state = 1;

CREATE INDEX metadata_backup_run_claims_by_worker
ON metadata_backup_run_claims(
    worker_node_id, worker_incarnation, state, lease_expires_at, backup_id
);
