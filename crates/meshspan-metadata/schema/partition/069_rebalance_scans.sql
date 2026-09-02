-- SPDX-License-Identifier: GPL-2.0-only

-- Rebalance pages advance only after every repair selected from that page has been durably
-- admitted. Exact keyset progress makes a large-volume scan restart-safe without offsets.
CREATE TABLE maintenance_rebalance_scans (
    work_id BLOB PRIMARY KEY REFERENCES maintenance_work_jobs(work_id) ON DELETE RESTRICT
        CHECK (length(work_id) = 16),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE RESTRICT
        CHECK (length(volume_id) = 16),
    topology_revision INTEGER NOT NULL CHECK (topology_revision > 0),
    cursor_publication_operation_id BLOB
        CHECK (cursor_publication_operation_id IS NULL
            OR length(cursor_publication_operation_id) = 16),
    cursor_stripe_index INTEGER CHECK (cursor_stripe_index IS NULL OR cursor_stripe_index >= 0),
    scanned_stripes INTEGER NOT NULL CHECK (scanned_stripes >= 0),
    queued_repairs INTEGER NOT NULL CHECK (
        queued_repairs >= 0 AND queued_repairs <= scanned_stripes
    ),
    superseded_by_revision INTEGER CHECK (superseded_by_revision > topology_revision),
    evidence_digest BLOB NOT NULL CHECK (length(evidence_digest) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK ((cursor_publication_operation_id IS NULL) = (cursor_stripe_index IS NULL))
) STRICT;

CREATE TABLE maintenance_rebalance_effects (
    effect_operation_id BLOB PRIMARY KEY
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(effect_operation_id) = 16),
    work_id BLOB NOT NULL UNIQUE REFERENCES maintenance_rebalance_scans(work_id)
        ON DELETE RESTRICT CHECK (length(work_id) = 16),
    scanned_stripes INTEGER NOT NULL CHECK (scanned_stripes >= 0),
    queued_repairs INTEGER NOT NULL CHECK (
        queued_repairs >= 0 AND queued_repairs <= scanned_stripes
    ),
    superseded_by_revision INTEGER CHECK (superseded_by_revision > 0),
    evidence_digest BLOB NOT NULL CHECK (length(evidence_digest) = 32),
    committed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;
