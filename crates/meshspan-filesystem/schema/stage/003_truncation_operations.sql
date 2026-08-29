-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE stage_truncation_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    stage_id BLOB NOT NULL REFERENCES stages(stage_id) ON DELETE CASCADE
        CHECK (length(stage_id) = 16),
    stage_fence INTEGER NOT NULL CHECK (stage_fence > 0),
    mutation_sequence INTEGER NOT NULL CHECK (mutation_sequence > 0),
    applied_at INTEGER NOT NULL,
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32),
    UNIQUE(stage_id, mutation_sequence)
) STRICT;

CREATE INDEX stage_truncations_by_stage
ON stage_truncation_operations(stage_id, mutation_sequence, operation_id);
