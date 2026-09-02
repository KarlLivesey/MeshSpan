-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE stages
ADD COLUMN declared_logical_length INTEGER
    CHECK (declared_logical_length IS NULL OR declared_logical_length >= 0);

UPDATE stages
SET declared_logical_length = 0
WHERE EXISTS (
    SELECT 1
    FROM stage_truncation_operations truncations
    WHERE truncations.stage_id = stages.stage_id
);

CREATE TABLE stage_length_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    stage_id BLOB NOT NULL REFERENCES stages(stage_id) ON DELETE CASCADE
        CHECK (length(stage_id) = 16),
    stage_fence INTEGER NOT NULL CHECK (stage_fence > 0),
    mutation_sequence INTEGER NOT NULL CHECK (mutation_sequence > 0),
    logical_length INTEGER NOT NULL CHECK (logical_length >= 0),
    applied_at INTEGER NOT NULL,
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32),
    UNIQUE(stage_id, mutation_sequence)
) STRICT;

CREATE INDEX stage_lengths_by_stage
ON stage_length_operations(stage_id, mutation_sequence, operation_id);
