-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE stage_abort_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    stage_id BLOB NOT NULL REFERENCES stages(stage_id) CHECK (length(stage_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    stage_fence INTEGER NOT NULL CHECK (stage_fence > 0),
    aborted_at INTEGER NOT NULL,
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32)
) STRICT;

CREATE INDEX stage_abort_operations_by_stage
ON stage_abort_operations(stage_id, stage_fence, aborted_at, operation_id);
