-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE stage_lease_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    stage_id BLOB NOT NULL REFERENCES stages(stage_id) CHECK (length(stage_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    expected_fence INTEGER NOT NULL CHECK (expected_fence > 0),
    resulting_fence INTEGER NOT NULL CHECK (
        resulting_fence = expected_fence OR resulting_fence = expected_fence + 1
    ),
    lease_expires_at INTEGER NOT NULL,
    committed_at INTEGER NOT NULL,
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32)
) STRICT;

CREATE INDEX stage_lease_operations_by_stage
ON stage_lease_operations(stage_id, resulting_fence, committed_at, operation_id);
