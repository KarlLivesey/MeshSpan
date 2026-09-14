-- SPDX-License-Identifier: GPL-2.0-only

-- 1: available; 2: retirement committed, unlink pending; 3: unlink directory-synced.
-- Segment IDs, routes and exact target-journal receipts remain retained history.
ALTER TABLE pack_segments ADD COLUMN lifecycle_state INTEGER NOT NULL DEFAULT 1
    CHECK (lifecycle_state BETWEEN 1 AND 3);
CREATE INDEX pack_segments_by_lifecycle ON pack_segments(lifecycle_state, sequence);

-- Recovery work scales with pending operations, not lifetime replay history.
CREATE INDEX provider_operations_pending
ON provider_operations(operation_kind, operation_id) WHERE state = 1;
CREATE INDEX provider_operations_incomplete_shard
ON provider_operations(shard_identity) WHERE state <> 4;
