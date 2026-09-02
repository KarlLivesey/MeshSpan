-- SPDX-License-Identifier: GPL-2.0-only

-- Drain and reconciliation scan exact current routes by target generation. Original routes and
-- copy-on-write replacement routes remain separate so each branch can use a selective index.
CREATE INDEX content_stripe_shards_by_target
ON content_stripe_shards(
    target_id, target_generation, operation_id, chunk_index, shard_index
)
WHERE receipt_recorded_at IS NOT NULL;

CREATE INDEX content_shard_repair_routes_by_target
ON content_shard_repair_routes(
    target_id, target_generation, publication_operation_id, chunk_index, shard_index
);
