-- SPDX-License-Identifier: GPL-2.0-only

-- The immutable manifest and shard bytes never change. Repair advances only the authoritative
-- location catalogue, retaining both provider receipts and every generation transition.
CREATE TABLE maintenance_repair_stripes (
    manifest_id BLOB NOT NULL CHECK (length(manifest_id) = 16),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE RESTRICT
        CHECK (length(volume_id) = 16),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    current_layout_generation INTEGER NOT NULL CHECK (current_layout_generation > 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (manifest_id, stripe_index)
) STRICT;

CREATE TABLE maintenance_repair_routes (
    manifest_id BLOB NOT NULL,
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    provider_operation_id BLOB NOT NULL UNIQUE CHECK (length(provider_operation_id) = 16),
    shard_generation INTEGER NOT NULL CHECK (shard_generation > 0),
    expected_length INTEGER NOT NULL CHECK (expected_length > 0),
    expected_digest BLOB NOT NULL CHECK (length(expected_digest) = 32),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    layout_generation INTEGER NOT NULL CHECK (layout_generation > 1),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (manifest_id, stripe_index, shard_index),
    FOREIGN KEY (manifest_id, stripe_index)
        REFERENCES maintenance_repair_stripes(manifest_id, stripe_index) ON DELETE RESTRICT
) STRICT;

CREATE TABLE maintenance_repair_effects (
    effect_operation_id BLOB PRIMARY KEY
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(effect_operation_id) = 16),
    work_id BLOB NOT NULL UNIQUE REFERENCES maintenance_work_jobs(work_id) ON DELETE RESTRICT,
    claim_generation INTEGER NOT NULL CHECK (claim_generation > 0),
    worker_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(worker_node_id) = 16),
    worker_incarnation INTEGER NOT NULL CHECK (worker_incarnation > 0),
    fence INTEGER NOT NULL CHECK (fence > 0),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE RESTRICT
        CHECK (length(volume_id) = 16),
    manifest_id BLOB NOT NULL CHECK (length(manifest_id) = 16),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation > 0),
    source_layout_generation INTEGER NOT NULL CHECK (source_layout_generation > 0),
    replacement_layout_generation INTEGER NOT NULL
        CHECK (replacement_layout_generation = source_layout_generation + 1),
    source_provider_operation_id BLOB NOT NULL CHECK (length(source_provider_operation_id) = 16),
    source_target_id BLOB NOT NULL CHECK (length(source_target_id) = 16),
    source_target_generation INTEGER NOT NULL CHECK (source_target_generation > 0),
    replacement_provider_operation_id BLOB NOT NULL UNIQUE
        CHECK (length(replacement_provider_operation_id) = 16),
    replacement_target_id BLOB NOT NULL CHECK (length(replacement_target_id) = 16),
    replacement_target_generation INTEGER NOT NULL CHECK (replacement_target_generation > 0),
    expected_length INTEGER NOT NULL CHECK (expected_length > 0),
    expected_digest BLOB NOT NULL CHECK (length(expected_digest) = 32),
    committed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (manifest_id, stripe_index, replacement_layout_generation),
    FOREIGN KEY (manifest_id, stripe_index)
        REFERENCES maintenance_repair_stripes(manifest_id, stripe_index) ON DELETE RESTRICT,
    CHECK (source_provider_operation_id != replacement_provider_operation_id),
    CHECK (source_target_id != replacement_target_id
        OR source_target_generation != replacement_target_generation)
) STRICT;

CREATE INDEX maintenance_repair_effects_by_stripe
ON maintenance_repair_effects(manifest_id, stripe_index, replacement_layout_generation);
