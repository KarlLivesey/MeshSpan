-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE content_chunks
ADD COLUMN storage_layout_digest BLOB NULL
CHECK (storage_layout_digest IS NULL OR length(storage_layout_digest) = 32);

CREATE TABLE content_stripe_layouts (
    operation_id BLOB NOT NULL,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    data_slices INTEGER NOT NULL CHECK (data_slices > 0),
    recovery_slices INTEGER NOT NULL CHECK (recovery_slices > 0),
    slice_bytes INTEGER NOT NULL CHECK (slice_bytes > 0),
    topology_revision INTEGER NOT NULL CHECK (topology_revision > 0),
    capacity_revision INTEGER NOT NULL CHECK (capacity_revision > 0),
    policy_format_version INTEGER NOT NULL CHECK (policy_format_version > 0),
    policy_evidence BLOB NOT NULL CHECK (
        length(policy_evidence) > 0 AND length(policy_evidence) <= 4096
    ),
    layout_digest BLOB NOT NULL CHECK (length(layout_digest) = 32),
    PRIMARY KEY (operation_id, chunk_index),
    FOREIGN KEY (operation_id, chunk_index)
        REFERENCES content_chunks(operation_id, chunk_index)
) STRICT;

CREATE TABLE content_stripe_shards (
    operation_id BLOB NOT NULL,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index >= 0 AND shard_index <= 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation > 0),
    provider_operation_id BLOB NOT NULL UNIQUE CHECK (length(provider_operation_id) = 16),
    expected_length INTEGER NOT NULL CHECK (expected_length > 0),
    expected_digest BLOB NOT NULL CHECK (length(expected_digest) = 32),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    receipt_recorded_at INTEGER NULL,
    PRIMARY KEY (operation_id, chunk_index, shard_index),
    FOREIGN KEY (operation_id, chunk_index)
        REFERENCES content_stripe_layouts(operation_id, chunk_index)
) STRICT;

CREATE INDEX content_stripe_shards_pending
ON content_stripe_shards(operation_id, receipt_recorded_at, chunk_index, shard_index);
