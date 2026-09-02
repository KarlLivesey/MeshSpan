-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE content_shard_repair_effects (
    effect_operation_id BLOB PRIMARY KEY CHECK (length(effect_operation_id) = 16),
    publication_operation_id BLOB NOT NULL REFERENCES content_publications(operation_id),
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
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
    shard_generation INTEGER NOT NULL CHECK (shard_generation > 0),
    expected_length INTEGER NOT NULL CHECK (expected_length > 0),
    expected_digest BLOB NOT NULL CHECK (length(expected_digest) = 32),
    committed_revision INTEGER NOT NULL CHECK (committed_revision > 0),
    UNIQUE (publication_operation_id, chunk_index, shard_index, replacement_layout_generation),
    FOREIGN KEY (publication_operation_id, chunk_index, shard_index)
        REFERENCES content_stripe_shards(operation_id, chunk_index, shard_index),
    CHECK (source_provider_operation_id != replacement_provider_operation_id),
    CHECK (source_target_id != replacement_target_id
        OR source_target_generation != replacement_target_generation)
) STRICT;

CREATE TABLE content_shard_repair_routes (
    publication_operation_id BLOB NOT NULL,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    provider_operation_id BLOB NOT NULL UNIQUE CHECK (length(provider_operation_id) = 16),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    shard_generation INTEGER NOT NULL CHECK (shard_generation > 0),
    expected_length INTEGER NOT NULL CHECK (expected_length > 0),
    expected_digest BLOB NOT NULL CHECK (length(expected_digest) = 32),
    layout_generation INTEGER NOT NULL CHECK (layout_generation > 1),
    effect_operation_id BLOB NOT NULL UNIQUE
        REFERENCES content_shard_repair_effects(effect_operation_id),
    committed_revision INTEGER NOT NULL CHECK (committed_revision > 0),
    PRIMARY KEY (publication_operation_id, chunk_index, shard_index),
    FOREIGN KEY (publication_operation_id, chunk_index, shard_index)
        REFERENCES content_stripe_shards(operation_id, chunk_index, shard_index)
) STRICT;
