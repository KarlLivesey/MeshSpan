-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE version_cleanup_item_completions (
    cleanup_operation_id BLOB NOT NULL,
    item_index INTEGER NOT NULL,
    permit_attempt_sequence INTEGER NOT NULL CHECK (permit_attempt_sequence > 0),
    provider_operation_id BLOB NOT NULL UNIQUE CHECK (length(provider_operation_id) = 16),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation BETWEEN 1 AND 4294967295),
    permit_digest BLOB NOT NULL CHECK (length(permit_digest) = 32),
    tombstone_digest BLOB NOT NULL UNIQUE CHECK (length(tombstone_digest) = 32),
    reporter_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(reporter_node_id) = 16),
    reporter_incarnation INTEGER NOT NULL CHECK (reporter_incarnation > 0),
    completion_operation_id BLOB NOT NULL UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(completion_operation_id) = 16),
    completed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    PRIMARY KEY (cleanup_operation_id, item_index),
    FOREIGN KEY (cleanup_operation_id, item_index)
        REFERENCES version_cleanup_items(cleanup_operation_id, item_index)
        ON DELETE RESTRICT,
    FOREIGN KEY (cleanup_operation_id, item_index, permit_attempt_sequence)
        REFERENCES version_cleanup_permit_attempts(
            cleanup_operation_id, item_index, attempt_sequence
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE version_cleanup_completions (
    cleanup_operation_id BLOB PRIMARY KEY
        REFERENCES version_cleanup_inventories(cleanup_operation_id) ON DELETE RESTRICT
        CHECK (length(cleanup_operation_id) = 16),
    completed_item_count INTEGER NOT NULL CHECK (completed_item_count > 0),
    completion_digest BLOB NOT NULL UNIQUE CHECK (length(completion_digest) = 32),
    completion_operation_id BLOB NOT NULL UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(completion_operation_id) = 16),
    completed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0)
) STRICT;

CREATE INDEX version_cleanup_item_completions_ordered
ON version_cleanup_item_completions(cleanup_operation_id, item_index);
