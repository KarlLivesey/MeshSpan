-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE version_cleanup_inventories (
    cleanup_operation_id BLOB PRIMARY KEY
        REFERENCES version_cleanup_intents(cleanup_operation_id) ON DELETE RESTRICT
        CHECK (length(cleanup_operation_id) = 16),
    cleanup_revision INTEGER NOT NULL CHECK (cleanup_revision > 0),
    authorisation_revision INTEGER NOT NULL CHECK (
        authorisation_revision > cleanup_revision
    ),
    expected_item_count INTEGER NOT NULL CHECK (expected_item_count > 0),
    item_count INTEGER NOT NULL CHECK (
        item_count >= 0 AND item_count <= expected_item_count
    ),
    rolling_digest BLOB NOT NULL CHECK (length(rolling_digest) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    created_at INTEGER NOT NULL,
    created_revision INTEGER NOT NULL CHECK (
        created_revision > authorisation_revision
    ),
    last_append_revision INTEGER NOT NULL CHECK (
        last_append_revision >= created_revision
    ),
    seal_operation_id BLOB UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (seal_operation_id IS NULL OR length(seal_operation_id) = 16),
    sealed_at INTEGER,
    sealed_revision INTEGER CHECK (
        sealed_revision IS NULL OR sealed_revision > last_append_revision
    ),
    CHECK (
        (state = 1 AND seal_operation_id IS NULL
            AND sealed_at IS NULL AND sealed_revision IS NULL)
        OR
        (state = 2 AND item_count = expected_item_count
            AND seal_operation_id IS NOT NULL
            AND sealed_at IS NOT NULL AND sealed_revision IS NOT NULL)
    )
) STRICT;

CREATE TABLE version_cleanup_items (
    cleanup_operation_id BLOB NOT NULL
        REFERENCES version_cleanup_inventories(cleanup_operation_id) ON DELETE RESTRICT,
    item_index INTEGER NOT NULL CHECK (item_index >= 0),
    removal_operation_id BLOB NOT NULL UNIQUE CHECK (length(removal_operation_id) = 16),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation > 0),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    append_operation_id BLOB NOT NULL
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(append_operation_id) = 16),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (cleanup_operation_id, item_index),
    UNIQUE (
        cleanup_operation_id, target_id, target_generation, manifest_digest,
        stripe_index, shard_index, shard_generation
    )
) STRICT;

CREATE INDEX version_cleanup_items_by_removal
ON version_cleanup_items(cleanup_operation_id, removal_operation_id);
