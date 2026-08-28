-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    migration_digest BLOB NOT NULL CHECK (length(migration_digest) = 32),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE pack_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    mesh_id BLOB NOT NULL CHECK (length(mesh_id) = 16),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    marker_fingerprint BLOB NOT NULL CHECK (length(marker_fingerprint) = 32),
    pack_sequence INTEGER NOT NULL CHECK (pack_sequence > 0),
    created_at INTEGER NOT NULL,
    last_opened_at INTEGER NOT NULL
) STRICT;

CREATE TABLE shards (
    record_number INTEGER PRIMARY KEY AUTOINCREMENT,
    shard_identity BLOB NOT NULL UNIQUE CHECK (length(shard_identity) = 46),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation >= 0),
    stored_length INTEGER NOT NULL CHECK (stored_length > 0),
    stored_digest BLOB NOT NULL CHECK (length(stored_digest) = 32),
    stored_bytes BLOB NULL,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    put_operation_id BLOB NOT NULL CHECK (length(put_operation_id) = 16),
    created_at INTEGER NOT NULL,
    tombstoned_at INTEGER NULL,
    unlinked_at INTEGER NULL,
    CHECK ((state = 3) = (stored_bytes IS NULL)),
    CHECK ((state >= 2) = (tombstoned_at IS NOT NULL)),
    CHECK ((state = 3) = (unlinked_at IS NOT NULL))
) STRICT;

CREATE INDEX shards_by_record
ON shards(state, record_number, shard_identity);

CREATE TABLE pack_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    operation_kind INTEGER NOT NULL CHECK (operation_kind BETWEEN 1 AND 2),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    shard_identity BLOB NOT NULL CHECK (length(shard_identity) = 46),
    result_receipt BLOB NOT NULL,
    completed_at INTEGER NOT NULL
) STRICT;
