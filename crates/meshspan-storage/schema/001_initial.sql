-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    migration_digest BLOB NOT NULL CHECK (length(migration_digest) = 32),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE target_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    mesh_id BLOB NOT NULL CHECK (length(mesh_id) = 16),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    marker_fingerprint BLOB NOT NULL CHECK (length(marker_fingerprint) = 32),
    usage_limit_kind INTEGER NOT NULL CHECK (usage_limit_kind IN (1, 2)),
    usage_limit_value INTEGER NOT NULL CHECK (usage_limit_value > 0),
    repair_reserve_bytes INTEGER NOT NULL CHECK (repair_reserve_bytes >= 0),
    policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
    committed_bytes INTEGER NOT NULL DEFAULT 0 CHECK (committed_bytes >= 0),
    reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
    capability_key BLOB NOT NULL CHECK (length(capability_key) = 32),
    created_at INTEGER NOT NULL,
    last_opened_at INTEGER NOT NULL
) STRICT;

CREATE TABLE reservations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    reservation_digest BLOB NOT NULL CHECK (length(reservation_digest) = 32),
    reservation_class INTEGER NOT NULL CHECK (reservation_class BETWEEN 1 AND 3),
    maximum_bytes INTEGER NOT NULL CHECK (maximum_bytes > 0),
    expires_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_at INTEGER NOT NULL,
    terminal_at INTEGER NULL
) STRICT;

CREATE INDEX reservations_by_expiry
ON reservations(state, expires_at, operation_id);

CREATE TABLE provider_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    operation_kind INTEGER NOT NULL CHECK (operation_kind BETWEEN 1 AND 3),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 6),
    shard_identity BLOB NULL,
    expected_length INTEGER NULL CHECK (expected_length IS NULL OR expected_length >= 0),
    expected_digest BLOB NULL CHECK (expected_digest IS NULL OR length(expected_digest) = 32),
    pack_sequence INTEGER NULL CHECK (pack_sequence IS NULL OR pack_sequence > 0),
    pack_offset INTEGER NULL CHECK (pack_offset IS NULL OR pack_offset >= 0),
    receipt BLOB NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE inventory (
    shard_identity BLOB PRIMARY KEY,
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation >= 0),
    pack_sequence INTEGER NOT NULL CHECK (pack_sequence > 0),
    pack_offset INTEGER NOT NULL CHECK (pack_offset >= 0),
    stored_length INTEGER NOT NULL CHECK (stored_length >= 0),
    stored_digest BLOB NOT NULL CHECK (length(stored_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    committed_operation_id BLOB NOT NULL REFERENCES provider_operations(operation_id),
    committed_at INTEGER NOT NULL,
    last_verified_at INTEGER NULL
) STRICT;

CREATE INDEX inventory_by_pack
ON inventory(pack_sequence, pack_offset, shard_identity);

CREATE TABLE tombstones (
    shard_identity BLOB PRIMARY KEY REFERENCES inventory(shard_identity),
    cleanup_operation_id BLOB NOT NULL UNIQUE CHECK (length(cleanup_operation_id) = 16),
    permit_digest BLOB NOT NULL CHECK (length(permit_digest) = 32),
    tombstone_digest BLOB NOT NULL CHECK (length(tombstone_digest) = 32),
    tombstoned_at INTEGER NOT NULL,
    bytes_unlinked_at INTEGER NULL
) STRICT;

CREATE TABLE scrub_cursor (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    cursor_version INTEGER NOT NULL CHECK (cursor_version > 0),
    cursor_value BLOB NOT NULL,
    completed_cycles INTEGER NOT NULL CHECK (completed_cycles >= 0),
    updated_at INTEGER NOT NULL
) STRICT;

INSERT INTO scrub_cursor(
    singleton, cursor_version, cursor_value, completed_cycles, updated_at
) VALUES (1, 1, X'', 0, 0);
