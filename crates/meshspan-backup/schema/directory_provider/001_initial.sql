-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    migration_digest BLOB NOT NULL CHECK (length(migration_digest) = 32),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE provider_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    destination_id BLOB NOT NULL CHECK (length(destination_id) = 16),
    provider_generation INTEGER NOT NULL CHECK (provider_generation > 0),
    maximum_bytes INTEGER NOT NULL CHECK (maximum_bytes > 0),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE backup_objects (
    backup_id BLOB NOT NULL CHECK (length(backup_id) = 16),
    destination_id BLOB NOT NULL CHECK (length(destination_id) = 16),
    provider_generation INTEGER NOT NULL CHECK (provider_generation > 0),
    object_reference TEXT NOT NULL UNIQUE CHECK (length(object_reference) BETWEEN 1 AND 2048),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    stored_at INTEGER NOT NULL,
    retired_at INTEGER,
    retirement_revision INTEGER,
    PRIMARY KEY (backup_id, destination_id, provider_generation),
    CHECK ((state = 2) = (retired_at IS NOT NULL)),
    CHECK ((state = 2) = (retirement_revision IS NOT NULL))
) STRICT;

CREATE TABLE backup_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    operation_kind INTEGER NOT NULL CHECK (operation_kind IN (1, 2)),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    backup_id BLOB NOT NULL CHECK (length(backup_id) = 16),
    object_reference TEXT NOT NULL CHECK (length(object_reference) BETWEEN 1 AND 2048),
    completed_at INTEGER NOT NULL,
    retirement_revision INTEGER
) STRICT;

CREATE INDEX backup_objects_by_state
ON backup_objects(state, stored_at, backup_id);

PRAGMA user_version = 1;
