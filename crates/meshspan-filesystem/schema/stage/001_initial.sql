-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    migration_digest BLOB NOT NULL UNIQUE CHECK (length(migration_digest) = 32),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE stages (
    stage_id BLOB PRIMARY KEY CHECK (length(stage_id) = 16),
    stage_fence INTEGER NOT NULL CHECK (stage_fence > 0),
    maximum_bytes INTEGER NOT NULL CHECK (maximum_bytes > 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    mutation_sequence INTEGER NOT NULL CHECK (mutation_sequence >= 0),
    logical_extent INTEGER NOT NULL CHECK (logical_extent >= 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
) STRICT;

CREATE TABLE stage_writes (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    stage_id BLOB NOT NULL REFERENCES stages(stage_id) ON DELETE CASCADE,
    mutation_sequence INTEGER NOT NULL CHECK (mutation_sequence > 0),
    stage_fence INTEGER NOT NULL CHECK (stage_fence > 0),
    byte_offset INTEGER NOT NULL CHECK (byte_offset >= 0),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    content_digest BLOB NOT NULL CHECK (length(content_digest) = 32),
    part_name TEXT NOT NULL CHECK (length(part_name) = 37),
    applied_at INTEGER NOT NULL,
    UNIQUE(stage_id, mutation_sequence)
) STRICT;

CREATE INDEX stage_writes_by_stage
ON stage_writes(stage_id, mutation_sequence, operation_id);
