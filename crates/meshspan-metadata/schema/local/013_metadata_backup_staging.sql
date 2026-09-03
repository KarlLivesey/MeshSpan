-- SPDX-License-Identifier: GPL-2.0-only

-- Encrypted metadata-backup bytes are local restart state until provider publication becomes
-- authoritative. Only an application-derived relative filename is retained: absolute host paths
-- and recovery secrets never enter either replicated or local metadata.
CREATE TABLE local_metadata_backup_staging (
    backup_id BLOB PRIMARY KEY CHECK (length(backup_id) = 16),
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    mesh_id BLOB NOT NULL CHECK (length(mesh_id) = 16),
    relative_file_name TEXT NOT NULL UNIQUE
        CHECK (length(relative_file_name) BETWEEN 1 AND 128),
    last_log_index INTEGER NOT NULL CHECK (last_log_index >= 0),
    last_log_term INTEGER NOT NULL CHECK (last_log_term >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    source_schema_version INTEGER NOT NULL CHECK (source_schema_version > 0),
    source_byte_length INTEGER NOT NULL CHECK (source_byte_length > 0),
    source_digest BLOB NOT NULL CHECK (length(source_digest) = 32),
    encrypted_byte_length INTEGER NOT NULL CHECK (encrypted_byte_length > 0),
    encrypted_digest BLOB NOT NULL CHECK (length(encrypted_digest) = 32),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    prepared_at INTEGER NOT NULL CHECK (prepared_at >= created_at),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;
