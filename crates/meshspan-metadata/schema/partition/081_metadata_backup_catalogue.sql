-- SPDX-License-Identifier: GPL-2.0-only

-- No released MeshSpan build populated the original placeholder table. Refuse to
-- invent evidence if an experimental database nevertheless contains rows.
CREATE TABLE metadata_backup_migration_guard (
    value INTEGER NOT NULL CHECK (value = 0)
) STRICT;

INSERT INTO metadata_backup_migration_guard(value)
SELECT 1 FROM metadata_backups LIMIT 1;

DROP TABLE metadata_backup_migration_guard;
DROP TABLE metadata_backups;

CREATE TABLE metadata_backups (
    backup_id BLOB PRIMARY KEY CHECK (length(backup_id) = 16),
    partition_id BLOB NOT NULL REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT
        CHECK (length(partition_id) = 16),
    mesh_id BLOB NOT NULL REFERENCES meshes(mesh_id) ON DELETE RESTRICT
        CHECK (length(mesh_id) = 16),
    last_log_index INTEGER NOT NULL CHECK (last_log_index > 0),
    last_log_term INTEGER NOT NULL CHECK (last_log_term > 0),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    source_byte_length INTEGER NOT NULL CHECK (source_byte_length > 0),
    source_digest BLOB NOT NULL CHECK (length(source_digest) = 32),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    encrypted_byte_length INTEGER NOT NULL CHECK (encrypted_byte_length > 0),
    encrypted_digest BLOB NOT NULL CHECK (length(encrypted_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_at INTEGER NOT NULL,
    verified_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK ((state = 2) = (verified_at IS NOT NULL))
) STRICT;

CREATE INDEX metadata_backups_by_revision
ON metadata_backups(state_revision DESC, backup_id);

CREATE INDEX metadata_backups_by_state
ON metadata_backups(state, created_at DESC, backup_id);

CREATE TABLE backup_destinations (
    destination_id BLOB PRIMARY KEY CHECK (length(destination_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 128),
    destination_kind INTEGER NOT NULL CHECK (destination_kind BETWEEN 1 AND 3),
    target_id BLOB REFERENCES storage_targets(target_id) ON DELETE RESTRICT,
    remote_mesh_id BLOB CHECK (remote_mesh_id IS NULL OR length(remote_mesh_id) = 16),
    provider_instance_id BLOB REFERENCES component_instances(instance_id) ON DELETE RESTRICT,
    provider_generation INTEGER NOT NULL CHECK (provider_generation > 0),
    failure_relationship INTEGER NOT NULL CHECK (failure_relationship BETWEEN 1 AND 3),
    failure_evidence_digest BLOB NOT NULL CHECK (length(failure_evidence_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (destination_kind = 1 AND target_id IS NOT NULL AND remote_mesh_id IS NULL AND provider_instance_id IS NULL)
        OR (destination_kind = 2 AND target_id IS NULL AND remote_mesh_id IS NOT NULL AND provider_instance_id IS NULL)
        OR (destination_kind = 3 AND target_id IS NULL AND remote_mesh_id IS NULL AND provider_instance_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX backup_destinations_by_state
ON backup_destinations(state, destination_id);

CREATE TABLE backup_copies (
    backup_id BLOB NOT NULL REFERENCES metadata_backups(backup_id) ON DELETE RESTRICT,
    destination_id BLOB NOT NULL REFERENCES backup_destinations(destination_id) ON DELETE RESTRICT,
    provider_generation INTEGER NOT NULL CHECK (provider_generation > 0),
    object_reference TEXT NOT NULL CHECK (length(object_reference) BETWEEN 1 AND 2048),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    copy_digest BLOB NOT NULL CHECK (length(copy_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    stored_at INTEGER NOT NULL,
    verified_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (backup_id, destination_id),
    CHECK ((state = 2) = (verified_at IS NOT NULL))
) STRICT;

CREATE INDEX backup_copies_by_destination
ON backup_copies(destination_id, state, stored_at DESC, backup_id);
