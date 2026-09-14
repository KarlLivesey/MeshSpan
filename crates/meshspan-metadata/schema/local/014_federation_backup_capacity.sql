-- SPDX-License-Identifier: GPL-2.0-only

-- Uses the same allocation counters as shards. A backup is not a shard record.
CREATE TABLE local_federation_backup_capacity (
    allocation_id BLOB NOT NULL REFERENCES local_federation_storage_usage(allocation_id)
        ON DELETE RESTRICT,
    destination_id BLOB NOT NULL CHECK (length(destination_id) = 16),
    provider_generation INTEGER NOT NULL CHECK (provider_generation > 0),
    backup_id BLOB NOT NULL CHECK (length(backup_id) = 16),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3, 4)),
    updated_at INTEGER NOT NULL CHECK (updated_at > 0),
    PRIMARY KEY (allocation_id, destination_id, provider_generation, backup_id)
) STRICT;

CREATE INDEX local_federation_backup_pending
ON local_federation_backup_capacity(allocation_id, destination_id, provider_generation, state, backup_id);

CREATE TRIGGER local_federation_backup_identity_immutable
BEFORE UPDATE OF allocation_id, destination_id, provider_generation, backup_id, byte_length, digest
ON local_federation_backup_capacity
BEGIN
    SELECT RAISE(ABORT, 'federated backup capacity identity is immutable');
END;
