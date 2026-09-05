-- SPDX-License-Identifier: GPL-2.0-only

-- Charges share target_state counters with shard reservations/inventory. Pending
-- backup charges deliberately have no TTL: bytes may exist after a lost reply.
CREATE TABLE backup_capacity (
    destination_id BLOB NOT NULL CHECK (length(destination_id) = 16),
    backup_id BLOB NOT NULL CHECK (length(backup_id) = 16),
    provider_generation INTEGER NOT NULL CHECK (provider_generation > 0),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    PRIMARY KEY (destination_id, backup_id, provider_generation)
) STRICT;
