-- SPDX-License-Identifier: GPL-2.0-only

-- Entire streams commit atomically; these are node attestations, not admitted routes.
CREATE TABLE partition_recovery_restorations (
    target_id BLOB NOT NULL REFERENCES partition_recovery_targets(target_id) ON DELETE RESTRICT,
    source_target_id BLOB NOT NULL CHECK (length(source_target_id) = 16),
    source_generation INTEGER NOT NULL CHECK (source_generation > 0),
    message BLOB NOT NULL CHECK (length(message) BETWEEN 1 AND 1024),
    signature BLOB NOT NULL CHECK (length(signature) BETWEEN 8 AND 72),
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (target_id, source_target_id, source_generation)
) STRICT;
CREATE TABLE partition_recovery_shards (
    target_id BLOB NOT NULL,
    source_target_id BLOB NOT NULL,
    source_generation INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    receipt BLOB NOT NULL CHECK (length(receipt) = 126),
    PRIMARY KEY (target_id, source_target_id, source_generation, ordinal),
    FOREIGN KEY (target_id, source_target_id, source_generation)
        REFERENCES partition_recovery_restorations(target_id, source_target_id, source_generation)
        ON DELETE RESTRICT
) STRICT;
CREATE TRIGGER partition_recovery_restorations_immutable BEFORE UPDATE ON partition_recovery_restorations
BEGIN SELECT RAISE(ABORT, 'recovery restoration is immutable'); END;
CREATE TRIGGER partition_recovery_restorations_not_deletable BEFORE DELETE ON partition_recovery_restorations
BEGIN SELECT RAISE(ABORT, 'recovery restoration must be retained'); END;
CREATE TRIGGER partition_recovery_shards_immutable BEFORE UPDATE ON partition_recovery_shards
BEGIN SELECT RAISE(ABORT, 'recovery shard receipt is immutable'); END;
CREATE TRIGGER partition_recovery_shards_not_deletable BEFORE DELETE ON partition_recovery_shards
BEGIN SELECT RAISE(ABORT, 'recovery shard receipt must be retained'); END;
