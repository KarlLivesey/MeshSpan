-- SPDX-License-Identifier: GPL-2.0-only

-- Offline replacement envelopes retain source ciphertext, not active recipient grants.
CREATE TABLE partition_recovery_secret_material (
    singleton INTEGER NOT NULL DEFAULT 1 REFERENCES partition_recovery_preparation(singleton)
        ON DELETE RESTRICT CHECK (singleton = 1),
    recovery_id BLOB NOT NULL CHECK (length(recovery_id) = 16),
    secret_kind INTEGER NOT NULL,
    secret_id BLOB NOT NULL,
    generation INTEGER NOT NULL,
    material BLOB NOT NULL CHECK (length(material) BETWEEN 1 AND 1048576),
    material_digest BLOB NOT NULL CHECK (length(material_digest) = 32),
    staged_at INTEGER NOT NULL,
    PRIMARY KEY (secret_kind, secret_id, generation),
    FOREIGN KEY (secret_kind, secret_id, generation)
        REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE TABLE partition_recovery_secret_inventory (
    singleton INTEGER PRIMARY KEY REFERENCES partition_recovery_preparation(singleton)
        ON DELETE RESTRICT CHECK (singleton = 1),
    recovery_id BLOB NOT NULL CHECK (length(recovery_id) = 16),
    generation_count INTEGER NOT NULL CHECK (generation_count > 0),
    inventory_digest BLOB NOT NULL CHECK (length(inventory_digest) = 32),
    sealed_at INTEGER NOT NULL
) STRICT;

CREATE TRIGGER partition_recovery_secret_material_immutable
BEFORE UPDATE ON partition_recovery_secret_material
BEGIN SELECT RAISE(ABORT, 'prepared secret material is immutable'); END;

CREATE TRIGGER partition_recovery_secret_material_not_deletable
BEFORE DELETE ON partition_recovery_secret_material
BEGIN SELECT RAISE(ABORT, 'prepared secret material must be retained'); END;

CREATE TRIGGER partition_recovery_secret_material_sealed
BEFORE INSERT ON partition_recovery_secret_material
WHEN EXISTS(SELECT 1 FROM partition_recovery_secret_inventory)
BEGIN SELECT RAISE(ABORT, 'prepared secret inventory is sealed'); END;

CREATE TRIGGER partition_recovery_secret_inventory_immutable
BEFORE UPDATE ON partition_recovery_secret_inventory
BEGIN SELECT RAISE(ABORT, 'prepared secret inventory is immutable'); END;

CREATE TRIGGER partition_recovery_secret_inventory_not_deletable
BEFORE DELETE ON partition_recovery_secret_inventory
BEGIN SELECT RAISE(ABORT, 'prepared secret inventory must be retained'); END;
