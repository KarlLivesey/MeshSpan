-- SPDX-License-Identifier: GPL-2.0-only

-- Offline, immutable prepared ciphertext. This never publishes new active key heads.
CREATE TABLE partition_recovery_control_material (
    singleton INTEGER PRIMARY KEY REFERENCES partition_recovery_preparation(singleton)
        ON DELETE RESTRICT CHECK (singleton = 1),
    recovery_id BLOB NOT NULL CHECK (length(recovery_id) = 16),
    material BLOB NOT NULL CHECK (length(material) BETWEEN 1 AND 1048576),
    material_digest BLOB NOT NULL CHECK (length(material_digest) = 32),
    staged_at INTEGER NOT NULL
) STRICT;

CREATE TRIGGER partition_recovery_control_material_immutable
BEFORE UPDATE ON partition_recovery_control_material
BEGIN
    SELECT RAISE(ABORT, 'recovery control material is immutable');
END;

CREATE TRIGGER partition_recovery_control_material_not_deletable
BEFORE DELETE ON partition_recovery_control_material
BEGIN
    SELECT RAISE(ABORT, 'recovery control material is retained for admission');
END;
