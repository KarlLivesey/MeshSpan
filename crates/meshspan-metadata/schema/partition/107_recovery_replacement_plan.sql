-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE partition_recovery_replacement_plan (
    singleton INTEGER PRIMARY KEY REFERENCES partition_recovery_preparation(singleton)
        ON DELETE RESTRICT CHECK (singleton = 1),
    recovery_id BLOB NOT NULL CHECK (length(recovery_id) = 16),
    manifest BLOB NOT NULL CHECK (length(manifest) BETWEEN 1 AND 2097152),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    staged_at INTEGER NOT NULL
) STRICT;

CREATE TRIGGER partition_recovery_replacement_plan_immutable
BEFORE UPDATE ON partition_recovery_replacement_plan
BEGIN SELECT RAISE(ABORT, 'recovery replacement plan is immutable'); END;

CREATE TRIGGER partition_recovery_replacement_plan_not_deletable
BEFORE DELETE ON partition_recovery_replacement_plan
BEGIN SELECT RAISE(ABORT, 'recovery replacement plan must be retained'); END;
