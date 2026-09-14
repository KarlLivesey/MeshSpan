-- SPDX-License-Identifier: GPL-2.0-only

-- This is a local, offline preparation barrier, not a replicated recovery completion.
-- The exported source cannot contain its own later metadata_backups catalogue entry;
-- its identity is authenticated by the signed container, not a fabricated foreign key.
CREATE TABLE partition_recovery_preparation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    mesh_id BLOB NOT NULL REFERENCES meshes(mesh_id) ON DELETE RESTRICT
        CHECK (length(mesh_id) = 16),
    recovery_id BLOB NOT NULL CHECK (length(recovery_id) = 16),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch > 0),
    source_backup_id BLOB NOT NULL CHECK (length(source_backup_id) = 16),
    authorization BLOB NOT NULL CHECK (length(authorization) BETWEEN 213 AND 284),
    prepared_at INTEGER NOT NULL
) STRICT;

CREATE TRIGGER partition_recovery_preparation_immutable
BEFORE UPDATE ON partition_recovery_preparation
BEGIN
    SELECT RAISE(ABORT, 'recovery preparation is immutable');
END;

CREATE TRIGGER partition_recovery_preparation_not_deletable
BEFORE DELETE ON partition_recovery_preparation
BEGIN
    SELECT RAISE(ABORT, 'recovery preparation requires explicit admission');
END;
