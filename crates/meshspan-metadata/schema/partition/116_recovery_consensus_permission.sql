-- SPDX-License-Identifier: GPL-2.0-only

-- One offline-root decision per preparation, not an activated epoch or readiness receipt.
CREATE TABLE partition_recovery_consensus_permission (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    preparation INTEGER NOT NULL CHECK (preparation = 1)
        REFERENCES partition_recovery_preparation(singleton),
    permission BLOB NOT NULL CHECK (length(permission) BETWEEN 1 AND 512),
    recorded_at INTEGER NOT NULL
) STRICT;
CREATE TRIGGER partition_recovery_consensus_permission_immutable
BEFORE UPDATE ON partition_recovery_consensus_permission
BEGIN SELECT RAISE(ABORT, 'recovery consensus decision is immutable'); END;
CREATE TRIGGER partition_recovery_consensus_permission_not_deletable
BEFORE DELETE ON partition_recovery_consensus_permission
BEGIN SELECT RAISE(ABORT, 'recovery consensus decision must be retained'); END;
