-- SPDX-License-Identifier: GPL-2.0-only

-- Staged node attestations only. No active target/provider route is created here.
CREATE TABLE partition_recovery_targets (
    target_id BLOB PRIMARY KEY CHECK (length(target_id) = 16),
    operation_id BLOB NOT NULL UNIQUE CHECK (length(operation_id) = 16),
    node_id BLOB NOT NULL CHECK (length(node_id) = 16),
    preparation INTEGER NOT NULL REFERENCES partition_recovery_credential_fence(singleton)
        ON DELETE RESTRICT CHECK (preparation = 1),
    report BLOB NOT NULL CHECK (length(report) BETWEEN 1 AND 512),
    recorded_at INTEGER NOT NULL
) STRICT;
CREATE INDEX partition_recovery_targets_node ON partition_recovery_targets(node_id, target_id);
CREATE TRIGGER partition_recovery_targets_immutable BEFORE UPDATE ON partition_recovery_targets
BEGIN SELECT RAISE(ABORT, 'recovery target is immutable'); END;
CREATE TRIGGER partition_recovery_targets_not_deletable BEFORE DELETE ON partition_recovery_targets
BEGIN SELECT RAISE(ABORT, 'recovery target must be retained'); END;
