-- SPDX-License-Identifier: GPL-2.0-only

-- Recovery is an explicit root-authorised origin, never a fabricated Raft log entry.
ALTER TABLE consensus_active_quorum_plan ADD COLUMN activation_kind INTEGER NOT NULL
    DEFAULT 1 CHECK (activation_kind IN (1, 2));
CREATE TABLE partition_recovery_consensus_activation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    preparation INTEGER NOT NULL CHECK (preparation = 1)
        REFERENCES partition_recovery_preparation(singleton),
    permission BLOB NOT NULL CHECK (length(permission) BETWEEN 1 AND 512),
    previous_plan BLOB NOT NULL CHECK (length(previous_plan) BETWEEN 1 AND 65536),
    initial_term INTEGER NOT NULL CHECK (initial_term > 0),
    applied_revision INTEGER NOT NULL CHECK (applied_revision > 0),
    activated_at INTEGER NOT NULL
) STRICT;
CREATE TRIGGER partition_recovery_consensus_activation_immutable
BEFORE UPDATE ON partition_recovery_consensus_activation
BEGIN SELECT RAISE(ABORT, 'recovery consensus activation is immutable'); END;
CREATE TRIGGER partition_recovery_consensus_activation_not_deletable
BEFORE DELETE ON partition_recovery_consensus_activation
BEGIN SELECT RAISE(ABORT, 'recovery consensus activation must be retained'); END;
