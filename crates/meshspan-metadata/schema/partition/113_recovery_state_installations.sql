-- SPDX-License-Identifier: GPL-2.0-only

-- Historical exact-package attestations, never an implicit "latest" or admission flag.
CREATE TABLE partition_recovery_state_installations (
    node_id BLOB NOT NULL CHECK (length(node_id) = 16),
    state_digest BLOB NOT NULL CHECK (length(state_digest) = 32),
    preparation INTEGER NOT NULL REFERENCES partition_recovery_preparation(singleton),
    transfer BLOB NOT NULL CHECK (length(transfer) BETWEEN 1 AND 512),
    signature BLOB NOT NULL CHECK (length(signature) BETWEEN 8 AND 72),
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, state_digest),
    CHECK (preparation = 1)
) STRICT;
CREATE TRIGGER partition_recovery_state_installations_immutable
BEFORE UPDATE ON partition_recovery_state_installations
BEGIN SELECT RAISE(ABORT, 'recovery state installation is immutable'); END;
CREATE TRIGGER partition_recovery_state_installations_not_deletable
BEFORE DELETE ON partition_recovery_state_installations
BEGIN SELECT RAISE(ABORT, 'recovery state installation must be retained'); END;
