-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE consensus_active_quorum_plan (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    phase_kind INTEGER NOT NULL CHECK (phase_kind IN (1, 2)),
    membership_epoch INTEGER NOT NULL CHECK (membership_epoch > 0),
    record_version INTEGER NOT NULL CHECK (record_version = 1),
    canonical_plan BLOB NOT NULL CHECK (length(canonical_plan) BETWEEN 1 AND 65536),
    proof_digest BLOB NOT NULL CHECK (length(proof_digest) = 32),
    activated_log_index INTEGER NOT NULL CHECK (activated_log_index >= 0),
    activated_log_term INTEGER NOT NULL CHECK (activated_log_term >= 0),
    updated_at INTEGER NOT NULL,
    CHECK ((activated_log_index = 0) = (activated_log_term = 0))
) STRICT;
