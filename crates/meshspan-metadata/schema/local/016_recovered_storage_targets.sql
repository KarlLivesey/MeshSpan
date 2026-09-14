-- SPDX-License-Identifier: GPL-2.0-only

-- Local mount hints, not registration commands or authority to serve data.
CREATE TABLE local_recovered_targets (
    target_id BLOB PRIMARY KEY CHECK(length(target_id) = 16),
    node_id BLOB NOT NULL CHECK(length(node_id) = 16),
    mesh_id BLOB NOT NULL CHECK(length(mesh_id) = 16),
    recovery_id BLOB NOT NULL CHECK(length(recovery_id) = 16),
    state_digest BLOB NOT NULL CHECK(length(state_digest) = 32 AND state_digest != zeroblob(32)),
    generation INTEGER NOT NULL CHECK(generation > 0),
    marker_fingerprint BLOB NOT NULL CHECK(length(marker_fingerprint) = 32 AND marker_fingerprint != zeroblob(32)),
    canonical_path BLOB NOT NULL UNIQUE CHECK(length(canonical_path) BETWEEN 1 AND 16384),
    journal_directory BLOB NOT NULL CHECK(length(journal_directory) BETWEEN 1 AND 16384),
    policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
    usage_limit_kind INTEGER NOT NULL CHECK(usage_limit_kind IN (1, 2)),
    usage_limit_value INTEGER NOT NULL CHECK(usage_limit_value > 0 AND (usage_limit_kind = 2 OR usage_limit_value <= 100))
) STRICT;

CREATE TRIGGER local_recovered_targets_insert BEFORE INSERT ON local_recovered_targets
BEGIN
    SELECT RAISE(ABORT, 'recovered target identity conflict')
    WHERE NEW.node_id != (SELECT node_id FROM local_identity WHERE singleton = 1)
       OR EXISTS(SELECT 1 FROM local_targets WHERE target_id = NEW.target_id OR canonical_path = NEW.canonical_path)
       OR (SELECT COUNT(*) FROM local_recovered_targets) + (SELECT COUNT(*) FROM local_targets) >= 1024;
END;

CREATE TRIGGER local_targets_recovery_conflict BEFORE INSERT ON local_targets
BEGIN
    SELECT RAISE(ABORT, 'target already installed by recovery')
    WHERE EXISTS(SELECT 1 FROM local_recovered_targets WHERE target_id = NEW.target_id OR canonical_path = NEW.canonical_path);
END;

CREATE TRIGGER local_recovered_targets_immutable BEFORE UPDATE ON local_recovered_targets
BEGIN SELECT RAISE(ABORT, 'recovered target binding is immutable'); END;
CREATE TRIGGER local_recovered_targets_no_delete BEFORE DELETE ON local_recovered_targets
BEGIN SELECT RAISE(ABORT, 'recovered target binding is retained'); END;
