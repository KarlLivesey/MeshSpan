-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE version_retention_policy_revisions (
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE CASCADE,
    policy_sequence INTEGER NOT NULL CHECK (policy_sequence > 0),
    history_enabled INTEGER NOT NULL CHECK (history_enabled IN (0, 1)),
    minimum_age_micros INTEGER NOT NULL CHECK (minimum_age_micros >= 0),
    maximum_age_micros INTEGER CHECK (
        maximum_age_micros IS NULL OR maximum_age_micros >= minimum_age_micros
    ),
    minimum_versions INTEGER CHECK (minimum_versions IS NULL OR minimum_versions > 0),
    reclaim_mode INTEGER NOT NULL CHECK (reclaim_mode IN (1, 2, 3)),
    soft_minimum_breakable INTEGER NOT NULL CHECK (soft_minimum_breakable IN (0, 1)),
    conflict_minimum_age_micros INTEGER NOT NULL CHECK (conflict_minimum_age_micros >= 0),
    configured_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    configured_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (volume_id, policy_sequence)
) STRICT;

INSERT INTO version_retention_policy_revisions(
    volume_id, policy_sequence, history_enabled, minimum_age_micros,
    maximum_age_micros, minimum_versions, reclaim_mode, soft_minimum_breakable,
    conflict_minimum_age_micros, configured_by, configured_at, revision
)
SELECT volume_id, 1, 1, 2592000000000, NULL, NULL, 1, 1,
       2592000000000, created_by, created_at, revision
FROM volumes;
