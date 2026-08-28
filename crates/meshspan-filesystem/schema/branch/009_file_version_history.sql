-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE file_version_history (
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    version_id BLOB NOT NULL REFERENCES file_versions(version_id)
        CHECK (length(version_id) = 16),
    superseded_by_version_id BLOB NOT NULL UNIQUE REFERENCES file_versions(version_id)
        CHECK (length(superseded_by_version_id) = 16),
    superseded_at INTEGER NOT NULL,
    ordinary_history_enabled INTEGER NOT NULL CHECK (ordinary_history_enabled IN (0, 1)),
    policy_sequence INTEGER NOT NULL CHECK (policy_sequence > 0),
    PRIMARY KEY (branch_id, version_id),
    CHECK (version_id <> superseded_by_version_id)
) STRICT;

CREATE INDEX file_version_history_by_age
ON file_version_history(superseded_at, branch_id, version_id);

CREATE TABLE file_version_conflict_protections (
    version_id BLOB PRIMARY KEY REFERENCES file_versions(version_id)
        CHECK (length(version_id) = 16),
    first_observed_at INTEGER NOT NULL
) STRICT;

INSERT INTO file_version_history(
    branch_id, version_id, superseded_by_version_id, superseded_at,
    ordinary_history_enabled, policy_sequence
)
SELECT child.branch_id, parent.version_id, child.version_id, child.created_at, 1, 1
FROM file_versions AS parent
JOIN file_versions AS child
  ON child.parent_version_id = parent.version_id
 AND child.volume_id = parent.volume_id
 AND child.object_id = parent.object_id
WHERE NOT EXISTS (
    SELECT 1 FROM branch_files AS heads
    WHERE heads.branch_id = child.branch_id
      AND heads.current_version_id = parent.version_id
);
