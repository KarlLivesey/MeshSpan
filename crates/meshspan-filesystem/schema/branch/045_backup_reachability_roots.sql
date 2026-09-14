-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE version_reachability_roots_with_backups (
    operation_id BLOB NOT NULL REFERENCES version_reachability_scans(operation_id) ON DELETE CASCADE,
    root_ordinal INTEGER NOT NULL CHECK (root_ordinal >= 0),
    source_kind INTEGER NOT NULL CHECK (source_kind IN (1, 2, 3)),
    source_id BLOB NOT NULL CHECK (length(source_id) = 16),
    namespace_commit_id BLOB NOT NULL CHECK (length(namespace_commit_id) = 16),
    root_object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(root_object_revision_id) = 16),
    record_digest BLOB NOT NULL CHECK (length(record_digest) = 32),
    PRIMARY KEY (operation_id, root_ordinal),
    UNIQUE (operation_id, source_kind, source_id),
    CHECK (source_kind != 3 OR source_id = namespace_commit_id)
) STRICT;

INSERT INTO version_reachability_roots_with_backups
SELECT * FROM version_reachability_roots;
DROP TABLE version_reachability_roots;
ALTER TABLE version_reachability_roots_with_backups RENAME TO version_reachability_roots;
