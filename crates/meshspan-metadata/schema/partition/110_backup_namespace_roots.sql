-- SPDX-License-Identifier: GPL-2.0-only

CREATE UNIQUE INDEX volume_head_transitions_root_identity
ON volume_head_transitions(volume_id, namespace_commit_id);

CREATE TABLE backup_capture_windows (
    backup_id BLOB PRIMARY KEY REFERENCES metadata_backup_runs(backup_id) ON DELETE RESTRICT,
    opened_revision INTEGER NOT NULL CHECK (opened_revision > 0),
    sealed_revision INTEGER CHECK (sealed_revision >= opened_revision)
) STRICT;

CREATE TABLE backup_namespace_roots (
    backup_id BLOB NOT NULL REFERENCES backup_capture_windows(backup_id) ON DELETE CASCADE,
    volume_id BLOB NOT NULL,
    source_kind INTEGER NOT NULL CHECK (source_kind IN (1, 2)),
    source_id BLOB NOT NULL CHECK (length(source_id) = 16),
    namespace_commit_id BLOB NOT NULL CHECK (length(namespace_commit_id) = 16),
    from_revision INTEGER NOT NULL CHECK (from_revision > 0),
    until_revision INTEGER CHECK (until_revision > from_revision),
    PRIMARY KEY (backup_id, source_kind, source_id, from_revision),
    FOREIGN KEY (volume_id, namespace_commit_id)
        REFERENCES volume_head_transitions(volume_id, namespace_commit_id) ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;

CREATE INDEX backup_namespace_roots_by_volume
ON backup_namespace_roots(volume_id, namespace_commit_id, backup_id);

CREATE INDEX backup_namespace_roots_open
ON backup_namespace_roots(volume_id, source_kind, source_id, backup_id)
WHERE until_revision IS NULL;

-- Older captures did not retain revision windows. Conservatively hold all surviving
-- head history for those retained or in-progress generations until they retire;
-- do not invent an exact past root set or claim already-lost bytes were recovered.
INSERT INTO backup_capture_windows(backup_id, opened_revision, sealed_revision)
SELECT r.backup_id, 1, b.state_revision
FROM metadata_backup_runs r LEFT JOIN metadata_backups b USING(backup_id)
WHERE (b.state IN (1, 2)) OR (r.state = 2 AND b.backup_id IS NULL);

INSERT INTO backup_namespace_roots(
    backup_id, volume_id, source_kind, source_id, namespace_commit_id, from_revision, until_revision
)
SELECT w.backup_id, h.volume_id, 1, h.volume_id, h.namespace_commit_id, h.revision, NULL
FROM backup_capture_windows w CROSS JOIN volume_head_transitions h;
