-- SPDX-License-Identifier: GPL-2.0-only

-- Earlier incomplete runs labelled an unverified generation retired without
-- retiring its provider copies. Preserve those bytes as recorded, not usable:
-- the new retention command alone grants exact physical deletion authority.
UPDATE metadata_backups SET state = 1
WHERE state = 3
  AND EXISTS (SELECT 1 FROM metadata_backup_runs r
              WHERE r.backup_id = metadata_backups.backup_id AND r.state = 5)
  AND EXISTS (SELECT 1 FROM backup_copies c
              WHERE c.backup_id = metadata_backups.backup_id)
  AND NOT EXISTS (SELECT 1 FROM backup_copies c
                  WHERE c.backup_id = metadata_backups.backup_id AND c.state IN (2, 4));

CREATE INDEX metadata_backups_retention
ON metadata_backups(state, state_revision DESC, backup_id);

CREATE INDEX backup_copies_retired
ON backup_copies(state, backup_id, destination_id);

-- Retirement is authority; a receipt is evidence that the exact provider object
-- was physically removed. Never conflate the two on crash or connection loss.
CREATE TABLE backup_copy_reclamations (
    backup_id BLOB NOT NULL,
    destination_id BLOB NOT NULL,
    operation_id BLOB NOT NULL UNIQUE CHECK (length(operation_id) = 16),
    retirement_revision INTEGER NOT NULL CHECK (retirement_revision > 0),
    provider_generation INTEGER NOT NULL CHECK (provider_generation > 0),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    copy_digest BLOB NOT NULL CHECK (length(copy_digest) = 32),
    reclaimed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (backup_id, destination_id),
    FOREIGN KEY (backup_id, destination_id)
        REFERENCES backup_copies(backup_id, destination_id) ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;
