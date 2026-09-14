-- SPDX-License-Identifier: GPL-2.0-only

-- Intent precedes provider IO; it is neither a receipt nor an admitted backup copy.
CREATE TABLE backup_publication_intents (
    backup_id BLOB NOT NULL REFERENCES metadata_backup_runs(backup_id) CHECK(length(backup_id) = 16),
    destination_id BLOB NOT NULL REFERENCES backup_destinations(destination_id) CHECK(length(destination_id) = 16),
    canonical_command BLOB NOT NULL CHECK(length(canonical_command) BETWEEN 1 AND 512),
    revision INTEGER NOT NULL CHECK(revision > 0),
    PRIMARY KEY(backup_id, destination_id)
) STRICT, WITHOUT ROWID;
