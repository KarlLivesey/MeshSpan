-- SPDX-License-Identifier: GPL-2.0-only

-- Completion never replaces retirement authority or fabricates an admitted backup copy.
CREATE TABLE abandoned_backup_reclamations (
    backup_id BLOB NOT NULL CHECK(length(backup_id) = 16),
    destination_id BLOB NOT NULL CHECK(length(destination_id) = 16),
    operation_id BLOB NOT NULL UNIQUE CHECK(length(operation_id) = 16),
    retirement_revision INTEGER NOT NULL CHECK(retirement_revision > 0),
    provider_generation INTEGER NOT NULL CHECK(provider_generation > 0),
    byte_length INTEGER NOT NULL CHECK(byte_length > 0),
    copy_digest BLOB NOT NULL CHECK(length(copy_digest) = 32),
    reclaimed_at INTEGER NOT NULL CHECK(reclaimed_at >= 0),
    revision INTEGER NOT NULL CHECK(revision > 0),
    PRIMARY KEY(backup_id, destination_id),
    FOREIGN KEY(backup_id, destination_id)
        REFERENCES abandoned_backup_retirements(backup_id, destination_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
