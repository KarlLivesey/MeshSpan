-- SPDX-License-Identifier: GPL-2.0-only

-- Terminal run evidence plus an exact object receipt, never a missing catalogue row alone.
CREATE TABLE abandoned_backup_retirements (
    backup_id BLOB NOT NULL REFERENCES metadata_backup_runs(backup_id) CHECK(length(backup_id) = 16),
    destination_id BLOB NOT NULL REFERENCES backup_destinations(destination_id) CHECK(length(destination_id) = 16),
    canonical_command BLOB NOT NULL CHECK(length(canonical_command) BETWEEN 1 AND 4096),
    retirement_revision INTEGER NOT NULL CHECK(retirement_revision > 0),
    PRIMARY KEY(backup_id, destination_id)
) STRICT, WITHOUT ROWID;
