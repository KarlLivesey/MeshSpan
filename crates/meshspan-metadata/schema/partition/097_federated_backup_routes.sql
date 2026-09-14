-- SPDX-License-Identifier: GPL-2.0-only

-- An intent is not a stored/verified backup copy. Keep it even after failed IO:
-- absence of a response cannot prove absence of remote durable bytes.
CREATE TABLE federated_backup_routes (
    backup_id BLOB NOT NULL REFERENCES metadata_backup_runs(backup_id),
    destination_id BLOB NOT NULL REFERENCES backup_destinations(destination_id),
    relationship_id BLOB NOT NULL REFERENCES federation_relationships(relationship_id),
    canonical_record BLOB NOT NULL CHECK(length(canonical_record) BETWEEN 1 AND 320),
    revision INTEGER NOT NULL CHECK(revision > 0),
    PRIMARY KEY(backup_id, destination_id),
    CHECK(length(backup_id) = 16),
    CHECK(length(destination_id) = 16),
    CHECK(length(relationship_id) = 16)
) WITHOUT ROWID;

CREATE INDEX federated_backup_routes_by_relationship
    ON federated_backup_routes(relationship_id, backup_id, destination_id);

CREATE TRIGGER federated_backup_routes_no_update
BEFORE UPDATE ON federated_backup_routes BEGIN
    SELECT RAISE(ABORT, 'federated backup routes are immutable');
END;
