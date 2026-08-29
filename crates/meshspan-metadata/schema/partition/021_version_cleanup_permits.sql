-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE version_cleanup_permit_attempts (
    cleanup_operation_id BLOB NOT NULL,
    item_index INTEGER NOT NULL,
    attempt_sequence INTEGER NOT NULL CHECK (attempt_sequence > 0),
    permit_operation_id BLOB NOT NULL UNIQUE CHECK (length(permit_operation_id) = 16),
    mesh_id BLOB NOT NULL CHECK (length(mesh_id) = 16),
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    catalogue_revision INTEGER NOT NULL CHECK (catalogue_revision > 0),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    permit_digest BLOB NOT NULL UNIQUE CHECK (length(permit_digest) = 32),
    issue_operation_id BLOB NOT NULL UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(issue_operation_id) = 16),
    revision INTEGER NOT NULL UNIQUE CHECK (revision = catalogue_revision),
    PRIMARY KEY (cleanup_operation_id, item_index, attempt_sequence),
    FOREIGN KEY (cleanup_operation_id, item_index)
        REFERENCES version_cleanup_items(cleanup_operation_id, item_index)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX version_cleanup_permit_attempts_latest
ON version_cleanup_permit_attempts(cleanup_operation_id, item_index, attempt_sequence DESC);
