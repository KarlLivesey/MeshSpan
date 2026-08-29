-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE version_cleanup_item_reclamations (
    cleanup_operation_id BLOB NOT NULL,
    item_index INTEGER NOT NULL,
    tombstone_digest BLOB NOT NULL CHECK (length(tombstone_digest) = 32),
    bytes_unlinked_at INTEGER NOT NULL,
    reclaimed_bytes INTEGER NOT NULL CHECK (reclaimed_bytes > 0),
    reclamation_digest BLOB NOT NULL UNIQUE CHECK (length(reclamation_digest) = 32),
    reporter_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(reporter_node_id) = 16),
    reporter_incarnation INTEGER NOT NULL CHECK (reporter_incarnation > 0),
    reclamation_operation_id BLOB NOT NULL UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(reclamation_operation_id) = 16),
    reclaimed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    PRIMARY KEY (cleanup_operation_id, item_index),
    FOREIGN KEY (cleanup_operation_id, item_index)
        REFERENCES version_cleanup_item_completions(cleanup_operation_id, item_index)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE version_cleanup_reclamations (
    cleanup_operation_id BLOB PRIMARY KEY
        REFERENCES version_cleanup_completions(cleanup_operation_id) ON DELETE RESTRICT
        CHECK (length(cleanup_operation_id) = 16),
    reclaimed_item_count INTEGER NOT NULL CHECK (reclaimed_item_count > 0),
    reclaimed_bytes INTEGER NOT NULL CHECK (reclaimed_bytes > 0),
    reclamation_digest BLOB NOT NULL UNIQUE CHECK (length(reclamation_digest) = 32),
    reclamation_operation_id BLOB NOT NULL UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(reclamation_operation_id) = 16),
    reclaimed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0)
) STRICT;

CREATE INDEX version_cleanup_item_reclamations_ordered
ON version_cleanup_item_reclamations(cleanup_operation_id, item_index);
