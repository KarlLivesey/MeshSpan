-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE open_handles
ADD COLUMN working_logical_length INTEGER NOT NULL DEFAULT 0
    CHECK (working_logical_length >= 0);

UPDATE open_handles
SET working_logical_length = CASE
    WHEN create_disposition IN (4, 5) THEN 0
    ELSE (
        SELECT logical_length
        FROM file_versions
        WHERE version_id = open_handles.opened_version_id
    )
END;

CREATE TABLE handle_information_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    operation_kind INTEGER NOT NULL CHECK (operation_kind IN (1, 2)),
    handle_id BLOB NOT NULL REFERENCES open_handles(handle_id),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    handle_fence INTEGER NOT NULL CHECK (handle_fence > 0),
    working_logical_length INTEGER NOT NULL CHECK (working_logical_length >= 0),
    delete_on_close INTEGER NOT NULL CHECK (delete_on_close IN (0, 1)),
    changed_at INTEGER NOT NULL,
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32)
) STRICT;
