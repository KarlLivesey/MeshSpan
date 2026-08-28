-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE snapshot_expiry_requests (
    snapshot_id BLOB PRIMARY KEY REFERENCES volume_snapshots(snapshot_id) ON DELETE CASCADE,
    operation_id BLOB NOT NULL UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED,
    automatic INTEGER NOT NULL CHECK (automatic IN (0, 1)),
    reason_code INTEGER NOT NULL CHECK (reason_code > 0),
    requested_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0)
) STRICT;
