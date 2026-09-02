-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE smb_exports (
    export_id BLOB PRIMARY KEY NOT NULL CHECK (length(export_id) = 16),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id),
    root_object_id BLOB NOT NULL REFERENCES namespace_objects(object_id),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 240),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 240),
    gateway_policy INTEGER NOT NULL CHECK (gateway_policy IN (1, 2)),
    encryption_required INTEGER NOT NULL CHECK (encryption_required IN (0, 1)),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    created_by BLOB NOT NULL REFERENCES principals(principal_id),
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE UNIQUE INDEX smb_exports_active_root
    ON smb_exports(volume_id, root_object_id)
    WHERE state = 1;

CREATE TABLE smb_export_gateways (
    export_id BLOB NOT NULL REFERENCES smb_exports(export_id) ON DELETE CASCADE,
    node_id BLOB NOT NULL REFERENCES nodes(node_id),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (export_id, node_id)
) WITHOUT ROWID, STRICT;

CREATE INDEX smb_export_gateways_by_node
    ON smb_export_gateways(node_id, export_id);
