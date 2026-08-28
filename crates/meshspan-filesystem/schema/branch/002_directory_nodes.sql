-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE directory_nodes (
    node_digest BLOB PRIMARY KEY CHECK (length(node_digest) = 32),
    format_version INTEGER NOT NULL CHECK (format_version = 1),
    encoded_node BLOB NOT NULL CHECK (
        length(encoded_node) > 0 AND length(encoded_node) <= 307200
    ),
    recorded_at INTEGER NOT NULL
) STRICT;
