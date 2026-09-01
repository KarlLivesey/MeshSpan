-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE node_activations (
    node_id BLOB PRIMARY KEY REFERENCES nodes(node_id) ON DELETE CASCADE
        CHECK (length(node_id) = 16),
    incarnation INTEGER NOT NULL CHECK (incarnation > 0),
    private_endpoint TEXT NOT NULL CHECK (length(private_endpoint) BETWEEN 3 AND 512),
    capability_digest BLOB NOT NULL CHECK (length(capability_digest) = 32),
    activated_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE UNIQUE INDEX node_activations_by_endpoint
ON node_activations(private_endpoint);
