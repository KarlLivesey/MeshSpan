-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE pending_node_activations (
    node_id BLOB PRIMARY KEY REFERENCES nodes(node_id) ON DELETE CASCADE
        CHECK (length(node_id) = 16),
    wrapping_public_key BLOB NOT NULL UNIQUE CHECK (length(wrapping_public_key) = 32),
    wrapping_key_fingerprint BLOB NOT NULL UNIQUE CHECK (length(wrapping_key_fingerprint) = 32),
    private_endpoint TEXT NOT NULL CHECK (
        length(private_endpoint) BETWEEN 3 AND 512
        AND private_endpoint NOT GLOB '*[^a-z0-9.:[\]-]*'
    ),
    admitted_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;
