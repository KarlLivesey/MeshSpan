-- SPDX-License-Identifier: GPL-2.0-only

-- Immutable local approval to attempt pairing; deliberately not a relationship grant.
CREATE TABLE federation_connection_intents (
    relationship_id BLOB PRIMARY KEY CHECK (length(relationship_id) = 16),
    operation_id BLOB NOT NULL UNIQUE CHECK (length(operation_id) = 16),
    actor_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    inviting_mesh_id BLOB NOT NULL CHECK (length(inviting_mesh_id) = 16),
    material_verifier BLOB NOT NULL CHECK (length(material_verifier) = 32 AND material_verifier <> zeroblob(32)),
    remote_endpoint TEXT NOT NULL CHECK (length(remote_endpoint) BETWEEN 9 AND 512),
    certificate_fingerprint BLOB NOT NULL CHECK (length(certificate_fingerprint) = 32 AND certificate_fingerprint <> zeroblob(32)),
    expires_at INTEGER NOT NULL,
    local_peer BLOB NOT NULL CHECK (length(local_peer) BETWEEN 128 AND 18432),
    started_at INTEGER NOT NULL CHECK (started_at >= 0 AND expires_at > started_at),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;
