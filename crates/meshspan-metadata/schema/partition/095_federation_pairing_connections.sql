-- SPDX-License-Identifier: GPL-2.0-only

-- Possession-proved public transport material; private signing/TLS keys stay node-local.
CREATE TABLE federation_pairing_connections (
    relationship_id BLOB PRIMARY KEY REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    inviting_mesh_id BLOB NOT NULL CHECK (length(inviting_mesh_id) = 16),
    material_verifier BLOB NOT NULL CHECK (length(material_verifier) = 32 AND material_verifier <> zeroblob(32)),
    consumed_invitation_revision INTEGER CHECK (consumed_invitation_revision > 0),
    local_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    local_peer BLOB NOT NULL CHECK (length(local_peer) BETWEEN 128 AND 18432),
    remote_peer BLOB NOT NULL CHECK (length(remote_peer) BETWEEN 128 AND 18432),
    prepared_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    preparation_operation_id BLOB NOT NULL UNIQUE CHECK (length(preparation_operation_id) = 16),
    prepared_at INTEGER NOT NULL CHECK (prepared_at >= 0),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE INDEX federation_pairing_connections_by_node
ON federation_pairing_connections(local_node_id, relationship_id);
