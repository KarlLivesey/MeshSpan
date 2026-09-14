-- SPDX-License-Identifier: GPL-2.0-only

-- These records approve connection attempts, not node enrolment or file access.
CREATE TABLE federation_pairing_invitations (
    relationship_id BLOB PRIMARY KEY CHECK (length(relationship_id) = 16),
    mesh_id BLOB NOT NULL REFERENCES meshes(mesh_id) ON DELETE RESTRICT,
    issuing_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    issued_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    issuance_operation_id BLOB NOT NULL UNIQUE CHECK (length(issuance_operation_id) = 16),
    issuance_key_generation INTEGER NOT NULL CHECK (issuance_key_generation > 0),
    material_verifier BLOB NOT NULL UNIQUE CHECK (length(material_verifier) = 32 AND material_verifier <> zeroblob(32)),
    endpoint TEXT NOT NULL CHECK (length(CAST(endpoint AS BLOB)) BETWEEN 9 AND 512),
    certificate_fingerprint BLOB NOT NULL CHECK (length(certificate_fingerprint) = 32 AND certificate_fingerprint <> zeroblob(32)),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at AND expires_at - issued_at <= 3600000000),
    state INTEGER NOT NULL CHECK (state IN (1, 3)),
    cancellation_reason TEXT CHECK (length(CAST(cancellation_reason AS BLOB)) BETWEEN 1 AND 512),
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK ((state = 1 AND cancellation_reason IS NULL) OR (state = 3 AND cancellation_reason IS NOT NULL))
) STRICT;

CREATE INDEX federation_pairing_invitations_by_expiry
ON federation_pairing_invitations(state, expires_at, relationship_id);
