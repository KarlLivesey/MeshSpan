-- SPDX-License-Identifier: GPL-2.0-only

-- A governance peer signs its complete immediate-parent chain at approval.
-- Empty chains are represented by a header with edge_count zero.
CREATE TABLE federation_governance_proofs (
    relationship_id BLOB PRIMARY KEY
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    remote_authority_epoch INTEGER NOT NULL CHECK (remote_authority_epoch > 0),
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    proof_digest BLOB NOT NULL CHECK (length(proof_digest) = 32),
    signer_generation INTEGER NOT NULL CHECK (signer_generation > 0),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    accepted_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE federation_governance_proof_edges (
    relationship_id BLOB NOT NULL
        REFERENCES federation_governance_proofs(relationship_id) ON DELETE RESTRICT,
    edge_sequence INTEGER NOT NULL CHECK (edge_sequence >= 0),
    parent_mesh_id BLOB NOT NULL CHECK (length(parent_mesh_id) = 16),
    child_mesh_id BLOB NOT NULL CHECK (length(child_mesh_id) = 16),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (relationship_id, edge_sequence),
    CHECK (parent_mesh_id <> child_mesh_id)
) STRICT;

CREATE INDEX federation_governance_proof_edges_by_child
ON federation_governance_proof_edges(child_mesh_id, relationship_id, edge_sequence);

CREATE TRIGGER federation_governance_proofs_reject_update
BEFORE UPDATE ON federation_governance_proofs
BEGIN
    SELECT RAISE(ABORT, 'federation governance proofs are immutable');
END;

CREATE TRIGGER federation_governance_proofs_reject_delete
BEFORE DELETE ON federation_governance_proofs
BEGIN
    SELECT RAISE(ABORT, 'federation governance proofs are immutable');
END;

CREATE TRIGGER federation_governance_proof_edges_reject_update
BEFORE UPDATE ON federation_governance_proof_edges
BEGIN
    SELECT RAISE(ABORT, 'federation governance proof edges are immutable');
END;

CREATE TRIGGER federation_governance_proof_edges_reject_delete
BEFORE DELETE ON federation_governance_proof_edges
BEGIN
    SELECT RAISE(ABORT, 'federation governance proof edges are immutable');
END;
