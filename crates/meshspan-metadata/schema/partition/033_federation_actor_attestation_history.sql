-- SPDX-License-Identifier: GPL-2.0-only

-- Current attestations are replaceable read models. Every accepted signed home-
-- swarm actor lifecycle statement remains immutable for reconciliation audits.
CREATE TABLE federation_actor_attestation_history (
    relationship_id BLOB NOT NULL
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    home_mesh_id BLOB NOT NULL CHECK (length(home_mesh_id) = 16),
    principal_id BLOB NOT NULL CHECK (length(principal_id) = 16),
    identity_revision INTEGER NOT NULL CHECK (identity_revision > 0),
    principal_kind INTEGER NOT NULL CHECK (principal_kind IN (1, 2, 3)),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    statement_digest BLOB NOT NULL CHECK (length(statement_digest) = 32),
    signer_generation INTEGER NOT NULL CHECK (signer_generation > 0),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    accepted_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (relationship_id, home_mesh_id, principal_id, identity_revision)
) STRICT;

CREATE INDEX federation_actor_attestation_history_by_revision
ON federation_actor_attestation_history(revision, relationship_id, home_mesh_id, principal_id);

CREATE TRIGGER federation_actor_attestation_history_reject_update
BEFORE UPDATE ON federation_actor_attestation_history
BEGIN
    SELECT RAISE(ABORT, 'federated actor attestation history is immutable');
END;

CREATE TRIGGER federation_actor_attestation_history_reject_delete
BEFORE DELETE ON federation_actor_attestation_history
BEGIN
    SELECT RAISE(ABORT, 'federated actor attestation history is immutable');
END;
