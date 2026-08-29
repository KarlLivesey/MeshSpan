-- SPDX-License-Identifier: GPL-2.0-only

-- A pre-authorised recovery successor is swarm-wide. Activation fences every
-- authority claim whose home/owner swarm is the retired identity; it does not
-- silently copy credentials, keys or consensus membership.
CREATE TABLE federation_ownership_successions (
    succession_id BLOB PRIMARY KEY CHECK (length(succession_id) = 16),
    relationship_id BLOB NOT NULL
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    retiring_mesh_id BLOB NOT NULL CHECK (length(retiring_mesh_id) = 16),
    successor_mesh_id BLOB NOT NULL CHECK (length(successor_mesh_id) = 16),
    relationship_authority_epoch INTEGER NOT NULL
        CHECK (relationship_authority_epoch > 0),
    succession_epoch INTEGER NOT NULL CHECK (succession_epoch > 0),
    designation_digest BLOB NOT NULL CHECK (length(designation_digest) = 32),
    designation_signer_generation INTEGER NOT NULL
        CHECK (designation_signer_generation > 0),
    designation_signature BLOB NOT NULL CHECK (length(designation_signature) = 64),
    acceptance_digest BLOB CHECK (acceptance_digest IS NULL OR length(acceptance_digest) = 32),
    acceptance_signer_generation INTEGER
        CHECK (acceptance_signer_generation IS NULL OR acceptance_signer_generation > 0),
    acceptance_signature BLOB
        CHECK (acceptance_signature IS NULL OR length(acceptance_signature) = 64),
    activation_digest BLOB CHECK (activation_digest IS NULL OR length(activation_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    designated_at INTEGER NOT NULL,
    accepted_at INTEGER,
    activated_at INTEGER,
    revoked_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (retiring_mesh_id, succession_epoch),
    CHECK (retiring_mesh_id <> successor_mesh_id),
    CHECK (
        (state = 1 AND acceptance_digest IS NULL
            AND acceptance_signer_generation IS NULL AND acceptance_signature IS NULL
            AND activation_digest IS NULL AND accepted_at IS NULL
            AND activated_at IS NULL AND revoked_at IS NULL)
        OR (state = 2 AND acceptance_digest IS NOT NULL
            AND acceptance_signer_generation IS NOT NULL AND acceptance_signature IS NOT NULL
            AND activation_digest IS NULL AND accepted_at IS NOT NULL
            AND activated_at IS NULL AND revoked_at IS NULL)
        OR (state = 3 AND acceptance_digest IS NOT NULL
            AND acceptance_signer_generation IS NOT NULL AND acceptance_signature IS NOT NULL
            AND activation_digest IS NOT NULL AND accepted_at IS NOT NULL
            AND activated_at IS NOT NULL AND revoked_at IS NULL)
        OR (state = 4 AND activation_digest IS NULL
            AND activated_at IS NULL AND revoked_at IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX one_live_successor_designation_per_retiring_swarm
ON federation_ownership_successions(retiring_mesh_id)
WHERE state IN (1, 2, 3);

CREATE INDEX federation_ownership_successions_by_relationship
ON federation_ownership_successions(relationship_id, state, retiring_mesh_id);

-- Every presented ancestry edge is retained with the retiring swarm's signed
-- designation. The nearest edge has sequence zero and chains towards its root.
CREATE TABLE federation_ownership_succession_ancestry (
    succession_id BLOB NOT NULL
        REFERENCES federation_ownership_successions(succession_id) ON DELETE RESTRICT,
    edge_sequence INTEGER NOT NULL CHECK (edge_sequence >= 0),
    retiring_mesh_id BLOB NOT NULL CHECK (length(retiring_mesh_id) = 16),
    successor_mesh_id BLOB NOT NULL CHECK (length(successor_mesh_id) = 16),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (succession_id, edge_sequence),
    CHECK (retiring_mesh_id <> successor_mesh_id)
) STRICT;

CREATE TRIGGER federation_ownership_succession_identity_immutable
BEFORE UPDATE OF succession_id, relationship_id, retiring_mesh_id, successor_mesh_id,
    relationship_authority_epoch, succession_epoch, designation_digest,
    designation_signer_generation, designation_signature, designated_at
ON federation_ownership_successions
BEGIN
    SELECT RAISE(ABORT, 'federation ownership succession identity is immutable');
END;

CREATE TRIGGER federation_ownership_succession_ancestry_reject_update
BEFORE UPDATE ON federation_ownership_succession_ancestry
BEGIN
    SELECT RAISE(ABORT, 'federation ownership succession ancestry is immutable');
END;

CREATE TRIGGER federation_ownership_succession_ancestry_reject_delete
BEFORE DELETE ON federation_ownership_succession_ancestry
BEGIN
    SELECT RAISE(ABORT, 'federation ownership succession ancestry is immutable');
END;

CREATE TABLE federation_ownership_succession_events (
    succession_id BLOB NOT NULL
        REFERENCES federation_ownership_successions(succession_id) ON DELETE RESTRICT,
    event_sequence INTEGER NOT NULL CHECK (event_sequence BETWEEN 1 AND 3),
    event_kind INTEGER NOT NULL CHECK (event_kind BETWEEN 1 AND 4),
    prior_state INTEGER CHECK (prior_state IS NULL OR prior_state BETWEEN 1 AND 4),
    resulting_state INTEGER NOT NULL CHECK (resulting_state BETWEEN 1 AND 4),
    event_digest BLOB NOT NULL CHECK (length(event_digest) = 32),
    reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 1024),
    changed_by BLOB NOT NULL CHECK (length(changed_by) = 16),
    changed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (succession_id, event_sequence)
) STRICT;

CREATE TRIGGER federation_ownership_succession_events_reject_update
BEFORE UPDATE ON federation_ownership_succession_events
BEGIN
    SELECT RAISE(ABORT, 'federation ownership succession events are immutable');
END;

CREATE TRIGGER federation_ownership_succession_events_reject_delete
BEFORE DELETE ON federation_ownership_succession_events
BEGIN
    SELECT RAISE(ABORT, 'federation ownership succession events are immutable');
END;
