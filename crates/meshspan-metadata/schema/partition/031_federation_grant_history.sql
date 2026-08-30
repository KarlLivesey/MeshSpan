-- SPDX-License-Identifier: GPL-2.0-only

-- Renewal and restriction create a new immutable grant. This edge records why
-- the old authority ended and prevents ambiguous successor histories.
CREATE TABLE federation_grant_successions (
    predecessor_grant_id BLOB PRIMARY KEY
        REFERENCES federation_grants(grant_id) ON DELETE RESTRICT,
    successor_grant_id BLOB NOT NULL UNIQUE
        REFERENCES federation_grants(grant_id) ON DELETE RESTRICT,
    relationship_id BLOB NOT NULL
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    succession_kind INTEGER NOT NULL CHECK (succession_kind IN (1, 2)),
    reason TEXT NOT NULL CHECK (
        length(reason) BETWEEN 1 AND 512
        AND length(CAST(reason AS BLOB)) BETWEEN 1 AND 512
    ),
    succeeded_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (predecessor_grant_id <> successor_grant_id)
) STRICT;

CREATE INDEX federation_grant_successions_by_relationship
ON federation_grant_successions(relationship_id, succeeded_at, predecessor_grant_id);

CREATE TRIGGER federation_grants_authority_immutable
BEFORE UPDATE OF relationship_id, issuer_mesh_id, recipient_mesh_id,
    upstream_grant_id, route_depth,
    resource_kind, authority_mesh_id, volume_id, object_id, authority_epoch,
    valid_from, valid_until, effective_policy_digest, issued_at
ON federation_grants
BEGIN
    SELECT RAISE(ABORT, 'federation grant authority is immutable');
END;

CREATE TRIGGER federation_grant_route_hops_reject_update
BEFORE UPDATE ON federation_grant_route_hops
BEGIN
    SELECT RAISE(ABORT, 'federation grant route hops are immutable');
END;

CREATE TRIGGER federation_grant_route_hops_reject_delete
BEFORE DELETE ON federation_grant_route_hops
BEGIN
    SELECT RAISE(ABORT, 'federation grant route hops are immutable');
END;

CREATE TRIGGER federation_grant_restrictions_reject_update
BEFORE UPDATE ON federation_grant_restrictions
BEGIN
    SELECT RAISE(ABORT, 'federation grant restrictions are immutable');
END;

CREATE TRIGGER federation_grant_restrictions_reject_delete
BEFORE DELETE ON federation_grant_restrictions
BEGIN
    SELECT RAISE(ABORT, 'federation grant restrictions are immutable');
END;

CREATE TRIGGER federation_grant_assignments_authority_immutable
BEFORE UPDATE OF grant_id, subject_principal_id, rights, valid_from, valid_until,
    activation_policy_id, created_by, created_at
ON federation_grant_assignments
BEGIN
    SELECT RAISE(ABORT, 'federation grant assignment authority is immutable');
END;

CREATE TRIGGER federation_grant_assignment_activations_authority_immutable
BEFORE UPDATE OF assignment_id, principal_id, policy_id, reason,
    authentication_digest, identity_revision, assignment_revision,
    policy_revision, activated_at, expires_at
ON federation_grant_assignment_activations
BEGIN
    SELECT RAISE(ABORT, 'federation grant assignment activation is immutable');
END;

CREATE TRIGGER federation_grant_successions_reject_update
BEFORE UPDATE ON federation_grant_successions
BEGIN
    SELECT RAISE(ABORT, 'federation grant successions are immutable');
END;

CREATE TRIGGER federation_grant_successions_reject_delete
BEFORE DELETE ON federation_grant_successions
BEGIN
    SELECT RAISE(ABORT, 'federation grant successions are immutable');
END;
