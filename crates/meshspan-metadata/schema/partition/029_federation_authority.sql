-- SPDX-License-Identifier: GPL-2.0-only

-- Relationships are local authoritative views of agreements between autonomous
-- swarms. The peer is never inserted into `meshes`: that table names this swarm.
CREATE TABLE federation_relationships (
    relationship_id BLOB PRIMARY KEY CHECK (length(relationship_id) = 16),
    local_mesh_id BLOB NOT NULL REFERENCES meshes(mesh_id) ON DELETE RESTRICT,
    remote_mesh_id BLOB NOT NULL CHECK (length(remote_mesh_id) = 16),
    relationship_kind INTEGER NOT NULL CHECK (relationship_kind IN (1, 2)),
    governance_direction INTEGER NOT NULL CHECK (governance_direction BETWEEN 0 AND 2),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    remote_display_name TEXT NOT NULL
        CHECK (length(remote_display_name) BETWEEN 1 AND 256),
    proposed_at INTEGER NOT NULL,
    approved_at INTEGER,
    restricted_at INTEGER,
    revoked_at INTEGER,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (local_mesh_id <> remote_mesh_id),
    CHECK (
        (relationship_kind = 1 AND governance_direction = 0)
        OR (relationship_kind = 2 AND governance_direction IN (1, 2))
    ),
    CHECK (approved_at IS NULL OR approved_at >= proposed_at),
    CHECK (restricted_at IS NULL OR approved_at IS NOT NULL),
    CHECK (revoked_at IS NULL OR approved_at IS NOT NULL),
    CHECK (retired_at IS NULL OR revoked_at IS NOT NULL),
    CHECK (
        (state = 1 AND approved_at IS NULL AND restricted_at IS NULL
            AND revoked_at IS NULL AND retired_at IS NULL)
        OR (state = 2 AND approved_at IS NOT NULL AND restricted_at IS NULL
            AND revoked_at IS NULL AND retired_at IS NULL)
        OR (state = 3 AND approved_at IS NOT NULL AND restricted_at IS NOT NULL
            AND revoked_at IS NULL AND retired_at IS NULL)
        OR (state = 4 AND approved_at IS NOT NULL AND revoked_at IS NOT NULL
            AND retired_at IS NULL)
        OR (state = 5 AND approved_at IS NOT NULL AND revoked_at IS NOT NULL
            AND retired_at IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX one_live_federation_relationship_per_peer
ON federation_relationships(remote_mesh_id)
WHERE state BETWEEN 1 AND 3;

CREATE INDEX federation_relationships_by_state
ON federation_relationships(state, remote_mesh_id, relationship_id);

-- Both sides' public identities are versioned independently. Private keys are
-- node-local and never enter authoritative metadata.
CREATE TABLE federation_trust_identities (
    relationship_id BLOB NOT NULL
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    identity_owner INTEGER NOT NULL CHECK (identity_owner IN (1, 2)),
    generation INTEGER NOT NULL CHECK (generation > 0),
    certificate_fingerprint BLOB NOT NULL CHECK (length(certificate_fingerprint) = 32),
    verifying_key BLOB NOT NULL CHECK (length(verifying_key) = 32),
    valid_from INTEGER NOT NULL,
    valid_until INTEGER NOT NULL CHECK (valid_until > valid_from),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (relationship_id, identity_owner, generation),
    UNIQUE (certificate_fingerprint),
    CHECK ((state = 1 AND retired_at IS NULL) OR (state IN (2, 3) AND retired_at IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX one_active_federation_identity_per_owner
ON federation_trust_identities(relationship_id, identity_owner)
WHERE state = 1;

-- Horizontal relationships have no row here. Governance permits one immediate
-- parent per child; repository validation additionally rejects transitive cycles.
CREATE TABLE federation_governance_edges (
    relationship_id BLOB PRIMARY KEY
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    parent_mesh_id BLOB NOT NULL CHECK (length(parent_mesh_id) = 16),
    child_mesh_id BLOB NOT NULL CHECK (length(child_mesh_id) = 16),
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 2),
    activated_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (parent_mesh_id <> child_mesh_id),
    CHECK ((state = 1 AND revoked_at IS NULL) OR (state = 2 AND revoked_at IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX one_active_governance_parent_per_child
ON federation_governance_edges(child_mesh_id)
WHERE state = 1;

CREATE INDEX federation_governance_by_parent
ON federation_governance_edges(parent_mesh_id, state, child_mesh_id);

-- A grant binds an exact remote principal to one owner-qualified resource.
-- Effective policy is reconstructed by intersecting every active restriction;
-- no side can broaden another side's ceiling.
CREATE TABLE federation_grants (
    grant_id BLOB PRIMARY KEY CHECK (length(grant_id) = 16),
    relationship_id BLOB NOT NULL
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    subject_home_mesh_id BLOB NOT NULL CHECK (length(subject_home_mesh_id) = 16),
    subject_principal_id BLOB NOT NULL CHECK (length(subject_principal_id) = 16),
    resource_kind INTEGER NOT NULL CHECK (resource_kind BETWEEN 1 AND 4),
    authority_mesh_id BLOB NOT NULL CHECK (length(authority_mesh_id) = 16),
    volume_id BLOB,
    object_id BLOB,
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    valid_from INTEGER NOT NULL,
    valid_until INTEGER,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    effective_policy_digest BLOB NOT NULL CHECK (length(effective_policy_digest) = 32),
    issued_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (subject_home_mesh_id <> authority_mesh_id),
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    CHECK ((state IN (1, 2) AND revoked_at IS NULL) OR (state = 3 AND revoked_at IS NOT NULL)),
    CHECK (
        (resource_kind = 1 AND volume_id IS NOT NULL AND object_id IS NULL)
        OR (resource_kind = 2 AND volume_id IS NOT NULL AND object_id IS NOT NULL)
        OR (resource_kind = 3 AND volume_id IS NOT NULL AND object_id IS NOT NULL)
        OR (resource_kind = 4 AND volume_id IS NULL AND object_id IS NULL)
    )
) STRICT;

CREATE INDEX federation_grants_by_subject
ON federation_grants(
    subject_home_mesh_id, subject_principal_id, state, valid_until, grant_id
);

CREATE INDEX federation_grants_by_resource
ON federation_grants(
    authority_mesh_id, resource_kind, volume_id, object_id, state, grant_id
);

-- Exactly one restriction per imposing swarm. Namespace and storage policy
-- shapes are disjoint so malformed mixtures fail at the storage boundary.
CREATE TABLE federation_grant_restrictions (
    grant_id BLOB NOT NULL REFERENCES federation_grants(grant_id) ON DELETE RESTRICT,
    imposing_mesh_id BLOB NOT NULL CHECK (length(imposing_mesh_id) = 16),
    policy_kind INTEGER NOT NULL CHECK (policy_kind IN (1, 2)),
    rights INTEGER,
    allows_downstream_delegation INTEGER,
    maximum_storage_bytes INTEGER,
    counts_towards_protection INTEGER,
    serves_reads INTEGER,
    maximum_offline_micros INTEGER CHECK (
        maximum_offline_micros IS NULL OR maximum_offline_micros > 0
    ),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (grant_id, imposing_mesh_id),
    CHECK (
        (policy_kind = 1 AND rights IS NOT NULL AND rights > 0
            AND (rights & ~8191) = 0 AND allows_downstream_delegation IN (0, 1)
            AND maximum_storage_bytes IS NULL
            AND counts_towards_protection IS NULL AND serves_reads IS NULL)
        OR (policy_kind = 2 AND rights IS NULL AND allows_downstream_delegation IS NULL
            AND maximum_storage_bytes IS NOT NULL AND maximum_storage_bytes > 0
            AND counts_towards_protection IN (0, 1) AND serves_reads IN (0, 1))
    )
) STRICT;

CREATE INDEX federation_restrictions_by_imposing_swarm
ON federation_grant_restrictions(imposing_mesh_id, grant_id);

-- Remote users and groups stay qualified by home swarm. They never become
-- local principals and cannot collide with local identifiers.
CREATE TABLE federation_principal_projections (
    relationship_id BLOB NOT NULL
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    home_mesh_id BLOB NOT NULL CHECK (length(home_mesh_id) = 16),
    principal_id BLOB NOT NULL CHECK (length(principal_id) = 16),
    principal_kind INTEGER NOT NULL CHECK (principal_kind IN (1, 2, 3)),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    identity_revision INTEGER NOT NULL CHECK (identity_revision > 0),
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    projection_digest BLOB NOT NULL CHECK (length(projection_digest) = 32),
    observed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (relationship_id, home_mesh_id, principal_id)
) STRICT;

CREATE INDEX federation_principals_by_name
ON federation_principal_projections(
    relationship_id, canonical_name, home_mesh_id, principal_id
);

-- Ownership/governance transfer is explicit and two-sided. An accepted
-- successor does not become active until its bounded proof is committed.
CREATE TABLE federation_successor_designations (
    relationship_id BLOB NOT NULL
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    retiring_mesh_id BLOB NOT NULL CHECK (length(retiring_mesh_id) = 16),
    successor_mesh_id BLOB NOT NULL CHECK (length(successor_mesh_id) = 16),
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    designation_digest BLOB NOT NULL CHECK (length(designation_digest) = 32),
    acceptance_digest BLOB CHECK (acceptance_digest IS NULL OR length(acceptance_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    designated_at INTEGER NOT NULL,
    accepted_at INTEGER,
    activated_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (relationship_id, retiring_mesh_id, authority_epoch),
    CHECK (retiring_mesh_id <> successor_mesh_id),
    CHECK (
        (state = 1 AND acceptance_digest IS NULL AND accepted_at IS NULL AND activated_at IS NULL)
        OR (state = 2 AND acceptance_digest IS NOT NULL AND accepted_at IS NOT NULL
            AND activated_at IS NULL)
        OR (state = 3 AND acceptance_digest IS NOT NULL AND accepted_at IS NOT NULL
            AND activated_at IS NOT NULL)
    )
) STRICT;

-- Acknowledged disconnected work which no longer satisfies authoritative
-- policy remains immutable and invisible until an authorised resolution.
CREATE TABLE federation_quarantine (
    quarantine_id BLOB PRIMARY KEY CHECK (length(quarantine_id) = 16),
    relationship_id BLOB NOT NULL
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    operation_id BLOB NOT NULL CHECK (length(operation_id) = 16),
    grant_id BLOB NOT NULL REFERENCES federation_grants(grant_id) ON DELETE RESTRICT,
    subject_home_mesh_id BLOB NOT NULL CHECK (length(subject_home_mesh_id) = 16),
    subject_principal_id BLOB NOT NULL CHECK (length(subject_principal_id) = 16),
    accepted_at INTEGER NOT NULL,
    reason_kind INTEGER NOT NULL CHECK (reason_kind BETWEEN 1 AND 5),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    acknowledgement_digest BLOB NOT NULL CHECK (length(acknowledgement_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    surfaced_at INTEGER,
    resolved_at INTEGER,
    resolution_kind INTEGER CHECK (resolution_kind IS NULL OR resolution_kind BETWEEN 1 AND 3),
    resolution_operation_id BLOB CHECK (
        resolution_operation_id IS NULL OR length(resolution_operation_id) = 16
    ),
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (relationship_id, operation_id),
    CHECK (
        (state = 1 AND surfaced_at IS NULL AND resolved_at IS NULL
            AND resolution_kind IS NULL AND resolution_operation_id IS NULL)
        OR (state = 2 AND surfaced_at IS NOT NULL AND resolved_at IS NULL
            AND resolution_kind IS NULL AND resolution_operation_id IS NULL)
        OR (state IN (3, 4) AND surfaced_at IS NOT NULL AND resolved_at IS NOT NULL
            AND resolution_kind IS NOT NULL AND resolution_operation_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX federation_quarantine_unresolved
ON federation_quarantine(state, accepted_at, quarantine_id)
WHERE state IN (1, 2);

CREATE TRIGGER federation_quarantine_identity_immutable
BEFORE UPDATE OF relationship_id, operation_id, grant_id, subject_home_mesh_id,
    subject_principal_id, accepted_at, reason_kind, payload_digest, acknowledgement_digest
ON federation_quarantine
BEGIN
    SELECT RAISE(ABORT, 'quarantine evidence is immutable');
END;
