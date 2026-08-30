-- SPDX-License-Identifier: GPL-2.0-only

-- A remote namespace commit and the accepting swarm's signed authority receipt are one immutable
-- fact.  Local-only commits have no row; a federated commit must never acquire or lose one later.
CREATE TABLE federated_namespace_mutation_acknowledgements (
    namespace_commit_id BLOB PRIMARY KEY REFERENCES namespace_commits(namespace_commit_id)
        CHECK (length(namespace_commit_id) = 16),
    source_operation_id BLOB NOT NULL CHECK (length(source_operation_id) = 16),
    grant_id BLOB NOT NULL CHECK (length(grant_id) = 16),
    relationship_id BLOB NOT NULL CHECK (length(relationship_id) = 16),
    subject_home_mesh_id BLOB NOT NULL CHECK (length(subject_home_mesh_id) = 16),
    subject_principal_id BLOB NOT NULL CHECK (length(subject_principal_id) = 16),
    accepting_mesh_id BLOB NOT NULL CHECK (length(accepting_mesh_id) = 16),
    resource_kind INTEGER NOT NULL CHECK (resource_kind BETWEEN 1 AND 3),
    authority_mesh_id BLOB NOT NULL CHECK (length(authority_mesh_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    object_id BLOB CHECK (object_id IS NULL OR length(object_id) = 16),
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    accepted_at INTEGER NOT NULL,
    required_rights INTEGER NOT NULL CHECK (required_rights > 0),
    storage_bytes INTEGER NOT NULL CHECK (storage_bytes = 0),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    signer_generation INTEGER NOT NULL CHECK (signer_generation > 0),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    acknowledgement_digest BLOB NOT NULL CHECK (length(acknowledgement_digest) = 32),
    CHECK (
        (resource_kind = 1 AND object_id IS NULL)
        OR (resource_kind IN (2, 3) AND object_id IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX federated_namespace_mutation_acknowledgements_by_operation
ON federated_namespace_mutation_acknowledgements(source_operation_id);

CREATE TRIGGER federated_namespace_mutation_acknowledgements_reject_update
BEFORE UPDATE ON federated_namespace_mutation_acknowledgements
BEGIN
    SELECT RAISE(ABORT, 'federated mutation acknowledgements are immutable');
END;

CREATE TRIGGER federated_namespace_mutation_acknowledgements_reject_delete
BEFORE DELETE ON federated_namespace_mutation_acknowledgements
BEGIN
    SELECT RAISE(ABORT, 'federated mutation acknowledgements are immutable');
END;
