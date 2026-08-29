-- SPDX-License-Identifier: GPL-2.0-only

-- Authenticated remote observations remain node-local cache state. They never
-- become local permission authority without a separate replicated transition.
CREATE TABLE local_federation_authority_snapshots (
    relationship_id BLOB PRIMARY KEY CHECK (length(relationship_id) = 16),
    local_mesh_id BLOB NOT NULL CHECK (length(local_mesh_id) = 16),
    remote_mesh_id BLOB NOT NULL CHECK (length(remote_mesh_id) = 16),
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    remote_authority_revision INTEGER NOT NULL CHECK (remote_authority_revision > 0),
    relationship_bytes BLOB NOT NULL
        CHECK (length(relationship_bytes) BETWEEN 1 AND 16777216),
    relationship_digest BLOB NOT NULL CHECK (length(relationship_digest) = 32),
    last_update_digest BLOB NOT NULL CHECK (length(last_update_digest) = 32),
    observed_at INTEGER NOT NULL,
    CHECK (local_mesh_id <> remote_mesh_id)
) STRICT;

CREATE TABLE local_federation_authority_grants (
    relationship_id BLOB NOT NULL
        REFERENCES local_federation_authority_snapshots(relationship_id) ON DELETE CASCADE,
    grant_id BLOB NOT NULL CHECK (length(grant_id) = 16),
    record_revision INTEGER NOT NULL CHECK (record_revision > 0),
    record_bytes BLOB NOT NULL CHECK (length(record_bytes) BETWEEN 1 AND 16777216),
    record_digest BLOB NOT NULL CHECK (length(record_digest) = 32),
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (relationship_id, grant_id)
) STRICT;

CREATE INDEX local_federation_grants_by_relationship_revision
ON local_federation_authority_grants(relationship_id, record_revision, grant_id);
