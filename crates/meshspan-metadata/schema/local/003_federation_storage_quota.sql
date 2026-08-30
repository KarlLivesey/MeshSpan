-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE local_federation_storage_usage (
    allocation_id BLOB PRIMARY KEY CHECK (length(allocation_id) = 16),
    relationship_id BLOB NOT NULL CHECK (length(relationship_id) = 16),
    remote_mesh_id BLOB NOT NULL CHECK (length(remote_mesh_id) = 16),
    grant_id BLOB NOT NULL CHECK (length(grant_id) = 16),
    provider_node_id BLOB NOT NULL CHECK (length(provider_node_id) = 16),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    maximum_bytes INTEGER NOT NULL CHECK (maximum_bytes > 0),
    committed_bytes INTEGER NOT NULL DEFAULT 0 CHECK (committed_bytes >= 0),
    reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
    valid_from INTEGER NOT NULL CHECK (valid_from > 0),
    valid_until INTEGER NOT NULL CHECK (valid_until > valid_from),
    relationship_authority_epoch INTEGER NOT NULL CHECK (relationship_authority_epoch > 0),
    grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
    allocation_revision INTEGER NOT NULL CHECK (allocation_revision > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at > 0),
    CHECK (committed_bytes <= maximum_bytes),
    CHECK (reserved_bytes <= maximum_bytes - committed_bytes)
) STRICT;

CREATE INDEX local_federation_storage_usage_by_target
ON local_federation_storage_usage(target_id, target_generation, allocation_id);

CREATE TABLE local_federation_storage_reservations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    allocation_id BLOB NOT NULL REFERENCES local_federation_storage_usage(allocation_id)
        ON DELETE RESTRICT,
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    capability_nonce BLOB NOT NULL UNIQUE CHECK (length(capability_nonce) = 32),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation BETWEEN 1 AND 4294967295),
    action INTEGER NOT NULL CHECK (action IN (1, 4)),
    maximum_bytes INTEGER NOT NULL CHECK (maximum_bytes > 0),
    permit_digest BLOB NOT NULL CHECK (length(permit_digest) = 32),
    expires_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    affected_bytes INTEGER,
    charged_bytes INTEGER,
    content_digest BLOB,
    result_digest BLOB,
    absence_evidence_digest BLOB,
    issued_at INTEGER NOT NULL CHECK (issued_at > 0),
    completed_at INTEGER,
    CHECK (expires_at > issued_at),
    CHECK (
        (state = 1 AND affected_bytes IS NULL AND charged_bytes IS NULL
            AND content_digest IS NULL AND result_digest IS NULL
            AND absence_evidence_digest IS NULL AND completed_at IS NULL)
        OR (state = 2 AND affected_bytes BETWEEN 1 AND maximum_bytes
            AND charged_bytes BETWEEN 0 AND affected_bytes
            AND length(content_digest) = 32 AND length(result_digest) = 32
            AND absence_evidence_digest IS NULL AND completed_at >= issued_at)
        OR (state = 3 AND affected_bytes IS NULL AND charged_bytes IS NULL
            AND content_digest IS NULL AND result_digest IS NULL
            AND length(absence_evidence_digest) = 32 AND completed_at >= expires_at)
    )
) STRICT;

CREATE INDEX local_federation_storage_reservations_by_allocation_state
ON local_federation_storage_reservations(allocation_id, state, expires_at, operation_id);

CREATE TABLE local_federation_storage_shards (
    grant_id BLOB NOT NULL CHECK (length(grant_id) = 16),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation BETWEEN 1 AND 4294967295),
    allocation_id BLOB NOT NULL REFERENCES local_federation_storage_usage(allocation_id)
        ON DELETE RESTRICT,
    length INTEGER NOT NULL CHECK (length > 0),
    content_digest BLOB NOT NULL CHECK (length(content_digest) = 32),
    committed_operation_id BLOB NOT NULL UNIQUE
        REFERENCES local_federation_storage_reservations(operation_id) ON DELETE RESTRICT,
    committed_at INTEGER NOT NULL CHECK (committed_at > 0),
    PRIMARY KEY (
        grant_id, target_id, target_generation, manifest_digest,
        stripe_index, shard_index, shard_generation
    )
) STRICT;

CREATE INDEX local_federation_storage_shards_by_allocation
ON local_federation_storage_shards(allocation_id, committed_at, manifest_digest);

CREATE TRIGGER local_federation_storage_shards_reject_update
BEFORE UPDATE ON local_federation_storage_shards
BEGIN
    SELECT RAISE(ABORT, 'federated storage shard evidence is immutable');
END;

CREATE TRIGGER local_federation_storage_shards_reject_delete
BEFORE DELETE ON local_federation_storage_shards
BEGIN
    SELECT RAISE(ABORT, 'federated storage shard evidence requires reclamation');
END;
