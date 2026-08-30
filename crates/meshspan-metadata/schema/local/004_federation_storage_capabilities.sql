-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE local_federation_storage_capabilities (
    capability_digest BLOB PRIMARY KEY CHECK (length(capability_digest) = 32),
    operation_id BLOB NOT NULL CHECK (length(operation_id) = 16),
    permit_digest BLOB NOT NULL CHECK (length(permit_digest) = 32),
    relationship_id BLOB NOT NULL CHECK (length(relationship_id) = 16),
    remote_mesh_id BLOB NOT NULL CHECK (length(remote_mesh_id) = 16),
    provider_mesh_id BLOB NOT NULL CHECK (length(provider_mesh_id) = 16),
    allocation_id BLOB NOT NULL CHECK (length(allocation_id) = 16),
    grant_id BLOB NOT NULL CHECK (length(grant_id) = 16),
    provider_node_id BLOB NOT NULL CHECK (length(provider_node_id) = 16),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation BETWEEN 1 AND 4294967295),
    action INTEGER NOT NULL CHECK (action BETWEEN 1 AND 6),
    maximum_bytes INTEGER NOT NULL CHECK (maximum_bytes > 0),
    relationship_authority_epoch INTEGER NOT NULL CHECK (relationship_authority_epoch > 0),
    grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
    allocation_revision INTEGER NOT NULL CHECK (allocation_revision > 0),
    capability_nonce BLOB NOT NULL CHECK (length(capability_nonce) = 32),
    scope_digest BLOB NOT NULL CHECK (length(scope_digest) = 32),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    issued_at INTEGER NOT NULL CHECK (issued_at > 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    protocol_major INTEGER NOT NULL CHECK (protocol_major > 0),
    protocol_minor INTEGER NOT NULL CHECK (protocol_minor >= 0),
    request_id BLOB NOT NULL CHECK (length(request_id) = 16),
    trace_id BLOB NOT NULL CHECK (length(trace_id) = 16),
    request_deadline INTEGER NOT NULL CHECK (request_deadline >= expires_at),
    response_replay_nonce BLOB NOT NULL CHECK (length(response_replay_nonce) = 32),
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= issued_at),
    UNIQUE (operation_id, capability_digest),
    UNIQUE (operation_id, response_replay_nonce)
) STRICT;

CREATE INDEX local_federation_storage_capabilities_by_operation
ON local_federation_storage_capabilities(operation_id, recorded_at, capability_digest);

CREATE TRIGGER local_federation_storage_capabilities_reject_update
BEFORE UPDATE ON local_federation_storage_capabilities
BEGIN
    SELECT RAISE(ABORT, 'federated storage capability presentation is immutable');
END;

CREATE TRIGGER local_federation_storage_capabilities_reject_delete
BEFORE DELETE ON local_federation_storage_capabilities
BEGIN
    SELECT RAISE(ABORT, 'federated storage capability presentation is retained for receipts');
END;
