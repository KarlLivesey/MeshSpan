-- SPDX-License-Identifier: GPL-2.0-only

CREATE UNIQUE INDEX local_federation_storage_capabilities_scrub_parent
ON local_federation_storage_capabilities(
    capability_digest, operation_id, permit_digest, action
);

CREATE TABLE local_federation_storage_scrubs (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    remote_mesh_id BLOB NOT NULL CHECK (length(remote_mesh_id) = 16),
    scope_digest BLOB NOT NULL CHECK (length(scope_digest) = 32),
    grant_id BLOB NOT NULL CHECK (length(grant_id) = 16),
    allocation_id BLOB NOT NULL REFERENCES local_federation_storage_usage(allocation_id)
        ON DELETE RESTRICT,
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation BETWEEN 1 AND 4294967295),
    capability_digest BLOB NOT NULL CHECK (length(capability_digest) = 32),
    permit_digest BLOB NOT NULL CHECK (length(permit_digest) = 32),
    capability_action INTEGER NOT NULL CHECK (capability_action = 3),
    expected_length INTEGER NOT NULL CHECK (expected_length > 0),
    expected_digest BLOB NOT NULL CHECK (length(expected_digest) = 32),
    observed_length INTEGER,
    observed_digest BLOB,
    outcome INTEGER NOT NULL CHECK (outcome IN (1, 2, 3, 4, 6)),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    completed_at INTEGER NOT NULL CHECK (completed_at > 0),
    FOREIGN KEY (capability_digest, operation_id, permit_digest, capability_action)
        REFERENCES local_federation_storage_capabilities(
            capability_digest, operation_id, permit_digest, action
        ) ON DELETE RESTRICT,
    CHECK (
        (outcome = 1 AND observed_length = expected_length
            AND observed_digest = expected_digest)
        OR (outcome = 3 AND observed_length >= 0 AND length(observed_digest) = 32
            AND (observed_length != expected_length OR observed_digest != expected_digest))
        OR (outcome IN (2, 4, 6) AND observed_length IS NULL AND observed_digest IS NULL)
    )
) STRICT;

CREATE INDEX local_federation_storage_scrubs_by_shard
ON local_federation_storage_scrubs(
    remote_mesh_id, scope_digest, target_id, target_generation, manifest_digest,
    stripe_index, shard_index, shard_generation, completed_at
);

CREATE TRIGGER local_federation_storage_scrubs_reject_update
BEFORE UPDATE ON local_federation_storage_scrubs
BEGIN
    SELECT RAISE(ABORT, 'federated storage scrub evidence is immutable');
END;

CREATE TRIGGER local_federation_storage_scrubs_reject_delete
BEFORE DELETE ON local_federation_storage_scrubs
BEGIN
    SELECT RAISE(ABORT, 'federated storage scrub evidence is retained');
END;
