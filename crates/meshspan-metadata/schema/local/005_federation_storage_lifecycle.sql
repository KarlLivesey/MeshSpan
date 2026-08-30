-- SPDX-License-Identifier: GPL-2.0-only

DROP TRIGGER local_federation_storage_shards_reject_update;
DROP TRIGGER local_federation_storage_shards_reject_delete;
DROP INDEX local_federation_storage_shards_by_allocation;
ALTER TABLE local_federation_storage_shards RENAME TO local_federation_storage_shards_v3;

DROP INDEX local_federation_storage_reservations_by_allocation_state;
ALTER TABLE local_federation_storage_reservations
RENAME TO local_federation_storage_reservations_v3;

CREATE TABLE local_federation_storage_reservations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    allocation_id BLOB NOT NULL REFERENCES local_federation_storage_usage(allocation_id)
        ON DELETE RESTRICT,
    remote_mesh_id BLOB NOT NULL CHECK (length(remote_mesh_id) = 16),
    scope_digest BLOB NOT NULL CHECK (length(scope_digest) = 32),
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

INSERT INTO local_federation_storage_reservations(
    operation_id, allocation_id, remote_mesh_id, scope_digest, request_digest,
    capability_nonce, manifest_digest, stripe_index, shard_index, shard_generation,
    action, maximum_bytes, permit_digest, expires_at, state, affected_bytes,
    charged_bytes, content_digest, result_digest, absence_evidence_digest, issued_at,
    completed_at
)
SELECT
    reservation.operation_id, reservation.allocation_id, usage.remote_mesh_id,
    (
        SELECT capability.scope_digest
        FROM local_federation_storage_capabilities AS capability
        WHERE capability.operation_id = reservation.operation_id
        ORDER BY capability.recorded_at, capability.capability_digest
        LIMIT 1
    ),
    reservation.request_digest, reservation.capability_nonce, reservation.manifest_digest,
    reservation.stripe_index, reservation.shard_index, reservation.shard_generation,
    reservation.action, reservation.maximum_bytes, reservation.permit_digest,
    reservation.expires_at, reservation.state, reservation.affected_bytes,
    reservation.charged_bytes, reservation.content_digest, reservation.result_digest,
    reservation.absence_evidence_digest, reservation.issued_at, reservation.completed_at
FROM local_federation_storage_reservations_v3 AS reservation
JOIN local_federation_storage_usage AS usage
    ON usage.allocation_id = reservation.allocation_id;

CREATE TABLE local_federation_storage_reservations_migration_guard (
    expected_count INTEGER NOT NULL,
    migrated_count INTEGER NOT NULL,
    CHECK (expected_count = migrated_count)
) STRICT;

INSERT INTO local_federation_storage_reservations_migration_guard(
    expected_count, migrated_count
)
SELECT
    (SELECT count(*) FROM local_federation_storage_reservations_v3),
    (SELECT count(*) FROM local_federation_storage_reservations);

DROP TABLE local_federation_storage_reservations_migration_guard;

CREATE INDEX local_federation_storage_reservations_by_allocation_state
ON local_federation_storage_reservations(allocation_id, state, expires_at, operation_id);

CREATE TABLE local_federation_storage_shards (
    grant_id BLOB NOT NULL CHECK (length(grant_id) = 16),
    remote_mesh_id BLOB NOT NULL CHECK (length(remote_mesh_id) = 16),
    scope_digest BLOB NOT NULL CHECK (length(scope_digest) = 32),
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
        remote_mesh_id, scope_digest, target_id, target_generation, manifest_digest,
        stripe_index, shard_index, shard_generation
    )
) STRICT;

INSERT INTO local_federation_storage_shards(
    grant_id, remote_mesh_id, scope_digest, target_id, target_generation, manifest_digest,
    stripe_index, shard_index, shard_generation, allocation_id, length, content_digest,
    committed_operation_id, committed_at
)
SELECT
    shard.grant_id,
    reservation.remote_mesh_id, reservation.scope_digest,
    shard.target_id, shard.target_generation, shard.manifest_digest,
    shard.stripe_index, shard.shard_index, shard.shard_generation, shard.allocation_id,
    shard.length, shard.content_digest, shard.committed_operation_id, shard.committed_at
FROM local_federation_storage_shards_v3 AS shard
JOIN local_federation_storage_reservations AS reservation
    ON reservation.operation_id = shard.committed_operation_id;

CREATE TABLE local_federation_storage_shards_migration_guard (
    expected_count INTEGER NOT NULL,
    migrated_count INTEGER NOT NULL,
    CHECK (expected_count = migrated_count)
) STRICT;

INSERT INTO local_federation_storage_shards_migration_guard(expected_count, migrated_count)
SELECT
    (SELECT count(*) FROM local_federation_storage_shards_v3),
    (SELECT count(*) FROM local_federation_storage_shards);

DROP TABLE local_federation_storage_shards_migration_guard;
DROP TABLE local_federation_storage_shards_v3;
DROP TABLE local_federation_storage_reservations_v3;

CREATE INDEX local_federation_storage_shards_by_allocation
ON local_federation_storage_shards(allocation_id, committed_at, manifest_digest);

CREATE INDEX local_federation_storage_shards_by_scope
ON local_federation_storage_shards(
    remote_mesh_id, scope_digest, target_id, target_generation, committed_at, manifest_digest
);

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

CREATE TABLE local_federation_storage_lifecycle (
    retire_operation_id BLOB PRIMARY KEY CHECK (length(retire_operation_id) = 16),
    remote_mesh_id BLOB NOT NULL CHECK (length(remote_mesh_id) = 16),
    scope_digest BLOB NOT NULL CHECK (length(scope_digest) = 32),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    stripe_index INTEGER NOT NULL CHECK (stripe_index >= 0),
    shard_index INTEGER NOT NULL CHECK (shard_index BETWEEN 0 AND 65535),
    shard_generation INTEGER NOT NULL CHECK (shard_generation BETWEEN 1 AND 4294967295),
    allocation_id BLOB NOT NULL REFERENCES local_federation_storage_usage(allocation_id)
        ON DELETE RESTRICT,
    charged_bytes INTEGER NOT NULL CHECK (charged_bytes > 0),
    retire_capability_digest BLOB NOT NULL
        REFERENCES local_federation_storage_capabilities(capability_digest) ON DELETE RESTRICT,
    retire_permit_digest BLOB NOT NULL CHECK (length(retire_permit_digest) = 32),
    provider_manifest_digest BLOB NOT NULL CHECK (length(provider_manifest_digest) = 32),
    provider_permit_digest BLOB NOT NULL CHECK (length(provider_permit_digest) = 32),
    provider_tombstone_digest BLOB NOT NULL CHECK (length(provider_tombstone_digest) = 32),
    logical_tombstone_digest BLOB NOT NULL CHECK (length(logical_tombstone_digest) = 32),
    retired_at INTEGER NOT NULL CHECK (retired_at > 0),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    reclaim_operation_id BLOB UNIQUE CHECK (
        reclaim_operation_id IS NULL OR length(reclaim_operation_id) = 16
    ),
    reclaim_capability_digest BLOB
        REFERENCES local_federation_storage_capabilities(capability_digest) ON DELETE RESTRICT,
    reclaim_permit_digest BLOB,
    bytes_unlinked_at INTEGER,
    reclaimed_bytes INTEGER,
    provider_reclamation_digest BLOB,
    logical_reclamation_digest BLOB,
    CHECK (
        (state = 1 AND reclaim_operation_id IS NULL AND reclaim_capability_digest IS NULL
            AND reclaim_permit_digest IS NULL AND bytes_unlinked_at IS NULL
            AND reclaimed_bytes IS NULL AND provider_reclamation_digest IS NULL
            AND logical_reclamation_digest IS NULL)
        OR (state = 2 AND length(reclaim_operation_id) = 16
            AND length(reclaim_capability_digest) = 32 AND length(reclaim_permit_digest) = 32
            AND bytes_unlinked_at >= retired_at AND reclaimed_bytes = charged_bytes
            AND length(provider_reclamation_digest) = 32
            AND length(logical_reclamation_digest) = 32)
    ),
    UNIQUE (
        remote_mesh_id, scope_digest, target_id, target_generation, manifest_digest,
        stripe_index, shard_index, shard_generation
    )
) STRICT;

CREATE INDEX local_federation_storage_lifecycle_by_allocation_state
ON local_federation_storage_lifecycle(allocation_id, state, retired_at, retire_operation_id);

CREATE TRIGGER local_federation_storage_lifecycle_reject_delete
BEFORE DELETE ON local_federation_storage_lifecycle
BEGIN
    SELECT RAISE(ABORT, 'federated storage lifecycle evidence is retained');
END;

CREATE TRIGGER local_federation_storage_lifecycle_reject_rewrite
BEFORE UPDATE ON local_federation_storage_lifecycle
WHEN OLD.state != 1 OR NEW.state != 2
    OR NEW.retire_operation_id != OLD.retire_operation_id
    OR NEW.remote_mesh_id != OLD.remote_mesh_id
    OR NEW.scope_digest != OLD.scope_digest
    OR NEW.target_id != OLD.target_id
    OR NEW.target_generation != OLD.target_generation
    OR NEW.manifest_digest != OLD.manifest_digest
    OR NEW.stripe_index != OLD.stripe_index
    OR NEW.shard_index != OLD.shard_index
    OR NEW.shard_generation != OLD.shard_generation
    OR NEW.allocation_id != OLD.allocation_id
    OR NEW.charged_bytes != OLD.charged_bytes
    OR NEW.retire_capability_digest != OLD.retire_capability_digest
    OR NEW.retire_permit_digest != OLD.retire_permit_digest
    OR NEW.provider_manifest_digest != OLD.provider_manifest_digest
    OR NEW.provider_permit_digest != OLD.provider_permit_digest
    OR NEW.provider_tombstone_digest != OLD.provider_tombstone_digest
    OR NEW.logical_tombstone_digest != OLD.logical_tombstone_digest
    OR NEW.retired_at != OLD.retired_at
BEGIN
    SELECT RAISE(ABORT, 'federated storage lifecycle evidence is immutable');
END;
