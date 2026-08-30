-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE federation_storage_allocations (
    allocation_id BLOB PRIMARY KEY CHECK (length(allocation_id) = 16),
    grant_id BLOB NOT NULL REFERENCES federation_grants(grant_id) ON DELETE RESTRICT,
    provider_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    maximum_bytes INTEGER NOT NULL CHECK (maximum_bytes > 0),
    valid_from INTEGER NOT NULL CHECK (valid_from > 0),
    valid_until INTEGER NOT NULL CHECK (valid_until > valid_from),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    issued_at INTEGER NOT NULL CHECK (issued_at > 0),
    revoked_at INTEGER,
    revocation_reason TEXT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK ((state = 1 AND revoked_at IS NULL AND revocation_reason IS NULL)
        OR (state = 2 AND revoked_at IS NOT NULL
            AND length(revocation_reason) BETWEEN 1 AND 512)),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
) STRICT;

CREATE INDEX federation_storage_allocations_by_grant_interval
ON federation_storage_allocations(grant_id, state, valid_from, valid_until, allocation_id);

CREATE INDEX federation_storage_allocations_by_provider_target
ON federation_storage_allocations(provider_node_id, target_id, target_generation, state,
    valid_until, allocation_id);

CREATE TRIGGER federation_storage_allocations_reject_identity_update
BEFORE UPDATE OF allocation_id, grant_id, provider_node_id, target_id, target_generation,
    maximum_bytes, valid_from, valid_until, issued_at
ON federation_storage_allocations
BEGIN
    SELECT RAISE(ABORT, 'federation storage allocation identity is immutable');
END;

CREATE TRIGGER federation_storage_allocations_reject_delete
BEFORE DELETE ON federation_storage_allocations
BEGIN
    SELECT RAISE(ABORT, 'federation storage allocation evidence is immutable');
END;
