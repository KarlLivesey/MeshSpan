-- SPDX-License-Identifier: GPL-2.0-only

-- Exact local intent is durable before a provider marker is created. The row
-- then bridges marker installation and the separately committed root-authority
-- command without treating either database as transactionally atomic with the
-- other.
CREATE TABLE local_targets (
    target_id BLOB PRIMARY KEY CHECK (length(target_id) = 16),
    registration_operation_id BLOB NOT NULL UNIQUE
        CHECK (length(registration_operation_id) = 16),
    mesh_id BLOB NOT NULL CHECK (length(mesh_id) = 16),
    node_id BLOB NOT NULL CHECK (length(node_id) = 16),
    host_id BLOB NOT NULL CHECK (length(host_id) = 16),
    actor_principal_id BLOB NOT NULL CHECK (length(actor_principal_id) = 16),
    audit_event_id BLOB NOT NULL CHECK (length(audit_event_id) = 16),
    provider_instance_id BLOB NOT NULL UNIQUE CHECK (length(provider_instance_id) = 16),
    target_display_name TEXT NOT NULL CHECK (length(target_display_name) BETWEEN 1 AND 256),
    provider_display_name TEXT NOT NULL CHECK (length(provider_display_name) BETWEEN 1 AND 256),
    canonical_path BLOB NOT NULL UNIQUE CHECK (length(canonical_path) BETWEEN 1 AND 16384),
    generation INTEGER NOT NULL CHECK (generation > 0),
    usage_limit_kind INTEGER NOT NULL CHECK (usage_limit_kind IN (1, 2)),
    usage_limit_value INTEGER NOT NULL CHECK (usage_limit_value > 0),
    provider_implementation_id TEXT NOT NULL
        CHECK (length(provider_implementation_id) BETWEEN 1 AND 80),
    provider_contract_major INTEGER NOT NULL CHECK (provider_contract_major > 0),
    provider_contract_minor INTEGER NOT NULL CHECK (provider_contract_minor >= 0),
    provider_schema_version INTEGER NOT NULL CHECK (provider_schema_version > 0),
    provider_configuration BLOB NOT NULL CHECK (length(provider_configuration) <= 524288),
    provider_configuration_digest BLOB NOT NULL
        CHECK (length(provider_configuration_digest) = 32),
    marker_fingerprint BLOB CHECK (marker_fingerprint IS NULL OR length(marker_fingerprint) = 32),
    authority_result_digest BLOB
        CHECK (authority_result_digest IS NULL OR length(authority_result_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    prepared_at INTEGER NOT NULL,
    marker_written_at INTEGER,
    authority_committed_at INTEGER,
    activated_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (usage_limit_kind != 1 OR usage_limit_value <= 100),
    CHECK ((state = 1) = (marker_fingerprint IS NULL)),
    CHECK ((state < 3) = (authority_result_digest IS NULL)),
    CHECK ((state >= 2) = (marker_written_at IS NOT NULL)),
    CHECK ((state >= 3) = (authority_committed_at IS NOT NULL)),
    CHECK ((state = 4) = (activated_at IS NOT NULL))
) STRICT;

CREATE INDEX local_targets_by_state
ON local_targets(state, target_id);

CREATE TRIGGER local_targets_identity_immutable
BEFORE UPDATE OF target_id, registration_operation_id, mesh_id, node_id, host_id,
    actor_principal_id, audit_event_id, provider_instance_id, target_display_name,
    provider_display_name, canonical_path, generation, usage_limit_kind,
    usage_limit_value, provider_implementation_id, provider_contract_major,
    provider_contract_minor, provider_schema_version, provider_configuration,
    provider_configuration_digest
ON local_targets
BEGIN
    SELECT RAISE(ABORT, 'local storage target intent is immutable');
END;

CREATE TRIGGER local_targets_not_deletable
BEFORE DELETE ON local_targets
BEGIN
    SELECT RAISE(ABORT, 'local storage target evidence cannot be deleted');
END;
