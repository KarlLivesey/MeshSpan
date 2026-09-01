-- SPDX-License-Identifier: GPL-2.0-only

-- Paths remain node-local. Replicated metadata binds one stable target to its
-- owning node/host, selected provider and exact durable marker generation.
CREATE TABLE storage_targets (
    target_id BLOB PRIMARY KEY CHECK (length(target_id) = 16),
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    host_id BLOB NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    provider_instance_id BLOB NOT NULL
        REFERENCES component_instances(instance_id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),
    current_generation INTEGER NOT NULL CHECK (current_generation > 0),
    usage_limit_kind INTEGER NOT NULL CHECK (usage_limit_kind IN (1, 2)),
    usage_limit_value INTEGER NOT NULL CHECK (usage_limit_value > 0),
    admitted_at INTEGER NOT NULL,
    draining_at INTEGER,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (usage_limit_kind != 1 OR usage_limit_value <= 100),
    CHECK (state != 5 OR retired_at IS NOT NULL)
) STRICT;

CREATE INDEX storage_targets_by_node
ON storage_targets(node_id, state, target_id);

CREATE INDEX storage_targets_by_host
ON storage_targets(host_id, state, target_id);

CREATE INDEX storage_targets_by_provider
ON storage_targets(provider_instance_id, state, target_id);

CREATE TABLE target_generations (
    target_id BLOB NOT NULL REFERENCES storage_targets(target_id) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation > 0),
    marker_fingerprint BLOB NOT NULL CHECK (length(marker_fingerprint) = 32),
    backing_device_fingerprint BLOB
        CHECK (backing_device_fingerprint IS NULL OR length(backing_device_fingerprint) = 32),
    filesystem_fingerprint BLOB
        CHECK (filesystem_fingerprint IS NULL OR length(filesystem_fingerprint) = 32),
    activated_at INTEGER NOT NULL,
    retired_at INTEGER,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (target_id, generation),
    CHECK (state != 4 OR retired_at IS NOT NULL)
) STRICT;

CREATE UNIQUE INDEX one_live_storage_target_generation
ON target_generations(target_id)
WHERE state = 1;

CREATE TRIGGER storage_target_node_host_must_match
BEFORE INSERT ON storage_targets
WHEN NOT EXISTS (
    SELECT 1 FROM nodes
    WHERE node_id = NEW.node_id AND host_id = NEW.host_id AND retired_at IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'storage target node and host do not match');
END;

CREATE TRIGGER storage_target_provider_must_be_active
BEFORE INSERT ON storage_targets
WHEN NOT EXISTS (
    SELECT 1 FROM component_instances
    WHERE instance_id = NEW.provider_instance_id
      AND component_kind = 1
      AND desired_state = 1
      AND active_config_revision IS NOT NULL
      AND retired_at IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'storage provider is not active');
END;

CREATE TRIGGER target_generations_immutable
BEFORE UPDATE ON target_generations
BEGIN
    SELECT RAISE(ABORT, 'storage target generations are immutable');
END;

CREATE TRIGGER target_generations_not_deletable
BEFORE DELETE ON target_generations
BEGIN
    SELECT RAISE(ABORT, 'storage target generations cannot be deleted');
END;
