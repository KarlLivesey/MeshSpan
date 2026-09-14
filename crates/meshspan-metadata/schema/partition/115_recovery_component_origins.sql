-- SPDX-License-Identifier: GPL-2.0-only

-- The migration runner rebuilds these referenced tables with foreign-key enforcement
-- suspended on its private connection, then checks every reference before committing.
-- No child rows are deleted, no principal is invented, and ordinary provenance survives.
CREATE TABLE saved_component_instances AS SELECT * FROM component_instances;
CREATE TABLE saved_component_configurations AS SELECT * FROM component_configurations;
DROP TABLE component_configurations;
DROP TABLE component_instances;

CREATE TABLE component_instances (
    instance_id BLOB PRIMARY KEY CHECK (length(instance_id) = 16),
    component_kind INTEGER NOT NULL CHECK (component_kind BETWEEN 1 AND 10),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 256),
    implementation_id TEXT NOT NULL CHECK (length(implementation_id) BETWEEN 1 AND 80),
    contract_major INTEGER NOT NULL CHECK (contract_major > 0),
    contract_minor INTEGER NOT NULL CHECK (contract_minor >= 0),
    scope_kind INTEGER NOT NULL CHECK (scope_kind BETWEEN 1 AND 4),
    scope_id BLOB CHECK (scope_id IS NULL OR length(scope_id) = 16),
    desired_state INTEGER NOT NULL CHECK (desired_state BETWEEN 1 AND 5),
    active_config_revision INTEGER,
    created_by BLOB REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    recovery_preparation INTEGER REFERENCES partition_recovery_preparation(singleton)
        ON DELETE RESTRICT CHECK (recovery_preparation = 1),
    CHECK ((created_by IS NOT NULL) != (recovery_preparation IS NOT NULL)),
    UNIQUE (component_kind, canonical_name, scope_kind, scope_id)
) STRICT;

CREATE TABLE component_configurations (
    instance_id BLOB NOT NULL REFERENCES component_instances(instance_id) ON DELETE CASCADE,
    config_revision INTEGER NOT NULL CHECK (config_revision > 0),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    canonical_config BLOB NOT NULL CHECK (length(canonical_config) <= 16777216),
    config_digest BLOB NOT NULL CHECK (length(config_digest) = 32),
    secret_generation_id BLOB CHECK (secret_generation_id IS NULL OR length(secret_generation_id) = 16),
    created_by BLOB REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    recovery_preparation INTEGER REFERENCES partition_recovery_preparation(singleton)
        ON DELETE RESTRICT CHECK (recovery_preparation = 1),
    CHECK ((created_by IS NOT NULL) != (recovery_preparation IS NOT NULL)),
    PRIMARY KEY (instance_id, config_revision)
) STRICT;

INSERT INTO component_instances SELECT *, NULL FROM saved_component_instances;
INSERT INTO component_configurations SELECT *, NULL FROM saved_component_configurations;
DROP TABLE saved_component_configurations;
DROP TABLE saved_component_instances;

CREATE TRIGGER component_recovery_origin_requires_projection
BEFORE INSERT ON component_instances
WHEN NEW.recovery_preparation IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM partition_recovery_node_key_projection p
    JOIN partition_recovery_credential_fence f ON f.singleton = p.singleton
    WHERE p.singleton = NEW.recovery_preparation AND p.completed = 0
      AND p.manifest_digest = f.manifest_digest AND p.reserved_revision = f.source_revision + 1
      AND NEW.created_at = p.projected_at AND NEW.revision = p.reserved_revision)
BEGIN SELECT RAISE(ABORT, 'recovery component requires open authorised projection'); END;

CREATE TRIGGER component_configuration_recovery_origin_requires_projection
BEFORE INSERT ON component_configurations
WHEN NEW.recovery_preparation IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM partition_recovery_node_key_projection p
    JOIN component_instances c ON c.instance_id = NEW.instance_id
    WHERE p.singleton = NEW.recovery_preparation AND p.completed = 0
      AND c.recovery_preparation = p.singleton AND c.revision = p.reserved_revision
      AND NEW.created_at = p.projected_at AND NEW.config_revision = 1)
BEGIN SELECT RAISE(ABORT, 'recovery configuration requires open authorised projection'); END;

CREATE TRIGGER component_origin_immutable
BEFORE UPDATE ON component_instances
WHEN NEW.created_by IS NOT OLD.created_by OR NEW.created_at != OLD.created_at
    OR NEW.recovery_preparation IS NOT OLD.recovery_preparation
BEGIN SELECT RAISE(ABORT, 'component creation authority is immutable'); END;

CREATE TRIGGER component_configuration_origin_immutable
BEFORE UPDATE ON component_configurations
WHEN NEW.created_by IS NOT OLD.created_by OR NEW.created_at != OLD.created_at
    OR NEW.recovery_preparation IS NOT OLD.recovery_preparation
BEGIN SELECT RAISE(ABORT, 'configuration creation authority is immutable'); END;
