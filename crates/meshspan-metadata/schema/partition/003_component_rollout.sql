-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE node_component_support (
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    node_incarnation INTEGER NOT NULL CHECK (node_incarnation > 0),
    component_kind INTEGER NOT NULL CHECK (component_kind BETWEEN 1 AND 10),
    implementation_id TEXT NOT NULL CHECK (length(implementation_id) BETWEEN 1 AND 80),
    contract_major INTEGER NOT NULL CHECK (contract_major > 0),
    contract_minor INTEGER NOT NULL CHECK (contract_minor >= 0),
    reported_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, node_incarnation, component_kind, implementation_id)
) STRICT;

CREATE TABLE component_observations (
    instance_id BLOB NOT NULL REFERENCES component_instances(instance_id) ON DELETE CASCADE,
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    node_incarnation INTEGER NOT NULL CHECK (node_incarnation > 0),
    config_revision INTEGER NOT NULL CHECK (config_revision > 0),
    observed_state INTEGER NOT NULL CHECK (observed_state BETWEEN 1 AND 6),
    bounded_error_code INTEGER,
    observed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (instance_id, node_id)
) STRICT;

CREATE INDEX component_observations_by_state
ON component_observations(instance_id, config_revision, observed_state, node_id);
