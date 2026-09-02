-- SPDX-License-Identifier: GPL-2.0-only

-- Locality and failure independence are separate promises. Cells describe where a complete copy
-- may live; overlapping fault groups describe what may fail together.
CREATE TABLE availability_cells (
    cell_id BLOB PRIMARY KEY CHECK (length(cell_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 256),
    parent_cell_id BLOB REFERENCES availability_cells(cell_id) ON DELETE RESTRICT,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (parent_cell_id IS NULL OR parent_cell_id <> cell_id)
) STRICT;

CREATE INDEX availability_cells_by_parent
ON availability_cells(parent_cell_id, state, canonical_name, cell_id);

CREATE TABLE host_cell_memberships (
    host_id BLOB NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    cell_id BLOB NOT NULL REFERENCES availability_cells(cell_id) ON DELETE RESTRICT,
    source_kind INTEGER NOT NULL CHECK (source_kind BETWEEN 1 AND 3),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (host_id, cell_id)
) STRICT;

CREATE INDEX host_cell_memberships_by_cell
ON host_cell_memberships(cell_id, host_id);

CREATE TABLE target_cell_memberships (
    target_id BLOB NOT NULL REFERENCES storage_targets(target_id) ON DELETE RESTRICT,
    cell_id BLOB NOT NULL REFERENCES availability_cells(cell_id) ON DELETE RESTRICT,
    source_kind INTEGER NOT NULL CHECK (source_kind BETWEEN 1 AND 3),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (target_id, cell_id)
) STRICT;

CREATE INDEX target_cell_memberships_by_cell
ON target_cell_memberships(cell_id, target_id);

-- Terms in one scenario fail simultaneously. Separate scenarios are alternative promises which
-- must each be satisfied.
CREATE TABLE protection_policies (
    policy_id BLOB PRIMARY KEY CHECK (length(policy_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE protection_scenarios (
    scenario_id BLOB PRIMARY KEY CHECK (length(scenario_id) = 16),
    policy_id BLOB NOT NULL REFERENCES protection_policies(policy_id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    scenario_order INTEGER NOT NULL CHECK (scenario_order >= 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (policy_id, scenario_order)
) STRICT;

CREATE INDEX protection_scenarios_by_policy
ON protection_scenarios(policy_id, scenario_order, scenario_id);

CREATE TABLE protection_scenario_terms (
    term_id BLOB PRIMARY KEY CHECK (length(term_id) = 16),
    scenario_id BLOB NOT NULL REFERENCES protection_scenarios(scenario_id) ON DELETE RESTRICT,
    class_id BLOB NOT NULL REFERENCES fault_group_classes(class_id) ON DELETE RESTRICT,
    failure_count INTEGER NOT NULL CHECK (failure_count > 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (scenario_id, class_id)
) STRICT;

CREATE INDEX protection_scenario_terms_by_class
ON protection_scenario_terms(class_id, scenario_id);

CREATE TABLE locality_policies (
    locality_policy_id BLOB PRIMARY KEY CHECK (length(locality_policy_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 256),
    maximum_lag_micros INTEGER CHECK (maximum_lag_micros IS NULL OR maximum_lag_micros > 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE locality_requirements (
    requirement_id BLOB PRIMARY KEY CHECK (length(requirement_id) = 16),
    locality_policy_id BLOB NOT NULL
        REFERENCES locality_policies(locality_policy_id) ON DELETE RESTRICT,
    cell_id BLOB NOT NULL REFERENCES availability_cells(cell_id) ON DELETE RESTRICT,
    requirement_kind INTEGER NOT NULL CHECK (requirement_kind BETWEEN 1 AND 3),
    local_protection_policy_id BLOB
        REFERENCES protection_policies(policy_id) ON DELETE RESTRICT,
    requirement_order INTEGER NOT NULL CHECK (requirement_order >= 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (locality_policy_id, cell_id, requirement_kind),
    UNIQUE (locality_policy_id, requirement_order)
) STRICT;

CREATE INDEX locality_requirements_by_cell
ON locality_requirements(cell_id, locality_policy_id);

CREATE TABLE object_locality_bindings (
    binding_id BLOB PRIMARY KEY CHECK (length(binding_id) = 16),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE RESTRICT,
    object_id BLOB REFERENCES namespace_objects(object_id) ON DELETE RESTRICT,
    locality_policy_id BLOB REFERENCES locality_policies(locality_policy_id) ON DELETE RESTRICT,
    inheritance_mode INTEGER NOT NULL CHECK (inheritance_mode BETWEEN 1 AND 3),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    assigned_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (locality_policy_id IS NOT NULL OR inheritance_mode = 3)
) STRICT;

CREATE UNIQUE INDEX one_active_volume_locality_binding
ON object_locality_bindings(volume_id)
WHERE object_id IS NULL AND state = 1;

CREATE UNIQUE INDEX one_active_object_locality_binding
ON object_locality_bindings(object_id)
WHERE object_id IS NOT NULL AND state = 1;

CREATE INDEX object_locality_bindings_by_policy
ON object_locality_bindings(locality_policy_id, state, binding_id);

CREATE TABLE acknowledgement_policies (
    acknowledgement_policy_id BLOB PRIMARY KEY CHECK (length(acknowledgement_policy_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 256),
    consistency_class INTEGER NOT NULL CHECK (consistency_class IN (1, 2)),
    minimum_durable_targets INTEGER NOT NULL CHECK (minimum_durable_targets > 0),
    minimum_distinct_nodes INTEGER NOT NULL CHECK (minimum_distinct_nodes > 0),
    strong_wait_micros INTEGER CHECK (strong_wait_micros IS NULL OR strong_wait_micros > 0),
    fallback_mode INTEGER NOT NULL CHECK (fallback_mode BETWEEN 1 AND 3),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (minimum_distinct_nodes <= minimum_durable_targets),
    CHECK (consistency_class = 2 OR strong_wait_micros IS NULL)
) STRICT;

CREATE TABLE acknowledgement_policy_scenarios (
    acknowledgement_policy_id BLOB NOT NULL
        REFERENCES acknowledgement_policies(acknowledgement_policy_id) ON DELETE RESTRICT,
    scenario_id BLOB NOT NULL REFERENCES protection_scenarios(scenario_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (acknowledgement_policy_id, scenario_id)
) STRICT;

CREATE TABLE acknowledgement_zone_requirements (
    acknowledgement_policy_id BLOB NOT NULL
        REFERENCES acknowledgement_policies(acknowledgement_policy_id) ON DELETE RESTRICT,
    cell_id BLOB NOT NULL REFERENCES availability_cells(cell_id) ON DELETE RESTRICT,
    requirement_kind INTEGER NOT NULL CHECK (requirement_kind BETWEEN 1 AND 3),
    minimum_durable_targets INTEGER
        CHECK (minimum_durable_targets IS NULL OR minimum_durable_targets > 0),
    minimum_distinct_nodes INTEGER
        CHECK (minimum_distinct_nodes IS NULL OR minimum_distinct_nodes > 0),
    local_protection_policy_id BLOB
        REFERENCES protection_policies(policy_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (acknowledgement_policy_id, cell_id),
    CHECK (minimum_durable_targets IS NULL
        OR minimum_distinct_nodes IS NULL
        OR minimum_distinct_nodes <= minimum_durable_targets)
) STRICT;

CREATE INDEX acknowledgement_zone_requirements_by_cell
ON acknowledgement_zone_requirements(cell_id, acknowledgement_policy_id);

CREATE TABLE object_acknowledgement_bindings (
    binding_id BLOB PRIMARY KEY CHECK (length(binding_id) = 16),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE RESTRICT,
    object_id BLOB REFERENCES namespace_objects(object_id) ON DELETE RESTRICT,
    acknowledgement_policy_id BLOB NOT NULL
        REFERENCES acknowledgement_policies(acknowledgement_policy_id) ON DELETE RESTRICT,
    inheritance_mode INTEGER NOT NULL CHECK (inheritance_mode BETWEEN 1 AND 3),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    assigned_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE UNIQUE INDEX one_active_volume_acknowledgement_binding
ON object_acknowledgement_bindings(volume_id)
WHERE object_id IS NULL AND state = 1;

CREATE UNIQUE INDEX one_active_object_acknowledgement_binding
ON object_acknowledgement_bindings(object_id)
WHERE object_id IS NOT NULL AND state = 1;

CREATE INDEX object_acknowledgement_bindings_by_policy
ON object_acknowledgement_bindings(acknowledgement_policy_id, state, binding_id);

-- Existing volumes resolve missing values through versioned built-in defaults. New volume commands
-- write explicit policy IDs once the policy administration surface is available.
ALTER TABLE volumes ADD COLUMN protection_policy_id BLOB
    REFERENCES protection_policies(policy_id) ON DELETE RESTRICT;
ALTER TABLE volumes ADD COLUMN default_locality_policy_id BLOB
    REFERENCES locality_policies(locality_policy_id) ON DELETE RESTRICT;
ALTER TABLE volumes ADD COLUMN default_acknowledgement_policy_id BLOB
    REFERENCES acknowledgement_policies(acknowledgement_policy_id) ON DELETE RESTRICT;
