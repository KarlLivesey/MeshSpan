-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    migration_digest BLOB NOT NULL UNIQUE CHECK (length(migration_digest) = 32),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE applied_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    last_log_index INTEGER NOT NULL CHECK (last_log_index >= 0),
    last_log_term INTEGER NOT NULL CHECK (last_log_term >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    CHECK ((last_log_index = 0) = (last_log_term = 0))
) STRICT;

CREATE TABLE consensus_vote (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    current_term INTEGER NOT NULL CHECK (current_term >= 0),
    voted_for_node_id BLOB CHECK (voted_for_node_id IS NULL OR length(voted_for_node_id) = 16),
    membership_epoch INTEGER NOT NULL CHECK (membership_epoch >= 0),
    persisted_at INTEGER NOT NULL
) STRICT;

CREATE TABLE consensus_log (
    log_index INTEGER PRIMARY KEY CHECK (log_index > 0),
    term INTEGER NOT NULL CHECK (term > 0),
    entry_kind INTEGER NOT NULL CHECK (entry_kind > 0),
    entry_version INTEGER NOT NULL CHECK (entry_version > 0),
    payload BLOB NOT NULL,
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32)
) STRICT;

CREATE TABLE consensus_quorum_plans (
    log_index INTEGER PRIMARY KEY REFERENCES consensus_log(log_index) ON DELETE CASCADE,
    membership_epoch INTEGER NOT NULL CHECK (membership_epoch > 0),
    plan_version INTEGER NOT NULL CHECK (plan_version > 0),
    canonical_plan BLOB NOT NULL,
    proof_digest BLOB NOT NULL CHECK (length(proof_digest) = 32)
) STRICT;

CREATE TABLE consensus_snapshots (
    snapshot_id BLOB PRIMARY KEY CHECK (length(snapshot_id) = 16),
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    last_log_index INTEGER NOT NULL CHECK (last_log_index > 0),
    last_log_term INTEGER NOT NULL CHECK (last_log_term > 0),
    membership_epoch INTEGER NOT NULL CHECK (membership_epoch > 0),
    quorum_plan_payload BLOB NOT NULL,
    proof_digest BLOB NOT NULL CHECK (length(proof_digest) = 32),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    local_path TEXT NOT NULL CHECK (length(local_path) BETWEEN 1 AND 4096),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    created_at INTEGER NOT NULL,
    installed_at INTEGER,
    CHECK (installed_at IS NULL OR installed_at >= created_at)
) STRICT;

CREATE TABLE principals (
    principal_id BLOB PRIMARY KEY CHECK (length(principal_id) = 16),
    principal_kind INTEGER NOT NULL CHECK (principal_kind IN (1, 2, 3)),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_at INTEGER NOT NULL,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
) STRICT;

CREATE TABLE users (
    principal_id BLOB PRIMARY KEY REFERENCES principals(principal_id) ON DELETE RESTRICT,
    primary_email TEXT CHECK (primary_email IS NULL OR length(primary_email) BETWEEN 3 AND 320)
) STRICT;

CREATE TABLE access_activation_policies (
    policy_id BLOB PRIMARY KEY CHECK (length(policy_id) = 16),
    maximum_duration_micros INTEGER NOT NULL CHECK (maximum_duration_micros > 0),
    reason_required INTEGER NOT NULL CHECK (reason_required IN (0, 1)),
    minimum_assurance INTEGER NOT NULL CHECK (minimum_assurance BETWEEN 1 AND 3),
    valid_from INTEGER,
    valid_until INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
) STRICT;

CREATE TABLE groups (
    principal_id BLOB PRIMARY KEY REFERENCES principals(principal_id) ON DELETE RESTRICT,
    activation_policy_id BLOB REFERENCES access_activation_policies(policy_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE group_memberships (
    containing_group_id BLOB NOT NULL REFERENCES groups(principal_id) ON DELETE CASCADE,
    member_principal_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    valid_from INTEGER,
    valid_until INTEGER,
    activation_required INTEGER NOT NULL CHECK (activation_required IN (0, 1)),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (containing_group_id, member_principal_id),
    CHECK (containing_group_id <> member_principal_id),
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
) STRICT;

CREATE INDEX group_memberships_by_member
ON group_memberships(member_principal_id, containing_group_id);

CREATE TABLE group_closure (
    containing_group_id BLOB NOT NULL REFERENCES groups(principal_id) ON DELETE CASCADE,
    member_principal_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    path_count INTEGER NOT NULL CHECK (path_count > 0),
    minimum_depth INTEGER NOT NULL CHECK (minimum_depth > 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (containing_group_id, member_principal_id),
    CHECK (containing_group_id <> member_principal_id)
) STRICT;

CREATE INDEX group_closure_by_member
ON group_closure(member_principal_id, containing_group_id);

CREATE TABLE authentication_methods (
    method_id BLOB PRIMARY KEY CHECK (length(method_id) = 16),
    user_principal_id BLOB NOT NULL REFERENCES users(principal_id) ON DELETE CASCADE,
    method_kind INTEGER NOT NULL CHECK (method_kind BETWEEN 1 AND 7),
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    service_scope INTEGER NOT NULL CHECK (service_scope > 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    protected_material BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    valid_until INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (valid_until IS NULL OR valid_until > created_at)
) STRICT;

CREATE INDEX authentication_methods_by_user
ON authentication_methods(user_principal_id, state, method_kind);

CREATE TABLE authentication_sessions (
    session_id BLOB PRIMARY KEY CHECK (length(session_id) = 16),
    token_digest BLOB NOT NULL UNIQUE CHECK (length(token_digest) = 32),
    user_principal_id BLOB NOT NULL REFERENCES users(principal_id) ON DELETE CASCADE,
    assurance INTEGER NOT NULL CHECK (assurance BETWEEN 1 AND 3),
    identity_revision INTEGER NOT NULL CHECK (identity_revision > 0),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    revoked_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
) STRICT;

CREATE INDEX authentication_sessions_active
ON authentication_sessions(user_principal_id, expires_at, revoked_at);

CREATE TABLE operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    actor_principal_id BLOB REFERENCES principals(principal_id) ON DELETE RESTRICT,
    actor_node_id BLOB CHECK (actor_node_id IS NULL OR length(actor_node_id) = 16),
    operation_kind INTEGER NOT NULL CHECK (operation_kind > 0),
    request_version INTEGER NOT NULL CHECK (request_version > 0),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    outcome INTEGER NOT NULL CHECK (outcome BETWEEN 1 AND 8),
    durability_scope INTEGER CHECK (durability_scope IS NULL OR durability_scope BETWEEN 1 AND 3),
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    committed_log_index INTEGER,
    result_kind INTEGER,
    result_version INTEGER,
    result_payload BLOB,
    result_digest BLOB CHECK (result_digest IS NULL OR length(result_digest) = 32),
    error_kind INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (completed_at IS NULL OR completed_at >= started_at),
    CHECK (committed_log_index IS NULL OR committed_log_index > 0),
    CHECK ((result_payload IS NULL) = (result_version IS NULL)),
    CHECK ((result_payload IS NULL) = (result_digest IS NULL))
) STRICT;

CREATE INDEX operations_by_committed_log
ON operations(committed_log_index, operation_id);

CREATE TABLE audit_events (
    event_id BLOB PRIMARY KEY CHECK (length(event_id) = 16),
    operation_id BLOB REFERENCES operations(operation_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    actor_principal_id BLOB REFERENCES principals(principal_id) ON DELETE RESTRICT,
    actor_node_id BLOB CHECK (actor_node_id IS NULL OR length(actor_node_id) = 16),
    event_kind INTEGER NOT NULL CHECK (event_kind > 0),
    subject_kind INTEGER NOT NULL CHECK (subject_kind > 0),
    subject_id BLOB CHECK (subject_id IS NULL OR length(subject_id) = 16),
    occurred_at INTEGER NOT NULL,
    redacted_payload BLOB NOT NULL,
    previous_event_digest BLOB CHECK (previous_event_digest IS NULL OR length(previous_event_digest) = 32),
    event_digest BLOB NOT NULL UNIQUE CHECK (length(event_digest) = 32),
    UNIQUE (operation_id, sequence)
) STRICT;

CREATE INDEX audit_events_by_subject
ON audit_events(subject_kind, subject_id, occurred_at, event_id);

CREATE TABLE meshes (
    mesh_id BLOB PRIMARY KEY CHECK (length(mesh_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 256),
    created_at INTEGER NOT NULL,
    configuration_revision INTEGER NOT NULL CHECK (configuration_revision > 0),
    identity_revision INTEGER NOT NULL CHECK (identity_revision > 0),
    namespace_revision INTEGER NOT NULL CHECK (namespace_revision > 0),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE hosts (
    host_id BLOB PRIMARY KEY CHECK (length(host_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_at INTEGER NOT NULL,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE nodes (
    node_id BLOB PRIMARY KEY CHECK (length(node_id) = 16),
    host_id BLOB NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    current_incarnation INTEGER NOT NULL CHECK (current_incarnation > 0),
    admitted_at INTEGER NOT NULL,
    activated_at INTEGER,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE INDEX nodes_by_host ON nodes(host_id, state, node_id);

CREATE TABLE metadata_partitions (
    partition_id BLOB PRIMARY KEY CHECK (length(partition_id) = 16),
    partition_kind INTEGER NOT NULL CHECK (partition_kind BETWEEN 1 AND 3),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    routing_epoch INTEGER NOT NULL CHECK (routing_epoch > 0),
    current_membership_revision INTEGER NOT NULL CHECK (current_membership_revision > 0),
    created_at INTEGER NOT NULL,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE partition_voters (
    partition_id BLOB NOT NULL REFERENCES metadata_partitions(partition_id) ON DELETE CASCADE,
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    membership_revision INTEGER NOT NULL CHECK (membership_revision > 0),
    member_role INTEGER NOT NULL CHECK (member_role BETWEEN 1 AND 3),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (partition_id, node_id)
) STRICT;

CREATE INDEX partition_voters_by_node ON partition_voters(node_id, state, partition_id);

CREATE TABLE fault_group_classes (
    class_id BLOB PRIMARY KEY CHECK (length(class_id) = 16),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 128),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE fault_groups (
    group_id BLOB PRIMARY KEY CHECK (length(group_id) = 16),
    class_id BLOB NOT NULL REFERENCES fault_group_classes(class_id) ON DELETE RESTRICT,
    parent_group_id BLOB REFERENCES fault_groups(group_id) ON DELETE RESTRICT,
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 256),
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (class_id, canonical_name),
    CHECK (parent_group_id IS NULL OR parent_group_id <> group_id)
) STRICT;

CREATE TABLE host_fault_group_memberships (
    host_id BLOB NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    group_id BLOB NOT NULL REFERENCES fault_groups(group_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (host_id, group_id)
) STRICT;

CREATE INDEX host_fault_groups_by_group
ON host_fault_group_memberships(group_id, host_id);

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
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (component_kind, canonical_name, scope_kind, scope_id)
) STRICT;

CREATE TABLE component_configurations (
    instance_id BLOB NOT NULL REFERENCES component_instances(instance_id) ON DELETE CASCADE,
    config_revision INTEGER NOT NULL CHECK (config_revision > 0),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    canonical_config BLOB NOT NULL CHECK (length(canonical_config) <= 16777216),
    config_digest BLOB NOT NULL CHECK (length(config_digest) = 32),
    secret_generation_id BLOB CHECK (secret_generation_id IS NULL OR length(secret_generation_id) = 16),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    PRIMARY KEY (instance_id, config_revision)
) STRICT;

CREATE TABLE component_assignments (
    instance_id BLOB NOT NULL REFERENCES component_instances(instance_id) ON DELETE CASCADE,
    assignment_kind INTEGER NOT NULL CHECK (assignment_kind BETWEEN 1 AND 4),
    assignment_id BLOB NOT NULL CHECK (length(assignment_id) = 16),
    desired_state INTEGER NOT NULL CHECK (desired_state BETWEEN 1 AND 4),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (instance_id, assignment_kind, assignment_id)
) STRICT;

CREATE TABLE volumes (
    volume_id BLOB PRIMARY KEY CHECK (length(volume_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE owner_sets (
    owner_set_id BLOB PRIMARY KEY CHECK (length(owner_set_id) = 16),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE object_owners (
    owner_set_id BLOB NOT NULL REFERENCES owner_sets(owner_set_id) ON DELETE RESTRICT,
    owner_principal_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    assigned_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    assigned_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (owner_set_id, owner_principal_id)
) STRICT;

CREATE INDEX object_owners_by_principal
ON object_owners(owner_principal_id, owner_set_id);

CREATE TABLE namespace_objects (
    object_id BLOB PRIMARY KEY CHECK (length(object_id) = 16),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE CASCADE,
    parent_object_id BLOB REFERENCES namespace_objects(object_id) ON DELETE RESTRICT,
    object_kind INTEGER NOT NULL CHECK (object_kind IN (1, 2)),
    display_name TEXT NOT NULL CHECK (length(display_name) <= 255),
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) <= 255),
    owner_set_id BLOB NOT NULL REFERENCES owner_sets(owner_set_id) ON DELETE RESTRICT,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (volume_id, parent_object_id, canonical_name),
    CHECK (parent_object_id IS NULL OR parent_object_id <> object_id),
    CHECK ((parent_object_id IS NULL) = (length(canonical_name) = 0))
) STRICT;

CREATE UNIQUE INDEX one_root_per_volume
ON namespace_objects(volume_id) WHERE parent_object_id IS NULL;

CREATE INDEX namespace_objects_by_parent
ON namespace_objects(volume_id, parent_object_id, canonical_name, object_id);

CREATE TABLE permission_grants (
    grant_id BLOB PRIMARY KEY CHECK (length(grant_id) = 16),
    subject_principal_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    scope_kind INTEGER NOT NULL CHECK (scope_kind IN (1, 2, 3)),
    volume_id BLOB REFERENCES volumes(volume_id) ON DELETE CASCADE,
    object_id BLOB REFERENCES namespace_objects(object_id) ON DELETE CASCADE,
    rights INTEGER NOT NULL CHECK (rights > 0 AND (rights & ~8191) = 0),
    inheritance INTEGER NOT NULL CHECK (inheritance BETWEEN 1 AND 3),
    valid_from INTEGER,
    valid_until INTEGER,
    activation_policy_id BLOB REFERENCES access_activation_policies(policy_id) ON DELETE RESTRICT,
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from),
    CHECK ((scope_kind = 1 AND volume_id IS NULL AND object_id IS NULL)
        OR (scope_kind = 2 AND volume_id IS NOT NULL AND object_id IS NULL)
        OR (scope_kind = 3 AND volume_id IS NOT NULL AND object_id IS NOT NULL))
) STRICT;

CREATE INDEX permission_grants_by_subject
ON permission_grants(subject_principal_id, state, valid_until, grant_id);

CREATE INDEX permission_grants_by_scope
ON permission_grants(scope_kind, volume_id, object_id, state, grant_id);

CREATE TABLE access_activations (
    activation_id BLOB PRIMARY KEY CHECK (length(activation_id) = 16),
    principal_id BLOB NOT NULL REFERENCES users(principal_id) ON DELETE CASCADE,
    group_id BLOB REFERENCES groups(principal_id) ON DELETE CASCADE,
    grant_id BLOB REFERENCES permission_grants(grant_id) ON DELETE CASCADE,
    policy_id BLOB NOT NULL REFERENCES access_activation_policies(policy_id) ON DELETE RESTRICT,
    reason TEXT NOT NULL CHECK (length(reason) <= 512),
    authentication_digest BLOB NOT NULL CHECK (length(authentication_digest) = 32),
    identity_revision INTEGER NOT NULL CHECK (identity_revision > 0),
    source_revision INTEGER NOT NULL CHECK (source_revision > 0),
    policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
    activated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > activated_at),
    revoked_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK ((group_id IS NULL) <> (grant_id IS NULL))
) STRICT;

CREATE INDEX access_activations_current
ON access_activations(principal_id, expires_at, revoked_at, group_id, grant_id);

CREATE TABLE tags (
    tag_id BLOB PRIMARY KEY CHECK (length(tag_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 128),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE object_tags (
    object_id BLOB NOT NULL REFERENCES namespace_objects(object_id) ON DELETE CASCADE,
    tag_id BLOB NOT NULL REFERENCES tags(tag_id) ON DELETE CASCADE,
    assigned_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    assigned_at INTEGER NOT NULL,
    PRIMARY KEY (object_id, tag_id)
) STRICT;

CREATE INDEX object_tags_by_tag ON object_tags(tag_id, object_id);

CREATE TABLE principal_tags (
    principal_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    tag_id BLOB NOT NULL REFERENCES tags(tag_id) ON DELETE CASCADE,
    assigned_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    assigned_at INTEGER NOT NULL,
    PRIMARY KEY (principal_id, tag_id)
) STRICT;

CREATE INDEX principal_tags_by_tag ON principal_tags(tag_id, principal_id);

CREATE TABLE metadata_backups (
    backup_id BLOB PRIMARY KEY CHECK (length(backup_id) = 16),
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    last_log_index INTEGER NOT NULL CHECK (last_log_index >= 0),
    last_log_term INTEGER NOT NULL CHECK (last_log_term >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    created_at INTEGER NOT NULL,
    CHECK ((last_log_index = 0) = (last_log_term = 0))
) STRICT;

CREATE INDEX metadata_backups_by_revision
ON metadata_backups(state_revision DESC, backup_id);
