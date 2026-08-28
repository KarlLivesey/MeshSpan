-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    migration_digest BLOB NOT NULL UNIQUE CHECK (length(migration_digest) = 32),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE local_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    node_id BLOB NOT NULL CHECK (length(node_id) = 16),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0)
) STRICT;

CREATE TABLE local_component_bindings (
    instance_id BLOB NOT NULL CHECK (length(instance_id) = 16),
    binding_kind INTEGER NOT NULL CHECK (binding_kind BETWEEN 1 AND 4),
    authoritative_config_revision INTEGER NOT NULL CHECK (authoritative_config_revision > 0),
    local_binding_payload BLOB NOT NULL CHECK (length(local_binding_payload) <= 16777216),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (instance_id, binding_kind)
) STRICT;

CREATE TABLE local_branch_operations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    actor_principal_id BLOB NOT NULL CHECK (length(actor_principal_id) = 16),
    actor_session_id BLOB NOT NULL CHECK (length(actor_session_id) = 16),
    identity_revision INTEGER NOT NULL CHECK (identity_revision > 0),
    acl_revision INTEGER NOT NULL CHECK (acl_revision > 0),
    isolation_delegation_id BLOB NOT NULL CHECK (length(isolation_delegation_id) = 16),
    operation_kind INTEGER NOT NULL CHECK (operation_kind > 0),
    request_version INTEGER NOT NULL CHECK (request_version > 0),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    outcome INTEGER NOT NULL CHECK (outcome BETWEEN 1 AND 8),
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    result_payload BLOB,
    UNIQUE (operation_id, request_digest),
    CHECK (completed_at IS NULL OR completed_at >= started_at)
) STRICT;

CREATE TABLE local_branch_commits (
    namespace_commit_id BLOB PRIMARY KEY CHECK (length(namespace_commit_id) = 16),
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    root_object_revision_id BLOB NOT NULL CHECK (length(root_object_revision_id) = 16),
    operation_id BLOB NOT NULL UNIQUE REFERENCES local_branch_operations(operation_id) ON DELETE RESTRICT,
    origin_node_id BLOB NOT NULL CHECK (length(origin_node_id) = 16),
    causal_sequence INTEGER NOT NULL CHECK (causal_sequence > 0),
    created_at INTEGER NOT NULL,
    canonical_payload BLOB NOT NULL CHECK (length(canonical_payload) <= 16777216),
    root_digest BLOB NOT NULL CHECK (length(root_digest) = 32),
    commit_digest BLOB NOT NULL UNIQUE CHECK (length(commit_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4)
) STRICT;

CREATE INDEX local_branch_commits_by_branch
ON local_branch_commits(volume_id, branch_id, causal_sequence, namespace_commit_id);

CREATE TABLE local_branch_commit_parents (
    namespace_commit_id BLOB NOT NULL REFERENCES local_branch_commits(namespace_commit_id) ON DELETE CASCADE,
    parent_commit_id BLOB NOT NULL CHECK (length(parent_commit_id) = 16),
    parent_order INTEGER NOT NULL CHECK (parent_order >= 0),
    PRIMARY KEY (namespace_commit_id, parent_commit_id),
    UNIQUE (namespace_commit_id, parent_order),
    CHECK (namespace_commit_id <> parent_commit_id)
) STRICT;

CREATE TABLE local_branch_heads (
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    namespace_commit_id BLOB NOT NULL REFERENCES local_branch_commits(namespace_commit_id) ON DELETE RESTRICT,
    durability_scope INTEGER NOT NULL CHECK (durability_scope BETWEEN 1 AND 3),
    head_revision INTEGER NOT NULL CHECK (head_revision > 0),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (volume_id, branch_id)
) STRICT;

CREATE TABLE local_branch_objects (
    namespace_commit_id BLOB NOT NULL REFERENCES local_branch_commits(namespace_commit_id) ON DELETE CASCADE,
    record_kind INTEGER NOT NULL CHECK (record_kind > 0),
    record_id BLOB NOT NULL CHECK (length(record_id) = 16),
    canonical_payload BLOB NOT NULL CHECK (length(canonical_payload) <= 16777216),
    record_digest BLOB NOT NULL CHECK (length(record_digest) = 32),
    PRIMARY KEY (namespace_commit_id, record_kind, record_id)
) STRICT;

CREATE TABLE local_branch_receipts (
    receipt_id BLOB PRIMARY KEY CHECK (length(receipt_id) = 16),
    operation_id BLOB NOT NULL REFERENCES local_branch_operations(operation_id) ON DELETE RESTRICT,
    namespace_commit_id BLOB NOT NULL REFERENCES local_branch_commits(namespace_commit_id) ON DELETE RESTRICT,
    durability_scope INTEGER NOT NULL CHECK (durability_scope BETWEEN 1 AND 3),
    achieved_protection_digest BLOB NOT NULL CHECK (length(achieved_protection_digest) = 32),
    pending_debt_digest BLOB NOT NULL CHECK (length(pending_debt_digest) = 32),
    issued_at INTEGER NOT NULL,
    receipt_digest BLOB NOT NULL UNIQUE CHECK (length(receipt_digest) = 32)
) STRICT;

CREATE INDEX local_branch_receipts_by_operation
ON local_branch_receipts(operation_id, issued_at, receipt_id);

CREATE TABLE local_isolation_usage (
    delegation_id BLOB NOT NULL CHECK (length(delegation_id) = 16),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    generation INTEGER NOT NULL CHECK (generation > 0),
    allocated_bytes INTEGER NOT NULL CHECK (allocated_bytes >= 0),
    consumed_bytes INTEGER NOT NULL CHECK (consumed_bytes BETWEEN 0 AND allocated_bytes),
    evidence_digest BLOB NOT NULL CHECK (length(evidence_digest) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (delegation_id, target_id, generation)
) STRICT;
