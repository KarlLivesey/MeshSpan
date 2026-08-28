# Logical record schema

Status: draft for review. This catalogue fixes the information and relationships
MeshSpan needs. Migration DDL will be generated and tested during implementation;
column spellings may change before the design lock, but no required state may be
silently omitted.

## 1. Common representation

```text
Id            16-byte application-generated identifier
Digest        32-byte cryptographic digest plus algorithm where agility matters
Revision      non-negative 64-bit integer advanced by authority
LogPosition   term plus log index
Instant       signed UTC epoch microseconds
Duration      non-negative microseconds
State         closed, versioned text/integer enum
Bitset        fixed-width protocol-neutral rights/features value
Ciphertext    algorithm, key generation, nonce and authenticated bytes
```

Every mutable authoritative record has `revision`, creation metadata and, when
retained after removal, state/retirement metadata. Foreign keys are immediate
unless a documented transaction needs deferred validation. User-facing names
store both display and canonical forms.

## 2. Partition consensus records

These exist independently on each voter and are never replicated by SQL. They
share that partition's `partition.sqlite3` with section 3 so records requiring
one atomic partition-local commit have one transaction boundary.

```text
consensus_vote(
  singleton PK, partition_id, current_term, voted_for_node_id NULL,
  membership_epoch, persisted_at
)

consensus_log(
  log_index PK, term, entry_kind, entry_version, payload, payload_digest
)

consensus_quorum_plans(
  log_index PK -> consensus_log, membership_epoch, plan_version,
  canonical_plan, proof_digest
)

consensus_snapshots(
  snapshot_id PK, partition_id, last_log_index, last_log_term,
  membership_epoch, quorum_plan_payload, proof_digest, schema_version,
  state_revision, byte_length, digest, local_path, state, created_at,
  installed_at NULL
)
```

Vote/term persistence completes before a response is sent. Log indices are
contiguous after the snapshot boundary. Snapshot activation is atomic.

## 3. Replicated state-machine kernel

```text
schema_migrations(
  version PK, migration_digest UNIQUE, applied_at
)

applied_state(
  singleton PK, partition_id, last_log_index, last_log_term,
  state_revision, schema_version
)

operations(
  operation_id PK, partition_id, actor_principal_id NULL -> principals,
  actor_node_id NULL -> nodes, operation_kind, request_version, request_digest,
  outcome, durability_scope NULL, started_at, completed_at NULL,
  committed_log_index NULL,
  result_kind NULL, result_version NULL, result_payload NULL,
  error_kind NULL, revision
)

bulk_operation_manifests(
  manifest_id PK, operation_id UNIQUE -> operations,
  item_count, block_count, manifest_digest UNIQUE,
  state, sealed_at NULL, revision
)

bulk_operation_manifest_blocks(
  manifest_id -> bulk_operation_manifests, block_index,
  first_item_ordinal, item_count, block_digest,
  protected_blob_reference, state,
  PK(manifest_id, block_index),
  UNIQUE(manifest_id, block_digest)
)

distributed_transactions(
  transaction_id PK, operation_id UNIQUE -> operations,
  coordinator_partition_id -> metadata_partitions,
  manifest_id -> bulk_operation_manifests,
  transaction_kind, deadline, state, decision NULL,
  decision_log_index NULL, decision_digest NULL, revision
)

distributed_transaction_participants(
  transaction_id -> distributed_transactions,
  participant_partition_id -> metadata_partitions,
  expected_revision, prepared_revision NULL,
  prepare_digest NULL, state, applied_revision NULL,
  PK(transaction_id, participant_partition_id)
)

prepared_distributed_transactions(
  transaction_id PK,
  coordinator_partition_id -> metadata_partitions,
  operation_id, manifest_digest, transaction_kind,
  expected_revision, prepared_revision, prepare_digest,
  deadline, state, decision_digest NULL, applied_revision NULL
)

audit_events(
  event_id PK, operation_id NULL -> operations, sequence,
  actor_principal_id NULL -> principals, actor_node_id NULL -> nodes,
  event_kind, subject_kind, subject_id NULL, occurred_at,
  redacted_payload, previous_event_digest, event_digest,
  UNIQUE(operation_id, sequence)
)
```

One applied command and its operation result/audit entries commit atomically.
An operation ID may be replayed only with the same request digest. Coordinator
transactions and participant preparation records live in their owning metadata
partitions; the notation above describes their shared logical contract, not one
cross-partition SQL database. A prepared record fences its exact affected keys
until an authenticated decision is applied or a valid abort is proved.

### Node-local branch kernel

These tables live in `local.sqlite3`, keyed by partition, and are deliberately
outside the replicated state machine:

```text
local_branch_operations(
  operation_id PK, partition_id, branch_id,
  actor_principal_id, actor_session_id, identity_revision, acl_revision,
  isolation_delegation_id, operation_kind, request_version, request_digest,
  outcome, started_at, completed_at NULL, result_payload NULL,
  UNIQUE(operation_id, request_digest)
)

local_branch_commits(
  namespace_commit_id PK, partition_id, volume_id, branch_id,
  root_object_revision_id, operation_id UNIQUE -> local_branch_operations,
  origin_node_id, origin_cell_id NULL, causal_sequence,
  created_at, canonical_payload, root_digest, commit_digest UNIQUE, state
)

local_branch_commit_parents(
  namespace_commit_id -> local_branch_commits,
  parent_commit_id, parent_order,
  PK(namespace_commit_id, parent_commit_id),
  UNIQUE(namespace_commit_id, parent_order)
)

local_branch_heads(
  volume_id, branch_id, namespace_commit_id -> local_branch_commits,
  durability_scope, head_revision, updated_at,
  PK(volume_id, branch_id)
)

local_branch_objects(
  namespace_commit_id -> local_branch_commits,
  record_kind, record_id, canonical_payload, record_digest,
  PK(namespace_commit_id, record_kind, record_id)
)

local_branch_receipts(
  receipt_id PK, operation_id -> local_branch_operations,
  namespace_commit_id -> local_branch_commits,
  durability_scope, achieved_protection_digest, pending_debt_digest,
  issued_at, receipt_digest UNIQUE
)
```

External partition, volume, principal, session, node, cell, policy and delegation
IDs in this database are signed/revision-bound references, not cross-database
foreign keys. The branch transaction validates them against a cached authority
projection and stores the evidence digest. Local foreign keys still protect all
relationships inside this file.

Reconciliation validates canonical payloads, imports the same stable commit and
operation IDs through bounded typed consensus commands, then creates one merge
commit. It never attaches the local database to the replicated database or
writes authoritative rows outside the state machine.

## 4. Mesh, hosts and nodes

```text
meshes(
  mesh_id PK, display_name, canonical_name UNIQUE, created_at,
  configuration_revision, identity_revision, namespace_revision, revision
)

hosts(
  host_id PK, display_name, canonical_name UNIQUE, state, created_at,
  retired_at NULL, revision
)

nodes(
  node_id PK, host_id -> hosts, display_name, canonical_name UNIQUE,
  state, current_incarnation, admitted_at, activated_at NULL,
  last_retired_at NULL, revision
)

node_public_keys(
  node_id -> nodes, key_generation, algorithm, public_key, fingerprint UNIQUE,
  state, valid_from, valid_until NULL, revision,
  PK(node_id, key_generation)
)

node_capabilities(
  node_id -> nodes, capability_kind, state, enabled_at, disabled_at NULL,
  revision, PK(node_id, capability_kind)
)

node_endpoints(
  endpoint_id PK, node_id -> nodes, incarnation, service_kind, transport,
  address, priority, state, observed_by_authority_at, revision
)

node_activations(
  node_id -> nodes, incarnation, operation_id -> operations,
  certificate_fingerprint, activated_at, retired_at NULL,
  PK(node_id, incarnation)
)

join_grants(
  join_grant_id PK, secret_digest UNIQUE, issued_by -> principals,
  allowed_capabilities, allowed_host_id NULL -> hosts,
  constraints_payload, uses_remaining, valid_from, valid_until, state, revision
)
```

`node_id` is a daemon identity. `host_id` is the physical machine identity.
Multiple nodes on one host do not count as independent machine failures.

## 5. Metadata partitions and routing

```text
metadata_partitions(
  partition_id PK, partition_kind, display_name, state,
  routing_epoch, current_membership_revision,
  created_at, retired_at NULL, revision
)

partition_scopes(
  scope_kind, scope_id, partition_id -> metadata_partitions,
  ownership_epoch, handoff_state, source_partition_id NULL,
  destination_partition_id NULL, fence_log_index NULL, revision,
  PK(scope_kind, scope_id)
)

partition_voters(
  partition_id -> metadata_partitions, node_id -> nodes,
  membership_revision, member_role, state, revision,
  PK(partition_id, node_id)
)

partition_routes(
  routing_epoch, scope_kind, scope_id,
  partition_id -> metadata_partitions, ownership_epoch,
  voter_endpoints_payload, route_digest,
  PK(routing_epoch, scope_kind, scope_id)
)

partition_replica_watermarks(
  partition_id -> metadata_partitions, node_id -> nodes,
  last_log_index, snapshot_id NULL, observed_at,
  PK(partition_id, node_id)
)
```

Every authoritative database is opened for one `partition_id`; that partition
identity is also stored in its applied-state/snapshot headers. Foreign references
inside a partition cannot directly mutate a record owned by another partition.
Cross-partition references carry stable IDs plus the validated source revision.

`partition_routes` is a signed/cacheable catalogue projection. Only the
catalogue partition changes scope ownership. Handoff state and fences ensure one
partition has write authority at every point.

## 6. Component instances and configuration

```text
component_instances(
  instance_id PK, component_kind, display_name, canonical_name,
  implementation_id, contract_major, contract_minor,
  scope_kind, scope_id NULL, desired_state,
  active_config_revision, created_by -> principals,
  created_at, retired_at NULL, revision,
  UNIQUE(component_kind, canonical_name, scope_kind, scope_id)
)

component_configurations(
  instance_id -> component_instances, config_revision,
  schema_version, canonical_config, config_digest,
  secret_generation_id NULL, created_by -> principals,
  created_at, state,
  PK(instance_id, config_revision)
)

component_assignments(
  instance_id -> component_instances, assignment_kind,
  assignment_id, desired_state, revision,
  PK(instance_id, assignment_kind, assignment_id)
)

node_component_support(
  node_id -> nodes, incarnation, component_kind, implementation_id,
  implementation_version, minimum_contract_minor, maximum_contract_minor,
  capabilities, limits, observed_at,
  PK(node_id, incarnation, component_kind, implementation_id)
)

component_observations(
  instance_id -> component_instances, node_id -> nodes, node_incarnation,
  desired_config_revision, observed_state, active_implementation_version NULL,
  active_config_revision NULL, error_kind NULL, observed_at,
  PK(instance_id, node_id, node_incarnation)
)
```

`canonical_config` is a bounded, deterministic, schema-versioned component
record. It is not executable code and contains no plaintext secret. Desired
configuration is authoritative; support and observations describe node reality
and never change desired state implicitly.

Node-local `local.sqlite3` also contains:

```text
local_component_bindings(
  instance_id, binding_kind, authoritative_config_revision,
  local_binding_payload, state, updated_at,
  PK(instance_id, binding_kind)
)
```

Local payload holds only irreducibly local values such as a canonical folder
path, listen socket or protected local key reference. It cannot define volumes,
exports, users, permissions or protection policy.

## 7. Storage targets and local registration

Authoritative records:

```text
storage_targets(
  target_id PK, node_id -> nodes, host_id -> hosts,
  provider_instance_id -> component_instances, display_name,
  state, current_generation, capacity_class NULL, admitted_at,
  draining_at NULL, retired_at NULL, revision
)

target_generations(
  target_id -> storage_targets, generation, marker_fingerprint,
  backing_device_fingerprint NULL, filesystem_fingerprint NULL,
  activated_at, retired_at NULL, state,
  PK(target_id, generation)
)

target_observations(
  target_id -> storage_targets, generation, reporter_node_id -> nodes,
  observed_at, total_bytes, available_bytes, reserved_bytes,
  health_state, error_kind NULL, observation_revision,
  PK(target_id, generation, reporter_node_id)
)
```

Node-local `local.sqlite3` records:

```text
local_node(singleton PK, mesh_id, node_id, incarnation, state_dir_version)

local_targets(
  target_id PK, provider_instance_id, authoritative_config_revision,
  generation, canonical_path UNIQUE, marker_fingerprint,
  filesystem_fingerprint NULL, backing_device_fingerprint NULL,
  state, registered_at, last_opened_at
)

local_reservations(
  reservation_id PK, target_id -> local_targets, operation_id,
  bytes_reserved, expires_at, state
)

local_provider_operations(
  provider_operation_id PK, operation_id, target_id -> local_targets,
  operation_kind, shard_identity, temporary_name NULL, state,
  expected_length NULL, expected_digest NULL, updated_at
)

local_tombstones(
  target_id -> local_targets, shard_id, generation, cleanup_operation_id,
  permit_digest, tombstoned_at, bytes_unlinked_at NULL,
  PK(target_id, shard_id, generation)
)

local_scrub_cursors(
  target_id PK -> local_targets, cursor_version, cursor_value,
  completed_cycle, updated_at
)
```

Only `local_targets` contains host paths. A target generation changes when path
identity or target marker continuity cannot be proved.

## 8. Fault groups, cells and placement policies

```text
fault_group_classes(
  class_id PK, display_name, canonical_name UNIQUE,
  member_kind, system_managed, revision
)

fault_groups(
  group_id PK, class_id -> fault_group_classes, display_name, canonical_name,
  state, revision, UNIQUE(class_id, canonical_name)
)

host_fault_group_memberships(
  host_id -> hosts, group_id -> fault_groups, source_kind,
  evidence_payload NULL, revision, PK(host_id, group_id)
)

target_fault_group_memberships(
  target_id -> storage_targets, group_id -> fault_groups, source_kind,
  evidence_payload NULL, revision, PK(target_id, group_id)
)

availability_cells(
  cell_id PK, display_name, canonical_name UNIQUE,
  parent_cell_id NULL -> availability_cells,
  state, created_by -> principals, revision
)

host_cell_memberships(
  host_id -> hosts, cell_id -> availability_cells,
  source_kind, revision, PK(host_id, cell_id)
)

target_cell_memberships(
  target_id -> storage_targets, cell_id -> availability_cells,
  source_kind, revision, PK(target_id, cell_id)
)

partition_cell_placements(
  partition_id -> metadata_partitions, cell_id -> availability_cells,
  placement_role, state, revision,
  PK(partition_id, cell_id, placement_role)
)

protection_policies(
  policy_id PK, display_name, canonical_name UNIQUE, state,
  created_by -> principals, revision
)

protection_scenarios(
  scenario_id PK, policy_id -> protection_policies, display_name,
  scenario_order, revision, UNIQUE(policy_id, scenario_order)
)

protection_scenario_terms(
  term_id PK, scenario_id -> protection_scenarios,
  class_id -> fault_group_classes, failure_count,
  UNIQUE(scenario_id, class_id)
)

locality_policies(
  locality_policy_id PK, display_name, canonical_name UNIQUE,
  maximum_lag_duration NULL, state, created_by -> principals, revision
)

locality_requirements(
  requirement_id PK, locality_policy_id -> locality_policies,
  cell_id -> availability_cells, requirement_kind,
  local_protection_policy_id NULL -> protection_policies,
  requirement_order,
  UNIQUE(locality_policy_id, cell_id, requirement_kind)
)

object_locality_bindings(
  binding_id PK, volume_id -> volumes,
  object_id NULL -> namespace_objects,
  locality_policy_id -> locality_policies,
  inheritance_mode, state, assigned_by -> principals, revision
)

acknowledgement_policies(
  acknowledgement_policy_id PK, display_name, canonical_name UNIQUE,
  consistency_class, minimum_durable_targets, minimum_distinct_nodes,
  strong_wait_duration NULL, fallback_mode,
  state, created_by -> principals, revision
)

acknowledgement_policy_scenarios(
  acknowledgement_policy_id -> acknowledgement_policies,
  scenario_id -> protection_scenarios,
  PK(acknowledgement_policy_id, scenario_id)
)

acknowledgement_zone_requirements(
  acknowledgement_policy_id -> acknowledgement_policies,
  cell_id -> availability_cells,
  requirement_kind,
  minimum_durable_targets NULL, minimum_distinct_nodes NULL,
  local_protection_policy_id NULL -> protection_policies,
  PK(acknowledgement_policy_id, cell_id)
)

object_acknowledgement_bindings(
  binding_id PK, volume_id -> volumes,
  object_id NULL -> namespace_objects,
  acknowledgement_policy_id -> acknowledgement_policies,
  inheritance_mode, state, assigned_by -> principals, revision
)

cell_availability_status(
  object_id -> namespace_objects, version_id -> file_versions,
  cell_id -> availability_cells, policy_revision,
  placement_revision, status, complete_bytes, required_bytes,
  latest_available_version_id NULL -> file_versions,
  observed_at, revision,
  PK(object_id, version_id, cell_id)
)
```

Terms within one scenario fail simultaneously. Separate scenarios are all
required promises. Membership may overlap; evaluation removes the union.

## 9. Principals and nested groups

```text
principals(
  principal_id PK, principal_kind, display_name, canonical_name UNIQUE,
  state, created_at, disabled_at NULL, authorisation_revision, revision
)

users(
  principal_id PK -> principals, login_name, canonical_login UNIQUE,
  profile_payload, revision
)

groups(
  principal_id PK -> principals, description, group_kind,
  activation_policy_id NULL -> access_activation_policies, revision
)

group_memberships(
  containing_group_id -> groups, member_principal_id -> principals,
  added_by -> principals, added_at, revision,
  PK(containing_group_id, member_principal_id),
  CHECK(containing_group_id != member_principal_id)
)

group_closure(
  ancestor_group_id -> groups, descendant_principal_id -> principals,
  minimum_depth, path_count, closure_revision,
  PK(ancestor_group_id, descendant_principal_id)
)
```

Membership insertion first proves that the reverse closure does not exist.
`path_count` preserves a transitive relationship until its final independent
path is removed. A user may have any bounded number of direct group memberships.

## 10. Authentication methods

Common record:

```text
authentication_methods(
  method_id PK, user_id -> users, method_kind, label,
  service_scope, state, created_at, last_used_at NULL,
  expires_at NULL, credential_generation, revision
)
```

Exactly one matching subtype exists for each method:

```text
password_credentials(
  method_id PK -> authentication_methods, algorithm, parameters,
  salt, verifier, changed_at
)

webauthn_credentials(
  method_id -> authentication_methods, credential_id,
  public_key_algorithm, public_key, signature_counter,
  authenticator_guid NULL, transports, backup_eligible, backup_state,
  PK(method_id, credential_id), UNIQUE(credential_id)
)

totp_credentials(
  method_id PK -> authentication_methods, secret_ciphertext,
  algorithm, digits, period_seconds, accepted_step_window
)

recovery_codes(
  method_id -> authentication_methods, code_id, code_digest,
  created_at, used_at NULL, PK(method_id, code_id), UNIQUE(code_digest)
)

api_tokens(
  method_id -> authentication_methods, token_id, token_digest UNIQUE,
  scopes, valid_from, valid_until, last_used_at NULL,
  PK(method_id, token_id)
)

client_certificate_credentials(
  method_id -> authentication_methods, issuer_fingerprint,
  certificate_fingerprint, subject_key_fingerprint, valid_until,
  PK(method_id, certificate_fingerprint)
)

smb_credentials(
  method_id PK -> authentication_methods, verifier_ciphertext,
  protocol_profile, generated_at
)
```

Secrets capable of direct authentication are digests or encrypted typed
material, never plaintext.

## 11. Authentication policy and sessions

```text
authentication_policies(
  policy_id PK, scope_kind, scope_id NULL, operation_class,
  allowed_factor_classes, minimum_factor_count,
  maximum_session_duration, maximum_step_up_age NULL,
  valid_from NULL, valid_until NULL, revision
)

authentication_sessions(
  session_id PK, user_id -> users, token_digest UNIQUE, service_scope,
  assurance_level, identity_revision, issued_at, expires_at,
  last_used_at NULL, revoked_at NULL, revocation_reason NULL, revision
)

session_factors(
  session_id -> authentication_sessions,
  method_id -> authentication_methods, factor_class, verified_at,
  PK(session_id, method_id, verified_at)
)

authentication_attempts(
  bucket_digest, service_scope, window_started_at, attempt_count,
  blocked_until NULL, revision, PK(bucket_digest, service_scope)
)

isolation_delegations(
  delegation_id PK, partition_id -> metadata_partitions,
  node_id NULL -> nodes, cell_id NULL -> availability_cells,
  scope_kind, scope_id, allowed_operation_classes,
  identity_revision, acl_revision, delegation_epoch,
  byte_budget, valid_from, valid_until, state,
  issued_by -> principals, revision
)

isolation_delegation_target_scopes(
  delegation_id -> isolation_delegations,
  target_id -> storage_targets,
  target_generation, allocated_byte_budget,
  PK(delegation_id, target_id)
)

local_isolation_usage(
  delegation_id, target_id, operation_id,
  reserved_bytes, committed_bytes, state, updated_at,
  PK(delegation_id, target_id, operation_id)
)
```

The bucket digest derives from conservative normalized claims and source data;
it does not preserve raw credentials. Session factor count uses distinct factor
classes where policy requires it.

## 12. Roles and permission grants

Roles grant administrative capabilities. Permission grants govern namespace
objects. Neither silently implies the other.

```text
roles(
  role_id PK, display_name, canonical_name UNIQUE,
  capabilities_bitset, system_defined, revision
)

role_grants(
  role_id -> roles, principal_id -> principals, granted_by -> principals,
  valid_from NULL, valid_until NULL, revision,
  PK(role_id, principal_id)
)

permission_grants(
  grant_id PK, subject_principal_id -> principals,
  scope_kind, mesh_id -> meshes,
  volume_id NULL -> volumes, object_id NULL -> namespace_objects,
  rights_bitset, inheritance_mode, valid_from NULL, valid_until NULL,
  activation_policy_id NULL -> access_activation_policies,
  granted_by -> principals, created_at, supersedes_grant_id NULL,
  state, revision
)

access_activation_policies(
  activation_policy_id PK, maximum_duration, reason_required,
  minimum_assurance, valid_from NULL, valid_until NULL,
  created_by -> principals, state, revision
)

access_activations(
  activation_id PK, user_id -> users, subject_kind,
  group_id NULL -> groups, grant_id NULL -> permission_grants,
  reason, activated_at, expires_at,
  session_id -> authentication_sessions,
  operation_id UNIQUE -> operations,
  revoked_at NULL, revoked_by NULL -> principals,
  revocation_reason NULL, state, revision
)

permission_sets(
  permission_set_id PK, set_digest UNIQUE, created_at
)

permission_set_members(
  permission_set_id -> permission_sets,
  grant_id -> permission_grants,
  PK(permission_set_id, grant_id)
)
```

Permissions are allow-only. The scope tuple permits exactly one mesh-wide,
volume or object scope; a mesh-wide grant inherits to current and future volumes
and objects. Ending inheritance is an object policy, not a deny grant. An
activation row targets exactly one group or grant and cannot outlive its source,
policy, session or absolute validity window.

## 13. Volumes and exports

```text
volumes(
  volume_id PK, display_name, canonical_name UNIQUE,
  root_object_id UNIQUE,
  current_namespace_commit_id UNIQUE,
  protection_policy_id -> protection_policies,
  default_locality_policy_id NULL -> locality_policies,
  default_acknowledgement_policy_id -> acknowledgement_policies,
  state, quota_bytes NULL, new_child_owner_policy,
  stop_parent_grant_inheritance, revision
)

exports(
  export_id PK, volume_id -> volumes,
  connector_instance_id -> component_instances,
  protocol_id, display_name, canonical_name,
  gateway_scope, state, revision,
  UNIQUE(protocol_id, canonical_name, gateway_scope)
)
```

`gateway_scope` supports all authorised gateways or an explicit gateway set
without giving each gateway a different namespace truth.

## 14. Namespace, ownership and tags

```text
namespace_objects(
  object_id PK, volume_id -> volumes, object_kind,
  created_by -> principals, created_at, retired_at NULL
)

namespace_commits(
  namespace_commit_id PK, partition_id -> metadata_partitions,
  volume_id -> volumes, branch_id,
  root_object_revision_id, operation_id UNIQUE -> operations,
  origin_node_id -> nodes, origin_cell_id NULL -> availability_cells,
  identity_revision, causal_sequence, committed_log_index NULL,
  created_by -> principals, created_at, root_digest, state
)

namespace_commit_parents(
  namespace_commit_id -> namespace_commits,
  parent_commit_id -> namespace_commits, parent_order,
  PK(namespace_commit_id, parent_commit_id),
  UNIQUE(namespace_commit_id, parent_order)
)

namespace_merge_inclusions(
  merge_commit_id -> namespace_commits,
  included_commit_id -> namespace_commits,
  operation_id -> operations,
  PK(merge_commit_id, included_commit_id),
  UNIQUE(merge_commit_id, operation_id)
)

namespace_conflicts(
  conflict_id PK, merge_commit_id -> namespace_commits,
  object_id -> namespace_objects,
  conflict_kind, winning_commit_id -> namespace_commits,
  alternative_commit_id -> namespace_commits,
  conflict_sibling_object_id NULL -> namespace_objects,
  resolution_state, deterministic_digest UNIQUE
)

object_revisions(
  object_revision_id PK, object_id -> namespace_objects,
  parent_object_revision_id NULL -> object_revisions,
  file_version_id NULL -> file_versions,
  directory_root_block_id NULL -> directory_blocks,
  owner_set_id -> owner_sets,
  permission_set_id -> permission_sets,
  tag_set_id -> tag_sets,
  attribute_set_id -> attribute_sets,
  display_metadata, created_by -> principals, created_at,
  revision_digest UNIQUE
)

directory_blocks(
  directory_block_id PK, format_version, tree_level,
  entry_count, entries_digest, block_digest UNIQUE
)

directory_entries(
  directory_block_id -> directory_blocks,
  canonical_name, display_name,
  child_object_id -> namespace_objects,
  child_object_revision_id -> object_revisions,
  entry_kind, entry_digest,
  PK(directory_block_id, canonical_name)
)

owner_sets(
  owner_set_id PK, set_digest UNIQUE, created_at
)

object_owners(
  owner_set_id -> owner_sets,
  owner_principal_id -> principals,
  assigned_by -> principals, assigned_at, revision,
  PK(owner_set_id, owner_principal_id)
)

tags(
  tag_id PK, display_name, canonical_name UNIQUE,
  description, colour NULL, state, revision
)

tag_sets(
  tag_set_id PK, set_digest UNIQUE, created_at
)

object_tags(
  tag_set_id -> tag_sets, tag_id -> tags,
  assigned_by -> principals, assigned_at,
  PK(tag_set_id, tag_id)
)

principal_tags(
  principal_id -> principals, tag_id -> tags,
  assigned_by -> principals, assigned_at,
  PK(principal_id, tag_id)
)

attribute_sets(
  attribute_set_id PK, set_digest UNIQUE, created_at
)

snapshots(
  snapshot_id PK, volume_id -> volumes,
  namespace_commit_id -> namespace_commits,
  originating_branch_id NULL,
  display_name, canonical_name, state,
  locality_policy_id NULL -> locality_policies,
  protected_from_expiry, created_by -> principals,
  created_at, expires_at NULL, removed_at NULL, revision,
  UNIQUE(volume_id, canonical_name)
)

snapshot_schedules(
  schedule_id PK, volume_id -> volumes,
  schedule_expression, retention_count NULL,
  retention_duration NULL, locality_policy_id NULL -> locality_policies,
  state, revision
)

version_retention_policies(
  policy_id PK, volume_id UNIQUE -> volumes,
  history_enabled, minimum_age, minimum_versions NULL,
  reclaim_mode, pressure_threshold NULL,
  conflict_minimum_age, revision
)
```

An object must have at least one active effective owner at transaction end. The
owner can be a user, a group or several of either. Tags confer no authority.
The volume head points to one immutable globally converged namespace commit.
Local branch heads live only in the local branch store and may coexist during an
outage. Validated branch commits retain their IDs when imported. Ordinary
commits have one parent; deterministic reconciliation commits have two or more.
Directory blocks and object revisions reachable from any head, snapshot or
unresolved branch remain immutable.

## 15. File versions, streams and attributes

```text
file_versions(
  version_id PK, object_id -> namespace_objects, parent_version_id NULL,
  logical_length, content_digest, manifest_root_id,
  created_by -> principals, created_at, publication_operation_id -> operations,
  retention_class, earliest_reclaim_at NULL,
  state, revision, UNIQUE(object_id, publication_operation_id)
)

named_streams(
  stream_id PK, object_revision_id -> object_revisions, canonical_name,
  display_name, file_version_id NULL -> file_versions,
  state, UNIQUE(object_revision_id, canonical_name)
)

extended_attributes(
  attribute_set_id, namespace, canonical_name,
  value, value_digest,
  PK(attribute_set_id, namespace, canonical_name)
)
```

The unnamed data stream is the file version selected by the reachable object
revision. Attribute and stream names/values are bounded. Content and object
revisions are immutable after publish.

## 16. Handles, locks and write transactions

```text
open_handles(
  handle_id PK, object_id -> namespace_objects,
  session_id -> authentication_sessions, gateway_node_id -> nodes,
  handle_fence, desired_access, share_access, create_disposition,
  opened_object_revision, delete_on_close, lease_expires_at,
  state, opened_at, closed_at NULL, revision
)

range_locks(
  lock_id PK, object_id -> namespace_objects,
  stream_id NULL -> named_streams, handle_id -> open_handles,
  byte_start, byte_length, lock_kind, lease_expires_at, revision
)

write_transactions(
  write_id PK, operation_id UNIQUE -> operations,
  object_id -> namespace_objects, stream_id NULL -> named_streams,
  handle_id -> open_handles, base_version_id NULL -> file_versions,
  expected_object_revision, acknowledgement_policy_id -> acknowledgement_policies,
  acknowledgement_policy_revision, logical_length, content_digest NULL,
  state, started_at, expires_at, committed_version_id NULL -> file_versions,
  revision
)

write_acknowledgement_predicates(
  write_id -> write_transactions, predicate_id,
  predicate_kind, subject_id NULL, required_value, achieved_value,
  evidence_digest NULL, state, updated_at,
  PK(write_id, predicate_id)
)

write_receipts(
  receipt_id PK, write_id -> write_transactions,
  namespace_commit_id -> namespace_commits,
  durability_scope, policy_committed,
  achieved_protection_digest, pending_debt_digest,
  issued_at, receipt_digest UNIQUE
)
```

Overlapping incompatible range locks are forbidden. Handles are fenced; expiry
does not itself claim a write committed.

## 17. Manifests, stripes and shards

```text
manifest_roots(
  manifest_root_id PK, file_version_id UNIQUE -> file_versions,
  format_version, stripe_count, logical_length, root_digest, state
)

stripes(
  stripe_id PK, manifest_root_id -> manifest_roots,
  stripe_index, logical_offset, logical_length,
  content_digest, current_generation,
  UNIQUE(manifest_root_id, stripe_index)
)

stripe_generations(
  stripe_id -> stripes, generation, coding_scheme,
  data_shard_count, parity_shard_count, shard_length,
  encoded_digest, state, created_at,
  PK(stripe_id, generation)
)

shard_locations(
  stripe_id, stripe_generation, shard_index,
  shard_id UNIQUE, target_id -> storage_targets, target_generation,
  shard_length, shard_digest, state, durability_receipt_digest,
  published_at, retired_at NULL, revision,
  PK(stripe_id, stripe_generation, shard_index, target_id)
)
```

One stripe generation may temporarily have extra valid locations during repair,
but a shard index and target pair is unique. Placement validation uses the full
target/host fault-group membership snapshot recorded for the operation.

## 18. Staging and capacity reservations

```text
placement_reservations(
  reservation_id PK, write_id -> write_transactions,
  target_id -> storage_targets, target_generation,
  bytes_reserved, expires_at, state, revision
)

provisional_shards(
  provisional_id PK, write_id -> write_transactions,
  reservation_id -> placement_reservations,
  stripe_index, shard_index, shard_id, target_id -> storage_targets,
  target_generation, expected_length, expected_digest,
  receipt_payload NULL, state, revision,
  UNIQUE(write_id, stripe_index, shard_index, target_id)
)
```

A provisional receipt cannot become authoritative under a different write,
target generation or content identity.

## 19. Cleanup records

```text
cleanup_intents(
  cleanup_id PK, operation_id UNIQUE -> operations,
  reason, reachability_revision, state, created_at, completed_at NULL, revision
)

cleanup_items(
  cleanup_id -> cleanup_intents, item_index,
  object_id, version_id, shard_id, stripe_generation,
  target_id -> storage_targets, target_generation,
  expected_catalogue_revision, state, revision,
  PK(cleanup_id, item_index)
)

cleanup_completions(
  cleanup_id, item_index, target_id, target_generation,
  result_kind, provider_tombstone_digest, completed_at,
  reporter_node_id -> nodes, reporter_incarnation,
  PK(cleanup_id, item_index),
  FK(cleanup_id, item_index) -> cleanup_items
)
```

The removal permit is derived from one current cleanup item and leader epoch. It
is not a generic stored bearer token.

## 20. Repair, scrub and drain

```text
repair_jobs(
  repair_id PK, deduplication_key UNIQUE, object_id, version_id,
  stripe_id, source_generation, risk_level, reason,
  priority, state, next_attempt_at, attempt_count,
  created_at, completed_at NULL, revision
)

repair_claims(
  repair_id -> repair_jobs, claim_generation,
  worker_node_id -> nodes, worker_incarnation,
  fence, claimed_at, lease_expires_at, state,
  PK(repair_id, claim_generation)
)

scrub_findings(
  finding_id PK, target_id -> storage_targets, target_generation,
  shard_id, observed_at, observation_kind, observed_length NULL,
  observed_digest NULL, expected_digest NULL,
  deduplication_key, state, linked_repair_id NULL -> repair_jobs,
  revision
)

drain_jobs(
  drain_id PK, scope_kind, scope_id, requested_by -> principals,
  catalogue_revision, state, created_at, safe_at NULL,
  cancelled_at NULL, revision
)

drain_items(
  drain_id -> drain_jobs, item_index, shard_id,
  source_target_id -> storage_targets, replacement_repair_id NULL -> repair_jobs,
  state, revision, PK(drain_id, item_index)
)
```

Claims are leases; jobs are durable truth. A late claim cannot complete against a
newer generation or catalogue revision.

## 21. Certificates and encrypted secrets

```text
acme_configurations(
  config_id PK, directory_url, account_key_secret_id,
  challenge_kind, challenge_settings_ciphertext,
  contact_payload, state, revision
)

certificate_orders(
  order_id PK, config_id -> acme_configurations,
  requested_names, worker_node_id NULL -> nodes,
  worker_fence, state, attempt_count, next_attempt_at,
  last_error_kind NULL, created_at, completed_at NULL, revision
)

certificates(
  certificate_id PK, order_id -> certificate_orders,
  generation, names, chain_der, public_key_fingerprint,
  not_before, not_after, state, revision
)

secret_generations(
  secret_id, generation, secret_kind, public_fingerprint NULL,
  state, created_at, retired_at NULL,
  PK(secret_id, generation)
)

node_secret_envelopes(
  secret_id, generation, recipient_node_id -> nodes,
  recipient_key_generation, wrapping_algorithm, ciphertext,
  ciphertext_digest, state,
  PK(secret_id, generation, recipient_node_id)
)

secret_installations(
  secret_id, generation, node_id -> nodes,
  installed_public_fingerprint, installed_at, state,
  PK(secret_id, generation, node_id)
)
```

Private keys exist in replicated metadata only inside recipient-specific
authenticated ciphertext. A node can decrypt only its own envelope.

## 22. Uploads and API work

```text
upload_sessions(
  upload_id PK, operation_id UNIQUE -> operations,
  user_id -> users, volume_id -> volumes,
  destination_parent_id -> namespace_objects,
  destination_canonical_name, destination_display_name,
  overwrite_policy, expected_length NULL, expected_digest NULL,
  received_length, write_id -> write_transactions,
  state, created_at, expires_at, committed_object_id NULL -> namespace_objects,
  revision
)

upload_ranges(
  upload_id -> upload_sessions, byte_start, byte_length,
  range_digest, local_staging_reference, received_at,
  PK(upload_id, byte_start)
)

work_operations(
  operation_id PK -> operations, work_kind, subject_kind, subject_id,
  state, progress_completed NULL, progress_total NULL, progress_unit NULL,
  cancellation_requested_at NULL, started_at NULL, completed_at NULL,
  last_error_kind NULL, revision
)
```

Ranges may not overlap inconsistently and their combined coverage never exceeds
the declared/allowed upload length. Progress is advisory; the operation outcome
is authoritative.

## 23. Events, notifications and projections

```text
domain_events(
  event_id PK, committed_log_index, event_sequence,
  event_kind, subject_kind, subject_id NULL,
  occurred_at, event_version, redacted_payload,
  UNIQUE(committed_log_index, event_sequence)
)

notification_channels(
  channel_id PK, channel_kind, display_name,
  settings_ciphertext, event_filter, state, revision
)

notification_deliveries(
  delivery_id PK, channel_id -> notification_channels,
  event_id -> domain_events, attempt, state,
  next_attempt_at NULL, delivered_at NULL, last_error_kind NULL,
  UNIQUE(channel_id, event_id, attempt)
)
```

Projection cursors and metrics may be rebuilt from committed events and current
state. Delivery retries are bounded and deduplicated; notification ciphertext is
never included in event payloads.

## 24. Capacity accounting

```text
capacity_accounts(
  account_id PK, scope_kind, scope_id, logical_limit NULL,
  logical_committed, physical_committed, physical_provisional,
  repair_reserved, accounting_revision,
  UNIQUE(scope_kind, scope_id)
)

capacity_ledger(
  ledger_id PK, operation_id -> operations,
  account_id -> capacity_accounts, entry_kind,
  logical_delta, physical_delta, reservation_delta,
  committed_log_index, UNIQUE(operation_id, account_id, entry_kind)
)
```

Admission uses the ledger/account revision and observed target capacity. Quotas
are thin limits, not preallocated bytes. Derived dashboard totals reconcile to
the ledger and shard catalogue.

## 25. Backup and recovery records

```text
metadata_backups(
  backup_id PK, snapshot_id, mesh_id -> meshes,
  last_log_index, last_log_term, schema_version,
  manifest_digest, encrypted_recovery_material,
  state, created_at, verified_at NULL, revision
)

backup_target_copies(
  backup_id -> metadata_backups, target_id -> storage_targets,
  target_generation, object_reference, copy_digest,
  state, verified_at NULL, PK(backup_id, target_id)
)

recovery_epochs(
  recovery_epoch PK, source_backup_id -> metadata_backups,
  initiated_by -> principals, started_at, committed_at NULL,
  resulting_authority_fingerprint NULL, state, revision
)
```

Protected target copies do not vote and cannot appoint authority. Recovery
material remains encrypted for the administrator-held recovery mechanism.

## 26. Cross-record invariants

The command layer and database constraints jointly enforce:

1. every user/group has exactly one matching principal;
2. the group graph is acyclic and closure matches direct edges;
3. every live namespace object has at least one active effective owner;
4. current file versions are published, immutable and belong to that file;
5. a published version references a complete, verified manifest;
6. every authoritative shard location refers to the exact target generation;
7. a protection claim is evaluated from committed fault memberships;
8. a cleanup completion has an earlier exact cleanup item and valid permit;
9. a committed operation has one immutable typed result;
10. disabled credentials/sessions cannot create new capabilities;
11. secret envelopes target authorised current node keys; and
12. no local observation directly creates authoritative membership, placement or
    deletion state;
13. every selected component implementation satisfies the instance contract and
    configuration schema version;
14. every node-local binding names an authoritative instance and configuration
    revision; and
15. component observations never overwrite desired configuration;
16. every authoritative aggregate has exactly one owning metadata partition and
    every scope handoff has at most one owner able to advance the converged head;
17. every volume head and snapshot names a complete immutable namespace commit;
18. every reachable object revision names immutable owner, permission, tag,
    attribute and content/directory roots; and
19. every `complete` cell status has a locally decodable verified placement for
    the exact file version and locality policy revision;
20. every namespace commit has a complete acyclic causal parent graph and every
    local branch/converged volume head names a verified immutable commit;
21. every merge inclusion preserves one stable operation identity exactly once;
    and
22. every policy-committed write has immutable evidence satisfying each
    required acknowledgement predicate, while eventual and excluded zones do
    not hold its barrier; and
23. every isolated remote shard receipt is covered by one valid delegation,
    exact target generation and non-overspent node-local allocation.

Implementation must provide an offline invariant checker used by tests, backup
verification and recovery tooling. It reports contradictions without attempting
an unauthorised automatic rewrite.
