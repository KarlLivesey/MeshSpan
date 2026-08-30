# Metadata and relational schema

Status: **draft for review**.

## Engine boundary

Authoritative state uses portable SQLite-compatible SQL. SQLite is the initial engine. Turso may
replace it only after passing the same state-machine, migration, crash, power-loss and round-trip
suite. Neither engine appears in the private node protocol.

The initial adapter uses `rusqlite` with bundled SQLite so native Linux and
macOS builds do not depend on a separately administered system database. The
adapter cannot expose SQLite-only behaviour to domain or protocol interfaces.

The local database files are:

```text
<daemon-state-dir>/partitions/<partition-id>/partition.sqlite3
<daemon-state-dir>/local.sqlite3
```

A node stores a partition database only for metadata partitions it votes for or
replicates. That database contains both consensus durability records and the
authoritative applied state for that partition. `local.sqlite3` contains
node-specific bindings, observations and disconnected branch records keyed by
partition. Small meshes still use a real partition ID. Registered folders
contain provider records and immutable shards, never a metadata database.

No invariant depends on an atomic transaction across database files. Records
that require one atomic commit live in the same database. Work crossing from a
local branch or observation into authoritative state uses an operation ID,
immutable request digest and durable result receipt: the local source remains
until the authoritative outcome is known, and every step is safe to replay.
SQLite `ATTACH` and multi-file transaction behaviour are not correctness tools.

## SQL rules

- Use `STRICT` tables, foreign keys, unique constraints and explicit checks.
- Use application-generated 128-bit IDs stored as 16-byte blobs.
- Store cryptographic digests as fixed 32-byte blobs.
- Store authoritative instants as signed UTC epoch microseconds; frontend conversion uses Temporal.
- Do not use auto-increment identity, SQL clocks, random functions, locale collation or business
  logic triggers.
- Canonicalise names in Rust and store canonical and display forms separately.
- Give every mutable aggregate a revision and every query an explicit order and bound.
- Store no raw credential, private key, session token or file payload.
- Keep schema and application-state migrations explicit and monotonic.

## Consensus tables

```text
consensus_vote(term, voted_for, membership_epoch)
consensus_log(log_index, term, entry_kind, payload)
consensus_quorum_plans(log_index, membership_epoch, canonical_plan, proof_digest)
consensus_snapshots(snapshot_id, last_index, last_term, membership_epoch,
                    proof_digest, digest, local_path, state)
```

Consensus payloads are versioned semantic commands. Snapshot bytes are streamed, verified and
installed through a no-replace temporary file before activation.

## State-machine kernel

```text
schema_migrations(version, digest, applied_at)
applied_state(singleton, log_index, term, state_revision)
operations(operation_id, actor_id, kind, request_digest, outcome,
           committed_log_index, result_type, result_version, result_payload)
meshes(mesh_id, display_name, created_at, configuration_revision)
metadata_partitions(partition_id, kind, state, routing_epoch)
partition_scopes(partition_id, scope_kind, scope_id, handoff_state)
partition_voters(partition_id, node_id, membership_revision)
audit_events(event_id, operation_id, actor_id, kind, subject_id,
             occurred_at, redacted_payload)
```

Applying one command updates its domain records, operation result, audit events and `applied_state`
in one transaction. Replay with the same request digest returns the stored typed result; a different
digest under the same operation ID is rejected.

The local database has separate `local_branch_*` tables and applies the same
crash-safe transaction rule to one immutable namespace commit, its operation
outcome, local durability evidence, debt and branch-head advance. It does not
allocate a fake consensus log index or write the replicated `namespace_*` tables.
Reconciliation copies validated canonical records into the owning state machine
through bounded typed commands; it never attaches or writes a peer database
directly. Reconciliation retains the branch until the authoritative partition
returns or deduplicates its durable result, then records inclusion locally. A
lost response or crash can repeat either side without duplicating or losing the
acknowledged branch.

## Topology and fault tables

```text
hosts
nodes
node_public_keys
node_capabilities
node_endpoints
node_activations
join_grants
storage_targets
target_generations
target_observations
component_instances
component_configurations
component_assignments
node_component_support
component_observations
availability_cells
availability_cell_memberships
failure_classes
shared_failure_groups
machine_shared_failure_memberships
protection_policies
protection_scenarios
protection_scenario_terms
locality_policies
locality_requirements
object_locality_bindings
cell_availability_status
acknowledgement_policies
acknowledgement_policy_scenarios
acknowledgement_zone_requirements
object_acknowledgement_bindings
```

Join and first-boot claim secrets are stored only as verifier digests. The
node-local `local_claim_bundles` record binds one unconsumed digest to the node
public-key fingerprint and persists its created, consumed and revision state
across restart. Target paths remain in `local.sqlite3`; authoritative target
records use stable IDs and redacted display information.

Component configuration is replicated desired state. Installed implementation
support and active revisions are observations. Executable code and irreducibly
local bindings such as folder paths remain outside authoritative metadata.

## Identity and access tables

```text
principals
users
groups
group_memberships
group_closure
authentication_methods
webauthn_credentials
totp_credentials
recovery_codes
api_keys
authentication_policies
authentication_sessions
session_factors
authentication_attempts
isolation_delegations
isolation_delegation_target_scopes
roles
role_grants
permission_grants
access_activation_policies
access_activations
```

Subtype rows share the authentication method's primary key. Constraints ensure exactly the
permitted subtype for each method kind. Credential ciphertext carries key generation and algorithm.

`local_isolation_usage` lives in `local.sqlite3`. It consumes the disjoint
allocation issued by replicated `isolation_delegations`; it is not a second
mesh-wide quota authority.

## Namespace and tag tables

```text
volumes
namespace_objects
namespace_commits
namespace_commit_parents
namespace_merge_inclusions
namespace_conflicts
object_revisions
directory_blocks
directory_entries
owner_sets
object_owners
permission_sets
permission_set_members
file_versions
attribute_sets
extended_attributes
named_streams
tags
tag_sets
object_tags
principal_tags
snapshots
snapshot_schedules
exports
open_handles
range_locks
write_transactions
write_acknowledgement_predicates
write_receipts
upload_sessions
upload_ranges
```

The node-local branch database contains `local_branch_operations`,
`local_branch_commits`, `local_branch_commit_parents`, `local_branch_heads`,
`local_branch_objects` and `local_branch_receipts`. References to replicated
IDs carry signed projection evidence because SQLite cannot enforce foreign keys
across the two files.

Directory blocks and object revisions are immutable and digest-bound. The
logical directory tree rejects duplicate canonical names and multiple live
parents. File publication builds a complete new manifest/object path and
advances a local branch head only after its content catalogue is valid;
reconciliation later advances the volume's converged head through its owner.
Snapshots pin namespace commits without copying file bytes.

## Data and lifecycle tables

```text
manifest_roots
stripes
stripe_generations
shard_locations
provisional_shards
placement_reservations
cleanup_intents
cleanup_items
cleanup_completions
repair_jobs
repair_claims
scrub_findings
drain_jobs
drain_items
```

Removal permits are derived capabilities, not caller-created rows. Provider tombstones remain in
the target's local durable store; `cleanup_completions` records the authoritative acknowledgement.

## Certificate tables

```text
acme_configurations
certificate_orders
dns_challenge_tasks
external_certificate_publications
certificates
secret_generations
node_secret_envelopes
secret_installations
```

Secret tables contain encrypted material and recipient/generation metadata, never plaintext.

## Operations, capacity and recovery tables

```text
work_operations
domain_events
notification_channels
notification_deliveries
capacity_accounts
capacity_ledger
metadata_backups
backup_destinations
backup_copies
recovery_epochs
```

Events and progress are projections of committed operations, not a competing
authority. Notification settings and recovery material are encrypted. Protected
backup copies cannot vote or create a new authority by themselves.

## Critical transaction boundaries

| Transaction              | Atomic result                                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------------------------- |
| Group edge change        | edge, cycle validation, affected closure, identity revision and audit                                 |
| Ownership transfer       | new owner/policy/object revisions, prevent ownerless object, namespace head and audit                 |
| Open                     | target resolution/create reservation, sharing conflict check, handle/fence and receipt                |
| Local file publish       | verified manifest/catalogue, immutable file/object/path revisions, branch-head swap, receipt and debt |
| Converged/strong publish | validated branch inclusions, merge root, converged-head swap, predicate evidence and receipts         |
| Snapshot create          | exact namespace-commit root, retention/locality policy and audit                                      |
| Component configuration  | immutable desired revision, instance head, assignments and audit                                      |
| Scope handoff            | frozen source fence and exactly one destination ownership epoch                                       |
| Abort write              | transaction resolution plus bounded provisional cleanup intents                                       |
| Shard retirement         | irreversible cleanup item before any removal permit can exist                                         |
| Repair completion        | generation compare-and-swap, new location publication and old cleanup item                            |
| Node activation          | identity, keys, capabilities, endpoints and membership eligibility                                    |

## Migration and backup

Migrations run before service admission and are transactional where the engine permits. A failed
migration leaves the previous version usable or fails closed with recovery guidance.

An authoritative backup is a logical state-machine snapshot at an exact applied consensus position plus
encrypted key material and a manifest digest. Copying a live database file is not the backup
contract. Restore verifies mesh identity, schema, snapshot digest, membership and secrets before
opening public services. A destination may be a registered target, another
swarm or another installed backup-provider instance. Its declared failure overlap
with the protected source is retained and reported; a copy never becomes a voter.

## Turso eligibility

The same schema and query corpus may run against Turso in an optional local compatibility lane.
Runtime replacement requires:

1. identical semantic results and constraint failures;
2. acknowledged-commit survival under power-loss modelling;
3. clean ENOSPC, checkpoint and partial-I/O behaviour;
4. migration and backup/restore parity;
5. SQLite-to-Turso-to-SQLite round-trip evidence; and
6. no known applicable data-loss or corruption defect in the pinned release.
