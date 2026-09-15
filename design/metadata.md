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

## Non-voting metadata replicas

A storage-only node may retain an applied metadata projection without belonging
to the partition's voters or learners. `MetadataReplica` is the non-voting
application adapter; it never constructs a consensus core, votes, campaigns,
accepts client commands or acknowledges consensus replication. Its initial
database must already come from authenticated installation. This is a historical
read model, not an independent authority or a fresh permission decision.

The cursor binds partition, membership epoch, compiled plan digest, last applied
position and complete entry digest. A supplying voter can read at most 64 entries
and 16 MiB of aggregate command bytes through the existing metadata owner queue.
It returns only durably applied history and stops at each membership transition.
Historical phases end at their own applied transition, not today's unrelated
head. An empty page is not a read barrier or proof that the supplier is current.

The receiver requires an authenticated same-swarm voter in its exact phase and
incarnation. It revalidates bounds, continuity, command digests and operation IDs,
then uses the normal metadata and membership validators. Persistence precedes
application; application and its cursor advance are durable. Each command is
atomic, not an entire page. After a failed application the instance is fenced
until reopened; its unapplied tail cannot become visible merely because bytes
were persisted. Retry resumes from the durable applied cursor. Committed history
cannot be overwritten, and historical terms cannot erase a newer durable term.

If a committed transition admits the local node as a learner, passive application
stops and its durable state is available for the ordinary member runtime. Merely
being metadata-eligible does not cause this handoff. Fresh authorisation and
destructive permits still require current-authority checks, not these cursors.

The adapter, bounded authority-owner read and authenticated
[bulk transfer](protocol.md#non-voting-metadata-history-transfer) are implemented.
The daemon dispatches source requests separately from storage operations. Bulk
framing preserves the existing 64 KiB private-control limit while independently
bounding larger history bodies.

The owned passive worker opens only an existing installation, selects authenticated
voters from its installed phase, and applies successive pages automatically. Empty
pages poll at 250 ms; failures back off from 250 ms to eight seconds. Explicit
wake-ups coalesce rather than queue. Failed application drops the database
connection before reopening from its durable cursor. Missing state is retried,
never replaced with an empty database. Shutdown cancels network IO and drains
already-started parsing/application. Committed learner admission ends passive work
with a distinct handoff result. Progress remains historical, including after a
successful fetch; it must not be used as readiness or permission evidence.

Daemon startup now selects an initial non-member storage path from committed roles
and membership. That path owns private transport, the catch-up worker, local folder
providers and coarse HTTPS setup/health endpoints. Target registration forwards to
the actual authority and waits for its exact receipt to appear through replication;
there is no fabricated local consensus handle. Shard reads/writes use the existing
capability checks. Applied key/policy changes invalidate opened provider bindings.

This composition is incomplete: destructive/maintenance RPCs remain withheld until
live-authority checks are integrated. It deliberately reports degraded health and
does not instantiate file gateways, grant gateway keys or advertise cached progress
as full service readiness. Certificate maintenance, remaining role transitions and
complete recovered-file service acceptance still require integrated evidence.

## Private request admission

Forwarded commands and read-fence requests obtain fresh typed admission facts
through the existing metadata authority owner's bounded queue and retained
repository. They do not reopen the partition for each request. Store opening and
explicit integrity verification still independently check retained-log accounting;
only per-mutation accounting uses the transactional counters.

Admission reads do not append, establish a quorum fence or cache authorization.
They return only the mesh/partition identity, current node certificate and the
operation-specific voting, registration or certificate-installation facts needed
by the caller. Full ingress, stopped owners and the one-second response deadline
fail closed; cancelled queued reads are skipped. The daemon keeps canonical
decoding and installation-signature verification on owned blocking workers and
rechecks deadlines and authenticated bindings after waits. Read-fence responses
require fresh admission both before and after quorum confirmation, so a returned
fence cannot bypass a newly applied retirement or certificate replacement.

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
certificate_order_checkpoints
manual_dns_tasks
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

The automatic encrypted archive also contains fixed namespace-history and
content-layout journal members, captured and checked against that exact control
snapshot. Its outer digest covers all members; per-member authenticated evidence
preserves the distinction between control-state identity and filesystem history.
Metadata-only extraction must still authenticate every archived member. Copies
are not serving authority, and archived layouts do not prove that their physical
shards still exist. Claiming a capture atomically retains current volume heads and
user snapshots; subsequent head/snapshot changes retain revision windows until
the exact captured source revision is admitted. Admission seals only roots present
at that revision. Retirement releases that generation's pins, never another
backup's ownership. An abandoned, unrecorded capture releases its temporary pins;
an admitted but incompletely protected backup retains them until retirement.

Backup roots participate in the metadata retained-root query/digest and the
filesystem reachability proof. An archive covers its source's current heads and
user snapshots, not older archives' pins: backup generations must not recursively
inherit one another's retention. End-to-end physical reclamation and recovery
admission still need their assembled-stage proof before complete recoverability
can be claimed.

## Turso eligibility

The same schema and query corpus may run against Turso in an optional local compatibility lane.
Runtime replacement requires:

1. identical semantic results and constraint failures;
2. acknowledged-commit survival under power-loss modelling;
3. clean ENOSPC, checkpoint and partial-I/O behaviour;
4. migration and backup/restore parity;
5. SQLite-to-Turso-to-SQLite round-trip evidence; and
6. no known applicable data-loss or corruption defect in the pinned release.
