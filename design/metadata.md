# Metadata and relational schema

Status: **draft for review**.

## Engine boundary

Authoritative state uses portable SQLite-compatible SQL. SQLite is the initial engine. Turso may
replace it only after passing the same state-machine, migration, crash, power-loss and round-trip
suite. Neither engine appears in the private node protocol.

The proposed local files are:

```text
<daemon-state-dir>/consensus.sqlite3  # voter-local vote, log and snapshot metadata
<daemon-state-dir>/metadata.sqlite3   # replicated authoritative state machine
<daemon-state-dir>/local.sqlite3      # node-local registration and recovery state
```

Storage-only nodes omit the first two unless promoted. Registered folders contain provider records
and immutable shards, never the authoritative metadata database.

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
raft_vote(term, voted_for)
raft_log(log_index, term, entry_kind, payload)
raft_membership(log_index, configuration)
raft_snapshots(snapshot_id, last_index, last_term, digest, local_path, state)
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
audit_events(event_id, operation_id, actor_id, kind, subject_id,
             occurred_at, redacted_payload)
```

Applying one command updates its domain records, operation result, audit events and `applied_state`
in one transaction. Replay with the same request digest returns the stored typed result; a different
digest under the same operation ID is rejected.

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
fault_group_classes
fault_groups
host_fault_group_memberships
target_fault_group_memberships
protection_policies
protection_scenarios
protection_scenario_terms
```

Join secrets are stored as digests. Target paths remain in `local.sqlite3`; authoritative target
records use stable IDs and redacted display information.

## Identity and access tables

```text
principals
users
groups
group_memberships
group_closure
authentication_methods
password_credentials
webauthn_credentials
totp_credentials
recovery_codes
api_tokens
client_certificate_credentials
smb_credentials
authentication_policies
authentication_sessions
session_factors
authentication_attempts
roles
role_grants
permission_grants
```

Subtype rows share the authentication method's primary key. Constraints ensure exactly the
permitted subtype for each method kind. Credential ciphertext carries key generation and algorithm.

## Namespace and tag tables

```text
volumes
namespace_objects
directory_entries
object_owners
file_versions
extended_attributes
named_streams
tags
object_tags
principal_tags
exports
open_handles
range_locks
write_transactions
upload_sessions
upload_ranges
```

`directory_entries(parent_id, canonical_name)` is unique. Initial mode also makes `child_id`
unique, enforcing one parent. File publication updates `namespace_objects.current_version_id` only
after its content catalogue is valid.

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
backup_target_copies
recovery_epochs
```

Events and progress are projections of committed operations, not a competing
authority. Notification settings and recovery material are encrypted. Protected
backup copies cannot vote or create a new authority by themselves.

## Critical transaction boundaries

| Transaction | Atomic result |
| --- | --- |
| Group edge change | edge, cycle validation, affected closure, identity revision and audit |
| Ownership transfer | add/remove owners, prevent ownerless object, ACL revision and audit |
| Open | target resolution/create reservation, sharing conflict check, handle/fence and receipt |
| File publish | verified manifest/catalogue, immutable version, current-version swap and receipt |
| Abort write | transaction resolution plus bounded provisional cleanup intents |
| Shard retirement | irreversible cleanup item before any removal permit can exist |
| Repair completion | generation compare-and-swap, new location publication and old cleanup item |
| Node activation | identity, keys, capabilities, endpoints and membership eligibility |

## Migration and backup

Migrations run before service admission and are transactional where the engine permits. A failed
migration leaves the previous version usable or fails closed with recovery guidance.

An authoritative backup is a logical state-machine snapshot at an exact applied Raft position plus
encrypted key material and a manifest digest. Copying a live database file is not the backup
contract. Restore verifies mesh identity, schema, snapshot digest, membership and secrets before
opening public services.

## Turso eligibility

The same schema and query corpus may run against Turso in CI. Runtime replacement requires:

1. identical semantic results and constraint failures;
2. acknowledged-commit survival under power-loss modelling;
3. clean ENOSPC, checkpoint and partial-I/O behaviour;
4. migration and backup/restore parity;
5. SQLite-to-Turso-to-SQLite round-trip evidence; and
6. no known applicable data-loss or corruption defect in the pinned release.
