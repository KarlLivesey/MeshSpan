# Internal interface boundaries

Status: draft for review. These are semantic contracts, not final Rust traits.

## Rules shared by every boundary

- Inputs and outputs use domain IDs, revisions, capabilities and typed outcomes.
- No boundary returns a success boolean for a durable mutation.
- All collections and byte streams are bounded, cancellable and deadline-aware.
- Database rows, wire envelopes, operating-system paths and frontend models are
  converted explicitly; none is the universal internal type.
- Implementations may be replaced only if the same contract suite passes.
- A boundary is not justified merely by reducing file length.

## Domain command kernel

**Owns:** validation and deterministic transitions of authoritative records.

```text
validate(state_view, command, actor, operation_context)
  -> rejected | transition(events, typed_result)

apply(state_transaction, transition, log_position)
  -> committed_result
```

The kernel has no SQL, network, filesystem, clock, random or UI dependency.
External instants and generated IDs are validated command inputs. The same
command and prior state always produce the same transition.

## Metadata authority

**Owns:** linearizable mutation, consistent query and operation outcome.

```text
execute(command, actor, operation_id, expected_revision)
  -> committed | rejected | in_progress | unknown

query(typed_query, consistency, page)
  -> revision_bound_result

operation_status(operation_id)
  -> absent | in_progress | committed(result) | rejected(error) | aborted(error)

watch(after_revision, filters)
  -> ordered_events | snapshot_required
```

It accepts typed commands only. It does not expose SQL, a generic KV API or a
leader-specific client contract.

## Consensus engine

**Owns:** terms, log replication, membership and snapshot installation.

```text
propose(versioned_command) -> committed_log_position | not_leader | unavailable
read_barrier() -> committed_log_position
change_membership(joint_transition) -> committed_configuration
```

The engine does not interpret user permissions, namespace records or shards.
Application code does not mutate its log/storage directly.

## Metadata repository

**Owns:** transactional persistence of one deterministic state-machine command.

```text
read_view(at_revision) -> domain_state_view
apply(log_position, transition) -> committed_result
create_snapshot(log_position) -> verified_snapshot
install_snapshot(verified_snapshot) -> installed_position
check_invariants() -> exact_findings
```

SQLite and a future Turso implementation run the same repository contract. A
repository transaction never waits on network or shard IO.

## Storage provider

**Owns:** bytes and local recovery inside one registered folder.

```text
reserve(operation, bytes, expiry) -> reservation
put_exact(reservation, shard_identity, expected_length, expected_digest, bytes)
  -> durable_receipt
get_exact(read_capability, shard_identity) -> verified_byte_stream
tombstone(removal_permit, shard_identity) -> tombstone_receipt
unlink_tombstoned(tombstone_receipt) -> removal_result
inventory(cursor, limit) -> local_entries
scrub(cursor, budget) -> observations
```

The provider never sees paths, users, ACLs, volumes-as-shares or placement
policy. It cannot decide that a shard is authoritative or safe to delete.
Packfiles, one-file records or a future device backend remain private choices.

## Remote shard service

**Owns:** authentication, framing and transport of storage-provider operations.

It validates mTLS peer identity, message bounds and exact capabilities before
calling a provider. It converts provider receipts/errors to protocol records but
does not invent receipts, retry mutations under a new operation ID or interpret
namespace permissions.

## Coding scheme

**Owns:** deterministic streaming transform and reconstruction.

```text
encode(layout, logical_stream) -> indexed_shard_streams
reconstruct(layout, verified_available_shards, requested_ranges)
  -> verified_logical_stream
validate_layout(layout, bounds) -> valid | reason
```

It knows shard geometry but not targets, fault groups, users or network
locations. Implementations require cross-platform vectors and corruption tests.

## Placement planner

**Owns:** selecting a layout and eligible target set that proves a protection
policy at one committed topology/capacity revision.

```text
plan_write(policy, topology_snapshot, capacity_snapshot, object_shape)
  -> feasible_plan | explicit_infeasibility

plan_repair(manifest, failed_locations, topology_snapshot, capacity_snapshot)
  -> fenced_replacement_plan | explicit_infeasibility

evaluate(policy, layout, topology_snapshot) -> proof
```

Fault-group constraints are hard. Capacity, load and locality are weights only
after safety. The plan contains its evidence revision so later commits can
reject stale assumptions.

## Identity and access service

**Owns:** authentication ceremonies, sessions, group closure, permissions,
ownership, roles and bounded capabilities.

```text
authenticate(service, ceremony) -> pending | authenticated_session | rejected
authorise(session, object, operation, authority_revision)
  -> bounded_capability | denied
revoke(subject) -> committed_revision
```

Protocol adapters provide credentials/ceremony messages but do not calculate
effective rights. Storage nodes validate issued capabilities; they do not query
passwords or infer access from shard IDs.

## Filesystem service

**Owns:** protocol-neutral namespace and handle semantics.

Core operation families:

```text
resolve, stat, enumerate
open, read, write, flush, close
create_file, create_directory, copy
rename, move, unlink
get/set attributes, owners, grants and tags
lock/unlock byte ranges
```

Every operation takes an authenticated session/capability, volume/object or
bounded path, expected revisions where needed and an operation ID for mutations.
It returns protocol-neutral records and typed outcomes. It alone coordinates
metadata, placement, coding and remote shard work for access adapters.

## Access adapter

**Owns:** one public protocol's negotiation, authentication mapping, request
translation and response/status mapping.

```text
validate_export(versioned_config) -> validated_config | field_errors
start_export(validated_config, filesystem_service) -> running_export
drain_export(export_id, deadline) -> drained | timed_out
health(export_id) -> protocol_neutral_health
```

HTTPS and SMB are separate adapters using the same filesystem and identity
services. An adapter cannot read SQL, provider folders or raw shards. Future NFS,
WebDAV, SFTP and other adapters enter at this boundary.

## Work coordinator

**Owns:** durable scheduling of repair, scrub, drain, rebalance, recoding,
cleanup, certificate and maintenance work.

Claims are leased and fenced; the durable job remains authoritative. Workers
submit observations and receipts to normal domain commands. Queue priority and
resource budgets are policies, not a second source of truth.

## Event and observability projection

**Owns:** redacted, bounded read models for UI updates, notifications, metrics
and diagnostics.

It consumes committed events and local observations. It cannot mutate domain
state or turn an observation into a fact. Notification delivery has independent
idempotency so retries do not send an unbounded storm.

## Composition boundary

The daemon composition root selects implementations, owns task lifetimes and
injects clock, randomness, IO and resource budgets. Business modules do not use
global mutable singletons or discover dependencies at runtime.
