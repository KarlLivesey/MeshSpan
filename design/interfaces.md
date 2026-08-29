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

## Replaceable-component model

Major contracts are implemented through a common lifecycle without turning the
daemon into an unrestricted plugin host:

```text
describe() -> implementation ID, contract versions, capabilities and limits
validate(config version, canonical config) -> valid | bounded field errors
prepare(instance, desired revision) -> ready | incompatible | failed
activate(instance, desired revision) -> observed state
drain(instance, deadline) -> drained | timed_out | failed
retire(instance, desired revision) -> observed state
```

The implementation catalogue is compiled/installed code. Authoritative metadata
selects an implementation and stores its desired configuration; it does not
contain executable code. Nodes advertise installed support and report observed
instance state. Authority decides whether enough compatible nodes exist before
activation.

Replaceability applies to these major boundaries:

| Contract | Initial implementation | Replacement must preserve |
| --- | --- | --- |
| Storage provider | registered folder provider | exact shard identity, durable receipt, guarded removal and inventory semantics |
| Access connector | embedded HTTPS and SMB | filesystem/IAM outcomes and acknowledgement rules |
| Administration client | shipped Solid web panel | public administration API only |
| Metadata repository | SQLite | transactions, migrations, snapshots and domain invariants |
| Consensus engine | MeshSpan consensus core | one converged control/head history, quorum plans and read barriers |
| Coding scheme | selected Reed–Solomon implementation | recorded layout, deterministic vectors and verified reconstruction |
| Placement policy | fault-scenario planner | hard protection proof and revision-bound plans |
| Authentication handler | password, WebAuthn, TOTP and others | typed secret handling, assurance and revocation |
| Certificate challenge | HTTP-01 and DNS-01 handlers | fenced orders and secret isolation |
| Notification/metrics output | built-in sinks | redaction, bounded delivery and no authority |

Replacing an implementation is not permission to weaken the contract. If a
candidate cannot express an existing record or safety guarantee, validation
rejects the migration before activation.

## Configuration authority

```text
propose(instance, expected revision, schema version, canonical config)
  -> committed desired revision | rejected

reconcile(instance, desired revision, node support and local binding)
  -> pending | active | unsupported | failed

observe(instance, node, desired revision, observed state)
  -> bounded non-authoritative report
```

Configuration follows desired-versus-observed semantics. Consensus commits the
desired record atomically; nodes apply it idempotently and report the exact
revision they run. A committed desired setting is not falsely reported as active
everywhere while some nodes are pending or incompatible.

Node-local bindings contain only facts that cannot be portable, such as a folder
path, listen address, private key or decrypted secret cache. Each binding names
the authoritative component instance and desired revision. CLI flags and the
shipped admin panel both submit normal domain operations; neither is a second
configuration store.

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
  -> policy_committed | globally_converged | rejected | in_progress | unknown

query(typed_query, consistency, page)
  -> revision_bound_result

operation_status(operation_id)
  -> absent | branch_committed(receipt) | in_progress |
     globally_converged(receipt) | policy_committed(receipt) |
     rejected(error) | aborted(error)

watch(after_revision, filters)
  -> ordered_events | snapshot_required
```

It accepts typed commands only. It does not expose SQL, a generic KV API or a
leader-specific client contract.

Ordinary isolated filesystem operations use the branch repository/service, not
an invented successful consensus response. Authority validates and includes
their immutable commits later.

## Public API contract boundary

**Owns:** Rust request/response types, structural validation, OpenAPI generation
and stable HTTP outcome mapping.

```text
validate_request(raw bounded parts, access context)
  -> typed request | bounded field errors

execute(typed request, current actor, operation context)
  -> typed domain outcome

validate_response(typed outcome)
  -> contract response | internal_contract_failure

generate_openapi(api fixed point) -> canonical document + digest
```

The boundary has no direct SQL or provider-folder access. Zod and the generated
Fetch SDK are downstream artefacts, not authority. See
[`public-api.md`](public-api.md).

## Consensus engine

**Owns:** terms, log replication, flexible quorum plans, membership and snapshot
installation.

```text
propose(versioned_command) -> committed_log_position | not_leader | unavailable
read_barrier() -> committed_log_position
change_quorum_plan(proved_joint_transition) -> committed_configuration
```

The engine independently evaluates election, consensus-write and linearizable
read quorum families. The engine does not interpret user permissions, namespace
records, fault-placement policy or shards. Application code does not mutate its
log/storage directly. See [`consensus.md`](consensus.md).

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

## Branch repository and reconciler

**Owns:** durable local filesystem branch heads, causal commit graphs and
deterministic convergence proposals.

```text
commit_local(operation, authorised_revision, immutable_roots, local_receipts)
  -> branch_committed(receipt)
compare_heads(peer_frontier) -> missing_commit_ids
validate_branch(commits, objects, bounds) -> eligible | exact_rejections
merge(converged_head, eligible_heads) -> deterministic_merge_commit
record_inclusion(merge_commit, converged_position) -> convergence_receipts
```

It cannot mutate identity, permissions, voters, routing, secrets or global
configuration. It preserves every acknowledged operation and never uses wall
clock or message arrival order to choose a winner.

## Storage provider

**Owns:** bytes and local recovery inside one registered folder.

`CleanupWorkCatalogue` derives bounded independently dispatchable work only from
validated replicated inventory, permit, completion and reclamation records.
`CleanupProviderDispatch` is the replaceable local/remote tombstone and unlink
boundary. The worker executes one durable transition at a time and returns an
authoritative command; consensus submission remains a separate explicit side
effect.

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

Every request header's sender node and incarnation must equal the certificate-
authenticated peer passed by the connection owner. A payload claim cannot
substitute another enrolled node. Cleanup dispatch additionally requires that
peer to equal the sealed inventory's storage-node owner before opening a stream.
Its request deadline is the earlier of a bounded configured timeout and the
removal permit expiry. `CleanupConnectionSource` is the replaceable routing and
pool boundary: non-provider work bypasses it, while tombstone and reclamation
resolve only the inventory-bound node and independently verify the returned
certificate peer.

Put, get, tombstone and reclamation each use a distinct bounded data stream.
Tombstone accepts only a canonical current removal permit; physical reclamation
accepts only the exact earlier durable tombstone receipt. Both client and server
independently bind operation, mesh, target generation and shard identity, and
the client rejects a durable response whose canonical receipt digest does not
recompute.

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
plan_write(protection_policy, locality_policy, acknowledgement_policy, topology_snapshot,
           capacity_snapshot, object_shape)
  -> feasible_plan | explicit_infeasibility

plan_repair(manifest, protection_policy, locality_policy, failed_locations,
            topology_snapshot, capacity_snapshot)
  -> fenced_replacement_plan | explicit_infeasibility

evaluate(policy, layout, topology_snapshot) -> proof
```

Strong-barrier predicates are hard constraints for strong publication. An
eventual write may accept the best safe reachable layout and create exact debt
for missing desired protection/locality. Capacity, load and preferred locality
are weights after the applicable acknowledgement constraints. The plan contains its
topology, policy and capacity evidence revisions so later commits can reject
stale assumptions.

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
create/list/remove snapshot, restore snapshot scope
```

Every operation takes an authenticated session/capability, volume/object or
bounded path, expected revisions where needed and an operation ID for mutations.
It returns protocol-neutral records and typed outcomes including branch scope,
acknowledgement evidence and debt. It alone coordinates metadata, branches,
placement, coding and remote shard work for access adapters.

The implemented operation-time boundary is `FilesystemAccessAuthority`. An
adapter supplies only a digest of its session secret plus assurance, gateway
identity/incarnation and authoritative time. The filesystem resolves a path or
live handle to one stable logical object before asking for rights; the returned
grant must bind that exact request, current revisions, expiry and evidence
digest. Existing-file open repeats the expected-object check in its final SQLite
transaction. Provider locations and connector-specific credentials never cross
this boundary. The cluster adapter translates it to the replicated metadata
evaluator; no access adapter calculates effective rights.

`FilesystemFileAdapter` is the first semantic connector surface over that
authority boundary. An existing-file open supplies only an operation/handle
identity, logical volume/path, access/share intent, stage bound and lease times.
Read, write, flush, close, lease transfer and byte-range locking then supply
only their handle fence and semantic range, checkpoint or lifetime intent.
Immutable stat and directory paging similarly accept a logical path and bounded
cursor rather than a branch or database key. The daemon-bound
`BoundFilesystemAdapter` owns the local
branch, version-retention sequence and manifest format; it obtains the principal,
authorisation revision and gateway from committed authority/handle state and
derives the write digest itself. Those internal values therefore cannot be
forged or accidentally invented by an SMB or HTTPS translator. Empty-directory
creation and unlink already use this boundary: the daemon resolves the exact
parent or target, derives every internal identity and persists the complete
publication plan so a lost-response retry cannot silently rebase. The remaining
file-create, rename, administration and snapshot families must adopt the same
semantic boundary before the Stage 5 adapter contract is complete.

A live handle read pins its current private-stage sequence. The service reads
only the requested immutable-base range, overlays every intersecting verified
stage part in mutation order and returns a short result at logical EOF. One read
is capped at 8 MiB and never allocates in proportion to file size. Unflushed
bytes remain visible only through their owning handle.

Namespace `stat` resolves one immutable object revision and revalidates
`READ_ATTRIBUTES` before returning its verified kind, version and logical
length. Directory listing revalidates `LIST` before traversing the immutable
directory root and returns at most 1,024 minimal child records. Its continuation
binds the namespace commit, directory object/revision and last canonical name;
a changed head makes continuation explicitly stale instead of mixing views.

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

## Administration client

**Owns:** presentation and orchestration of authorised public API operations.

The shipped Solid panel, a CLI and a replacement third-party panel use the same
versioned HTTPS API, schemas, authentication, operation status and event stream.
An administration client may be omitted or replaced without changing daemon
state. It cannot load SQL, call internal Rust traits or gain rights unavailable
to its authenticated principal.

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
