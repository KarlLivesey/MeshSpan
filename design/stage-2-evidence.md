# Stage 2 completion evidence

Status: complete, including the federation retrofit, on 2026-08-29.

The authoritative correction and all closure gates are recorded in
[stage-1-3-audit.md](stage-1-3-audit.md).

Stage 2 establishes the single-partition authoritative metadata kernel. It does
not claim network consensus, node enrolment, storage folders, erasure coding or
public file access; those remain later roadmap stages.

## Delivered kernel

- `meshspan-metadata` owns one WAL/FULL-sync `partition.sqlite3` per authority
  and one `local.sqlite3` per daemon. Numbered migrations are transactional,
  contiguous and protected by committed SHA-256 fingerprints.
- Strict relational schemas cover consensus persistence, topology, principals,
  nested groups and exact closure, authentication/session records, roles,
  scheduled and activation-required grants, multiple user/group owners,
  volumes and namespace objects, tags, desired component configuration,
  assignments, observations, operation receipts, audit chaining and exact
  backup/snapshot positions.
- Federation schemas and typed commands cover independently administered swarm
  relationships, rotating identities, signed governance ancestry, bilateral
  grants/restrictions, remote actor lifecycle attestations, recovery succession and
  retained quarantine outcomes. Governance and succession ancestry reject
  direct and transitive cycles.
- A permanent root directory owns immutable metadata scopes and signed route
  epochs. Root-to-child handoff uses explicit prepare, freeze, activate and
  newer-fence abort transitions; child projections cannot author or rewind root
  state, and no transition exposes two writers.
- A typed engine-neutral `AuthoritativeMetadataKernel` boundary separates
  semantic commands and results from the initial `rusqlite` implementation.
  The reusable conformance vector runs against fresh implementations and proves
  deterministic receipts, exact replay, conflicting-operation rejection and
  clean invariants. A compatible engine can implement this boundary without
  becoming a generic KV store or exposing SQL to callers.
- One `IMMEDIATE` transaction validates authority and state revision, applies
  the typed command, stores the canonical request/result digests, appends the
  audit-chain event and advances the exact committed log position. Identical
  operation replay returns the original result without rerunning the mutation;
  different input under the same operation ID fails closed.
- Bootstrap creates the first mesh, administrator, explicit infrastructure
  role, host, node, partition and voter atomically. Administrators receive no
  implicit file access: ordinary global/volume/object rights remain explicit
  allow-only grants.
- Nested group closure is rebuilt from a bounded graph, rejects direct and
  transitive cycles, preserves diamond path counts and increments the shared
  identity revision in the membership transaction. Group and individual grant
  activation records bind schedule, reason, session expiry, assurance and
  exact source/policy/identity revisions.
- Volume, folder and file commands require a non-empty deduplicated set of
  active user/group owners. Parent kind/volume, scope and inheritance are
  validated before SQL mutation. Component configuration history and
  assignments use the same authorisation, replay and audit machinery.
- Atomic owner replacement first validates a complete non-empty set of active
  user/group principals, persists a fresh immutable owner set and switches the
  logical object's pointer in one transaction. Failed input leaves both the
  object and revision unchanged; prior owner sets remain immutable history.
- Typed tag commands create bounded canonical definitions and attach/detach them
  only to active principals or logical objects. They share exact replay,
  conflict and audit machinery but never modify ownership, grants or authority.
- Public repository reads are point lookups or explicit seek pages capped at
  1,000 records. Namespace and membership plan vectors assert their intended
  indexes. Internal graph and verification scans have explicit row/finding
  bounds.
- Online backup produces a closed-file length/digest manifest bound to exact
  partition identity, schema, applied term/index and state revision. Restore
  verifies the source read-only, requires an admitted voter, copies into a new
  never-overwritten path, then rechecks identity, state and integrity before
  returning the staged database.

## Exit-gate evidence

| Gate | Executable evidence |
| --- | --- |
| First vertical proof | One-node bootstrap; two users; nested groups; multi-user/group-owned volume, folder and file; scheduled activated permission; restart; exact result resolution and replay |
| Transaction crash safety | Deterministic interruption after command rows, operation receipt, audit event and applied-position update; every boundary retains the exact old state and the same entry then commits cleanly |
| Replay and hostile state | Exact replay preserves the original revision/result; conflicting reuse, stale position/revision, transitive cycles, malformed identifiers, digest drift and changed backup bytes fail closed |
| Migration and integrity | Thirty-eight immutable authoritative migrations and one local migration; reopen, wrong identity, newer/drifted history, strict constraints, `quick_check` and foreign-key vectors |
| IAM and ownership | Shared user/group namespace, bounded exact closure, scheduled grants, grant/group self-activation and non-empty multiple user/group owner sets |
| Atomic owner replacement | Empty, duplicate, missing and inactive owners plus missing objects fail without revision movement; a valid user/group replacement survives restart, exact replay and invariant verification while preserving the old immutable set |
| Descriptive tags | Create/attach/detach covers principal and object targets, exact replay, conflicting reuse, duplicate/missing-edge rejection, name bounds, audit rows and proof that a tagged user gains no authority |
| Desired configuration | Versioned component instances, retained configuration history, assignments, node support and desired-versus-observed records |
| Backup and restore | Exact position/revision/schema/identity manifest, SHA-256 byte verification, active-voter admission and never-overwrite staged restore |
| Bounded indexed reads | Validated page limits, seek cursors, explicit `LIMIT + 1`, named namespace index and membership primary-index query-plan assertions |
| Replaceable engine seam | Reusable `AuthoritativeMetadataKernel` conformance vector passes twice against fresh SQLite implementations |
| Federation authority | Relationship, grant, principal, succession and quarantine lifecycles are typed, signed, idempotent, restart-safe and retain exact immutable history and termination evidence |
| Federation graph safety | Signed remote ancestry rejects governance and succession cycles without advancing state; reflected identities, stale epochs and substituted evidence fail closed |
| Federation crash safety | Every relationship, grant, succession and quarantine command transition, plus complete approval/replacement/projection operations, rolls back exactly at injected command/apply boundaries |
| Root delegation | Scope creation, begin, freeze, activate, newer-fence abort and child projection installation have exact rollback/restart evidence and preserve single-writer routing |
| Federation backup and restore | Complete relationship, grant, projected-principal, succession, quarantine and root-route histories survive verified backup/restore and reject changed bytes |
| Complete local gate | `npm run check` runs generation drift, strict Rust/web lint, all tests and protocol/API compatibility locally with no GitHub Actions |

## Feedback-loop observation

The complete local gate passed after the federation retrofit in 80.23 seconds.
Its lanes remain independently scheduled across four resource-approved workers.
