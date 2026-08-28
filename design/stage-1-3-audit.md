# Stage 1–3 implementation audit

Status: active executable audit, started 2026-08-28.

This audit checks roadmap claims against production code and behavioural tests.
Schemas, message shapes, design prose and unused helpers are not implementation
evidence. A reopened stage returns to complete only when every closure gate below
passes locally.

## Stage 1

Stage 1 remains complete. The root local gate exercises the pinned Rust, Node and
TypeScript toolchains; strict Rust and web lint; typed domain transitions;
replaceable contract conformance; deterministic test seams; Protobuf validation;
Rust-authored OpenAPI plus generated TypeScript/Fetch/Zod parity; and the bounded
parallel scheduler. `npm run check` re-proved the complete gate in 10.00 seconds
with four workers after the first Stage 3 audit repair.

## Stage 2 findings

The existing vertical proof is real: one SQLite-backed kernel transactionally
creates users, nested groups, multi-principal-owned namespace records and an
activated time-bounded grant, then returns the exact receipt after restart.
Migration, crash, integrity, backup/restore and bounded-query tests also pass.

Two Stage 2 requirements currently stop at schema/domain representation rather
than a typed authoritative mutation:

- descriptive tags can be stored by the schema, but no command can create a tag
  or attach it to a principal or logical object;
- owner sets are created with namespace objects, but no atomic owner-transfer
  command proves that the final active owner cannot be removed.

### Stage 2 closure gates

1. Typed, audited and idempotent tag create/attach/detach commands prove tags
   never affect authority and attach only to logical objects or principals.
2. One atomic owner replacement command rejects an empty/inactive owner set and
   proves exact replay, conflicting reuse and restart recovery.
3. The complete Stage 2 vertical, crash-boundary, migration, integrity,
   backup/restore and indexed-query suites pass together.

## Stage 3 repairs already merged

PR #13 added the previously missing authoritative presence consumer and status
projection. Presence is now authenticated, bounded, monotonic within an accepted
process incarnation and fenced when that incarnation changes. Status derives
election, consensus-write, linearizable-read and bounded-stale availability
independently from the active compiled quorum plan. The complete local gate
passed in 10.00 seconds before its signed merge.

## Stage 3 findings

The quorum compiler, deterministic consensus state machine, persistence-first
driver, mTLS Quinn transport, snapshot validation, join-grant transaction,
routing-record handoff and three-process failover behaviours are substantive and
continue to pass. The active stable/joint plan is now stored, independently
decoded and re-proved on restore. The real process cycle starts with one voter;
administrator join transactions create the other identities, bounded mTLS/QUIC
snapshots establish their databases, and exact current-incarnation catch-up
evidence drives automatic committed joint then stable promotion. Every process
finishes with revision 5, three active voters and no staged learners.

The remaining composition does not yet satisfy the complete roadmap claim:

- the process proof creates a second partition record and performs a fenced route
  transition inside the original partition database. It does not start a second
  consensus/database authority and therefore cannot prove cross-partition
  handoff or the absence of two live writers.
- one-, two- and three-voter arithmetic shares one model, but real process
  execution currently covers only the fixed three-voter topology.

### Stage 3 closure gates

1. [x] Persist the canonical active stable or joint quorum plan with its proof,
   restore and independently recompile it, and fail closed on missing, stale or
   corrupt plan state. Crash every plan-transition persistence boundary.
2. [x] Start one voter, admit additional node identities through the authoritative
   join transaction, replicate them as learners, derive exact current-incarnation
   catch-up evidence and automatically commit joint then stable promotion.
3. [x] Restart during each promotion phase and continue from durable state without
   manual membership repair or a hard-coded replacement plan.
4. [x] Run the same real process cycle for one, two and three voters, including
   leader loss and return where the declared plan permits progress.
5. Run two independent partition databases and consensus authorities, transfer
   one scope through prepare/freeze/activate records, and prove every mutation is
   accepted by at most one authority throughout the handoff.
6. Re-run multi-way partition, stale-incarnation, corrupt-snapshot, saturated
   bulk-stream and complete local gates with exact expected outcomes.

Stage 4 implementation begins only after these gates pass, because its target
and shard authority must not depend on invented membership or routing safety.
