# Stage 1–3 implementation audit

Status: complete, 2026-08-28.

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

The two behaviours reopened by this audit now have typed authoritative commands
and exact executable evidence. The complete combined Stage 2 gate passed in
11.48 seconds with four workers.

### Stage 2 closure gates

1. [x] Typed, audited and idempotent tag create/attach/detach commands prove tags
   never affect authority and attach only to logical objects or principals.
2. [x] One atomic owner replacement command rejects an empty/inactive owner set and
   proves exact replay, conflicting reuse and restart recovery.
3. [x] The complete Stage 2 vertical, crash-boundary, migration, integrity,
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

Real process execution now covers one, two and three voters plus exact restart
from durable joint and stable promotion phases. Two separately identity-bound
SQLite databases and consensus cores also commit signed route transitions in
different orders; every real scoped proposal is admitted by at most one
authority. The consolidated adversarial gate also passes with exact non-empty
test selection.

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
5. [x] Run two independent partition databases and consensus authorities, transfer
   one scope through prepare/freeze/activate records, and prove every mutation is
   accepted by at most one authority throughout the handoff.
6. [x] Re-run multi-way partition, stale-incarnation, corrupt-snapshot, saturated
   bulk-stream and complete local gates with exact expected outcomes.

Stages 1–3 are complete. Every reopened closure gate has executable local
evidence; `npm run check:stage3-adversarial` also prevents an exact test filter
from silently succeeding with zero tests. Stage 4 can now build on the proven
metadata contract rather than bypass it.
