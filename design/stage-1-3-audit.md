# Stage 1–3 implementation audit

Status: Stages 1–3 executable evidence and the D-074–D-077 accepted-decision
retrofit are complete on 2026-08-30. See
[`pre-stage-6-retrofit-evidence.md`](pre-stage-6-retrofit-evidence.md).

This audit checks roadmap claims against production code and behavioural tests.
Schemas, message shapes, design prose and unused helpers are not implementation
evidence. A reopened stage returns to complete only when every closure gate below
passes locally.

The accepted autonomous-swarm federation contract adds work which this evidence
never claimed to prove. Stage 1's previously missing federation-qualified
identities, rights, restriction/delegation transitions and contract fixtures now
pass. Stage 2's authoritative federation records, transitions and evidence pass. Stage 3 now
mutually authenticates autonomous swarms and transfers bounded signed history over Quinn into one
durable, atomic receiver. See [`federation.md`](federation.md) and
[`roadmap.md`](roadmap.md).

## Stage 1

Stage 1's original scope remains complete. The root local gate exercises the pinned Rust, Node and
TypeScript toolchains; strict Rust and web lint; typed domain transitions;
replaceable contract conformance; deterministic test seams; Protobuf validation;
Rust-authored OpenAPI plus generated TypeScript/Fetch/Zod parity; and the bounded
parallel scheduler. `npm run check` re-proved the complete gate in 10.00 seconds
with four workers after the first Stage 3 audit repair.

The federation retrofit adds typed relationship/governance policy, offline
grant/quarantine and permanent-root delegation state machines plus a distinct
bounded cross-swarm Protobuf envelope. Canonical bytes and hostile vectors cover
swarm identity/replay binding, branch paging, exact durability states, remote
storage capabilities and capacity-relative handoff evidence. `npm run check`
passed the combined current repository in 91.56 seconds with four workers.

## Stage 2 findings

The existing vertical proof is real: one SQLite-backed kernel transactionally
creates users, nested groups, multi-principal-owned namespace records and an
activated time-bounded grant, then returns the exact receipt after restart.
Migration, crash, integrity, backup/restore and bounded-query tests also pass.

The original audit repairs and federation retrofit have typed authoritative
commands and executable evidence. Relationships, identities, signed governance
ancestry, bilateral swarm grants, recipient-local assignments, actor lifecycle attestations,
succession, quarantine and
permanent-root scope routing retain exact history and survive restart and
verified backup/restore. Every federation lifecycle command and compound apply
boundary has deterministic old-or-new crash evidence. The complete local gate
passed in 80.23 seconds with four workers.

### Stage 2 closure gates

1. [x] Typed, audited and idempotent tag create/attach/detach commands prove tags
       never affect authority and attach only to logical objects or principals.
2. [x] One atomic owner replacement command rejects an empty/inactive owner set and
       proves exact replay, conflicting reuse and restart recovery.
3. [x] The complete Stage 2 vertical, crash-boundary, migration, integrity,
       backup/restore and indexed-query suites pass together.
4. [x] Authoritative relationship, identity, governance, bilateral-grant,
       recipient-assignment, actor-attestation, succession and quarantine transitions are signed,
       idempotent, indexed and fail closed on stale or substituted evidence.
5. [x] Direct and transitive governance and succession cycles are rejected
       atomically, including signed three-swarm ancestry.
6. [x] Every federation command transition and compound apply boundary retains
       the exact old state after injected failure and then commits cleanly.
7. [x] Verified backup/restore retains complete federation histories and the
       permanent root delegation directory; create, handoff, abort and child-route
       projection transitions preserve a single writer.

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

Autonomous swarms now connect through relationship-bound mTLS identities without becoming local
nodes, voters or principals. Signed authority pages survive identity rotation and reject
revocation, stale epochs and replay. Namespace history is materialised incrementally into durable
cursor pages; independently framed immutable objects remain bound to the exact export and current
bilateral grant. The receiver persists every accepted page and object without a network-spanning
transaction, resumes the oldest missing object after restart, validates the complete cross-record
graph and publishes it in one SQLite transaction. A real Quinn proof deliberately stops after its
first non-empty page, resumes from disk, transfers the remaining objects and proves the receiving
store can export the imported commit.

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
7. [x] Mutually authenticate autonomous swarms from current relationship metadata, rotate both
       identities and fail closed after committed relationship revocation without admitting either
       swarm to local membership or consensus authority.
8. [x] Synchronise bounded signed remote-authority pages and reject stale cursors, changed
       authority, replay, excessive pages and incomplete snapshots without exposing partial state.
9. [x] Transfer canonical namespace commits and separately framed immutable bodies over mTLS
       Quinn, with exact grant/resource/export/digest binding and fresh replay-protected contexts.
10. [x] Stop a non-empty history transfer after page one, reopen durable receiver state, resume its
        exact cursor and missing-object sequence, atomically import the complete graph and retain the
        exact completion receipt across restart.

All original and federation closure gates now pass. On 2026-08-30,
`npm run check:stage3-adversarial` passed all four non-empty lanes in 9.00 seconds and the complete
four-worker `npm run check` gate passed in 109.90 seconds. Stage 3 is complete; remote shard
placement remains Stage 4, while swarm-targeted multi-writer reconciliation and quarantine
remain Stage 5.
