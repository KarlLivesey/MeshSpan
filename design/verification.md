# Verification strategy

Status: draft for review. Tests prove observable contracts with exact expected
state; they do not merely exercise lines or check that a process survived.

## 1. Feedback-speed contract

Proposed budgets on a standard development runner after warm build:

| Lane | Target | Local role |
| --- | ---: | --- |
| Format and generated-file check | 30 seconds | required, parallel |
| Rust lint/type/build partitions | 3 minutes each | required, parallel |
| Rust domain/unit partitions | 2 minutes each | required, parallel |
| Web format/type/lint/unit | 3 minutes | required, parallel |
| Schema/protocol compatibility | 2 minutes | required, parallel |
| Affected process integration shards | 5 minutes each | required, parallel |
| Complete virtual end-to-end matrix | 15 minutes | scheduled/release until optimised |
| Hardware, power and soak | hours/days | scheduled/release only |

Budgets are gates against accidental serialisation, not reasons to skip proof.
When a lane grows, split by independent responsibility or remove duplicated
setup/work; do not hide failures or tie every test to one `main` workflow.

Every local command prints duration and supports focused selection. The root
runner schedules independent lanes concurrently within explicit CPU, memory and
IO budgets, avoids nested worker oversubscription and reports one local summary.
GitHub Actions are absent during early implementation.

The Stage 1 runner is `npm run check`. It verifies deterministic generated-file
drift before scheduling independent Rust format, Rust lint/test, workspace
format, web lint, web typecheck and web test lanes. The initial warm local
baseline on 2026-08-28 was 6.4 seconds with four workers; the runner reports a
fresh duration for every lane instead of treating that observation as a fixed
promise. After separating Rust responsibilities and adding CPU/memory-aware
scheduling, the complete warm gate measured 3.4 seconds with four workers and
6.0 seconds through the single-worker fallback on the same workstation.

### Parallel execution contract

- Rust unit and conformance tests use the normal parallel harness or
  `cargo-nextest`; no global serial-test mechanism or routine
  `--test-threads=1` is permitted.
- Vitest and Playwright use bounded worker pools. Simulation seeds and scenario
  shards run concurrently within the same resource budget.
- Every case owns unique temporary folders, databases, mesh/node identities and
  dynamic loopback ports. Its clock, random source and seed are injected and
  reproducible.
- In-process tests do not mutate process-wide working directory, environment or
  singleton time/identity state. A test that must exercise process globals uses
  an explicitly configured child process.
- Serial execution is reserved for a named physical resource that cannot be
  virtualised or isolated. Its lock does not block unrelated lanes.
- A race exposed by parallel execution is fixed at the shared-state boundary;
  the suite is not serialised to hide it.
- Test partitions follow coherent responsibilities and measured cost. A shard is
  not a grab bag created merely to make reported duration look smaller.

### Web lint and responsibility limits

The web workspace uses ESLint flat configuration with typed strict and
stylistic rules, Solid correctness, strict JSX accessibility, promise safety,
exhaustive unions, import boundaries, regular-expression safety, test
correctness and described/used suppression rules. All warnings and unused
disable directives fail the local gate. Formatting remains Prettier's job.

Handwritten TypeScript permits no `any`: explicit `any` and unsafe `any` flows
through assignments, arguments, calls, member access, returns, assertions and
operations are errors. Boundary values start as `unknown` and are validated or
narrowed. `@ts-ignore`, `@ts-nocheck`, floating promises, non-null assertions,
import cycles and unhandled closed-union cases are errors.

Initial ceilings, excluding blank and comment-only lines, are cyclomatic
complexity 12, cognitive complexity 15, nesting depth 4, nested callbacks 3,
five parameters, 40 statements, 80 lines per function, 500 lines per source
module and one class per module. Tests and generated fixtures may have a
separately justified module-size ceiling but retain the same control-flow
limits.

These ceilings trigger design review: identify the operation's responsibility,
reason to change, inputs, outputs, invariants and side effects; then split,
recombine or reshape the interface accordingly. Extracting the final lines,
passing one context bag or creating a generic helper module solely to clear a
number does not pass review. Exceptions are narrow, described and justified by
a domain or platform constraint.

## 2. Behaviour vector format

Domain, API and protocol contract cases use reviewable fixtures containing:

```text
name
given committed records and revision
actor/session/node identity
input command or message
injected clock/random/fault events
expected typed outcome
expected committed revision and record changes
expected audit/events/work
expected provider bytes and tombstones
expected unchanged records
```

Fixtures include canonical serialization bytes where compatibility matters. A
case must fail if the behaviour is absent or wrong.

## 3. Domain and property tests

Deterministic tests cover:

- every allowed and forbidden state transition;
- operation replay with same/different request digests;
- nested group diamonds, removal paths, cycles and disabled principals;
- multiple user/group owners and last-owner transfer;
- time-window boundaries and capability invalidation;
- path/name canonicalisation and rename cycles;
- placement against overlapping fault-group unions;
- erasure recovery for every loss subset at and beyond the promised bound;
- locality inheritance plus per-cell complete/lagging/at-risk status;
- immutable namespace path-copying, snapshot roots, retention and restore;
- range/offset/length arithmetic at zero and integer boundaries;
- repair/delete compare-and-swap and stale worker fencing.

Property tests compare complex implementations with deliberately simple oracles
for small bounded topologies and namespaces.

## 4. Persistence conformance

The same repository suite runs against every candidate SQLite-compatible engine.
It asserts rows and domain projections, exact constraint failures, query paging
and plans for request-path queries.

Fault cases cut execution before/after each transaction, journal sync, snapshot
write and activation point. Reopen must produce one expected old/new state, pass
integrity and domain-invariant checks, and resolve every acknowledged operation.

Power-loss modelling covers torn/short writes, lost flushes, corrupt journals,
full filesystem, read-only transition, checkpoint interruption and restored old
database files. Real abrupt-power tests validate the model before release.

## 5. Protocol compatibility and hostile input

For every message:

- canonical encode/decode fixtures;
- previous-minor compatibility fixtures;
- required/unknown field behaviour;
- zero, maximum and over-limit lengths/counts/depths;
- truncation and malformed framing;
- wrong mesh/node/certificate identity;
- replayed operation/request IDs;
- stale term, incarnation, revision, capability and permit;
- cancellation, deadline and lost-response handling;
- fuzz targets for decoders and stateful stream sequences.

Bulk transfer tests assert bytes, digests, backpressure and memory bounds, not
only message completion.

## 6. Deterministic cluster simulation

A seeded simulator controls time, scheduling, storage completion and network
delivery. It can:

- start, stop and restart arbitrary node incarnations;
- partition into any number of components and heal selected links;
- delay, duplicate, reorder, drop and corrupt messages;
- pause or kill leaders/workers at every durable transition;
- fill, detach, replace, corrupt or slow targets;
- change memberships, permissions, policies and topology concurrently;
- advance time through lease, session, grant and certificate boundaries.

After every generated step it checks:

1. at most one globally converged head exists while every durable local branch
   has a valid causal history;
2. every acknowledged operation and alternative version remains present with
   the exact receipt scope;
3. no staged version is visible and no local branch is mislabelled converged;
4. each protection status matches actual valid shards/fault groups;
5. every deletion has an earlier exact cleanup decision;
6. no stale worker/process changes newer state;
7. owner/group/permission invariants hold;
8. bounded queues and reservations reconcile;
9. every delivery order produces the same merge root and conflict names; and
10. strong acknowledgement occurs only after every required-zone/protection
    predicate and the ACID converged-head commit, never after eventual zones.
11. every message and stored-data claim is revalidated for its operation; a
    corrupt, stale, misbound, oversized, replayed or unauthorised value can
    neither mutate state nor be returned as valid content.

Multi-partition invariants additionally assert one owner per scope, no
dual-owner converged-head handoff interval, explicit local branches, direct
routing without broadcast and continued progress for every component with
physically writable authorised storage.

Failing seeds are stable regression cases.

## 7. Real process integration

Local tests launch real daemon processes with real Quinn/mTLS sockets, SQLite
files and temporary provider folders. They do not replace consensus or storage
with mocks. Focused scenarios use one, two, three and six nodes as needed.

The core three-node cycle:

1. bootstrap and create an administrator;
2. issue a join grant and enrol two nodes headlessly;
3. register multiple differently sized folders per node;
4. create users, nested groups, owners, time grants, volume and exports;
5. perform file cycles through real HTTPS and SMB clients;
6. kill processes during writes, flush, repair and deletion;
7. partition leader/minority and then heal;
8. write different and same-name/file content through every isolated component;
9. corrupt/remove/fill selected targets;
10. verify exact acknowledged files, deterministic conflict siblings, eventual
    and strong outcomes, protection and convergence.

Tests allocate dynamic ports and isolated state folders and emit a reproducible
diagnostic bundle on failure.

## 8. Access-adapter conformance

One protocol-neutral filesystem vector suite defines expected operations and
states. HTTPS and SMB adapter tests drive their real public protocols and compare
the result with those vectors.

Required cross-adapter cycle:

- create via HTTPS, read/rename via SMB, range-read via HTTPS;
- random-write/flush via SMB, verify exact ETag/content via HTTPS;
- enforce the same user/group/owner/time permission through every gateway;
- hold conflicting handles/locks on separate gateways;
- revoke credentials and permissions mid-session;
- lose a gateway, voter and allowed storage failures;
- delete through one adapter and prove guarded asynchronous byte reclamation.

SMB interoperability uses multiple standards-compliant real clients. Client
names appear in the test matrix, not the product contract.

## 9. Web and API verification

- One fixture corpus proves Rust structural validation, generated OpenAPI and
  generated Zod 4 accept/reject the same request and response cases.
- Generated OpenAPI, strict TypeScript, native-Fetch SDK and Zod files are
  committed, regenerate deterministically, contain no `any` and fail on drift or
  manual modification.
- Fixtures cover unknown fields/variants, missing versus nullable, no implicit
  coercion, bounds, formats, discriminators, outgoing-response suppression and
  stable field-error envelopes.
- Version fixtures prove `latest`, compatible-major pins and every published
  exact fixed point; a candidate is not locked until its signed release manifest
  records exact schema and generated-client digests.
- Default-deny route tests prove missing access metadata prevents generation and
  unauthenticated traffic cannot reach expensive parsing/work.
- Pagination tests jump directly to indexed event time/filter ranges, follow
  returned next-page URLs and revoke/grant permissions between pages without
  leaks, skipped authorised results or client request storms.
- Conditional-request tests change resources and permissions independently and
  prove stale authorisation never receives `304`.
- SSE disconnect/replay tests prove events are optional and polling alone reaches
  the same current state.
- Browser tests cover create/join, user/admin panels, folder registration,
  protection simulation, repair/drain controls and file operations.
- Accessibility checks cover keyboard-only use, focus, labels, live status,
  contrast, colour independence, reduced motion and phone viewports.
- Upload tests cover resume, duplicate ranges, gaps, overlaps, expiry, quota,
  disconnect, bounded framing, forged offsets, final digest and commit replay.
- Download tests cover ranges, validators, cancellation, mutation races and no
  whole-file staging.
- Security tests cover CSRF, output encoding, hostile filenames/content types,
  cookies and session/step-up transitions.
- Cross-partition bulk tests stage bounded manifest blocks, fail every prepare and
  decision boundary, lose the coordinator/participants, and prove one global
  all-or-nothing result plus eventual guarded physical cleanup.

## 10. Hardware and destructive fault laboratory

Release gates include:

- six physical storage machines surviving two simultaneous machine failures;
- multiple targets per host and three simultaneous backing-device failures;
- abrupt host power removal rather than process signal only;
- switch/cable partition into several components for at least one hour;
- at least two availability cells with independent metadata collectives,
  gateways and locally complete data, proving every isolated building continues
  eventual local work and reconciles automatically;
- strong-policy tests requiring selected zones while other zones remain
  eventual, proving only required zones hold acknowledgement;
- real media corruption, out-of-space, read-only and partial-write injection;
- native Linux and macOS nodes/gateways plus mixed-host operation;
- supported container deployment;
- heterogeneous HDD/SSD/USB, sizes, CPU and network rates;
- real SMB clients and browsers;
- upgrade, rollback, backup and catastrophic-restore drills.

Expected file digests and operation receipts are stored outside the system under
test. The lab proves both survival within policy and exact, honest failure beyond
policy.

For each supported `k+m` geometry, an exhaustive bounded test removes every
slice subset through `m`, checks exact reconstruction from any `k`, then proves
the defined failure when fewer than `k` valid slices remain. Separate placement
oracles remove machine/device/custom-group unions rather than equating parity
count with fault-domain survival.

## 11. Soak and churn

Long-running tests continuously add, unplug, partition, return, drain and replace
nodes while users read/write through several gateways. They also rotate
certificates, expire sessions, scrub, repair, rebalance, compact and approach
capacity thresholds.

The gate measures data/metadata integrity, convergence time, foreground tail
latency, memory/descriptor/task growth, work amplification and notification
storms. Any unexplained committed-state divergence or acknowledged-byte mismatch
is a release blocker.

The physical churn rig must use real controllable power, USB/storage and network
switching rather than modelling every event as process `SIGKILL`. A randomized
schedule removes and returns several independent resources during each durable
transition. It asserts that unaffected services stay live, affected operations
have exact outcomes, replacement devices at reused paths are rejected, and the
mesh converges without an administrative repair step.

## 12. Performance proof

Benchmarks cover metadata operations, small files, sequential and random IO,
healthy/degraded reads, encoding, repair and scrub. Report throughput and p50/p95/
p99 latency with CPU, memory, allocations, disk/network IO and active resource
budgets.

Baselines include one small ARM node, three mixed nodes and a rack-scale synthetic
topology. A performance change states the workload it improves and the resource
or latency cost elsewhere. Correctness gates run before benchmark comparisons.

## 13. Release evidence

A release candidate records:

- source commit and signed tag;
- toolchain/dependency lock state;
- exact artefact checksums and provenance;
- every required suite, environment, duration and result;
- unresolved defects and explicitly deferred features;
- upgrade/rollback and recovery paths tested;
- measured MUP targets and soak duration.

One aggregate pass/fail indicator alone is not this evidence. Failed or skipped
required gates cannot be described as passed.
