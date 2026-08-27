# Verification strategy

Status: draft for review. Tests prove observable contracts with exact expected
state; they do not merely exercise lines or check that a process survived.

## 1. Feedback-speed contract

Proposed budgets on a standard development runner after warm build:

| Lane | Target | Pull-request role |
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

Every local command prints duration and supports focused selection. CI cancels
superseded runs and uses path-aware jobs without making deployment/release
workflow edits across feature branches.

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

1. at most one committed history exists;
2. every acknowledged operation is present with the exact result;
3. no uncommitted version is visible;
4. each protection status matches actual valid shards/fault groups;
5. every deletion has an earlier exact cleanup decision;
6. no stale worker/process changes newer state;
7. owner/group/permission invariants hold;
8. bounded queues and reservations reconcile.

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
8. corrupt/remove/fill selected targets;
9. verify exact acknowledged files, outcomes, protection and convergence.

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

- Generated TypeScript types compile against the actual API schema.
- Browser tests cover create/join, user/admin panels, folder registration,
  protection simulation, repair/drain controls and file operations.
- Accessibility checks cover keyboard-only use, focus, labels, live status,
  contrast, colour independence, reduced motion and phone viewports.
- Upload tests cover resume, duplicate ranges, gaps, overlaps, expiry, quota,
  disconnect and commit replay.
- Download tests cover ranges, validators, cancellation, mutation races and no
  whole-file staging.
- Security tests cover CSRF, output encoding, hostile filenames/content types,
  cookies and session/step-up transitions.

## 10. Hardware and destructive fault laboratory

Release gates include:

- six physical storage machines surviving two simultaneous machine failures;
- multiple targets per host and three simultaneous backing-device failures;
- abrupt host power removal rather than process signal only;
- switch/cable partition into several components for at least one hour;
- real media corruption, out-of-space, read-only and partial-write injection;
- native Linux and macOS nodes/gateways plus mixed-host operation;
- supported container deployment;
- heterogeneous HDD/SSD/USB, sizes, CPU and network rates;
- real SMB clients and browsers;
- upgrade, rollback, backup and catastrophic-restore drills.

Expected file digests and operation receipts are stored outside the system under
test. The lab proves both survival within policy and exact, honest failure beyond
policy.

## 11. Soak and churn

Long-running tests continuously add, unplug, partition, return, drain and replace
nodes while users read/write through several gateways. They also rotate
certificates, expire sessions, scrub, repair, rebalance, compact and approach
capacity thresholds.

The gate measures data/metadata integrity, convergence time, foreground tail
latency, memory/descriptor/task growth, work amplification and notification
storms. Any unexplained committed-state divergence or acknowledged-byte mismatch
is a release blocker.

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

CI status alone is not this evidence. Failed or skipped required gates cannot be
described as passed.
