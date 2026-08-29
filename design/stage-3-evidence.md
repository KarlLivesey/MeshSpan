# Stage 3 completion evidence

Status: original scope complete after its 2026-08-28 audit; Stage 3 reopened for
autonomous-swarm trust and exchange.

The missing federation transport/identity evidence and new closure gates are
recorded in [`federation.md`](federation.md) and [`roadmap.md`](roadmap.md). This
document does not claim that retrofit is implemented.

The original completion claim was broader than its executable proof. The
reopened audit repaired that gap; all corrected closure gates and their exact
status are in [stage-1-3-audit.md](stage-1-3-audit.md).

Stage 3 establishes the one-to-many metadata cluster kernel. It does not claim
storage-folder providers, filesystem operations, HTTPS, SMB, erasure coding or
the final appliance daemon; those remain later roadmap stages.

## Delivered cluster kernel

- `meshspan-consensus` owns a deterministic IO-free leader-based core. Term and
  vote changes, log truncation/append and membership epochs emit explicit
  persistence barriers. Messages, role changes and commit/application work do
  not escape until the exact mutation is durable.
- Quorum plans define election, consensus-write and linearizable-read families
  independently. Flat plans work for every one-to-nine voter count; nested
  thresholds and weighted voters are compiled to canonical minimal quorum and
  cut-set proofs. Unsafe, ambiguous or non-intersecting plans fail closed.
- Active quorum meaning is immutable within a membership epoch. Learner
  promotion requires exact current-incarnation, committed-history and plan
  evidence, then uses a proved, committed old-and-new joint phase before the
  stable successor can activate.
- `meshspan-transport` provides Quinn streams with mandatory bidirectional
  rustls authentication, certificate-fingerprint-to-node/incarnation binding,
  exact protocol-version negotiation and lower-of-both-peers resource limits.
  Consensus, metadata, snapshot and bulk-data streams have independent stream
  kinds and priorities.
- One bounded outbound worker owns one reusable negotiated connection per peer.
  Unreachable peers cannot block the consensus owner or create unbounded
  handshake tasks: each peer has a bounded queue, two-second operation timeout
  and reconnect backoff. Lost traffic remains ordinary consensus message loss
  and is repaired by later elections or append heartbeats.
- Protobuf consensus messages are converted only after framing and semantic
  validation. The adapter reconstructs log-entry digests rather than trusting
  received derived values, and binds every request to mesh, partition, routing
  epoch, authenticated node and process incarnation.
- Snapshot transfer is sequential, resumable and separately verifies snapshot
  identity, offsets, per-chunk SHA-256 and complete-image SHA-256. Installation
  stages into a never-overwritten database path, verifies SQLite identity,
  schema, integrity, applied position and quorum-plan digest, and never replaces
  a newer receiver vote with an older source vote.
- Join grants are expiring, use-limited administrator-issued digest records.
  Consumption atomically creates the host/node, certificate binding and learner
  membership. Invalid secrets do not advance state; exact lost-response replay
  does not consume another use. Private identity keys remain node-local.
- The live runtime starts with only the bootstrap voter. A newly authorised
  learner receives a bounded SQLite snapshot plus the canonical quorum plan,
  independently verifies both, catches up committed history, and is promoted
  automatically through committed joint and stable phases. It receives no
  consensus authority before admission and no vote before exact catch-up.
- Signed partition routes and immutable route history support an initial
  catalogue partition, creation of another metadata partition and a fenced
  active → preparing → frozen → active scope handoff. Source is the sole writer
  while the destination catches up, neither writes while frozen, and only the
  destination writes after activation.
- Scoped proposals cross one reusable consensus boundary that checks the exact
  local committed route and presented routing epoch before touching consensus.
  Missing, corrupt, stale or foreign authority fails closed.
- The private catalogue already defines bounded branch-head comparison,
  cursor-paged immutable commit/object transfer and inclusion-result messages.
  Filesystem branch creation and deterministic merge behaviour intentionally
  remain Stage 5 work.

## Exit-gate evidence

| Gate | Executable evidence |
| --- | --- |
| Quorum correctness | Independent flat-plan truth tables for one through nine voters, weighted/hierarchical vectors, exhaustive minimal quorums/cut sets and old/new joint-transition proofs |
| Multi-way partitions | Every 1–9-voter set partition (26,442 cases) campaigns independently; at most one component obtains authority and writes commit only when its compiled write family is satisfied |
| Durability ordering | Campaign, higher-term step-down, proposal append and membership activation tests require exact SQLite persistence acknowledgement before dependent effects escape |
| One/two/three and growth | Real process cycles cover all three sizes: one voter restarts and resumes writes; two voters fence writes after one loss and resume after return; three voters lose the leader and continue through the surviving majority. The growth proof also moves one → two → three through authoritative learner admission, exact catch-up and automatic joint/stable promotion; the compiler exercises every voter count and ordinary recommendations progress 1, 2, 3, 5, 7, 9 |
| Stale/replayed traffic | Wrong incarnation, membership epoch, quorum-plan digest, persistence ID, conflicting uncommitted tail and committed-tail replacement attempts fail closed |
| Node identity | Real Quinn/rustls mTLS accepts an enrolled certificate-bound peer and rejects a TLS-valid certificate absent from committed topology |
| Negotiation and bounds | Mandatory `NodeHello`/`NodeWelcome` chooses the highest exact common version and the lower peer resource ceilings; every control frame is length-bounded before allocation/decode |
| Join admission | The authoritative join vector rejects a wrong secret, consumes one valid use, creates exactly one certificate-bound learner and returns the original receipt on replay |
| Snapshot recovery | Resumable transfer rejects corrupt, reordered and excessive chunks without advancing; installation rejects the wrong plan/image and preserves the receiver's newer durable vote |
| Promotion restart | Real processes enter exact epoch-3 joint and stable promotion phases, terminate together only after the phase is durable and propagated, reopen independent SQLite state, re-prove the stored plan, automatically finalise joint state and commit the next correctly sequenced metadata write without manual repair |
| Partition handoff | Two independent consensus cores over separately identity-bound SQLite files commit the signed active → preparing → frozen → active history in deliberately different orders. Actual scoped proposals are attempted on both after every partial update; accepted writer counts are exactly 1 → 1/0 → 1 → 1 → 0 → 0 → 1 and never two |
| Traffic isolation | A real QUIC test stalls an 8 MiB bulk-data write while a consensus ping completes on its independent high-priority stream within one second |
| Three-process cycle | Three OS processes use distinct SQLite databases, certificates and dynamic loopback ports; only node one starts authoritative; committed grants admit nodes two and three, which install verified snapshots, catch up and become voters; the cycle then commits routing proof records, redirects a follower request, resolves a deliberately lost reply by durable operation ID, kills the leader, elects and writes through another, restarts the old process and catches it up |
| Outage bounds | Per-peer reusable connection workers bound queueing, timeout and reconnect work; the process cycle commits through the surviving pair while the killed peer is unreachable |
| Adversarial closure | `npm run check:stage3-adversarial` runs the exact multi-way partition, stale-incarnation, corrupt/reordered/excessive snapshot and saturated bulk-stream tests concurrently, and fails if any filter executes zero tests |
| Complete local gate | `npm run check` runs generation drift, strict Rust/web lint, unit/conformance/simulation, real Quinn and real-process tests locally with four concurrent workers and no GitHub Actions |

## Feedback-loop observation

The final complete local gate measured 6.17 seconds with live learner admission,
the one/two/three process matrix and exact joint/stable restart proofs. All five
real-process cases complete together in approximately 4.9 seconds, dominated by
the main bootstrap, admission, promotion, handoff, failover and restart cycle.
The four-case adversarial closure completes in 4.66 seconds. Both use four
workers, and the cluster lane remains isolated so unrelated lanes continue
concurrently.

## Deliberate later-stage boundaries

- The Stage 3 headless process is an executable cluster acceptance harness, not
  the final appliance command-line surface. Repeated `--storage-path` and the
  final `--daemon-state-dir`/`--join-code` experience arrive with Stages 4 and 6.
- Pre-enrolment HTTPS transport, administrator/user panels and public API
  authentication remain Stage 6. Stage 3 proves the single authoritative join
  transaction and certificate-bound private activation beneath those adapters.
- Presence and component-support message validation exists, while final
  operator-facing reachability/protection reporting waits for storage targets
  and public status in later stages.
