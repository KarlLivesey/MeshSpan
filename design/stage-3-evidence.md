# Stage 3 completion evidence

Status: historical evidence; completion audit reopened on 2026-08-28.

The behaviours below still pass, but this document's original completion claim
was broader than its executable proof. The authoritative correction and closure
gates are in [stage-1-3-audit.md](stage-1-3-audit.md).

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
- Signed partition routes and immutable route history support an initial
  catalogue partition, creation of another metadata partition and a fenced
  active → preparing → frozen → active scope handoff. Source is the sole writer
  while the destination catches up, neither writes while frozen, and only the
  destination writes after activation.
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
| One/two/three and growth | The same core and flat-plan compiler exercise every voter count; promotion selects only an eligible fully caught-up learner and ordinary recommendations progress 1, 2, 3, 5, 7, 9 |
| Stale/replayed traffic | Wrong incarnation, membership epoch, quorum-plan digest, persistence ID, conflicting uncommitted tail and committed-tail replacement attempts fail closed |
| Node identity | Real Quinn/rustls mTLS accepts an enrolled certificate-bound peer and rejects a TLS-valid certificate absent from committed topology |
| Negotiation and bounds | Mandatory `NodeHello`/`NodeWelcome` chooses the highest exact common version and the lower peer resource ceilings; every control frame is length-bounded before allocation/decode |
| Join admission | The authoritative join vector rejects a wrong secret, consumes one valid use, creates exactly one certificate-bound learner and returns the original receipt on replay |
| Snapshot recovery | Resumable transfer rejects corrupt, reordered and excessive chunks without advancing; installation rejects the wrong plan/image and preserves the receiver's newer durable vote |
| Partition handoff | Signed route vectors reject forged activation and prove no dual-writer interval; the real-process log applies creation and the full prepare/freeze/activate handoff on every voter |
| Traffic isolation | A real QUIC test stalls an 8 MiB bulk-data write while a consensus ping completes on its independent high-priority stream within one second |
| Three-process cycle | Three OS processes use distinct SQLite databases, certificates and dynamic loopback ports; they commit bootstrap, two grants, two enrolments, a second partition and handoff; route a follower request; resolve a deliberately lost reply by durable operation ID; kill the leader; elect and write through another; restart the old process and catch it up |
| Outage bounds | Per-peer reusable connection workers bound queueing, timeout and reconnect work; the process cycle commits through the surviving pair while the killed peer is unreachable |
| Complete local gate | `npm run check` runs generation drift, strict Rust/web lint, unit/conformance/simulation, real Quinn and real-process tests locally with four concurrent workers and no GitHub Actions |

## Feedback-loop observation

The complete warm local gate measured 5.7–7.4 seconds during the final Stage 3
work. The real three-process bootstrap, handoff, failover and restart cycle
completes in approximately 3.5–5.4 seconds and remains isolated in the cluster
lane, so unrelated lanes continue concurrently.

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
