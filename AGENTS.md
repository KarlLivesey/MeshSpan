# MeshSpan agent guidelines

MeshSpan is a self-healing distributed filesystem appliance written primarily
in Rust. It combines folder-backed storage across one or more nodes and exposes
one authoritative namespace through built-in HTTPS and SMB services.

## Start here

Before changing behaviour, read:

1. [`README.md`](README.md)
2. [`design/README.md`](design/README.md)
3. the design documents relevant to the change
4. [`design/decisions.md`](design/decisions.md)

The design pack is currently draft. Do not present a proposed decision as
accepted. Once locked, code and tests must preserve its invariants or update the
decision explicitly.

## Non-negotiable principles

1. **Keep it simple.** Prefer one clear state machine and one source of truth.
2. **Protect correctness.** Refuse unsafe work; never invent durability,
   authority, identity or success.
3. **Prove changes locally.** CI confirms a locally tested change; it is not the
   primary debugging loop.
4. **Test behaviour.** Every meaningful change needs a test that fails for the
   missing or incorrect behaviour and passes after the change.
5. **Assert invariants.** Reject contradictions at the boundary instead of
   papering over them with fallback state.
6. **Validate hypotheses.** Reproduce and isolate failures before changing code.
7. **Keep paths extensible.** Protocol, storage and access adapters depend on
   narrow domain interfaces, not on one another's implementation details.
8. **Preserve the appliance.** Internal roles, branches, shards and consensus
   must not become routine setup or recovery work for users.

## Safety invariants

- Only a voter majority may advance a partition's converged head or commit
  security-critical control metadata. Ordinary filesystem work may commit to a
  durable local CoW branch during isolation and must advertise that exact scope.
- Authority is per metadata partition; every mutable aggregate has exactly one
  converged owner. Outage branches never become a second control-plane authority
  and reconcile into that owner's head without discarding acknowledged content.
- Eventual convergence is the normal availability-first write policy. Strong
  publication waits only for predicates and zones explicitly marked required;
  eventual zones create debt and never hold its barrier.
- Branch exchange, conflict preservation, convergence and protection repair are
  automatic. An administrator never selects internal histories or shards.
- A response is not success unless the operation has a durable committed
  outcome and receipt scope. Connection loss means unknown, not success or
  failure.
- One-node and many-node operation use the same records and code paths.
- Storage location alone never authorises shard deletion.
- Provider folders contain private chunks, not the user-visible filesystem.
- Access services use the filesystem/domain service; they do not query database
  tables or provider folders directly.
- Published content, namespace roots and component configuration are immutable
  CoW revisions advanced by atomic head changes.
- A claimed complete local copy must be provably decodable inside the named cell;
  locality never substitutes for fault-domain protection.
- Major implementations are replaceable behind versioned contracts; metadata
  selects installed code and stores desired configuration, never executable code.
- Node, host, target, device and fault-group identities are distinct.
- Private identity keys are generated locally and never leave their node.
- Secrets and credentials never appear in logs, diagnostics or protocol errors.
- All project-authored licence references use exactly `GPL-2.0-only`.

## Repository shape

The implementation layout will be introduced by the accepted roadmap. Preserve
these boundaries when it is scaffolded:

```text
crates/
  domain/       pure identifiers, commands, state machines and invariants
  metadata/     SQLite-compatible persistence behind domain repositories
  consensus/    replicated command log and voter membership
  protocol/     versioned Protobuf messages and Quinn transport
  storage/      folder provider, shard IO and storage capability interface
  filesystem/   protocol-neutral namespace and handle semantics
  gateway-http/ HTTPS adapter
  gateway-smb/  embedded SMB adapter
  daemon/       composition, configuration and process lifecycle
web/            user and administrator interface
tests/          cross-crate, protocol, simulation and end-to-end suites
```

Do not create a crate merely to shorten a file. A boundary must own a coherent
responsibility, stable inputs and outputs, and a reason to change independently.

## Dependency direction

```text
HTTPS / SMB / future adapters
            |
       filesystem service
            |
      domain operations
       /      |      \
metadata  consensus  storage capability
                 \   /
              private protocol
```

The domain layer has no network, SQL, web or SMB dependency. Database rows and
wire messages convert at explicit boundaries. Do not expose raw SQL, generic KV
operations or storage paths through the private protocol.

## Code quality

- Use descriptive names and small modules with one clear responsibility.
- Use plain language. Prefer a longer familiar phrase to compressed project
  jargon that a new contributor cannot infer.
- Split code along domain operations and invariants, not arbitrary line counts.
- Within a module, put the public operation before the private helpers it calls
  so the main flow reads from top to bottom.
- Keep pure decisions separate from IO and make side effects explicit.
- Prefer concrete types for IDs, revisions, epochs, byte counts and timestamps.
- Use `Temporal` in web code for date/time domain values; do not add new
  arithmetic based on JavaScript `Date`.
- Bound untrusted allocations, collections, streams and recursion.
- Avoid `unwrap`, `expect`, unchecked indexing and lossy conversions on runtime
  input paths. Tests and statically proved startup constants may use them when
  the reason is evident.
- Errors must identify the failed operation and stable error kind without
  leaking secrets.
- Comments explain invariants, ordering and non-obvious trade-offs; they do not
  narrate syntax.
- No new dependency without a concrete need, maintenance/legal review and a
  reason the standard library or current workspace cannot do the job cleanly.

## Database and transaction rules

- Target SQLite-compatible SQL, not engine-specific convenience APIs.
- All schema changes use numbered, transactional migrations and compatibility
  fixtures.
- Foreign keys are enabled and checked. Integrity checks are part of backup,
  restore and fault tests.
- Authoritative state changes occur through typed domain commands with explicit
  preconditions and revisions.
- Never use wall-clock order as consensus order.
- Do not hold a database transaction across network IO.
- Queries used on request paths must have an intentional index and bounded
  result size. Inspect query plans for non-trivial queries.
- Persisted enum values and state transitions are versioned contracts; unknown
  values fail closed.

## Async and concurrency rules

- Never block an async executor thread with filesystem, database or CPU-heavy
  coding work; use the designated bounded worker mechanism.
- Every spawned task has an owner, cancellation path and observed result.
- Every remote operation has a deadline. Retries require idempotency and bounded
  backoff.
- Consensus/control work is isolated from bulk data work.
- Locks must have documented scope and ordering. Do not hold a lock across
  `.await` unless the primitive and invariant explicitly require it.
- Background queues are durable where losing work would reduce correctness, and
  bounded everywhere.

## Testing strategy

Use the smallest test that can prove the behaviour, then the narrowest necessary
integration layer.

1. Domain transition tables: deterministic inputs, outputs and rejected states.
2. Persistence contract tests: run the same repository suite against supported
   SQLite-compatible engines.
3. Protocol fixtures: canonical encoding, limits, malformed input and version
   compatibility.
4. Deterministic simulation: loss, duplication, reordering, partitions, crashes
   and stale workers under a seeded scheduler and clock.
5. Process integration: real Quinn peers and real folder IO.
6. Adapter conformance: the same filesystem vectors through HTTPS and SMB.
7. End to end: multiple real daemon processes and real protocol clients.
8. Hardware, power-loss, soak and performance gates for release milestones.

Tests must assert exact committed revisions, operation outcomes, visible bytes,
authoritative shard sets and durable recovery state where relevant. Avoid tests
that only assert that an error occurred or a process remained alive.

Keep fast suites independently runnable and parallel. A new slow test belongs in
an explicitly named suite with its expected duration and reason. Do not make all
pull requests wait for hardware or soak tests.

## Local validation

Once the workspace exists, the root task runner will provide canonical commands
for these gates:

- format check;
- Rust workspace build and unit tests;
- Rust lint with warnings denied across all targets and features;
- web format, type-check, lint and unit tests;
- schema and protocol compatibility tests;
- affected integration tests.

Until those commands exist, do not invent successful results. Record exactly
what was run and what could not yet run.

For a defect:

1. reproduce it locally with the smallest failing test;
2. record the expected and actual state;
3. validate the suspected cause;
4. fix the responsible boundary;
5. run the focused test, then the affected fast suites;
6. inspect the diff for unrelated churn.

Do not bounce speculative fixes through GitHub Actions.

If a test first fails after the current change, investigate it as a regression
from that change. Do not repeatedly stash, revert or push variants merely to ask
whether `main` also fails. Compare with `main` only after local evidence leaves a
real baseline question.

## Git and review workflow

- Start from current `main` with a clean understanding of existing user changes.
- Use one short-lived branch for one reviewable vertical change.
- Commit coherent progress frequently, but do not create placeholder commits.
- Sign every commit and tag.
- Push after local validation so progress is visible.
- Open one pull request, address it, merge it promptly, then delete the branch.
- Do not stack ordinary work on unmerged branches or leave completed branches
  floating.
- Never rewrite or discard user changes without explicit approval.

Commit subjects use a short lowercase imperative summary, optionally prefixed by
a component:

```text
protocol: reject stale removal permits

Explain why the change is needed and which invariant it protects.

Tests: cargo test -p meshspan-protocol removal_permit
```

The body explains intent and non-obvious trade-offs, not a line-by-line diff.

## Pull request evidence

Every pull request states:

- the behaviour added or changed;
- the invariant or requirement IDs involved;
- exact local validation performed and its duration;
- known gaps or deferred release gates; and
- migration, protocol or persisted-state impact.

Documentation-only planning must not be reported as implemented product
behaviour.

## Performance work

- Establish a reproducible baseline before optimising.
- Measure throughput and tail latency separately for metadata, small-file,
  large-file, repair and degraded reads.
- Track CPU, allocation, memory, file descriptors, disk IO and network bytes.
- Keep benchmarks deterministic enough to detect regressions and realistic
  enough to matter.
- Do not trade away durability or integrity for a benchmark result.

## Stop conditions

Stop and make the uncertainty visible when:

- a requested change conflicts with an accepted invariant;
- safe behaviour depends on an unresolved authority or durability rule;
- a migration could make committed state unreadable;
- a destructive target cannot be resolved exactly; or
- required validation cannot be run or its result cannot be trusted.

Do not silently choose a weaker contract.
