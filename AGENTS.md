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

Public HTTPS or web-client work must also read
[`design/public-api.md`](design/public-api.md).

The design pack is currently draft. Do not present a proposed decision as
accepted. Once locked, code and tests must preserve its invariants or update the
decision explicitly.

## Non-negotiable principles

1. **Keep it simple.** Prefer one clear state machine and one source of truth.
2. **Protect correctness.** Refuse unsafe work; never invent durability,
   authority, identity or success.
3. **Prove changes locally.** Local verification is the sole early-development
   gate. Do not add or depend on GitHub Actions until an explicit later decision.
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

- Only a valid leader with an active-plan consensus-write quorum may advance a
  partition's converged head or commit security-critical control metadata. A
  leader is valid only after satisfying the active election predicate. Ordinary
  filesystem work may commit to a durable local CoW branch during isolation and
  must advertise that exact scope.
- Authority is per metadata partition; every mutable aggregate has exactly one
  converged owner. Outage branches never become a second control-plane authority
  and reconcile into that owner's head without discarding acknowledged content.
- Every swarm begins with one permanent root control Raft owning all scopes. It
  may epoch-fence and delegate exact operation families/key ranges to directly
  routed Raft groups, but remains authority for swarm identity, node enrolment,
  federation trust and the delegation directory. Delegated mutations do not
  append through the root log.
- Federation never creates consensus across swarms. Every shared scope retains
  one owning swarm; peers may commit only inside signed delegations and exchange
  bounded immutable history asynchronously. Governance is acyclic, horizontal
  sharing may form a graph, and effective authority is every applicable side's
  intersection.
- Each swarm is the intrinsic root principal for every volume, folder, file and
  version it owns. Local user/group grants and outbound swarm grants are sibling
  delegations from that root; no synthetic self-federation grant represents
  ownership, and every external re-delegation is explicit and narrowing.
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
- Treat every byte and every claim about it as suspect. Presence, a successful
  system call, an authenticated peer, a database row, a receipt, a checksum or a
  prior verification result is evidence only within its bound identity,
  authority, revision and lifetime; revalidate at every trust-boundary crossing.
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
- Every authored source file uses the language-appropriate
  `SPDX-License-Identifier: GPL-2.0-only` comment. Cargo, npm, OpenAPI, OCI,
  release and SBOM metadata use exactly `GPL-2.0-only`; no later-version grant
  is permitted.

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
  api-contract/ public Rust boundary types, validation and OpenAPI generation
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

Compose the consensus crate from deterministic core, quorum proof and membership
pieces with explicit inputs and effects. SQL persistence, Quinn/Protobuf,
MeshSpan commands, timers and daemon lifecycle are outer adapters. Do not add
application callbacks or concrete infrastructure dependencies to the core merely
for convenience; do not replace clear composition with premature generic
abstractions solely to make the crate independently publishable.

## Code quality

- Use descriptive names and small modules with one clear responsibility.
- Use plain language. Prefer a longer familiar phrase to compressed project
  jargon that a new contributor cannot infer.
- Complexity and size ceilings are responsibility alarms. Fix a violation by
  reconsidering ownership, control flow, inputs, outputs and side effects. Split
  or recombine domain operations where that clarifies the model; never extract an
  arbitrary suffix into a helper, context bag or generic `utils` module merely to
  satisfy a number.
- Within a module, put the public operation before the private helpers it calls
  so the main flow reads from top to bottom.
- Keep pure decisions separate from IO and make side effects explicit.
- Prefer concrete types for IDs, revisions, epochs, byte counts and timestamps.
- Use TypeScript 6.0.3 until the selected generator and typed ESLint stack
  officially support TypeScript 7; keep 7 as the next toolchain upgrade target.
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
- Dependency and generated-code licences must be recorded and compatible with
  distributing the complete MeshSpan artefacts as `GPL-2.0-only`.

## TypeScript and ESLint contract

Use ESLint flat configuration with type information. Start from
`@eslint/js` recommended plus `typescript-eslint` `strictTypeChecked` and
`stylisticTypeChecked`, then apply Solid, JSX accessibility, regular-expression,
import, test and ESLint-directive rules. Do not enable an `all` preset blindly;
every additional rule must have a known purpose and no conflict with the typed
configuration. Prettier owns formatting; deprecated ESLint formatting rules do
not.

All warnings fail the local gate. Unused disable directives fail it too.
Handwritten source and tests follow these rules. Generated API code is exempt
only from human responsibility/size ceilings: it still compiles strictly,
contains no `any` and passes generated-schema behaviour tests. Vendored files are
excluded at their directory boundary rather than weakened with inline comments.

Type safety is non-negotiable:

- `any` is forbidden, including explicit `any` and inferred `any` flowing
  through assignment, arguments, calls, member access, returns, assertions or
  operations. Untrusted data enters as `unknown` and is narrowed or validated.
- `@ts-ignore` and `@ts-nocheck` are forbidden. A narrowly scoped
  `@ts-expect-error` is allowed only in a type-test fixture with a description of
  the exact error being proved.
- Floating, misused and unhandled promises, awaiting non-promises, throwing
  non-errors and unsafe async callbacks are errors.
- Switches over closed unions are exhaustive. Unnecessary assertions,
  conditions, type arguments, conversions and non-null assertions are errors.
- Public module boundaries have explicit return types. Type-only imports and
  exports are consistent; import cycles, self-imports, duplicate imports and
  undeclared dependencies are errors.
- Equality is strict; fallthrough, unreachable loops, accidental constructor
  returns, prototype-built-in calls, dynamic evaluation and production
  `console`, `debugger` or `alert` calls are errors.
- Solid reactivity rules and strict JSX accessibility rules apply to every
  component. Security-sensitive regular expressions use the recommended regexp
  rules.
- Domain date/time arithmetic uses `Temporal`; direct use of JavaScript `Date`
  for domain logic is a restricted global.
- Layer boundaries use restricted imports. A gateway, view or persistence
  module may not bypass its declared domain interface.

Initial maintainability ceilings are:

| Measure | Maximum |
| --- | ---: |
| Cyclomatic complexity | 12 |
| Cognitive complexity | 15 |
| Nested blocks | 4 |
| Nested callbacks | 3 |
| Parameters | 5 |
| Statements per function | 40 |
| Non-blank, non-comment lines per function | 80 |
| Non-blank, non-comment lines per source module | 500 |
| Classes per module | 1 |

Test vectors and generated fixtures may use a separately justified module-size
ceiling, but their functions keep the same control-flow limits. A rule exception
must be the narrowest possible suppression, have a description, and explain the
domain reason. Raising a ceiling requires a reviewed configuration change; it is
not an inline escape hatch.

TypeScript compiler projects enable `strict`, `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`, `noImplicitOverride`,
`noFallthroughCasesInSwitch`, `noPropertyAccessFromIndexSignature`,
`useUnknownInCatchVariables`, `verbatimModuleSyntax` and `isolatedModules`.

## Public API contract

- Rust boundary types and structural constraints generate OpenAPI; never
  hand-maintain the same API model in Rust and TypeScript.
- Commit generated OpenAPI, TypeScript, native-Fetch SDK and Zod 4 schemas. Do
  not edit generated files. Regeneration must be deterministic and drift-free.
- Validate every request and outgoing response in Rust. Zod validates web
  boundaries but is never server authority and never a requirement for external
  clients.
- Requests reject unknown fields, implicit coercion and ambiguous variants.
  Missing and nullable fields remain distinct.
- Every endpoint declares access policy, operation/outcome types and concrete
  bounds. Missing access metadata is default-deny and prevents route generation.
- Every mutation carries an operation ID and canonical request digest.
- `/api/latest` is rolling. Exact `/api/vM.m` routes are immutable only after a
  signed release publishes their schema digest; `/api/vM.x` tracks the newest
  compatible published minor.
- Large collections filter and order on the server, use opaque cursors and return
  a relative next-page URL. Every page applies current permissions.
- Raw file bytes stream outside JSON/Zod with bounded frames, incremental
  integrity and verified resume ranges.

## Rust lint contract

- Run `rustfmt --check` and Clippy across the workspace, all targets and all
  features with warnings denied.
- Configure workspace lints centrally. Use the normal Clippy groups plus a
  reviewed pedantic selection; do not enable the complete `restriction` or
  `nursery` group.
- Runtime and library code denies `unwrap`, `expect`, `panic!`, `todo!`,
  `unimplemented!`, debug macros and stray stdout/stderr. A test or statically
  proved startup constant may use a narrow exception whose reason is evident.
- Deny unsafe code by default. Any future isolated unsafe boundary needs its own
  accepted safety contract and must still deny unsafe operations inside an
  `unsafe fn` unless they appear in an explicit unsafe block.
- Deny unreachable public items, unexpected configuration names, redundant
  clones, needless mutable references and undocumented public APIs at exported
  boundary crates.
- Configure Clippy responsibility tripwires for excessive arguments, cognitive
  complexity, type complexity and function length. Resolve them using the same
  ownership and data-flow review required for TypeScript, not mechanical helper
  extraction.
- A lint exception is scoped to the smallest item and states the invariant or
  platform constraint that requires it. Crate-wide blanket allowances are not
  acceptable.

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
4. Public API fixtures: Rust validation, OpenAPI, generated Zod and Fetch types
   agree for valid and invalid requests and responses.
5. Deterministic simulation: loss, duplication, reordering, partitions, crashes
   and stale workers under a seeded scheduler and clock.
6. Process integration: real Quinn peers and real folder IO.
7. Adapter conformance: the same filesystem vectors through HTTPS and SMB.
8. End to end: multiple real daemon processes and real protocol clients.
9. Hardware, power-loss, soak and performance gates for release milestones.

Tests must assert exact committed revisions, operation outcomes, visible bytes,
authoritative shard sets and durable recovery state where relevant. Avoid tests
that only assert that an error occurred or a process remained alive.

Keep fast suites independently runnable and parallel. A new slow test belongs in
an explicitly named suite with its expected duration and reason. Do not make all
pull requests wait for hardware or soak tests.

Tests run concurrently by default at both lane and case level. Rust tests use the
normal parallel harness or `cargo-nextest`; do not add a global serial-test
mechanism or routine `--test-threads=1`. Vitest, Playwright and deterministic
simulation use bounded worker pools. Each case owns unique temporary folders,
database files, mesh identities, clocks, random seeds and dynamic loopback ports.
Do not mutate process-wide working directory or environment from an in-process
test; use an explicitly configured child process when that behaviour must be
tested. Serial execution is allowed only around a named, genuinely exclusive
physical resource and must not block unrelated lanes. If concurrency exposes a
race, fix the shared state instead of serialising the suite.

## Local validation

Run `npm run check` from the repository root as the canonical fast local gate.
It verifies generated API drift first, then schedules independent lanes with a
bounded worker pool. Set `MESHSPAN_CHECK_WORKERS` from 1 to 32 only when the
machine needs a different limit. The gate includes:

- format check;
- Rust workspace build and unit tests;
- Rust lint with warnings denied across all targets and features;
- web format, type-check, lint and unit tests;
- schema and protocol compatibility tests;
- affected integration tests.

Record exactly what was run, its duration and anything that could not run.

For a defect:

1. reproduce it locally with the smallest failing test;
2. record the expected and actual state;
3. validate the suspected cause;
4. fix the responsible boundary;
5. run the focused test, then the affected fast suites;
6. inspect the diff for unrelated churn.

Do not bounce speculative fixes through GitHub Actions.

Do not create `.github/workflows` during early implementation. Release
automation remains a documented future stage, not a current development gate.

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
