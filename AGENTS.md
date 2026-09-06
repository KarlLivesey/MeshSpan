# MeshSpan agent guidelines

MeshSpan is a self-healing distributed filesystem appliance written primarily
in Rust. It combines folder-backed storage across one or more nodes and exposes
one authoritative namespace through built-in HTTPS and SMB services.

## Working mandate

- Follow the current request. A review or question does not authorise edits;
  an implementation request authorises its necessary, scoped implementation.
- Simplicity, reliability, speed, extensibility and security must reinforce one
  another. Do not simplify by removing required capability or claiming weaker
  durability. Routine operation must not require an administrator to repair
  internal histories, shards or consensus state.
- Work headlessly. Do not operate the user's browser or depend on external
  services for built-in filesystem, authentication or access functionality.
- Local tests only: do not add, trigger or rely on GitHub Actions.
- **Publication is prohibited until the user explicitly lifts the hold.** Do not
  create releases or tags, publish packages/images, or run publication workflows.
  Preparing scripts and local artefacts is allowed within the requested stage.
  An older goal mentioning publication does not override this restriction.
- Preserve user changes. Do not bundle unrelated staged work into a commit,
  discard it, or rewrite history without authorisation.

## Orient, plan, finish

1. Inspect the branch and working tree. Read [README.md](README.md), the
   [design index](design/README.md), [roadmap](design/roadmap.md), current stage
   evidence and the contracts relevant to the change. Read applicable nested
   instructions before editing their files; avoid rereading unrelated documents.
2. Distinguish accepted decisions from proposals using
   [decisions.md](design/decisions.md) and its linked stage decisions. A draft
   heading does not make accepted decisions optional. Surface genuine conflicts.
3. Find the existing owner, implementation and tests before adding anything.
   For HTTPS/web work, also read [public-api.md](design/public-api.md).
4. Before coding, state the intended observable behaviour, affected boundaries,
   acceptance tests and exclusions. Use a short plan proportional to the task;
   do not turn a small fix into another architecture project.
5. Complete a coherent end-to-end feature with focused tests. Then review the
   integrated stage for missing behaviour, adversarial cases and useful refactors.
   Fix known correctness/security defects immediately; do not repeatedly delay
   the remaining features for speculative hardening of unfinished interfaces.
6. Close each stage against its existing acceptance checklist, with evidence and
   explicit gaps. Continue through the authorised stages without asking again
   unless blocked or redirected. Never silently defer a required item to claim
   completion. Documents, scaffolding and passing unit tests alone are not a
   working product.

While working, give concise progress updates at least every minute. Report
**stage; behaviour completed; current work; remaining acceptance items; blocker**
as relevant. A branch name or test count alone is not progress. Record durable
milestones in the existing stage evidence file, not a new parallel status system.
After a restart, resume from that evidence and the actual working tree; do not
repeat completed work or infer success from an old narrative.

## Toolchain and commands

Use NVM for **every** Node/npm/pnpm invocation, including subprocess launchers.
Initialise it in each fresh shell; never fall back to an ambient Node executable.
The repository's `.nvmrc` selects the user's NVM default:

```bash
# In a Bash shell, from the repository root:
source "${NVM_DIR:-$HOME/.nvm}/nvm.sh"
nvm use
node --version
pnpm --version
```

Check selected tools against repository engine requirements; report mismatches
instead of silently switching runtimes. Read exact versions from manifests,
lockfiles and `rust-toolchain.toml`, not this document. Keep TypeScript 6 until
the selected generator and typed ESLint stack support the planned 7 upgrade.

| Purpose                        | Command from repository root                                          |
| ------------------------------ | --------------------------------------------------------------------- |
| Focused Rust regression        | `cargo test -p <crate> <test-filter>`                                 |
| Affected Rust lint             | `cargo clippy -p <crate> --all-targets --all-features -- -D warnings` |
| Rust formatting                | `cargo fmt --all -- --check`                                          |
| Focused web tests              | `pnpm --filter @meshspan/web test <test-file>`                        |
| Web static checks              | `pnpm web:lint` and `pnpm web:typecheck`                              |
| Generated contract drift       | `pnpm check:generated`                                                |
| Regenerate API artefacts       | `pnpm generate:api`                                                   |
| Dependency licence checks      | `pnpm check:licences`                                                 |
| Full local integration gate    | `pnpm check`                                                          |
| Dependency/toolchain candidate | `pnpm check:dependency-update`                                        |

Use existing scripts and installed project tools; do not add global tools or
download a new runner to perform a routine check. Prefer incremental debug builds
for development; optimised builds belong to a specific benchmark or packaging
proof. Avoid concurrent Cargo commands that merely contend for the same build
lock; use the existing bounded check scheduler for independent lanes.

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

## Architecture and ownership

Use [interfaces.md](design/interfaces.md) for permitted dependencies and the
root `Cargo.toml` for the actual crate inventory. HTTPS, SMB and future adapters
use protocol-neutral filesystem/domain operations; the daemon composes them
with persistence, consensus, storage and transport. The web panel is an API
client, not a privileged alternative path.

Keep work in the component that owns its state. A new crate, public export or
trait is an interface decision: identify its consumer and responsibility first.
Prefer private or `pub(crate)` items unless external use is required. Do not
create parallel helpers, adapters or miniature files when an existing owner
fits; do not force unrelated responsibilities together to avoid a new module.

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
- Use `Temporal` in web code for date/time domain values; do not add new
  arithmetic based on JavaScript `Date`.
- Bound untrusted allocations, collections, streams and recursion.
- Avoid `unwrap`, `expect`, unchecked indexing and lossy conversions on runtime
  input paths. Tests and statically proved startup constants may use them when
  the reason is evident.
- Errors must identify the failed operation and stable error kind without
  leaking secrets.
- Do not silently discard fallible results, including with `let _ =`. Propagate,
  handle or deliberately record the failure with appropriate redaction and
  bounded reporting. Best-effort telemetry must not make a data operation fail.
- Match closed state-machine enums exhaustively; avoid catch-all arms that hide
  newly added states. Represent invalid combinations out of the type where
  practical rather than coordinating unrelated booleans or sentinel strings.
- Comments explain invariants, ordering and non-obvious trade-offs; they do not
  narrate syntax.
- No new dependency without a concrete need, maintenance/legal review and a
  reason the standard library or current workspace cannot do the job cleanly.
- An obsolete release line which no longer receives upstream security or bug
  fixes is never an acceptable compatibility solution. Use a maintained
  release, adapt the boundary, replace the dependency or own the required code.
- Dependency and generated-code licences must be recorded and compatible with
  distributing the complete MeshSpan artefacts as `GPL-2.0-only`.
- Every dependency change must pass `cargo deny check licenses`; the allow-only
  policy includes development dependencies and intentionally excludes plain
  `Apache-2.0`.
- Dependency/toolchain candidates must run `pnpm check:dependency-update` under
  the active NVM toolchain. It requires Rust and JavaScript advisory scans plus
  the entire canonical local gate; an unavailable scan is not a passing result.
- Keep dependency updates targeted; inspect transitive features and lockfile
  changes. Do not refresh unrelated dependencies as a side effect of a fix.

## TypeScript and ESLint contract

Preserve [the typed flat ESLint configuration](tooling/eslint/eslint.config.mjs):
JS recommended, TypeScript strict/stylistic type-checked, Solid, accessibility,
regexp, imports, tests and directive checks. Do not blindly enable `all` presets;
Prettier owns formatting. Warnings and unused disable directives fail validation.

- No explicit or inferred `any`, unsafe assignments/calls/returns/assertions or
  member access. Accept untrusted values as `unknown` and validate them.
- No `@ts-ignore` or `@ts-nocheck`. Described, narrowly scoped `@ts-expect-error`
  belongs only in a fixture proving the specific type error.
- Enforce safe promises/async callbacks, valid awaits and thrown Error values.
  Closed unions require exhaustive handling; reject unnecessary conditions,
  assertions, non-null assertions, conversions and type arguments.
- Require explicit public return types, consistent type-only imports/exports,
  declared dependencies and acyclic imports without duplicates or self-imports.
- Keep strict equality and checks for fallthrough, unreachable loops,
  constructor returns and prototype-built-in misuse. Forbid dynamic evaluation
  and production `console`, `debugger` or `alert` calls.
- Preserve Solid reactivity, strict JSX accessibility, regexp safety, restricted
  layer imports and the restriction on domain arithmetic with JavaScript `Date`.

Handwritten tests follow these rules. Generated code is exempt only from human
size/responsibility ceilings: strict compilation, no `any` and schema behaviour
tests still apply. Exclude vendored code at its boundary, not with inline bypasses.

Maintainability ceilings (not targets to code up to):

| Measure                                        | Maximum |
| ---------------------------------------------- | ------: |
| Cyclomatic complexity                          |      12 |
| Cognitive complexity                           |      15 |
| Nested blocks                                  |       4 |
| Nested callbacks                               |       3 |
| Parameters                                     |       5 |
| Statements per function                        |      40 |
| Non-blank, non-comment lines per function      |      80 |
| Non-blank, non-comment lines per source module |     500 |
| Classes per module                             |       1 |

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
- Prefer `#[expect(lint, reason = "...")]` where supported so an obsolete
  exception is detected. Do not weaken warning levels to make a check pass.

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
- At cancellable IO boundaries, distinguish dropping a future from undoing its
  effects. Test interruption and retry without duplicate acknowledgement.
- Every remote operation has a deadline. Retries require idempotency and bounded
  backoff.
- Consensus/control work is isolated from bulk data work.
- Locks must have documented scope and ordering. Do not hold a lock across
  `.await` unless the primitive and invariant explicitly require it.
- Background queues are durable where losing work would reduce correctness, and
  bounded everywhere.

## Testing strategy

- Check existing coverage first. Extend the nearest suitable harness and fixture
  conventions; do not duplicate scenarios or invent another test framework.
- Every meaningful behaviour change needs a regression or acceptance test.
  Prove a defect's test fails before the fix and passes after it. Assert expected
  outputs independently of the implementation, not through its own calculation.
- Choose the layer that proves the claim: domain transition tables; persistence
  contracts across supported engines; canonical/malformed protocol fixtures;
  Rust/OpenAPI/Zod/Fetch agreement; seeded fault simulation; real Quinn/folder IO;
  shared HTTPS/SMB conformance vectors; real multi-daemon client workflows.
- Assert exact outcomes, revisions, visible bytes, authorised shard sets and
  recovery state where relevant. A process staying alive or returning any error
  is insufficient. Include denied and interrupted operations, not only success.
- Exercise public behaviour through real interfaces. Inject faults at the owned
  boundary; mocks cannot prove wire interoperability or durable recovery. Use
  real files and restarts for persistence claims, not only in-memory databases.
- Review generated fixtures and snapshot diffs against the intended contract.
  Never accept changed expected output solely because it matches today's code.
- Keep tests parallel and isolated: unique folders, databases, identities, ports,
  clocks and seeds. No in-process changes to global environment or working
  directory. Use configured child processes when testing those behaviours.
- Use bounded worker pools and Rust's parallel harness; no routine serial-test
  workaround. Serialise only a named exclusive physical resource, not its whole
  suite. Resolve races instead of hiding them with serial execution.
- Prefer controlled clocks and explicit readiness/completion signals over fixed
  sleeps. Real-process waits need a bounded deadline and useful failure state.
  Preserve failing seeds; a passing retry does not erase a flaky failure.
- Name slow suites and their purpose/runtime. Hardware, power-loss, soak and
  performance proofs remain explicit stage gates, not every-edit checks. Never
  describe synthetic faults, ignored tests or cross-compilation as those proofs.

## Validation cadence and debugging

1. **During a change:** run the focused regression and affected crate/web tests,
   formatting and lint. Broaden to consumers when a shared contract changes.
2. **Before integration:** run `pnpm check` on the completed candidate. It checks
   generated drift, builds the embedded web bundle and runs Rust/web static,
   licence and test lanes. Run additional affected acceptance suites explicitly;
   the default gate is not proof of ignored or environment-dependent tests.
3. **After further edits:** rerun checks whose evidence was invalidated. Changes
   to implementation after the integration gate require a new final gate;
   prose-only edits need document/link/diff checks, not another workspace build.
4. **Dependencies/toolchains:** always use the full dependency-update gate.

Keep the existing scheduler's bounded parallelism; `MESHSPAN_CHECK_WORKERS`
accepts 1–32. Record commands, duration, tested revision/tree, failures and skipped
checks. Do not claim success for an unrun, timed-out or still-running command.

For failures: minimise the reproducer, state expected versus actual, gather
evidence for one hypothesis, fix its owning boundary, rerun the focused test,
then broaden. After two failed fix attempts without new evidence, stop patching
and reassess the model; do not try a third speculative variant. Report a blocker
if progress needs new authority, context or an unavailable environment.

Treat failures after a change as potential regressions. Do not repeatedly stash,
revert, increase timeouts or push variants to seek a green result. A baseline
comparison is justified when local evidence leaves a genuine baseline question.

## Git and review workflow

- When Git work is authorised, start new work from current `main` on one
  short-lived `codex/` branch per reviewable feature. Understand an existing dirty
  branch before switching; do not stack routine work on unfinished branches.
- Check signing configuration and authentication availability early. Sign every
  commit; never bypass signing or repeatedly retry a failing authentication
  prompt. Preserve work and report the blocker. Verify signatures, not just the
  signing configuration; if claiming GitHub verification, check GitHub's result.
- Commit coherent progress and push after relevant local checks; a progress push
  need not repeat the full gate. Before merge, satisfy the integration gate above.
- Wait for successful commit and push before opening/updating a PR. Use properly
  formatted Markdown with actual newlines. Verify the remote branch/PR state.
- Merge completed PRs into `main` promptly, confirm inclusion, then remove merged
  branches. Do not leave completed work floating or report a merge before it exists.
- Use a lowercase imperative subject, optionally component-prefixed. Describe
  intent, protected requirements/invariants, exact tests/durations, remaining gaps
  and schema/wire/persistence impact in the commit/PR evidence, not a diff narration.

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

## Maintaining these instructions

Keep reusable instructions here; live progress belongs in stage evidence and
architecture detail in design documents. Do not copy volatile crate inventories
or tool versions into this file. Add rules for demonstrated recurring mistakes,
with a concrete action; do not accumulate one-off fixes or edit instructions to
excuse the current implementation. Propose changes during feature work; edit
this file when that change is requested or explicitly authorised.

Research informing this revision (ideas adapted, not imported project policies):

- [Turso](https://github.com/tursodatabase/turso/blob/main/AGENTS.md): harness
  selection, concise commands and evidence-led regression investigation.
- [uv](https://github.com/astral-sh/uv/blob/main/AGENTS.md): focused tests,
  exhaustive enum handling, expiring lint exceptions and targeted updates.
- [rust-analyser](https://github.com/rust-lang/rust-analyzer/blob/master/CLAUDE.md):
  existing ownership, deliberate public interfaces and generated-diff review.
- [Zed](https://github.com/zed-industries/zed/blob/main/.rules): explicit error
  handling and a high bar for adding permanent agent instructions.
