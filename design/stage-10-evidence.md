# Stage 10 implementation evidence

Status: **in progress**. Stage 11 has not started. Publication remains on hold
pending the owner's dependency review.

Current task status and outstanding acceptance live in the single numbered
[Stage 10 task list](stage-tasks.md#stage-10--certificates-packaging-and-operations).
This file is a historical evidence log: earlier statements such as “unmerged”
or “remaining” describe their recorded point in time, not necessarily current
status. Later evidence must resolve them explicitly; a passing retry alone does
not close an unexplained failure.

## INT-01 — daemon drain reaches the underlying transport lifetime

The first assembled daemon lifecycle run passes **7 tests** and fails **2**
(**15.24 s**, build **66 s**). The new real private-handler proof blocks the
existing owned admission worker for one exact metadata `CreateUser` operation,
drops its response receiver, starts shutdown, then releases the worker. Shutdown
waits and the original committed receipt survives reopening and exact retry.
The two remaining failures are configured-generation UDP reuse and an invalid
passkey origin in the new repeated-cycle fixture. Log:
`/tmp/meshspan-int01-daemon-lifecycle.log`.

After correcting that fixture and placing the runtime-ownership assertion before
socket reuse, both configured-generation cases still fail `AddrInUse`
(**6.82 s**). The bind-failure case explicitly reports **zero retained
PrivateConsensusRuntime owners**. Log:
`/tmp/meshspan-int01-private-generation-diagnostic.log`.

Local Quinn source inspection identifies a separate lower-level lifetime:
`EndpointRef::drop` wakes its internally spawned endpoint driver, which releases
the socket on a later poll. Closing connections or waiting for idle connections
does not join that driver. Two independent current-thread transport regressions
reproduce `AddrInUse` (**0.05 s**): immediate socket reuse after close/drop, and
reuse of the prepared server socket after the second socket bind fails. Neither
test yields, sleeps or retries the required bind. Log:
`/tmp/meshspan-int01-quinn-driver-baseline.log`.

The transport owner now retains bounded Quinn driver handles. Shutdown first
drains admitted MeshSpan workers, then closes driver admission, releases endpoint
handles and cancels/joins residual protocol drivers. A canceled waiter preserves
the shared join state. Driver panics and capacity rejection remain terminal
failures; owner-requested cancellation is expected cleanup. A prepared-transport
guard postpones driver startup through all fallible network preparation and
synchronously releases sockets when abandoned. There are no dependency, wire or
persistence changes.

All **9** focused transport rotation/lifecycle tests pass (**0.39 s**, build
**2.35 s**), including both previously failing immediate-rebind cases, abandonment
after both sockets bind, canceled-waiter recovery, capacity rejection and panic
reporting. Log: `/tmp/meshspan-int01-quinn-driver-fixed.log`. Initial compilation
and Clippy caught scoped mutability/import issues, which were corrected.
Affected transport/cluster/daemon all-target/all-feature Clippy passes with
warnings denied (**15.35 s**). Log: `/tmp/meshspan-int01-assembled-clippy.log`.

All **9** assembled appliance lifecycle tests now pass (**21.73 s**, build
**78 s**), including the formerly failing configured bind-failure case, three
controlled configured restarts with immediate socket reuse and no retained
PrivateConsensusRuntime owner, and exact committed-receipt recovery after a
private caller disconnects. Public and private production cleanup paths are
directly awaited; the bounded snapshot-install worker is not a losing select
branch. Log: `/tmp/meshspan-int01-daemon-lifecycle-fixed.log`. The broader **22** transport tests pass (**1.41 s**, build **3.25 s**) and
**36** network tests pass (**11.43 s**, build **15.47 s**). The maximum-command
case passes here; this does not explain its earlier full-gate timeout. Logs:
`/tmp/meshspan-int01-transport-tests.log` and
`/tmp/meshspan-int01-network-integrated-tests.log`.

Real HTTPS mesh creation/restart and three-process join, voter promotion and
restart both pass (**25.08 s**, build **58.98 s**); exact capability identity and
historical strong receipts remain checked. Log:
`/tmp/meshspan-int01-native-create-join-restart.log`. The original offline-backup
regression is running; the update-handoff regressions require the musl target
on Linux and are not counted by this native build. Final required integration
gate and affected additional acceptance remain pending. No stage completion is
claimed.

## INT-01 — configured startup retains the private generation

On `8ea5586a` plus the new lifecycle regression, real first-mesh setup returned
`CREATED`, published `Configured` and acquired its private UDP address. A forced
public HTTP-01 bind failure then returned from `serve_daemon_cycle` and stopped
the authority, but the private UDP address still returned `AddrInUse` after
fixture-owned runtime references were dropped. The regression failed in
**5.50 s** (build **37.32 s**); log:
`/tmp/meshspan-int01-configured-bind-baseline.log`.

Stage 10 tasks **10/12**, pack **INT-01**, therefore still require owned private
network/dispatcher/topology shutdown, drainage of admitted work and cleanup after
partial startup. This is failure evidence, not a completed lifecycle proof.

The network-specific baseline also reproduced premature completion: a real
70 KiB outbound append was admitted and blocked at its owned codec boundary;
the old close-only path returned while that worker retained the network
(**0.07 s**, build **5.72 s**). Log/command:
`/tmp/meshspan-int01-network-close-baseline.txt`.

The new network owner registers bounded accept, outbound and connection jobs,
reaps them during operation and retains admission permits through success or
panic observation. Startup prepares all initial jobs before starting its
supervisor. Closing admission precedes transport closure; all shutdown callers
await the same retained supervisor handle and cached result. Canceling one
waiter does not cancel drainage. Five focused tests pass (**0.16 s**, build
**8.53 s**), followed by all **29** network tests (**8.68 s**). They include
admitted work, canceled waiting, exhausted-capacity route preservation, pending
negotiation and registration racing with closure. All **135** cluster tests then
pass (**51.67 s**); affected all-target/all-feature Clippy passes with warnings
denied (**3.97 s**), as do scoped formatting/diff checks. Logs:
`/tmp/meshspan-int01-cluster-tests.log` and
`/tmp/meshspan-int01-network-clippy.log`.

Worker admission has explicit operational bounds of **4096 outbound workers**,
**4096 connection workers** and **128 connections per authenticated peer**.
Queued, running and replaced workers retain their admission slots until reaped.
Exhaustion rejects admission; these bounds do not confer metadata authority or
claim availability under arbitrary resource exhaustion. Configuration validates
the outbound capacity before starting jobs. A new typed shutdown error reports
unknown/failed drainage; wire, persistence and dependency formats are unchanged.
The existing synchronous close operation only initiates shutdown. Daemon and
storage consumers still need the awaited barrier and their own admitted-worker
drain; integrated daemon validation remains pending.

## Integration gate — retained vote-persistence failure

The NVM dependency-update gate on signed/pushed `d6807f5e` failed after
**244.92 s**. Advisory scans, generated drift, embedded web build, workspace
format/lint, TypeScript, both licence checks, tooling and web tests passed.
The Rust lane stopped in `meshspan-cluster`: **127 passed, 2 failed, 62.93 s**;
later Rust targets were not reached. Log:
`/tmp/meshspan-dependency-update-d6807f5e.log`.

The three-voter maximum-provider regression now retains the actual failure:
authority 1 exited with `Driver(Persistence(InvalidMutation))`. Its database
at `/home/karl/.cache/meshspan-validation/tmp/.tmpTcnUxl/quinn-node-1.sqlite3`
has term **10**, no vote, log through index **8** and applied index **7**.
The persistence adapter rejects a same-term transition from no vote to a first
candidate, although the deterministic core legitimately emits that transition.
A new durable restart regression reproduced `InvalidMutation` before the fix
(**1.22 s**, build **17.90 s**). Permitting only that first vote makes all eight
consensus-store tests pass (**3.91 s**, build **3.45 s**), including restart,
idempotent repeat, rejected vote clearing/switching and rejected term rollback.
This is a source-confirmed persistence defect consistent with the retained
failure; the original failing mutation itself was not captured.

The separate maximum-generic-command transport test reached its existing
15-second receive deadline. Its outbound send currently hides the typed send
failure from the fixture, so slow delivery and an early transfer error remain
unresolved alternatives. Neither a passing retry nor the vote fix closes that
transport failure. Its fixture now reports bounded queue, authenticated-support,
codec and reservation observations on the original timeout, then closes both
endpoints. It neither retries the message nor extends the receive deadline.

A real core/SQL driver regression also failed before the vote fix with
`Persistence(InvalidMutation)` (**1.07 s**, build **13.89 s**). It observes a
higher term without voting, grants the first candidate only after SQL durability,
reopens both SQL and the core, rejects a competing candidate and permits an exact
repeat by the original candidate. With the fix, all **130** affected cluster
tests pass (**56.08 s**), including both previously failing maximum-command
scenarios. The unexplained transport failure remains open. No stage or full
integration gate is declared complete.

Final affected metadata/cluster all-target/all-feature Clippy passes with warnings
denied (**3.44 s**); workspace Rustfmt and diff checks pass. The driver regression
passes again after test-only lint cleanup (**1.15 s**). No persistence schema,
wire format, dependency or publication change is required for the vote fix.

## ACC-02 — historical strong receipt recovery

The daemon can now distinguish verified immutable publication facts from a
strictly verified current local head. Exact historical strong confirmation uses
the existing authoritative `namespace_publication_is_committed` lookup. Only an
unconfirmed outcome proceeds to the unchanged current-head proof and proposal
path, including its original deadline. This adds a narrow opaque filesystem
proof for its daemon consumer; no wire, persistence or public HTTPS schema
changes are required.

The new daemon regression first ran with the old strict-first ordering and
failed with `StrongBarrierFailed` (**1.64 s**, build **63 s**). Moving historical
confirmation before the head check makes it pass (**1.46 s**, build **11.30 s**).
Both strong-publication tests pass together (**1.70 s**, build **0.26 s**). They
exercise real local publication storage and a running metadata authority,
reopen local storage and authority readers, and check exact prior confirmation
without a new log entry or head/revision change. Substituted receipts and stale
unconfirmed publications reject. An expired waiting budget does not erase an
already-confirmed outcome. This is repository reopen evidence; the authority
process is not restarted by that focused test.

The filesystem immutable-proof regression passes (**0.13 s**, build **6.09 s**),
including historical proof after later publication/reopen while the strict head
verifier still returns `StaleHead`.

The extended existing native test
`real_headless_process_creates_mesh_over_https_and_restarts` passes (**10.20 s**,
build **37.09 s**). Both different files return explicit strong, globally
converged, policy-committed receipts without fallback. After the second
publication advances the namespace, exact replay of the original first request
returns the same response, object and acknowledgement. The process then stops
and restarts; exact bytes, the old response and changed-body rejection are
checked again alongside the existing authentication/range proofs. The request
and waiting budgets are unchanged. Log: `/tmp/meshspan-native-strong-replay.log`.
This resolves the previously recorded historical strong-replay gap. Combined
filesystem/daemon all-target/all-feature Clippy passes with warnings denied
(**21.29 s**), as do workspace Rustfmt and diff checks. The full integration
gate remains pending; no stage is declared complete.

## Integration gate — unresolved three-voter maximum-command failure

The full NVM dependency-update gate on signed/pushed `198e7251` failed after
**334.17 s**. Advisory scans, generated drift, embedded web build, workspace
Rust/Web formatting and lint, TypeScript, both licence checks, tooling tests and
web tests passed. The Rust lane stopped in `meshspan-cluster`: **128 passed,
1 failed, 65.03 s**, with `Unavailable` from
`three_real_voters_commit_and_reopen_maximum_provider_configuration`. Later Rust
targets were not reached. Log: `/tmp/meshspan-dependency-update-198e7251.log`.

An isolated retry passed (**5.83 s**, build **23.34 s**); that does not resolve
the gate failure. The bulk harness could previously stop at a failed shutdown
request without joining the failed authority or preserving its underlying
runtime error. Diagnostic cleanup now observes all owners, aggregates bounded
errors and retains failed fixtures. All **23** focused authority tests passed
(**20.26 s**), followed by **129** affected cluster tests (**53.91 s**), still
without reproducing the original failure. Cargo artifact fingerprints show the
focused package and canonical workspace use different dependency graphs. The
workspace test artifacts were rebuilt with the exact gate settings (**3.68 s**,
no tests run). That canonical cluster binary also passed all **129** tests
(**50.37 s**) with four workers and the gate's quiet harness setting. The original
failure remains open; further repetition is deferred until the next required
integration run. Affected cluster Clippy passes (**11.75 s**), as do workspace
Rustfmt and diff checks. No full-gate or integration pass is claimed.

## Integration gate — generated barrel drift after the native checkpoint

On signed/pushed `f4cd8c82`, the NVM dependency-update gate passed both advisory
scans, then stopped at generated drift (**3.93 s** overall). Its normal generation
pipeline removed one duplicate `export * from "./fetch.gen"` from the generated
TypeScript barrel; no API schema, client method or type changed. A subsequent
`pnpm check:generated` passes with no further drift. No generated file was edited
by hand. Later canonical lanes were not reached in this attempt; full validation
still needs a completed run. Log: `/tmp/meshspan-dependency-update-f4cd8c82.log`.

## ACC-01/02 — combined two-user workflow exposes commit replay failure

The new native HTTPS/encrypted-SMB checkpoint reached an exact replay defect on
`598dffe9` plus its test fixture. Bob's upload returned a committed, eventual,
node-local receipt; immediate replay of the retained path and original request
bytes returned HTTP **409** (**23.01 s**, build **3.24 s**). Fixture `.tmpKZDihO`
is retained under the configured disk-backed validation TMPDIR. The preceding
checks proved administrator access to exact known HTTPS bytes over SMB, Bob's
HTTPS and SMB denial before a grant, wrong-SMB-identity rejection, explicit
permission grant and Bob's subsequent HTTPS commit. The combined 65-second open
and restart checks were **not reached** in this run.

The owned upload journal hashes server-generated operation time and content
cutoff, both regenerated by the API on retry. The existing filesystem test
reproduced `OperationConflict` when its server clock advanced (**0.41 s**).
The focused later-clock retry now passes (**0.39 s**, build **1.76 s**) using
the frozen execution context while rechecking current authority and matching
client input. A separate API-service regression reproduced loss of the recorded
outcome after rename and reopen (`NativeUploadError::Failed`, **0.45 s**, build
**60 s**); returning object metadata bound to the immutable publication receipt
makes that test pass (**0.43 s**, build **26.07 s**).

A retry now uses current attempt time for storage IO while retaining its original
intent and cutoff. Both production publisher paths reproduced provider reservation
attempts after cutoff: unprotected **2 → 3** (**0.94 s**) and protected **7 → 10**
(**1.08 s**). Guards now reject expired prepared recovery before opening its spool
or invoking a provider. Completed catalog evidence still resolves after cutoff.
All **15** tests in the two affected recovery targets pass (**1.07 s + 5.13 s**,
build **1.36 s**), preserving live and full-restart recovery. No trait or public
schema change was needed.

The extended filesystem retry regression passes (**0.39 s**, build **2.62 s**):
changed sequence, fence, length and digest reject; revoked current authority
rejects; completed receipts recover after the original cutoffs with current
authority; expired unfinished content performs no new begin; completed content
can finish namespace recovery after its content cutoff. Upload-session expiry
still rejects uncommitted operations.

The next native run passed enrollment/restart and failed sharing after **87.49 s**
(build **26.10 s**): the immediate exact replay and retained 65-second SMB open
passed, then a later exact replay returned HTTP **500**. Private fixture
`.tmpwftB41` is retained. It contains the committed upload, complete content and
intact stage bytes; cleanup was ruled out. The upload receipt is namespace
sequence **2**, while subsequent SMB publications advanced it to **3** and **4**.
`NativeFilesystemRuntime::publish_file_head` requires a current-head proof even
for recovery of an already-committed eventual write, matching the existing
`StaleHead` regression in the publication store. The focused daemon regression
failed with `StrongBarrierFailed` (**0.39 s**, build **23.96 s**). Eventual replay
now verifies every immutable receipt field after normalizing only disposition;
strong head advancement still requires the strict current-head proof. All **5**
upload-service tests pass (**1.03 s**, build **23.42 s**), including substituted
receipt rejection and exact response recovery after rename/reopen.

The final native rerun **passes both tests in 111.50 s**, build **19.92 s**:
`cargo test -p meshspan-daemon --test headless_process user_enrollment:: --
--include-ignored --test-threads=2`, with four build jobs, disk-backed TMPDIR,
the existing private Samba lease helper and pinned local SMB client image.
Log: `/tmp/meshspan-native-two-user-checkpoint-final.log`. The sharing test proves
independent public enrollment/sign-in; known-file HTTPS and SMB denial before a
grant; Bob-bound SMB credentials and wrong-identity rejection; explicit grant;
exact administrator/Bob bytes through both protocols; a retained 65-second SMB
open with read/write/close; process restart and independent sign-in; exact bytes
and original commit replay after restart; and changed-body rejection. Responses
assert eventual, node-local, policy-committed scope without fallback. This is the
pack's first two-user checkpoint for ordinary API-key enrollment, not passkey or
all-policy completion. Combined filesystem/daemon all-target/all-feature Clippy
passes with warnings denied (**28.11 s**); final workspace Rustfmt and diff checks
pass. One expression received formatting only after lint. The full
dependency-update gate remains pending; the earlier failed fixtures remain
evidence of diagnosed defects.

A separate strong-replay gap remains explicit: authoritative historical
confirmation already exists, but the daemon currently obtains its immutable
command facts only through a current-head verifier. Recovering a previously
confirmed strong receipt after later local publications must reuse verified
historical facts without authorizing a stale new head proposal. This eventual
slice does not claim that case, the whole replay contract or Stage 11 task 8.

Fixture development also observed HTTP 404 for a new unmaterialized volume and
SMB `ls` returning `NT_STATUS_NO_SUCH_FILE`. Those were not permission-denial
proofs. The test now targets administrator-verified existing file bytes. Earlier
fixture-only status/response-shape assumptions were corrected against the Rust
and OpenAPI contracts; no production behavior was weakened to satisfy them.
This is earlier Stage 6 prerequisite work for Stage 11 task 8. Stage 11 remains
not started as an integrated stage.

## Dependency gate — Rustls advisory and yanked wnaf patch

On clean signed candidate `7f35e683`, NVM `pnpm check:dependency-update` stopped
at Rust advisories in **1.41 s**. Rustls **0.23.43** is affected by
[RUSTSEC-2026-0285 / GHSA-2mjx-qc3c-rqvc](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc),
a TLS 1.3 handshake encryption-level validation defect. JavaScript audit and
canonical integration checks were not reached. The same scan separately warned
that transitive **wnaf 0.14.0** was yanked. Log:
`/tmp/meshspan-viability-integration-7f35e683.log`. An earlier attempt could not
start because an external timing binary was absent; the actual run used Bash's
built-in timer. Neither attempt is an integration pass.

All three Rustls declarations now require **0.23.45**, the upstream patched
release. The lockfile changes only Rustls and **wnaf 0.14.1**; the latter adds an
edge to already-locked `primefield` for its endianness bounds. No other package
version or enabled application feature changed. Both retain compatible MIT
licence options. `cargo deny check licenses` passes. Thirteen focused TLS/QUIC
adapter, external-chain and real mutual-TLS tests pass (**6.33 s** build; **0.19 s**
reported test time). Affected all-target/all-feature Clippy passes **3.64 s**.
The NVM advisory recheck passes both Rust and JavaScript scans in **1.62 s**.
The complete dependency-update gate remains required after the assembled
candidate is ready. Publication, live-CA and Stage 10/11 proof remain open.

## CORE-02 — interrupted bulk retry through three authorities

The remaining interrupted/reconnect proof now passes. The existing real Quinn
three-authority harness captures a genuine leader request, admits a partial
body, resets the connection and verifies released transfer capacity. During
interruption there is no accepted match above the baseline, no committed/applied
index advance, no follower log advance and no operation receipt. The same
original probe and entry then cross a new connection; the correlated match
response binds the exact probe and digest, all three authorities apply the exact
index/receipt, and reopening all three repositories retains canonical bytes and
receipt identity. No new operation substitutes for the interrupted one.

The first focused run passed **1/1, 5.13 s** (build **7.55 s**). After strengthening
match-index and bounded diagnostic assertions, all four authority-bulk tests
passed **8.69 s** (build **5.74 s**). Cluster all-target/all-feature Clippy passed
**1.98 s**; scoped Rustfmt and diff checks passed. A five-second election window
belongs only to the named controlled-interruption fixture; existing test timing
is unchanged. Changes are test-only and reuse the existing transport/authority
harness. Tested tree: `67ca152a` plus these four test files. This resolves the
previously recorded CORE-02 interrupted-reconnect acceptance gap. Integration
still requires the complete dependency-update gate; Stage 10/11 remain open.

## CORE-02 / ACC-01 — legacy migration fixtures after schemas 118/119 and 17

Pre-gate compatibility review found two stale fixture assumptions introduced by
the additive enrollment/capability schemas. The v109 backup fixture retained
post-v109 tables and failed reopening with `user_enrollments already exists`
(**1.56 s**). Its teardown now removes the 118/119 tables before replaying normal
migrations; the existing exact surviving-history assertions remain unchanged.
The focused test passed **1.49 s** (build **3.59 s**).

The v14 quota fixture reached the correct new local schema 17 but still expected
16 (**1 failed, 1.74 s**). Its expected version now names 17 and documents the
new capability-cache migration. Existing exact pending, committed and replayed
charge assertions remain unchanged. All **14** matching capacity-seal tests
passed **8.07 s** (build **3.95 s**). Metadata all-target/all-feature Clippy
passed **4.35 s**; scoped Rustfmt and diff checks passed. Fail-before runs used
the already-built metadata test binary; after-fix runs used Cargo with four
workers. Tested tree: `598a13b1` plus these two fixture changes. Production
migrations, safety assertions and dependency policy are unchanged; the full
gate remains pending.

## Stage 10 — retained readiness diagnostics before integration

The existing setup-status transport diagnostic is retained in the headless test
client. On cancellation or completion after five seconds, it reports the phase,
elapsed time, received byte count and bounded framing facts; it never prints
request credentials or response bodies. It does not alter request deadlines or
assertions. The latest native capability and enrollment tests exercised this
client. The earlier setup timeout investigation remains unresolved; absence of
a diagnostic line does not establish its cause. The final gate will test this
exact client along with the assembled implementation.

## ACC-05 — ordinary SMB lease renewal and owned connection shutdown

The connection owner now renews one due open per maintenance step, with a
one-second wake and half-life scheduling for the existing 60-second lease.
Uncertain renewal fences that open and advances the queue. Close removes its
renewal; disconnect releases clean opens and preserves acknowledged dirty staging
for durable expiry without implicit publication or abort. Filesystem branch
migration **046** explicitly distinguishes handle-bound locks from independently
timed locks. Live handle-bound locks renew atomically; immutable acquisition
deadlines and exact receipts survive replay. Legacy locks remain independent,
including when their original deadlines happen to equal the handle deadline.

SMB renewal samples its executed timestamp after acquiring native runtime
ownership. It retains the original operation ID and intended expiry, rejects
backward clocks, and never retries changed bytes after uncertainty. Other adapters
and explicit takeover retain caller-owned replay timestamps. Idle maintenance
preserves a partially read TCP frame. Shutdown signals idle readers, observes
started blocking work, and retains bounded dispatch/cleanup failure reports.

Fail-before evidence is retained:

- The real client held the same open for 65 seconds, then its read failed with
  errno 22 (**72.22 s**); fixture `.tmpcPkj4R` remains under the configured disk
  validation TMPDIR. No renewal implementation was present for that baseline.
- Lock continuity/corrupt-lifetime admission: **2 failed, 2 passed, 0.58 s**.
- Missing idle maintenance and abandoned work at the old 30-second shutdown
  deadline: **2 failed, 30.01 s**.
- Native mutex admission: **2 failed, 1 passed, 0.22 s**. A queued renewal at
  time 30 incorrectly extended an expired-at-60 handle to 90 after the clock
  reached 70; a backward clock was also accepted.

On `011d599f` plus the assembled working tree, focused native admission tests
passed **3/3, 0.21 s** (final fixture build **72 s**). The fixed server binary passed **5/5,
31.01 s**, including the named slow shutdown proof. Filesystem tests previously
passed **245/245** (unit **37.96 s**, integration **16.06 s**), and SMB tests
**65/65**. Their production behavior was unchanged after those runs. Combined
`cargo clippy -p meshspan-metadata -p meshspan-daemon -p meshspan-filesystem
-p meshspan-smb --all-targets --all-features -- -D warnings` passed in **19.57 s**.
The first lint pass found test-only `expect`/`panic` plumbing and separately
owned daemon composition/reporting/enrollment findings; these were corrected
without weakening lint rules. The changed native fixture was rerun afterward.
Targeted Rustfmt, diff checks and evidence Prettier passed; the latter used the
installed web tool under NVM Node **26.8.2**, pnpm **11.19.0**. Cargo used four
build workers, the shared target directory and disk-backed validation TMPDIR.

The real public SMB proof now **passes**: the same `SMBCFILE` stays idle for
65 seconds after acknowledged staging, reads exact bytes, rewrites and rereads
through that open, closes, then reopens exact published bytes. The combined
`cargo test -p meshspan-daemon --test headless_process -- --include-ignored
--test-threads=2 smb_lease:: user_enrollment:: --nocapture` ran in **73.11 s**
(build **16.15 s**): SMB passed, independent enrollment failed with HTTP 401
creating a TOTP challenge; `.tmp93Me3Q` is retained for that separate diagnosis.
This command is therefore a failed combined gate, not a passing checkpoint.

The optional local helper uses installed Samba 4.24.7 `libsmbclient`; no runner
was downloaded. Its authored source is GPL-2.0-only, but the external library is
GPL-3.0-or-later: the combined local binary is not distributable as GPL-2.0-only
and must never enter MeshSpan artifacts. It is selected only through
`MESHSPAN_SMB_LEASE_CLIENT`; no Samba implementation source or dependency was added.

ACC-05 remains open: native runtime lock contention can still delay unrelated
opens beyond expiry (CORE-06 fairness); explicit wire FLUSH and lock-continuity
proofs, current export generation/revocation binding, and accepted resource caps
remain. The old 30-second forced-abort behavior was unsafe and is removed; a
cooperative aggregate shutdown bound is **not** proved. Private INT-01 lifecycle,
the full integration gate, Stage 10 and publication remain open.

## ACC-01 — registration after another user is created

The native enrollment test reached a real server defect: TOTP challenge creation
returned 401 after Bob's creation. The active administrator session carried the
mesh identity revision (5), while the registration profile returned the unchanged
administrator principal revision (1). The shared TOTP/passkey registration profile
now returns the mesh identity revision; the recipient creation remains before
registration in the process test.

A focused metadata regression failed with revision 1 instead of 2 before the fix
(6.64-second build, 1.15-second test). All four registration-profile tests passed
afterward (4.60-second build, 2.13-second tests), using four build/test workers.
Formatting and diff checks passed. No schema, wire or dependency changes. The
native rerun exposed a second startup defect: integrity validation rejected a
replacement session's copied primary-factor timestamp, although migration 049
and step-up preserve its earlier authentication time. Reopening the committed
step-up fixture failed `IntegrityFailed` before the fix (**1.22 s**, build
**4.02 s**). The checker now accepts earlier factors only for replacement
sessions; corruption tests still reject stale normal-session and future
replacement-session factors. All five metadata session tests passed **3.18 s**
(build **2.73 s**); metadata all-target/all-feature Clippy passed **10.96 s**.

Native HTTPS enrollment/restart passed **1/1, 16.58 s** (build **13.17 s**): Bob
signs in independently as a nonmanager, then signs in again after restart and
recovers the exact enrollment receipt. Changed-request and second-operation
redemptions are rejected before restart. Scoped formatting and diff checks
passed. Tested tree: `68e476ad` plus this integrity fix and native acceptance
fixture. No schema, wire or dependency changes. First-passkey enrollment and
real two-user file sharing through HTTPS/SMB remain open; ACC-01 and Stage 10
are not closed.

## CORE-02 — bounded bulk replication and authoritative capability refresh

The 64 KiB consensus control envelope remains unchanged. Oversized append and
committed-prefix bodies use authenticated DataFrames on a separate, deadline-bound
bulk lane. The descriptor binds the exact request, probe, phase, entry count and
body digest; its receipt acknowledges ingress only, never durable replication.
DecodeLimits bound repeated entries before allocation. Per-peer (64 MiB) and
aggregate (128 MiB) reservations charge three simultaneous payload copies plus
frame/entry overhead and survive queue dispatch and cancellation. Immutable core
log payloads share Arc storage; these network reservations do not claim to bound
permanent log or persistence memory.

The original real-three-voter 70 KiB regression failed with NotLeader (**5.09 s**)
and then timed out replicating the same operation (**18.37 s**). The failures are
retained. After the bulk transport and exact admission fixtures, real Quinn tests
committed and reopened exact **70 KiB** and maximum **512 KiB provider
configuration** commands on all three repositories (**2/2, 7.55 s**, build
**2.16 s**). Earlier protocol bulk tests passed **3/3, 0.46 s** and cluster bulk
coverage passed **11/11, 9.78 s**, including generic 16 MiB command bytes,
malformed/reset bodies, reservation release and responsive vote controls while a
transfer stalls. The provider limit remains 512 KiB; metadata's 1 MiB codec bound
and the reusable core's 16 MiB bound are distinct contracts.

Large local proposals require every active-plan member's exact admitted
capability before pending insertion or append. Unknown and unsupported evidence
produce explicit errors without durable log changes (**2.13 s**). Local schema
**17** stores bounded canonical Hello preimages; partition schema **119** stores
root-committed current presentations separately from immutable activation.
Authenticated node self-reports use opcode **138**, a distinct node actor envelope,
principal NULL and the existing consensus/preflight/apply/receipt pipeline. Only
versions **18** (historical principal commands) and **19** are decoded; new
commands cannot be mislabeled as 18. The old exact-current-version consumer failed
with InvalidCommittedCommand (**1.28 s**, build **8.32 s**); the mixed replica
suite subsequently passed **17/17, 20.97 s**.

Exact cached evidence survives network restart with the source offline; changed
certificate, incarnation or digest fails admission. Cache tests passed **3/3,
0.32 s**. Repeated closed response waiters are pruned and live duplicates bounded
(**1/1, 0.45 s**). Current node codec tests passed **2/2, 0.02 s**. Those last two
commands used the already-built unit binaries whose tested behavior was current;
no concurrent Cargo build was started. Metadata capability tests passed **12/12,
6.67 s** (build **2.54 s**), including migration 17/119, truthful actors, rollback,
reopen/replay and prior-record guards. A new persisted upgrade-state fixture first
failed StaleRevision (**1.08 s**) when current incarnation 2 had immutable
activation 1. The fix accepts only a historical incarnation at or below current,
with exact activation revision/digest and independently checked current
certificate; the passing fixture preserves activation bytes unchanged.

The native three-daemon promotion proof failed (**28.48 s**): cached and committed
Hello digests agreed but retained learner roles after promotion. The network now
replaces roles fallibly and invalidates cached handshakes without closing
in-flight requests. A real Quinn regression passed (**0.12 s**, build **9.00 s**),
including invalid/duplicate/contradictory roles, no-op replacement and the new
handshake digest. The native three-daemon proof now passes: every daemon commits
presentations matching its actual voter Hello, all three stop and restart, and
the exact capability checks pass again. The combined native command ran in
**52.25 s** (build **48.76 s**), with **1 passed, 1 failed**: capability promotion
and restart passed; separate user enrollment failed on restart with
`MetadataStore(IntegrityFailed)`. The latter fixture `.tmpT2GVSj` is retained.
This is not a passing combined gate.

The daemon owns its periodic self-reporter and cancellation path. Peer reports
bind the current mTLS node, incarnation, certificate and validated Hello digest;
unsupported older endpoints remain retryable. Two focused reporter tests passed.
Applying authoritative metadata clears volatile peer budget overrides before
further replication. Combined metadata/daemon/filesystem/SMB all-target,
all-feature Clippy passed **19.57 s**, including the final incarnation guard and
reporter composition. Tested tree: `07ce8aad` plus this CORE-02 change. No new
CORE-02 dependency was introduced. The complete dependency-update/integration
gate, remaining CORE-02 edge-case acceptance, Stage 10 task 17 and Stage 11
candidate proofs remain open.

Final review reproduced an expired transfer waiting indefinitely for a shared
codec permit (**1 failed, 1.07 s**, build **9.26 s**). Both inbound and outbound
codec admission now use the original transfer deadline, as does network IO.
Started blocking codecs remain owned and observed; their late results cannot
enter a peer queue. The nearest real Quinn bulk tests passed **7/7, 8.43 s**
(build **4.24 s**), including exact encoded control payloads of **65,535**,
**65,536** and **65,537** bytes: the first two traverse the real inline path;
the last traverses normal queued bulk, all with exact decoded message bytes.
Affected cluster all-target/all-feature Clippy passed **4.60 s**; scoped Rustfmt
and diff checks passed. Reconnect-mid-body retry with exact matched/applied
indexes remains an explicit acceptance gap; reset/substitution tests currently
prove no dispatch and released reservations.

## CORE-02 — per-peer framing of replication backlogs

A peer's declared framing budget now limits both ordinary append and historical
committed-prefix batches before entry cloning. A conservative per-entry cost is
included alongside the existing 16 MiB command-byte and 64-entry limits. The
outer runtime supplies explicit, volatile budgets; membership activation clears
all peer overrides before emitting replication, including when an identity's
incarnation changes. This does not change durable records or weaken quorum proof.

Two focused regressions failed before batch selection used the new policy:
three individually legal small commands were sent together where only one fit;
two entries crossed the exact framing boundary where only one fit. After the
fix, `CARGO_BUILD_JOBS=4 cargo test -p meshspan-consensus --lib --
--test-threads=4` passed all 43 tests in 3.97 seconds. Affected all-target,
all-feature Clippy passed in 0.57 seconds; package formatting and diff checks
passed. Tested tree: `1b34523b` plus this core change. No dependencies changed.

Runtime capability admission, automatic presentation refresh, real distributed
acceptance and the complete integration gate remain separate unfinished work.
This is a progress slice, not closure of CORE-02 or Stage 10.

## Viability pack adoption and CORE-01 prefix proof

The owner adopted the pack on 2026-09-14. Archive SHA-256:
`55c28d1ea794a7b9611413f1d48a0c88402e383dae665c69a5f0f4e94ee86564`.
All 2,293 tracked checkout files matched its original source snapshot. The
baseline is signed progress commit `47da63689ca295b05d127d1f5ab0120bb953258c`
plus the preserved uncommitted headless status-request diagnostic and evidence.
It is not a clean integrated candidate: PR #270 is still draft, and fetched
remote main remains PR #269's `fcd65853fc9fbd54112859a7188231b4b1abf4d2`.
The failed complete gate and interrupted diagnostic recorded above remain open.

One integrator owns consensus, daemon composition, generated contracts and stage
evidence. Separate worktrees own ACC-02 browser outcomes, DATA-05 storage pack
retirement and NET-01 external TLS. Cargo validation has one owner at a time;
web validation uses bounded workers and NVM. Their worktrees start from the
unmerged signed checkpoint, not a claimed passing main. No existing stage task
or requirement is discarded; Stage 9 exit still needs integrated reconciliation,
Stage 10 remains incomplete and Stage 11 candidate acceptance has not started.

CORE-01's two new focused prefix regressions failed before the correction:
expected commit index **64**, actual **100** (build **2.09 s**, tests **0.01 s**).
The follower now retains its request-scoped reply through persistence, commits
only through that proven prefix and preserves an already higher commit on a
delayed heartbeat. Empty appends prove only their checked previous position.
Conflicts return a hint below the rejected probe, and current-term leader
contact steps a candidate down even when the prefix conflicts.
`cargo test -p meshspan-consensus -- --test-threads=4` then passed all **34 tests**
in **3.67 s**, build **1.28 s**; affected all-target/all-feature Clippy with
warnings denied passed in **0.55 s**. Cargo used four build workers. No dependency,
persisted schema or wire shape changed in this slice.

CORE-01 remains open for correlated, bounded append probes, delayed-response
and finite-backtracking regressions, and real transport validation. The full
integration gate has not run on this slice. Stage 10/11 estimates remain 81/126;
physical, interoperability, soak and independent-review gates are not claimed.
The publication hold remains in force.

### ACC-01 — native first API-key enrollment and generated client

A recent-step-up manager can issue and revoke short-lived consent for an active
user's first primary credential. Anonymous JSON redemption creates that user's
ordinary API key and consumes the invitation atomically. Partition migration
**118** persists digest-only consent. Exact replay is bound to the operation,
recipient, credential request and live consent; a second operation is rejected.
The public API and generated Zod/Fetch client expose all three operations.

Review found two secret-release defects before integration: a locally retained
receipt could bypass authoritative revocation during isolation, and a capability
could expire while its command committed. Both new regressions failed before the
fix (**2 failed, 2 passed; 2.70 s**, daemon build **71 s**). Enrollment now obtains
fresh quorum read fences and checks exact local applied history before secret
release, sampling time after synchronization. Final file-backed daemon service
tests: **4 passed, 2.67 s**, consumer build **72 s**. Migration compatibility through
118: **1 passed, 49.07 s**, build **15.56 s**. Earlier focused domain/metadata/API
checks passed **1/7/2 tests**. Rejection, unavailable authority and corrupt evidence
retain their distinct error classifications.

The client regressions initially found all three methods absent (**4 failed,
0.714 s**). The final enrollment and existing authentication suites passed
**13 tests, 0.473 s**, with two Vitest workers under NVM. Typecheck passed.
Full web lint initially found one oversized test group; separating manager and
recipient cases resolved it, and the affected-file lint passed. Generated API
artifacts were regenerated from Rust; the native Fetch generator was extended.

This is a progress checkpoint, not completed onboarding acceptance. The real
HTTPS two-user/restart test is authored but not yet run; browser and first-passkey
flows remain. Integration review also identified the need to accept existing
version-18 log entries alongside newly written version 19; its driver regression
and fix are in progress. That issue and the complete dependency-update gate must
be resolved before integration. No migration, hardware or full-suite result is
inferred from these focused checks.

### CORE-02 — bounded batches and shared immutable log payloads

The two new core regressions failed before the fix: two legal 9 MiB entries
were emitted together (expected one entry, actual two; **0.50 s**), and the
follower requested persistence for their oversized aggregate (**1.02 s**) rather
than rejecting it. Current append and historical-prefix selection now stop at
16 MiB aggregate command bytes as well as 64 entries. Receivers enforce the same
bound before persistence, and acknowledgement advances the next bounded batch.

Log-entry payloads are shared immutable bytes across core effects and durable
mutations. Transport adapters make independently owned wire copies after byte
reservation; inbound conversion avoids an extra temporary full-command copy.
The persistence boundary still independently validates command digests. No wire
or stored-log encoding changes in this core slice. This does not close the
separate lifetime log-compaction requirement.

Final `cargo test -p meshspan-consensus -- --test-threads=4`: **41 passed, 0 ignored,
3.94 s**. Affected all-target/all-feature Clippy with warnings denied: **0.41 s**.
Formatting and diff checks passed. Consumer integration, capability admission,
and the complete dependency-update gate remain pending; no whole stage is closed.

### ACC-02 follow-up — replacement-session logout

Integration review reproduced an uncertain logout being retained after a different
session signed in: the second logout incorrectly stayed `revocation_unknown`.
The new regression failed before the fix (**1 failed, 4 passed; 2.14 s**).
Retried revocations now belong to the exact session, and late outcomes cannot
clear a replacement login. The final two focused suites passed **9 tests in
0.991 s**; full web lint, typecheck and formatting passed under NVM. No public
contract or dependency changed. The assembled integration gate remains pending.

### DATA-05 — Stage 10 task 17, retiring fully reclaimed packs

The first pack retirement slice was integrated from the isolated worktree based
on `47da6368`. A fully reclaimed old pack can now be removed without losing exact
put, tombstone or reclamation replay. Target-journal migration **004** fences
retirement before deletion. Source identity/payload verification and the existing
exclusive provider lock protect deletion; directory sync precedes the durable
completion record. Pending packs remain visible to space observations.

The missing-payload-pack replay regression failed before the fix with `NotFound`
(build **3.20 s**, test **0.31 s**). Integration review found that prioritizing one
pending retirement would starve all later work behind a corrupt source. The new
two-candidate regression reproduced `Corrupt` on the second attempt (**0.41 s**).
Maintenance now uses its indexed cyclic cursor across active and pending packs:
the failure remains visible, later packs advance and wrapping retries the failure.
The final `cargo test -p meshspan-storage -- --test-threads=4` passed **59 tests**,
none ignored, in **6.00 s** (build **0.39 s**). Affected all-target/all-feature
Clippy with warnings denied passed in **0.50 s**; formatting and diff checks
passed. Four Cargo build workers were used. The exact patch was applied to the
integrator checkout without conflict; the assembled integration gate is pending.

DATA-05/task 17 is not closed: legacy oversized-pack splitting, terminal-history
archival, temporary-space reservation and measured compaction pause/throughput
remain. Receipts, routes and segment history still grow over the target lifetime;
the current provider lock and 32-pack observation limit are not claimed solved.
No dependency or wire/API contract changed. Stage estimates remain unchanged.

### ACC-02 — truthful browser mutation outcomes

The first browser slice retains the exact request and operation ID for uncertain
file namespace changes, API-key issuance, passkey registration, backup settings
and logout. Receipts are checked against the request. A successful mutation stays
committed when its later refresh fails. Lost responses and missing sign-out CSRF
state remain explicitly unknown with recovery controls. Retained sensitive
requests stay in memory; this is not persistent upload recovery.

Three pre-fix browser regressions failed: refresh failure reversed creation
success, lost mutation response claimed non-commit and missing-CSRF logout
claimed anonymity. Six focused suites passed **38 tests** in **2.28 s** in the
isolated worktree; focused strict lint, typecheck, formatting and diff checks
passed under NVM Node **26.8.2** / pnpm **11.19.0**. After exact patch integration,
the same six suites passed **38 tests** in **3.77 s** with two Vitest workers:
mutation-outcome, authentication-security-panel, backup-administration-panel,
file-browser-model, file-browser-panel and session-provider.

ACC-02 remains open for server outcome/retry classification, real dropped-response
daemon proof and the remaining credential/admin forms. Upload retry belongs to
ACC-04. The current API supplies no reliable rollback classification, so server
exceptions remain unknown. No dependency or generated/public API shape changed.
The complete assembled gate is pending; no stage acceptance is claimed closed.

### NET-01 — external P-384 certificate chains

External certificate HTTPS, ACME result validation and gateway publication now
select an explicit P-384-capable verification profile. Internal node/federation
identity and local signing retain P-256. Captured public service chains and an
independent OpenSSL-issued P-384 issuer/P-256 leaf fixture exercise the owning
boundaries, including exact application bytes through a TLS handshake. Negative
tests cover names, expiry, wrong roots and altered signatures.

Before the change the captured production ACME chain regression failed
(build **5.39 s**, test **0.00 s**). The provider suite then passed **9 tests**
(build **3.00 s**, tests **0.19 s**), and the daemon `p384_` filter passed **3 tests**
(build **98 s**, tests **0.08 s**). Affected all-target/all-feature Clippy passed
in **16.31 s**. Captured chains passed **4 tests** again after test-only lint
repairs; Rust formatting and `cargo deny check licenses` passed. The isolated
daemon build first lacked its ignored web bundle; the unchanged baseline bundle
was supplied before those tests. These are focused results, not live issuance.

The sole added dependency is `p384` **0.14.0**, selecting its MIT option. Existing
resolved dependency versions are unchanged. The full dependency-update gate is
still required before integration. NET-01 remains open for RSA interoperability,
real process issuance/installation and the remaining external acceptance. No
publication, signature-profile weakening or advisory exclusion occurred.

### CORE-01 — correlated replication proof

After the prefix correction, a focused delayed-response regression still failed:
a proven peer match of **100** retreated to **64**. The leader now retains at most
64 outstanding append probes per peer. Replies bind the exact request ID and
entry digest; accepted progress is monotonic, and only the latest conflict may
backtrack without crossing established proof. Phase changes and leadership loss
discard correlations. Unknown, duplicate or evicted probes cannot confirm reads
or writes. Current-term correlated negative contact can still satisfy the read
predicate without asserting a log match.

Private wire additions are request probe tag **11**, response probe tag **9**
and matched digest tag **10**. Successful legacy/missing correlation and malformed
digests fail closed. Uncorrelated negative membership notices carry no read proof.
No persisted schema or application command encoding changes in this slice.

The consensus suite passed **38 tests** in **3.80 s**, build **0.93 s**, including
the 64/100 prefix boundary, finite equal-tail backtracking, delayed success/failure,
forged digest/read contact and expired probes. Affected consensus Clippy passed
in **0.59 s**. Protocol correlation **4**, cluster wire **8**, read barrier **4**,
election deadline **2** and leadership waiter **1** tests passed; cluster/protocol
all-target/all-feature Clippy passed in **13.77 s**. The real three-node Quinn
leader-loss/re-election/commit test passed in **4.53 s**, build **5.18 s**.
The first equal-tail fixture incorrectly attempted an election while already
leader; correcting that setup is not counted as a production defect reproduction.
An additional synthetic restore/retransmit regression passed in **0.01 s**
(build **1.10 s**), covering crashes before/after term persistence without
claiming physical power-loss evidence. Final consensus Clippy passed in **0.31 s**.
These checks use four Cargo build/test workers. Final assembled acceptance,
the separate command-size transport defect (CORE-02), and the complete gate remain
open; these focused results do not close Stage 3/10/11 acceptance by themselves.

### INT-01 — public service and storage-worker shutdown ownership

Two focused regressions reproduced owned-task leaks: the public supervisor
returned its first error before a blocking writer completed, and failure to bind
the public HTTP01 listener left metadata authority running. Shutdown now withdraws
readiness and signals stop before draining every public-service result. The
storage reconciler belongs to that JoinSet and observes each blocking tick;
authority is explicitly stopped and joined after public startup/service failure.
The primary failure survives alongside a bounded count of cleanup failures.

The final lifecycle suite passed **6 tests** in **5.34 s**, build **34.48 s**;
daemon all-target/all-feature Clippy passed in **30.21 s**. Formatting/diff checks
passed. Earlier setup failures (missing storage path, invalid port-zero origin)
and a divergent generated-protocol worktree cache were failed builds/fixtures,
not behavioral evidence. The regressions ran against the assembled root checkout.

INT-01 is not closed: private network/topology generations, partial composition
cleanup, repeated configured-cycle restart and aggregate shutdown bounds remain.
Shutdown now waits for current storage work, including provider budgets up to
two minutes. No new forced abort, fixed sleep or timeout increase was introduced.

## Tasks 10/27 — Linux directory durability prerequisite

On 2026-09-14 the provided clean Linux checkout was fast-forwarded from
`3e3c3060` to PR #269's merge `fcd65853`; both Git fetch and the GitHub branch
API confirmed that remote main had no later commit. The three failed headless
tests recorded on that PR remain unresolved. Its owner-approved checkpoint merge
did not close Stage 10 or supply passing integration evidence. Earlier Stage 4
pack lifecycle and Stage 5 mesh-wide reuse gaps remain tracked once in task 17;
Stage 9's integrated exit evidence still needs reconciliation.

The initial offline-backup test could not build because `web/dist` was absent.
The prescribed `pnpm build:daemon` then passed with NVM Node **26.8.2**, pnpm
**11.19.0**, Rust **1.98.0** and four Cargo build workers: web **0.485 s**, Rust
**97 s**. The focused headless run on the unchanged source failed in **18.88 s**
(test build **13.51 s**) before backup capture: its storage folder remained
`configuring`. Failure state is retained at `/tmp/.tmpz4sbZs` on this host.

The existing `meshspan-storage` regression
`folder::tests::registration_preserves_siblings_and_identity_survives_path_move`
reproduced `EBADF` in **0.00 s** (build **5.00 s**). Linux capability directories
use `O_PATH`; duplicating that descriptor does not make it fsync-capable. Folder
publication now opens `.` readably through the held capability and fsyncs that
same directory. It neither resolves an ambient pathname nor suppresses a failed
flush. All **51 storage tests passed in 0.17 s**, build **1.31 s**, including
restart, path movement, corruption, guarded deletion and CoW reclamation.

The same defect in backup-object rename/unlink was independently reproduced by
`directory_provider_tests::exact_stream_survives_restart_replays_and_retires_once`
in **0.00 s** (build **3.83 s**). Applying the same capability-relative readable
open passed all **21 backup tests in 1.49 s**, build **0.64 s**. Tests used four
harness workers. Workspace Rust formatting and diff checks passed. Affected
storage/backup all-target/all-feature Clippy passed with warnings denied in
**3.40 s**. The real offline recovery rerun reached the later storage cleanup
workflow but failed in **109.86 s** (build **9.48 s**) because the storage node
rejected the newly enrolled cleanup peer as unknown. State is retained at
`/tmp/.tmpIg8wOS` and `/tmp/.tmpnYbkMD`. Read-only inspection confirms the storage
replica lacks that enrolled node, while both gateways retain it; the cause of
stalled catch-up is under investigation. This is not passing recovery evidence.

The original zero-root failure was then reproduced in **17.85 s**, build
**3.25 s**, by making the existing fixture await the protected startup archive
before creating its file. The old selection then predictably exported that
earlier empty archive. The fixture correction is being verified separately;
the Linux directory-sync correction does not claim to close it. The update
handoff filter selected **zero tests** on GNU Linux: its existing compile-time
gate requires macOS or musl, and this host currently has only the GNU Rust
target and no musl C compiler. Neither update failure has passing evidence.
The complete integration gate remains pending.

The recovery fixture now requests a fresh automatic capture after the strong
file upload and requires that exact-or-later schedule sequence. It deliberately
finishes the startup archive first and requires a different backup identity;
the existing root/manifests/content assertions are unchanged. The shared capture
helper has a general name and all its callers use it. The corrected run passed
the formerly failing history checks, then reproduced the later unknown-peer
cleanup failure in **93.46 s**, build **0.13 s**. The full test is still failed;
state is retained at `/tmp/.tmpkDjJ71` and `/tmp/.tmpdhR7ck`. No full-suite retry
was used to mask either defect.

One signed progress-commit attempt for the Linux directory correction failed:
the configured 1Password signer reported `failed to fill whole buffer`, and Git
reported `failed to write commit object`. No commit, push or merge occurred.
The staged Linux fix/evidence and separate recovery-fixture edits are preserved
on `codex/stage10-recovery-update-regressions`. Signing was not retried or
disabled; owner restoration of signing access has been requested. External and
physical acceptance infrastructure is expected later per the owner, not tested
or claimed available now.
Final daemon all-target/all-feature Clippy passed with warnings denied in
**52.23 s** on the corrected fixture tree. Rust formatting, both changed-document
format checks and staged/unstaged diff checks passed. The root `pnpm exec
prettier` lookup was unavailable; document checks used the already installed
web-package formatter under NVM. All test and check processes have completed.
No dependency, schema, protocol, licence or durability requirement changed.
Task estimates remain **Stage 10: 81; Stage 11: 126/not started**. No release,
tag, package/image publication or GitHub Actions ran.

### Signing retry — authorization prompt timed out

After the owner requested another attempt, the configured 1Password signer was
retried once for the staged Linux directory fix. It again returned `failed to
fill whole buffer`; Git created no commit. Read-only inspection found that the
local SSH agent responds and advertises the exact configured Ed25519 signing
key. The 1Password application log identifies an SSH authorization prompt timeout;
earlier attempts also recorded a background prompt waiting in the tray. The owner
reported seeing no request. Signing configuration remains intact, the staged fix
is preserved, and no unsigned fallback, push or merge occurred.

With 1Password in the foreground, the next owner-coordinated attempt succeeded:
`61c698342f9ef874a6b42c073f52d9eb5714d707` contains the two Linux directory
corrections and their initial evidence. `git verify-commit` reports a good SSH
signature. The progress branch was pushed, `git ls-remote` confirms that exact
head, and GitHub's commit API reports `verified: true`, reason `valid`. Remote
main remains `fcd65853`; nothing has been merged. The later recovery fixture
corrections and additional evidence remain separate uncommitted work.

### Storage-replica restart diagnosis — not closure

Disposable SQLite backups of retained failure state replayed successfully from
index **28/epoch 2** through **54/epoch 4**, then from **36/epoch 2** through
**62/epoch 4**, including each joint/stable boundary. Original retained databases
were opened read-only for copying. This narrows the live failure; it does not
prove the daemon worker performs that catch-up.

A test-only diagnostic used the storage node's installed identity to request its
exact missing page from the still-running recovered gateway. The recovery test
still failed in **105.13 s**, build **5.01 s**, while that fresh authenticated
fetch succeeded with five entries. State is retained at `/tmp/.tmpQPR6rH` and
`/tmp/.tmpbKmw60`. Temporary worker tracing then reproduced the failure in
**113.07 s**, build **9.48 s**, with a fresh fetch of eight entries succeeding;
state is retained at `/tmp/.tmpwbr8VV` and `/tmp/.tmpsH71xH`. Live worker tracing
showed advancement through index 36 before restart; diagnosis is continuing at
the worker startup/source-selection boundary. No production catch-up correction,
longer readiness deadline or passing full recovery is claimed.

Further trace-only runs failed in **115.46 s** (build **8.11 s**, retained
`/tmp/.tmpOZqHIE`, `/tmp/.tmpxm2clH`) and **125.68 s** (build **20.22 s**,
retained `/tmp/.tmp7dY4cV`, `/tmp/.tmpHYc0w0`). They confirmed that the storage-only
worker reopened correctly and began a fetch immediately before gateway death.
An attached debugger was unavailable under the host's ptrace policy; temporary
source tracing supplied the required observation instead.

The final diagnostic deliberately retained the original failure after observing
35 more seconds; it remained failed in **158.16 s**, build **3.76 s**. Its trace
showed the outstanding fetch reaching the existing **30-second** protocol
deadline, then automatic catch-up from index **36** to **62**, crossing both
joint/stable membership changes. A fresh fetch then returned zero entries at
epoch 4/index 62. State is retained at `/tmp/.tmp7Qy3hI` and `/tmp/.tmpUQdv2g`.
This explains the apparent stall: the cleanup fixture's generic 15-second routing
allowance expired before the interrupted history request's accepted deadline.

Only the post-restart fixture readiness budget now includes one existing history
transfer deadline plus its normal routing allowance. It still requires successful
real shard read, exact bytes and all unchanged cleanup/restart assertions. The
production deadline, retry policy, authentication and consensus rules are
unchanged. All temporary tracing, the delayed-failure observation and the scratch
example were removed before the corrected focused run. This is an evidence-led
fixture correction, not a claim that a longer wait fixes a production defect.

The corrected fixture's first run failed earlier in post-restart checks with an
unlabelled timeout in **137.53 s**, build **27.61 s**, before new-peer cleanup.
State is retained at `/tmp/.tmpDFwg1i`: both databases retain storage certificate
generation 2; the gateway is in term 4 while the passive replica remains at its
term-3 frontier. Certificate-handshake and returning-node-rejection timeouts now
identify their operation. This separate failure is not explained or closed by
the catch-up deadline finding. The full corrected workflow remains unverified.

The next corrected full offline recovery run **passed in 139.28 s**, build
**4.74 s**, with four test threads. It exercises the fresh post-upload export,
all original offline-verification/history/content checks, replacement services,
renewal and identity rejection, then exact committed cleanup and receipt replay
through both interruption windows while preserving original/new file bytes.
The added timeout messages do not alter either affected operation's deadline or
success criteria. This passing run does **not** explain the preceding
137.53-second timeout; its retained state remains an open reliability observation
for Stage 10/Stage 11 task 14. The other two PR #269 update tests still have no
passing proof on this GNU-only toolchain. No full integration gate ran.

Affected daemon all-target/all-feature Clippy passed with warnings denied in
**6.41 s** after removing diagnostics. Fresh `pnpm check:licences` under NVM
passed Rust licensing and **9 production / 28 tool-only** JavaScript packages.
Rust formatting and staged/unstaged diff checks passed. No dependency was added
or changed; project licensing remains `GPL-2.0-only`.

### Federation deadline diagnosis after the failed gate

A daemon-library run with four test threads and test-only error context reproduced
the federation failure in **72.70 s**, build **44.19 s**: the store after the
independent interruption proofs rejected `capability deadline elapsed`. The run
had **438 passing / 2 failing** tests; the additional failure was
`backup_provider_snapshot_is_independent_of_storage_maintenance_lock`, returning
`Unavailable`. Its cause is being isolated separately. The diagnostic log is
`/tmp/meshspan-federation-diagnostic-lib.log`.

The federation fixture created its five-second store context before allocation
setup, routing, the stalled-upload proof and the separate lost-result recovery
proof. The correction starts each attempt's existing five-second allowance when
that attempt is ready to run. It preserves the operation/object identity and
still replays the successful request exactly. No production deadline or authority
check changes. Verification is pending; neither this diagnosis nor the earlier
isolated passing retry closes the integration gate.

The corrected daemon-library run passed **440 tests in 38.10 s**, build
**19.99 s**, with four test threads. The federation regression passed. The
storage-maintenance snapshot test also passed, but its previous `Unavailable`
remains unexplained; its startup-wait failure now reports the observed time and
deadline. This diagnostic does not change its five-second allowance or lock
assertions. Affected all-target/all-feature daemon Clippy passed with warnings
denied in **5.52 s**; Rust formatting and diff checks passed. The complete gate
must be rerun on the corrected candidate before integration.

### Tasks 22/24/27 — local musl validation tooling

The Linux host had no musl compiler and passwordless system package installation
was unavailable. A local tool cache now contains the official `extra/musl`
**1.2.6-2 x86_64** package, downloaded from the configured Arch mirror. Its archive
SHA-256 is `476173e159e6eafb918bbeb804e322b51d2ad8cdd64ffb577e180d8ebfb3942c`.
The detached package signature verifies against the installed Arch keyring, using
key `C5D2A6E0ED2D11C66B9FA2A306313911057DD5A8`. The keyring first required dearmoring;
that initial verification attempt did not succeed and was not treated as trust.

Only the extracted compiler wrapper/specification paths were relocated beneath
`/home/karl/.cache/meshspan-validation/musl/root`. No system package or repository
toolchain configuration changed. The package retains its upstream MIT/permissive
copyright notices. A compiled C smoke executable is inspected as static x86-64
ELF and executes successfully. Rust's `x86_64-unknown-linux-musl` standard-library
component was installed for the repository's existing **1.98.0** toolchain.

This prepares the environment; no MeshSpan musl build, update handoff, packaged
acceptance or publication has yet run. The active GNU integration gate owns the
Cargo lane. Complete package notices must also cover the actual linked compiler/
standard-library components, beyond the current Cargo/npm source scan; this is
part of task 24's remaining dependency inventory, not a waived requirement.

### Corrected full local gate — three later headless failures

The next NVM `MESHSPAN_CHECK_WORKERS=4 CARGO_BUILD_JOBS=4 pnpm check` failed in
**587.50 s**; its Rust lane ran **546.13 s**. Executable/test source was commit
`2e3e6952`; the later `6efa9d0d` changes only evidence prose. All **440 daemon
library tests passed in 37.07 s**, including the corrected federation test.
Headless execution reached **27 passed / 3 failed / 11 ignored in 355.78 s**.
Offline recovery passed; later Rust targets were not reached.

Failures and retained local state:

- `federated_backup::remote_backup_forwards_through_gateway_to_distinct_storage_process`:
  scheduled capture remained `Recorded`, without its required protected result.
  State: `/tmp/.tmpx0lBPz`, `/tmp/.tmpYPOX5v`, `/tmp/.tmpBH9flI`.
- `incarnation::successor_incarnation_restarts_serves_files_and_accepts_a_new_peer`:
  HTTPS setup never reached `configured`; its last attempt was connection refused.
  State: `/tmp/.tmpe6cV5u`, `/tmp/.tmpjbq4bB`.
- `updates::real_signed_executable_passes_runtime_probe_and_retains_staging_after_restart`:
  signed executable upload exceeded the fixture's 60-second timeout.
  State: `/tmp/.tmpVDhvzL`.

Generated contracts **1.79 s**, embedded web **0.77 s**, Rust formatting **3.13 s**,
workspace Clippy **5.37 s**, Rust licences **0.40 s**, JavaScript licences
**1.04 s**, workspace formatting **3.91 s**, web lint **29.91 s**, web typecheck
**7.57 s**, tooling tests **0.64 s**, and web tests **17.76 s** all passed.
The log is `/tmp/meshspan-stage10-corrected-integration.log`. This is a failed
integration candidate. Draft PR **#270** remains unmerged; every pushed commit
has a locally verified and GitHub-verified signature. No publication occurred.

Read-only retained-state inspection finds valid SQLite integrity on both
incarnation nodes and the upload fixture. Both incarnation databases contain
35 log entries and the same admitted node incarnations (root 2, peer 1), narrowing
the failure to later startup/readiness rather than absent node admission. The
upload left **138,205,784 bytes** in its temporary artifact; the debug executable
is **674,825,752 bytes**. The production upload allowance is 30 minutes while this
fixture allows 60 seconds. These are diagnostic leads, not yet explanations or
fixes. A musl headless build is now running so the original two handoff failures
can finally be exercised on a supported platform; no source changes accompany it.

### Static musl execution and focused preparation diagnosis

The first musl headless build compiled in **3m 32s**, but the locally configured
musl compiler wrapper inserted an external ELF interpreter into Rust's static-PIE
link. The test executable could not launch (`No such file or directory`); no
handoff test ran in that attempt. A standalone Rust smoke executable using Rust's
standard linker path was static PIE and ran without an interpreter. Removing only
the local Cargo linker override rebuilt MeshSpan in **1m 36s**. `file` and
`readelf` confirm static PIE with no `INTERP` or `NEEDED` entries. The C compiler
remains the signature-verified local musl wrapper; repository configuration and
source are unchanged by this tooling correction.

All three musl handoff tests then **ran and failed in 47.93 s**, build **0.17 s**:
the single-copy safety scenario lacked its expected workload observation; both
original two-node scenarios failed earlier because the enrolled peer never became
available over HTTPS. Retained state is `/tmp/.tmpfa9RiW`, `/tmp/.tmppUPHDv`,
`/tmp/.tmp2NlX8P`, `/tmp/.tmpAwfK4V`, `/tmp/.tmpbzrMo4`. The two original PR #269
handoff failures still have no passing proof.

The isolated single-copy scenario also failed in **30.15 s**, build **0.09 s**,
retaining `/tmp/.tmpbMMCQA`: the node was still pending and had advertised no
artifact source. The read-only `verify-update` command authenticated that exact
fixture manifest/signature/public signer and **654,393,664-byte** executable in
**9.68 s**, without opening live mesh state. Public verification inputs are at
`/tmp/meshspan-update-verification-2347tqjl`.

A temporary test-only diagnostic deliberately preserved the original failure
while observing 45 more seconds. It remained **failed in 46.14 s**, build
**35.03 s**; the exact safe observation appeared **14.51 s after** the original
15-second allowance. It still reported `restart_authorised: false`, one excluded
target and the expected unavailable local content. State is retained at
`/tmp/.tmpgQOiD5`; log `/tmp/meshspan-musl-workload-late-observation.log`.
The next diagnostic is measuring durable source/staging milestones before choosing
a fixture or product correction. No verification, timeout or safety requirement
has been weakened to produce a pass; temporary diagnostics are not integration
changes and must be removed before final checks.

The second failure-preserving diagnostic recorded source advertisement at
**13.69 s**, staging at **26.29 s**, and the exact safe observation at **30.48 s**
after selection. It remained failed in **45.97 s**, build **28.86 s**, retaining
`/tmp/.tmpZC6voM`; log `/tmp/meshspan-musl-workload-milestones.log`. Thus each
verification made durable progress within the ordinary allowance, but the
combined preparation exceeded the fixture's single allowance.

The corrected workload waiter renews its existing **15-second** allowance only
when the exact active rollout's verified-source or staged-node count increases.
Progress is monotonic and capped at two advances per declared participant. The
original expected workload, excluded-target, restart refusal and exact file-byte
assertions remain. After correcting a `PageLimit` argument type before execution,
the focused single-copy test **passed in 45.69 s**, build **29.21 s**. Log:
`/tmp/meshspan-musl-workload-progress-fix.log`. A three-scenario run is checking
this under bounded parallel load while retaining any missed peer-startup deadline
as a failure and observing the peer's process state and later readiness.

### Task 22 — bounded real-artifact preparation and handoff

The progress-renewal trial above did not close the defect under parallel load:
all three scenarios failed in **57.18 s**, build **31.98 s**. Initial source
verification itself exceeded 15 seconds; both workload waiters observed zero
preparation progress. The installation scenario remained pending, while both
private readiness probes reported ready at index 32. Log:
`/tmp/meshspan-musl-handoff-peer-diagnostic.log`. No new peer-startup failure
occurred in that run; earlier startup failures remain unexplained.

A subsequent read-position diagnostic was invalidated by `/tmp` tmpfs exhaustion
and resulting `ENOSPC`/identity-file failures. It supplies no product conclusion.
Nine known completed failure fixtures were archived under
`/home/karl/.cache/meshspan-validation/failure-state`, retaining their original
`/tmp` names as symlinks. All retained artifact digests were checked; the mapping
is `failure-state/locations.json`. This relocation preserves diagnostic contents,
not physical inode/location evidence. New tests use the private disk-backed
`/home/karl/.cache/meshspan-validation/tmp` directory.

The same three scenarios then failed on disk-backed scratch in **43.64 s**,
build **0.33 s**. A read-only `/proc` file-position trace showed five workers
actively hashing the 654,393,664-byte executable at approximately **29.5–38.7
MiB/s**. They had reached only **412–519 MB** when the 15-second waits stopped
them. The log and trace are `/tmp/meshspan-musl-handoff-disk-scratch.log` and
`.jsonl`. This establishes ongoing mandatory artifact verification, rather than
an absent worker or stalled state machine.

Artifact upload, preparation, installation and cold-launch readiness now each
have one fixed **30-minute** maximum, matching the existing production bulk
transfer allowance. Durable progress remains diagnostic and cannot extend it.
Ordinary control/startup waits retain 15 seconds. Mandatory cache hashing,
signature authentication, executable probing, exact process images, preparation
identity, single-copy restart refusal and byte comparisons are unchanged. No
production deadline or verification was changed, and temporary tracing was removed.

All three musl handoff scenarios **passed in 262.54 s**, build **20.92 s**, with
four harness threads. This includes both originally failed PR #269 scenarios:
the peer reported the exact preparation; both processes installed and verified
the selected image; launching the original command retained that installation.
The single-copy test kept its file online and denied restart. Log:
`/tmp/meshspan-musl-handoff-artifact-operation.log`. A discarded partial-edit
attempt was interrupted before producing a usable result and is not validation.

The final review additionally binds HTTP polls to the same absolute deadlines,
so a stalled request cannot escape a waiter's maximum. Clippy first caught an
explicit standard-library/Tokio instant conversion missing from the new wrapper;
that was corrected before execution. Final musl all-target/all-feature Clippy
passed with warnings denied in **3.91 s**. All three final handoff scenarios then
**passed in 266.38 s**, build **21.41 s**, with four threads; log
`/tmp/meshspan-musl-handoff-final.log`. These focused passes do not close earlier
peer-startup observations, the later GNU gate failures, availability-preserving
coordination, packaging or assembled Stage 10/11 acceptance. No points are removed.

### Tasks 22/27 — GNU upload and native Linux SMB follow-up

The focused GNU run selected the three later headless failures together, with
four threads and disk-backed scratch. It finished **2 passed / 1 failed in
262.34 s**, build **10.35 s**; log `/tmp/meshspan-gnu-three-regressions.log`.
Federated backup protection/permission succession and successor-incarnation
HTTPS/new-peer admission passed. Their earlier failures remain unexplained.
Read-only local setup records additionally show the previously failed peers had
completed join setup; startup investigation is therefore after that durable step.

The complete **672,385,840-byte** GNU executable uploaded successfully beyond
the old 60-second allowance. A later, separate 15-second staging-status wait then
failed while the rollout remained pending. This GNU scenario must reject the
non-distribution target, not install it. Retained state is
`/home/karl/.cache/meshspan-validation/tmp/.tmpxG0UKn`. A failure-preserving
observation is measuring completion after that original staging deadline; no
production verification or deadline has changed.

The repository's existing `tests/smb-client/Dockerfile` built locally against its
pinned Debian base. The immutable local image ID is
`sha256:4282e160c6cc3090ee59f3b2581ee7a459fdd3f943323b7583824ea30a618eb0`;
its client reports **Samba 4.17.12-Debian**. Docker **29.8.0** runs natively on
this CachyOS host. Build log: `/tmp/meshspan-local-smbclient-build.log`. This is a
test-client image, not a MeshSpan package or publication.

Both a container hostname lookup and the unchanged successor SMB test fail
because native Linux Docker does not provide the fixture's expected
`host.docker.internal` route to the host loopback listener. The real test reports
`NT_STATUS_UNSUCCESSFUL`, retaining `.tmpeH39af` and `.tmpgvWisS` below the
private disk scratch directory. The combined diagnostic is still running at
this entry; log `/tmp/meshspan-gnu-staging-and-smb-diagnostic.log`. The intended
fixture correction uses native Linux host networking with an explicit loopback
hostname mapping. Protocol, authentication, file-byte and restart assertions stay
unchanged; passing SMB evidence is still pending.

The failure-preserving combined diagnostic finished **0 passed / 2 failed in
235.89 s**, build **3.47 s**. GNU verification completed **12.16 s after** the
original 15-second staging wait: state `paused`, sequence 2, one failed node,
zero staged/restarting/verified nodes. The original failure remains in the result;
state is retained at `.tmp822OEU` in disk scratch. The temporary observation was
removed before the correction.

The artifact staging-status waiter now uses the same fixed 30-minute artifact
allowance and bounds each HTTP poll by that absolute deadline. The Linux-only
SMB client fixture uses Docker host networking and maps the existing hostname to
127.0.0.1; daemon listen addresses and all protocol/file assertions are unchanged.
Final GNU all-target/all-feature daemon Clippy passed in **5.30 s**. The corrected
real SMB successor workflow has passed; the concurrent full GNU artifact upload/
compatibility-refusal test is still running. No full gate or merge is claimed.

The corrected pair **passed in 245.12 s**, build **5.57 s**, with four threads:
GNU upload reached its required compatibility refusal, and the real SMB successor
performed reads/writes/deletes with the existing assertions. Log:
`/tmp/meshspan-gnu-artifact-smb-final.log`. Final musl daemon all-target/all-feature
Clippy also passed in **1.53 s**. A six-case musl acceptance run is now checking
successful real-artifact staging, three-node distribution, SMB authentication
metrics, offline HTTPS/SMB recovery, three-gateway SMB and the six-process
protection fixture. It is pending, not passing evidence. The six-process fixture
is not a physical-machine proof. The complete integration gate still must pass
before any merge; no dependency, schema, protocol or production deadline changed.

### Tasks 22/27 and Stage 8 — broader musl acceptance

The final six-case musl run finished **5 passed / 1 failed in 346.16 s**, build
**21.02 s**, using four threads. Log:
`/tmp/meshspan-musl-artifact-smb-acceptance.log`. The source was subsequently
committed as **960fe0f4**, signed and pushed; both `git verify-commit` and GitHub
report a valid signature, and the remote branch matches that commit. PR #270
remains draft/unmerged.

Passing workflows are successful real-executable staging with exact retained
report after restart; three-daemon signed artifact distribution/restart;
real SMB authentication-rejection metrics/restart; three-gateway SMB file work;
and offline recovery through HTTPS and real SMB, storage restart and cleanup
interruption windows. These are development-binary, local-process proofs.

The six-process protection fixture failed during `configured` setup at
127.0.0.1:16412: an in-flight HTTP request reached the absolute 15-second deadline.
It did not reach the protection assertions. Its old cleanup dropped failed
fixture directories, so this run has only the log, not retained databases.
The fixture is being changed to use the existing failure-retention helper and
label the joining node. Temporary startup/listener-phase timing is being used
with the six-process and three-gateway workflows; it must be removed before
final checks. No startup allowance is increased and no full gate has been rerun.

### Task 27 / Stage 8 — strong publication confirmation and retained visibility failure

Startup-phase diagnostics did not reproduce the earlier HTTP readiness failure:
all six joining listeners became ready in approximately 9–12 seconds, with
listener binding and spawning taking approximately 1 millisecond. The diagnostic
pair nevertheless failed both workflows in **69.74 s**: three-gateway SMB file
visibility and the six-process strong HTTPS upload. Log:
`/tmp/meshspan-stage8-startup-diagnostic.log`. Temporary startup tracing was
removed; the six-process fixture now retains all failed directories and labels
the joining node. The original readiness failure remains unexplained.

The strong upload returned HTTP 503 despite all eight required shard receipts
and a committed local content publication. Retained databases passed SQLite
integrity checks. The root had committed the exact publication through its
background publisher at log index 119; the uploading gateway held that entry
but had applied only through 118. Its competing foreground proposal returned a
conflict before local application exposed the already committed outcome.

The foreground strong barrier now uses the catalogue's persisted strong cutoff
to await only the exact committed publication history after a retryable proposal
error. It neither resubmits the proposal nor treats the error as success. Missing
or expired cutoffs grant no additional wait, and retries cannot renew the cutoff.
The acknowledgement class, required receipts, authority proof and fallback policy
remain unchanged. There is no schema, wire or dependency change.

The catalogue's exact-reference, persisted-cutoff and existing publication cases
passed **14 tests in 1.42 s**. The daemon's background-first/later-head authority
regression passed **1 test in 1.21 s**, build **22.81 s**. An earlier incorrectly
qualified filter selected zero tests and supplies no evidence. Subsequent Clippy
caught the expanded catalogue test's function length; its independent pending/
failure policy case and explicit eventual-receipt case are now separate tests.
Final affected lint and the corrected test inventory remain pending here.

With the strong-barrier correction, the focused six-process workflow completed
its strong HTTPS upload and origin SMB write/read, then failed on another
gateway's file visibility: **73.45 s**, build **70 s**. Log:
`/tmp/meshspan-stage8-strong-confirmation.log`. All six replicas held the final
committed metadata head; the failed reader still lacked 97 and 110 immutable
bodies in two ongoing 209-record import sessions. This is an incomplete namespace
transfer at the fixture's 15-second observation cutoff, not evidence of a missing
committed authority head. A failure-preserving late-observation diagnostic is in
progress; no fixture allowance or production transfer deadline has been increased.
No complete gate, merge, publication or physical-machine proof is claimed.

The failure-preserving diagnostic then passed the isolated six-process workflow
in **66.04 s**, build **33.18 s**, and the paired six-process/three-gateway
workflows in **83.89 s**, build **0.08 s**, with four harness threads. Neither run
entered the late-observation window. Logs:
`/tmp/meshspan-stage8-visibility-diagnostic.log` and
`/tmp/meshspan-stage8-visibility-pair-diagnostic.log`. These passes exercise exact
HTTPS/SMB content and simulated two-node loss, but do not explain the earlier
visibility failure. The temporary late-observation diagnostic was removed;
startup and namespace visibility allowances are unchanged. The historical
readiness/visibility failures remain open; repeated passing retries are not
being used to close them.
The final catalogue inventory passed **15 tests in 1.18 s**; affected filesystem/
daemon all-target/all-feature Clippy passed in **1.15 s**, warnings denied.
Workspace Rust formatting and diff checks passed. These checks include removal
of the temporary diagnostic; no production edit followed the successful paired
proof. The complete local integration gate is still required before merge.

### Tasks 10/27 — complete gate reaches two stale metadata fixtures

Signed commit **bc581f7d23f39cb92be11b3642a32090156162fa** was pushed and
verified locally and by GitHub (`verified: true`, `valid`). PR #270 remains draft.
Its complete NVM local gate failed in **1283.52 s**, with four workers and
private disk-backed temporary storage. Log:
`/tmp/meshspan-stage10-publication-confirmation-integration.log`.

The gate passed generated drift, embedded web, workspace formatting, Rust and
web lint, TypeScript, both dependency licence checks, tooling and web tests.
All **440 daemon library tests passed in 44.77 s**, all **30 enabled headless
tests passed in 492.20 s** (11 ignored), and all **225 filesystem tests passed in 46.23 s**.
The later metadata library reached **560 passes / 2 failures in 417.03 s**;
subsequent Rust targets were not reached. Earlier unexplained timing failures
remain recorded; this pass is not their explanation.

Both metadata failures reproduced together in **3.52 s**. The backup-root
fixture claimed schema 109 while retaining recovery objects from migrations
116–117. Its existing downgrade now removes those two tables and the activation
column before reopening; production migrations are unchanged. The v14 quota
fixture expected schema 15 although the current reader also applies migration 16. Its explicit expectation now includes that recovered-target migration,
while retaining exact pending charge, seal, replay and committed-usage checks.
Both corrected tests passed in **2.90 s**, build **7.12 s**. All **22 neighbouring
backup-root/quota tests passed in 22.67 s**; metadata all-target/all-feature Clippy
passed in **32.86 s**, warnings denied. Rust/document formatting and diff checks
passed before the signed progress commit.
No schema, wire, dependency or production behaviour changed in these two fixes.
The complete integration gate is still failed; nothing has merged or published.

### Task 27 — musl opt-in failures retained for focused transport diagnosis

Signed commit **47da63689ca295b05d127d1f5ab0120bb953258c** contains the two
metadata-fixture corrections and evidence. Local SSH verification, remote branch
identity and GitHub signature verification all passed. PR #270 remains draft.

The 13-case musl/all-feature opt-in run finished **5 passed / 8 failed in
737.82 s**, build **67 s**, with four harness workers. Log:
`/tmp/meshspan-musl-final-opt-in-acceptance.log`. Passing cases were successor
SMB IO, SMB authentication metrics, exact uninterrupted preparation, keeping the
only file copy online, and real executable staging/restart. Six failures reached
the unchanged 15-second setup HTTP deadline: backup takeover, three-gateway SMB,
six-process protection (joining node 5), offline recovery, two-process executable
replacement, and three-daemon artifact distribution. Failed directories were
retained; inspected backup-takeover databases pass SQLite integrity checks.
Both slow ACME cases reached certificate issuance at the test CA but failed the
gateway TLS-installation deadline. These remain separate open findings.

One remaining artifact upload was observed progressing from 612 MB to 639 MB of
the 654,325,096-byte executable before its successful completion; it was not
aborted or treated as hung. The host reports 20 CPUs and observed daemon thread
counts were 22–25; no thread limit or timeout was changed to obtain a pass.

A focused four-workflow run now adds temporary cancellation-safe transport
observations to setup-status requests: TCP connect, TLS handshake, request write,
and response/EOF, with byte counts and bounded framing metadata only. It keeps
the original deadlines and failure outcome, and must be removed before final
checks. This tests whether the shared failure precedes the HTTP response or waits
for TLS closure after a complete response. No diagnosis is claimed yet; no full
gate rerun, merge or publication has occurred.

### Full local gate — failed; no integration

`MESHSPAN_CHECK_WORKERS=4 CARGO_BUILD_JOBS=4 pnpm check`, under the configured NVM
toolchain, failed in **510.74 s**. The tested base is `fcd65853`; the binary diff
of `crates` against that base has SHA-256
`64dd51044cdb5feb2a60ad610cd7d0aaaaed1fbd88663f5b15e6f192a54e0487`.
Only evidence prose changed during/after the run. The local gate log is
`/tmp/meshspan-stage10-linux-integration.log`.

Generated drift (**19.21 s**), embedded web (**0.82 s**), Rust format (**3.85 s**),
workspace all-target/all-feature Rust lint (**51.18 s**), Rust licensing
(**0.62 s**), JavaScript licensing (**1.26 s**), workspace format (**7.42 s**), web
lint (**44.74 s**), web types (**14.01 s**), tooling tests (**1.65 s**) and web
tests (**22.35 s**) passed. No advisory scan was run by this non-dependency gate.

The Rust test lane failed in **390.31 s** at the daemon library: **439 passed,
1 failed**, target runtime **44.91 s**. The failing test is
`consensus_authentication_authority_tests::federation_pairing::connection::federation_connection_recovers_lost_approval_reply_over_real_tls`,
returning `DeadlineExceeded`. Headless tests and later Rust targets were not
reached. The previously passing focused offline recovery is not a passing full
gate and neither missing update proof is closed.

A focused local reproduction attempt passed in **8.08 s**, build **55.34 s**.
That retry does not resolve the failure. Current source shows the named pairing
test also exercises native QUIC sessions, allocation and backup IO; several
backup requests use five-second deadlines, including a store request constructed
before other setup/proof work. This is a diagnostic lead, not a confirmed cause
or justification to relax deadlines. No federation code or test assertion was
changed in response, and the full gate was not rerun while investigating.

The existing 1Password signing failure remains unresolved. No retry, unsigned
commit, progress push, PR, merge or publication occurred. Staged Linux durability
changes and separate fixture/evidence edits remain in the provided checkout on
`codex/stage10-recovery-update-regressions`. Stage 10 remains **81 points**, task
10 **3 points**, and Stage 11 **126/not started**.

### Earlier-stage prerequisite reconciliation

Current-source/evidence inspection retains Stages 1–3's completed audit and the
accepted pre-Stage-6 retrofit; it does not rerun their historical exit proofs.
Stages 4 and 5 remain reopened for pack lifecycle/reuse, tracked once in Stage 10,
task 17. Stages 6–8 have recorded integrated evidence, while their ignored real-SMB
proofs still require separate execution on a candidate. The Stage 8 process test
starts six local `ProcessFixture` children; the `protected_content` test uses
real temporary folders and a test router's `set_offline_many`. Its historical
wording is clarified accordingly: neither establishes physical six-host loss.

Stage 9 has repair/scrub/drain workers and component tests in current source, but
its roadmap exit requires seeded long churn plus those operations alongside real
HTTPS/SMB traffic. No dedicated Stage 9 exit log or equivalent consolidated proof
has been located. That acceptance remains open; component presence and Stage 8
read reconstruction cannot substitute for it. Stage 11's integrated candidate
requirements and physical/soak/reviewer gates also remain open. This review does
not change task estimates or start automatic Stage 12 sharding.

## Task 10 — storage-only startup and shard service

### Committed cleanup acceptance — in progress

The recovered-daemon proof now adds a fresh gateway, commits cleanup proposal,
attestation, inventory and permit commands through private RPCs, and checks
tombstone/reclamation receipts and restart replay. Its reachability evidence is
test-owned for an opaque shard never published in the namespace: this is not
automatic retention-scanner acceptance. Original and newly written HTTPS/SMB
files must remain readable afterwards.

The first run failed before cleanup, in **90.40 s**, build **11.52 s**. The HTTPS
enrolment error conflated TLS rejection with an HTTP rejection. Read-only
inspection of retained metadata showed that admission had actually committed
(join-grant consumption and pending activation at revision 39). The recovered
gateway fixture used a non-UUID node ID, rejected by outgoing bootstrap-response
validation. A focused check of the actual recovery fixture constants reproduced
the exact `/bootstrap_peers/0/node_id` pattern error in **0.02 s**, build **5.55 s**.
Correcting the fixtures to UUIDv8 passed that check in **0.02 s**, build **5.88 s**;
neither certificate pinning nor production response validation was relaxed.
The first corrected real workflow stopped in **59.04 s**, build **0.14 s**, on
two overlooked helper loops still constructing the previous fixture IDs. Those
lookups now apply the same UUIDv8 framing. This was incomplete fixture maintenance,
not a newly demonstrated production failure. The following run reached successful
new-gateway enrolment/configuration, then failed in **79.20 s**, build **5.22 s**,
because the cleanup helper derived the recovered leader ID from its replacement
key instead of reading the installed recovery identity. That helper now reads
`local.sqlite3`, as the storage IO helper already does. The expanded real workflow
is being rerun; successful cleanup is not yet claimed.

That run reached the cleanup command boundary and failed in **73.87 s**, build
**5.95 s**: `ProposeVersionCleanup` was not supported by the canonical command
codec. Direct repository tests had not exercised replication. Private command
version **18** now carries all nine cleanup transitions (kinds 126–134), including
cancellation, exact signed attestations, bounded inventories and provider receipts.
Existing command layouts and database schemas are unchanged. Three focused codec
tests passed in **0.01 s**, build **10.42 s**; all **46 codec tests** passed in
**0.15 s**, build **0.19 s**. Coverage includes every field, every truncation,
trailing bytes, an independent golden byte layout and count/range rejection before
placement allocation. Affected metadata/cluster/daemon all-target/all-feature
Clippy passed in **45.26 s**, warnings denied. The next integrated run failed in
**79.81 s**, build **33.69 s**, on a live authority rejection. Its assertion did
not identify the command and did not preserve the fixture. The helper now returns
a contextual error, retains the state and reports the command tag plus a
rolled-back typed preflight diagnostic. No production admission rule was weakened;
the diagnostic run failed in **73.68 s**, build **6.63 s**, identifying key
registration (kind 123) against revision 47 after unrelated certificate maintenance
advanced the root to revision 48. No attestation key was committed; rolled-back
validation returned `StaleRevision`. The test now handles the existing authority's
`Rejected/Invalid` mapping only when its operation is absent and the revision has
advanced. It rebuilds the command against a fresh view within the original bounded
deadline. Durable/unknown/unchanged-state rejections are not retried. This does not
change production error mapping or weaken any maintenance admission check.

The next run committed the proposal, both attestations, inventory and permit, then
failed on shard transport in **76.41 s**, build **5.39 s**. Retained metadata had
one permit and no completion/reclamation. The checkpointed provider journal had
no tombstone/removal intent. Membership had advanced to epoch 4 during enrolment;
peer hello readiness did not prove the epoch-fenced provider had reopened. The
helper now reads and verifies the actual opaque shard before beginning cleanup,
and names initial deletion versus replay transport failures. This is a readiness
check, not a claimed fix to the transport failure. That run failed in **88.52 s**,
build **6.22 s**, before cleanup because the actual shard never became readable.

On 2026-09-14, preserving the readiness error exposed
`Transport(Read(FinishedEarly(0)))` after successful peer connection. The real
workflow failed in **100.48 s**, build **138 s**. Read-only inspection of the
retained database identified the cause: storage-permit generation 2 included the
storage-only node, but gateway enrolment produced generation 3 with only gateway
and recovery recipients. `redistribute_cluster_secrets` incorrectly reused the
volume-key recipient policy for storage-permit keys. The provider could no longer
load the latest key; transport readiness was not the missing safety condition.
An isolated metadata regression reproduced the missing-recipient acceptance in
**0.40 s**, build **66 s**. Permit redistribution now selects active gateways,
active/draining storage nodes and the verified recovery recipient; metadata
requires that exact set. Dual-role nodes are counted once and gateway-only secret
selection remains separate. All **9 secret-generation tests passed in 8.42 s**,
build **10.64 s**, including decryption by the storage-only recipient, failed
omission rollback, draining retention and metadata-only exclusion. Initial lint
identified a needless owned argument and a test assertion style issue; both were
corrected without exposing secret bytes or adding suppressions. Affected
metadata/daemon all-target/all-feature Clippy passed in **33.64 s**, warnings
denied. The real recovered-daemon cleanup workflow then **passed in 89.14 s**,
build **34.67 s**: gateway enrolment preserved storage access; authorised
tombstone/replay succeeded; premature reclamation was explicitly denied; committed
completion enabled reclamation of exactly **8192 bytes**; restart returned the
identical reclamation receipt; original/new HTTPS and SMB files remained readable.
This resolves the prior transport failure. The next extension interrupts the
storage daemon before tombstone completion and before reclamation accounting.
It failed in **77.39 s**, build **5.96 s**, on exact tombstone replay after restart.
The provider reopened against catalogue revision **64**, while the already
executed permit named revision **57**. Its freshness check prevented returning
the durable receipt, not just new deletion. An isolated restart regression
reproduced this in **0.06 s**, build **9.70 s**. Receipt resolution now checks the
exact committed journal/tombstone/inventory evidence in a read transaction before
the new-effect catalogue fence; MAC, epoch, expiry and identity checks still run
first. Prepared/missing operations cannot take that path. All **51 storage tests
passed in 2.23 s**, build **7.35 s**, including stale-new-deletion and forged/epoch
rejection with retained shard inventory and capacity unchanged. The expanded real
interruption proof then **passed in 127.85 s**, build **29.11 s**. It kills the
storage process after tombstone durability but before metadata completion, and
again after physical reclamation but before metadata accounting. Both exact
receipts replay across restart, premature reclamation remains denied, and a
further restart after accounting preserves the receipt. Original and new files
remain readable through real HTTPS and SMB clients. These are abrupt process-loss
checks at acknowledgement boundaries, not physical power-loss or arbitrary
instruction-level crash coverage. Storage-only health still reports degraded;
backup reclamation and the broader recovery/operational gates remain open.
Final focused checks passed on this candidate: **51 storage tests in 2.19 s**
(build **8.25 s**), **9 metadata secret-generation tests in 11.61 s** (build
**14.38 s**), **3 daemon permit-loading tests in 0.03 s** (build **49.13 s**), and
affected storage/metadata/daemon all-target/all-feature Clippy in **40.37 s** with
warnings denied. Workspace Rust formatting, changed-document formatting under
NVM **26.8.1** / pnpm **11.19.0**, and `git diff --check` passed. The complete local
integration/dependency-update gate has not run. No additional points are claimed;
no Git mutation or publication occurred.

This proof adds the existing workspace `ed25519-dalek` dependency to daemon
dev-dependencies to sign real cleanup attestations, with no new package/version
or runtime dependency. The licence gate passed and affected all-target/all-feature
Clippy passed in **21.18 s** before the fixture correction. The full
dependency-update/integration gate has not run on this candidate. No publication
or Git mutation occurred. Task 10 remains **3 points**.

### Storage-only committed cleanup admission

The passive storage service now composes the private read-fence endpoint with
its retained catch-up handle. Before touching a provider, it validates the request
and current peer, requests a fresh nonce-bound quorum frontier, waits for local
application outside provider locks, and checks the exact entry digest, active
plan, current sender/recipient identities, target ownership/generation and cleanup
record in one database read view. Historical watch progress never grants authority.
Requests have a bounded local admission budget and keep the existing cleanup-wire
deadline ceiling. Shutdown prevents provider admission; outstanding discovery is
owned and bounded by its existing 30-second deadline.

Tombstone requests must equal the latest committed permit, including epoch and
expiry. Physical reclamation requires the exact committed tombstone completion;
post-unlink reclamation accounting cannot be a precondition for unlink. Rejected
maintenance returns the existing typed wire outcome without calling a provider.
Federated maintenance and backup reclamation are not enabled by this path.
Provider configuration now reopens on an applied membership-epoch change, as it
already did for permit-key changes; existing clones keep their immutable fences.

The exact applied-entry reader is a bounded primary-key lookup rather than a
full-log recovery read. Its regression passed **1 test in 0.42 s**, build **9.21 s**,
covering unapplied/wrong-term records, corruption, oversized input, reopening and
both primary-key searches in the query plan. Cleanup lookup passed **1 test in
0.37 s**, build **20.54 s**, covering missing operations, exact permit/completion
and reopening. It reuses existing sealed-inventory validation, which still
includes an aggregate inventory count; this is not a claim that the entire
cleanup read is constant-time.

The daemon's focused admission suite passed **3 tests in 0.34 s**, build **54.57 s**,
covering exact frontier/application, phase and request substitution, permit
ownership/expiry and completion-before-reclamation. Initial affected lint found
four ownership/signature issues, then two missing test semicolons; these were
corrected without suppressions. Final lint and the expanded real HTTPS/SMB recovery
acceptance are pending below. The latter now requires explicit rejection of a
gateway's valid-MAC deletion with no committed cleanup and verifies unchanged
shard bytes before/after restarts.

The expanded real recovery workflow passed **1 test in 78.95 s**, build **41.65 s**:
HTTPS/SMB original and new-file bytes survive renewal and both abrupt restarts,
and the valid-MAC/no-commit deletion receives exactly `Unauthorised` while retained
shard bytes remain unchanged. The final affected all-target/all-feature Clippy
passed in **20.18 s**, warnings denied. Broader metadata cleanup regressions passed
**40 tests in 45.94 s**, build **7.08 s**, including the new superseded-permit lookup.
Final daemon admission tests passed **3 in 0.36 s**, build **14.00 s**; the shared
discovery tests passed **3 in 0.51 s**, build **0.13 s**, covering retry, rejection
and owned cancellation after generalising its result type. Full data-plane and
existing real-QUIC cleanup contract checks remain pending below.

Those final checks passed: the full data-plane run covered **10 tests** (6 library,
2 process, 1 remote-backup and 1 remote-shard), build **28.23 s**. Suite runtimes
were **0.00/0.87/0.33/0.32 s** respectively; doc-tests had no cases. The existing
real-QUIC cleanup contract suite passed **2 tests in 0.36 s**, build **35.16 s**,
including exact provider receipts and follow-up commands. That harness does not
run the storage-only daemon's metadata admission and therefore does not close its
successful committed-cleanup acceptance gap. Rust formatting, NVM-managed document
format checks and `git diff --check` passed. All test processes were observed to
completion; no full integration gate or signing attempt was made.

Storage health remains **Degraded**. Successful committed cleanup/reclamation,
quorum-loss interruption, operational admission and the other task-10 acceptance
items still need their integrated evidence. Task 10 remains **3 points**;
Stage 10 remains **81 points**, Stage 11 **126/not started**. No full `pnpm check`,
Git mutation, signing retry, dependency change or publication occurred here.

### Fresh-authority read prerequisite

Inspection before enabling storage-only privileged maintenance found that the
reactor discarded `ReadBarrierReady`, while the core allowed a newly elected
leader to confirm a read before establishing its current-term committed frontier.
The new deterministic regression failed in **0.00 s**, build **3.62 s**. The core
now holds that read until current-term commitment and local application; all
**30 consensus tests passed in 4.59 s**, build **7.04 s**.

The metadata reactor now owns bounded, deadline-limited, cancellable read requests
and returns an exact applied frontier rather than a local observation. Its first
read in a term without a current-term entry proposes a fixed no-op; later reads
do not append. Metadata persistence and passive replicas apply that no-op without
changing application revision, creating user receipts or manufacturing audit
actors. Queued application writes wait for the confirmation's application instead
of being rejected by preflight.

Initial read tests exposed an incorrect fixture comparison between an original
`Applied` receipt and its expected `Replayed` lookup. The test now explicitly
expects replay disposition while comparing every retained receipt field; production
code was unchanged for that correction. All **107 cluster library tests passed
in 51.32 s**, build **6.01 s**, including new quorum/application ordering, bounded
admission, cancellation, expiry, step-down and passive no-op replay/reopen coverage.
Affected Clippy found one redundant test closure; its direct method reference
replaces it without relaxing any lint. Real-Quinn read/failover acceptance and
final core tests/lint were pending at that point.

On resumption, the old test process handle was unavailable, so its result was not
assumed. The final metadata-authority rerun passed **18 tests in 16.05 s**, build
**0.11 s**, including real three-node Quinn reads before/after leader loss and
subsequent writes. The final focused core regressions passed **18 tests in 0.01 s**,
build **3.84 s**; affected consensus/metadata/cluster/daemon all-target/all-feature
Clippy passed with warnings denied in **26.17 s**.

The next slice adds the private request-bound read-fence endpoint, strict Protobuf
validation and client correlation checks. Daemon admission checks current identity
before quorum work and rechecks after application. Focused tests and real-wire
acceptance for this new slice remain pending; the earlier lint result does not
cover these subsequent edits.

The new boundary's focused checks passed: **2 client-correlation tests**, **1
daemon-admission test** and **1 structural protocol test**, each suite **0.00 s**,
combined build **63 s**. Expanded affected Clippy passed in **68 s** with warnings
denied, including the real-process test compilation. The first acceptance command
used an incomplete exact test name and selected zero tests (**45.54 s** build);
it is not acceptance evidence. The correctly selected run failed in **59.55 s**
because the new verifier called `load_consensus_state(1)` after recovery had
changed the membership epoch. The verifier now reads the installed plan's epoch;
production code and safety checks were unchanged for that correction.

The corrected real HTTPS/SMB recovery run passed in **79.59 s**, build **5.18 s**.
An actual storage-node identity requests the frontier from the recovered daemon;
the test compares partition, leader, epoch, plan and exact applied-entry digest
against the durable repository, and verifies an expired request receives precisely
`Deadline`, not a success. It repeats the admission/fence checks after private
certificate renewal and both storage/gateway restarts, while preserving original
and newly uploaded HTTPS/SMB bytes and rejecting pre-recovery identities. The new
read is classified as fetch work, so it does not hold the mutation permit. Broader
library and final post-fixture-edit lint checks remain pending below.

The broader library run passed **109 cluster tests in 50.74 s**, **32 consensus
tests in 4.59 s** and **12 protocol tests in 0.00 s**, combined build **28.61 s**.
No tests were ignored or filtered in those library suites. This includes every
one-to-nine-voter partition simulation already in the core suite, not a claim
of hardware power-loss, soak or an independent consensus proof. Full `pnpm check`
has not run on this candidate and remains required before integration.

Final affected all-target/all-feature Clippy passed in **4.02 s**, with warnings
denied, after the epoch-verifier correction. The complete protocol run passed
**56 tests** (12 library and 44 integration tests), each suite **0.00 s**, build
**39.12 s**; doc-tests contained no cases. Canonical wire, bounded/malformed input,
backup, delegation and federation compatibility fixtures remain green.

Next implementation boundary: retain the passive replica's catch-up handle,
obtain a fresh fence from a trusted voter candidate outside provider locks, and
verify the exact applied entry/phase in one local read view using bounded indexed
lookups. Then check the current recipient/target/key and exact committed cleanup
or reclamation evidence before enabling the corresponding maintenance RPC. A
request-supplied MAC or location cannot substitute for that record. Ordinary
capability-checked shard reads/writes keep their existing isolation behaviour.

The new read-fence library is not yet a storage-node remote-authorisation path.
The private RPC slice does not yet connect passive catch-up and exact committed
maintenance-permit checks. Both remain required before enabling destructive
storage-only service or healthy readiness.
No dependency, schema migration, release/tag, signing retry or Git mutation.
Task 10 remains **3 points**, Stage 10 **81**, Stage 11 **126/not started**.

### Storage-only private certificate renewal

The passive storage runtime now installs a committed private certificate candidate
using only its own identity key and forwards its signed installation acknowledgement
to a real voter. It receives no CA signing key, consensus vote or general metadata
write authority. The receiving boundary validates the sender/deadline, current node
and incarnation, server-resolved actor, exact staged generation/revision/fingerprint,
rotation lifetime and signature. An active or staged transport leaf may attest only
that node's exact candidate; other storage commands retain the registration allow-list.

The extended real recovery fixture initially failed waiting for renewal in
**78.44 s** and, after the installer was added, **78.14 s**. Retained databases
showed that the fixture shortened the previous expiry on the voter only. The
passive replica correctly rejected replay because the new certificate expired
before its unchanged original expiry. The scheduling injection now also updates
the passive fixture before the voter; production validation is unchanged. These
initial failures do not independently isolate the missing installer. Final live
renewal/restart acceptance is pending.

Review also found that fresh control requests reused a cached old-certificate
connection after local rotation. The actual Quinn regression failed in **0.20 s**.
Rotation now evicts cached connections without cancelling in-flight clones;
handshakes racing rotation cannot recache the old selection. All **17 control-network
tests passed in 2.56 s**, build **7.15 s**, including the regression, cancellation,
overlap and retirement checks. Two daemon admission tests passed in **0.04 s**
before the final active-leaf acknowledgement refinement; final daemon checks are
still required. No dependency, schema, wire-version or publication change.

The corrected real HTTPS/SMB recovery fixture passed in **76.18 s**, build
**34.16 s**. The non-voting storage node automatically installs generation 2,
retains its original identity key, replicates the installation receipt, serves
the exact new TLS leaf and preserves original/new file bytes across storage and
gateway restarts. Actual pre-recovery certificates remain rejected. This closes
that renewal/restart behaviour; it does not claim storage-only operational
readiness or close the other task acceptance. Affected Clippy and ordinary
voter-renewal regression are pending; estimates remain **3 / 81 / 126**.

All-target/all-feature daemon and cluster Clippy then identified two test-only
issues: the extended identity test exceeded 100 lines, and a match arm lacked a
semicolon. The complete remote identity/request-response assertion now has its
own helper, separate from renewal setup; no lint ceiling was relaxed. Clippy
passed with warnings denied in **27.13 s**. The ordinary automatic voter renewal,
join and restart process regression passed in **16.54 s**, build **13.97 s**.
Final focused tests after the test-only refactor remain pending below. No full
`pnpm check`, signing retry, commit, push, release, tag or publication occurred.

Final daemon forwarding/admission tests passed: **9 tests in 0.51 s**, build
**25.09 s**, including signature/identity substitution, current delivery deadlines,
candidate discovery, cancellation and exact operation outcome mapping.
The final post-refactor control-network rerun passed all **17 tests in 2.57 s**,
build **5.55 s**. The next task-10 boundary is fresh authority for storage-only
privileged maintenance; passive catch-up remains explicitly insufficient for it.

### New writes after replacement recovery

The existing real recovery fixture now creates fresh files through HTTPS and the
embedded SMB service using the original user's API key and restored volume. It
reads both files through both protocols, kills/restarts the storage daemon and
then the gateway, and repeats exact-byte reads without another upload. The
backed-up original file must still read correctly throughout, while its original
provider folder and filesystem journals remain unavailable. This checks recovered
service as writable storage, not merely a read-only view of the backup.

The first fixture compile attempted a Serde derive absent from this crate's direct
dependencies; explicit parsing through the existing `serde_json` dependency fixed
that without adding a dependency. The real HTTPS/SMB proof then passed in
**71.64 s**, build **9.17 s**. All-target/all-feature daemon Clippy identified
excessive cognitive complexity in the expanded lifecycle test. Readiness/early-exit
observation and kill/wait/restart now have shared lifecycle owners, reused on
initial boot and both restarts rather than extracting an arbitrary code suffix.
Warning-denied Clippy then passed in **6.52 s**.

The final rerun then **failed in 59.82 s**, build **5.55 s**, with HTTPS commit
`503 busy`; the first pass is not sufficient acceptance. Retained SQLite evidence
showed committed upload/content records and the same namespace operation in the
converged head, published by the background worker. Narrow temporary diagnostics
reproduced an authoritative rejection/strong-barrier-pending result in **61.87 s**,
build **20.40 s**. Comparing exact receipt fields exposed different source result
digests: foreground used the connector receipt, while background used canonical
history. The contract had incorrectly permitted both meanings in one field.

The deterministic `foreground_and_background_publication_use_identical_convergence_evidence`
regression failed in **0.08 s**, build **12.05 s**. Both paths now derive convergence
evidence from verified canonical immutable history, excluding separately verified
federation admission. Local connector receipts remain unchanged; no timeout or
test retry was added. The regression passed in **0.08 s**, build **5.23 s**. All
temporary diagnostics and their lint exceptions were removed. Full live rerun
and affected checks are pending below; the earlier unexplained `503` must not be
closed merely by a passing rerun. Pre-alpha metadata evidence meaning is narrowed;
no migration or compatibility alias is added for old experimental databases.

The corrected full HTTPS/real-SMB recovery, new-write and both-daemon restart
proof passed in **71.73 s**, build **38.40 s**. Boundary review then retained full
federation-record validation before deriving the admission-independent digest;
it does not skip a malformed stored acknowledgement. A separate regression proves
that a valid acknowledgement changes the transport-record hash but not immutable
convergence identity, and rejects a substituted acknowledgement payload. All
**224 filesystem library tests passed in 42.62 s**, build **5.39 s**, including
both new regressions and existing federation, corruption, restart and history
coverage. Final daemon acceptance and lint after that validation refinement are
still pending; no claim of assembled-stage or full integration-gate completion.

Final validation after that refinement: affected daemon/filesystem/metadata
all-target/all-feature Clippy passed with warnings denied in **47.10 s**. The
real HTTPS/SMB recovery, new-write and storage/gateway restart proof passed in
**69.64 s**, build **24.83 s**. NVM-default Prettier and `git diff --check` passed.
This closes the reproduced competing-publisher digest mismatch; unrelated earlier
generic `503` reports are not retrospectively declared fixed without evidence.

The ordinary real HTTPS create/upload/restart regression also passed in
**8.32 s**, build **0.15 s**. The recovery fixture was then extended with the
pre-recovery node's actual certificate/private key against both live replacement
services. It authenticates each server's exact installed certificate, requires an
explicit QUIC application close **1 / `unknown peer`**, and repeats after both
restarts. A timeout, setup failure or unrelated connection error is not a pass.
Admitted peers subsequently complete registration replay and shard IO, while all
original/new HTTPS/SMB bytes remain exact. The combined fixture passed in
**70.13 s**, build **6.58 s**. This proves returning-certificate fencing, not every
old-node recovery-authority transition or full role-specific operational readiness.
Final daemon all-target/all-feature Clippy passed with warnings denied in
**4.33 s**; NVM-default document formatting passed. No dependency change, full
`pnpm check`, signing retry, commit, push, release, tag or publication occurred.

This does not close storage-only operational readiness, recovery-authority fencing
or the other remaining task acceptance. Estimates remain **task 10: 3; Stage 10:
81; Stage 11: 126/not started**. No publication or Git mutation was performed.

### Storage-only composition and original-file recovery

Normal daemon startup now selects a separate path for an admitted storage node
outside the voter/learner set and without a gateway role. It does not construct
`ConsensusCore`, manufacture an authority handle or load gateway secrets. Shared
private-network configuration comes from the same admitted certificate/role
records as member startup. The cycle owns historical metadata catch-up, target
registration/opening, private shard IO and coarse HTTPS setup/health. Registration
forwards to real voters and requires the exact committed receipt to arrive through
replication. Missing media and target-local failures retry; changed applied
key/policy bindings require reopening. A failed target does not disable unrelated
healthy targets.

The cycle closes its transport and drains its owned provider/parser/maintenance
tasks on shutdown. Committed learner admission requests ordinary runtime restart.
Provider IO runs off the async executor, with bounded in-flight work. The private
network now exposes owner shutdown for both transport directions and outbound
queues. These changes do not alter the consensus algorithm or wire schema.

Local evidence on the uncommitted tree, 2026-09-09, Rust 1.98.0/four test threads:

- Initial daemon check completed in **18.14 s** and identified two unobserved
  nested results in shutdown. The cycle was reorganised around explicit task
  ownership and draining before the process proof, rather than ignoring results.
- The previously failing offline-export/replacement-admission process test passed
  in **58.82 s**, build **51.10 s**. Both replacement daemons reached HTTPS
  `configured`; the storage node no longer exits with `PrivateNetworkState`.
- The same fixture extended with automatic remote-authority folder registration
  passed in **60.05 s**, build **6.62 s**. It checks the exact local operation
  receipt, provider context on the gateway and absence of the storage node from
  consensus membership.
- A real private-shard client using the gateway's installed certificate and
  protected permit key then uploaded **8,192 opaque bytes**, checked its durable
  target/shard/length receipt, downloaded the exact bytes and rejected a forged
  read permit. The extended process proof passed in **59.01 s**, build **7.46 s**.
  An initial fixture compile used the wrong receipt field name; it was corrected
  to the existing `length` field. This proves shard service, not encryption of a
  logical file or recovered namespace access through HTTPS/SMB.
- Clippy identified wildcard imports, value/borrow handling, simpler result
  destructuring and the expanded fixture's size/complexity. Explicit imports and
  separate offline-admission/live-service responsibilities resolve these without
  exemptions or raised limits. Final daemon/cluster/transport all-target/all-feature
  Clippy passed with warnings denied in **6.53 s**.
- After the tool session was lost, the completed result could not be recovered;
  no success was inferred from the vanished process. The restart-extended fixture
  was rerun and passed in **59.72 s**, incremental build **0.15 s**. It kills the
  storage process after the shard upload, starts it again, checks the same target
  identity and reads the original bytes without another upload.
- Sender-authority review found that metadata forwarding did not pass the
  authenticated node identity to its command handler. A real storage-certificate
  regression replayed its legitimate registration successfully, then forged an
  administrator's audit actor on `CreateGroup`. Before the fix it returned
  **`Durable` instead of `Rejected`**, reproduced in **54.28 s**, build **7.45 s**.
  This was an actual privilege-boundary defect, not a speculative test case.
  The handler now performs owned blocking certificate/role/command admission and
  restricts storage-only identities to registration for their own node and host
  with the server-resolved registration actor. Gateway/current-voter forwarding
  retains its existing domain checks; metadata eligibility alone grants nothing.
  This does not claim a linearizable revocation barrier across disconnected nodes.
- The fixed real-certificate regression passed in **61.29 s**, build **30.49 s**.
  Expanded wire checks then rejected group creation and node/host/actor
  substitutions with explicit `Unauthorised` results, no committed revision or
  digest and no durable operation receipt. Exact legitimate registration replay
  succeeds before and after the rejected requests. Combined shard restart and
  forwarding proof passed in **60.44 s**, build **15.11 s**.
- Four focused forwarding tests passed in **0.00 s**, build **34.10 s**, including
  certificate/node/incarnation substitution, expiry, header identity substitution
  and deadline bounds. Clippy found two test-only borrowing/semicolon issues;
  these were corrected without exemptions. Affected all-target/all-feature
  Clippy then passed in **4.53 s**, as did Rust formatting. The ordinary real
  HTTPS create/upload/restart regression passed in **8.36 s**, build **0.14 s**.
  NVM-default Prettier and `git diff --check` passed for the recorded slice.

The next acceptance extension is now under test: actual offline commands prepare,
restore and collect a target on the storage-only replacement before final common
state export. The installer attaches that original restored target journal. During
live checks the original provider folder and filesystem/target journals are
unavailable; the original client credential must list/stat/read the backed-up
file through the replacement gateway's HTTPS API, before and after storage restart.
This paragraph records the test under construction, **not a passing result**.

The first extension run failed after **47.18 s**, build **7.03 s**, because its
new preparation assertion used a non-existent boolean instead of the existing
`outcome: prepared/recorded` response. Correcting that fixture contract exposed a
real live-service failure: **HTTPS directory listing returned 404** after otherwise
successful restoration/admission (**60.84 s**, build **4.89 s**). The private
fixture was retained. Read-only inspection found **one namespace commit** in the
restored root-level database and **zero** in the newly created runtime database
under `filesystem/`. Installation and admission had checked one layout while
normal service opened another.

Daemon installation now restores namespace/content databases directly beneath
`filesystem/`, with owner-only directory/files, and admission checks the same
location. Offline recovery workspaces retain their flat preparation layout.
Installation assertions and route-catalogue checks use the actual daemon paths;
no compatibility alias or second live database copy is introduced. An initial
fixture compile missed borrowing a `PathBuf`; it was corrected to the existing
catalogue API. The next run still returned **404** (**58.97 s**, build **6.21 s**).
Inspection confirmed the layout correction: the runtime database now had the
restored commit. Its only branch head, however, belonged to the original gateway;
the replacement's derived branch had no head for that volume.

Initial admission now fills absent gateway-local heads from the independently
verified recovered converged heads, using the existing typed head-adoption API.
It does so before metadata activation, preserves existing local heads and retries
idempotently after interruption. Storage-only nodes do not acquire gateway
branches. The combined test then **passed in 64.81 s**, build **21.48 s**: original
credentials list/stat/range-read/full-download exact original file bytes through
the replacement gateway, before and after abrupt storage restart, while original
provider data and filesystem/target journals are unavailable. This is the first
passing full-file HTTPS recovery proof in this sequence, not just shard IO.

A separate explicitly ignored real-SMB variant is now prepared for explicit local
execution with the existing client container. It publishes the share before the
backup and must read the same file through the replacement's embedded service.
No image is downloaded/built/published. The local image's tag lookup fails despite
its inventory entry; its immutable ID was successfully inspected as
`sha256:9daac97f82472b031c7bc56e5cdd2446ab01ceafd6dc2a4705cdd20a8ae90d6d`.
The explicit real-SMB variant **passed in 68.50 s**, build **22.49 s**. Both
HTTPS and the real `smbclient` retrieve the exact original file before and after
storage-process kill/restart, with original data/journals unavailable. The share
was published before the backup, not manually reconstructed in the replacement.
The command used the inspected immutable image through `MESHSPAN_SMB_PROOF_IMAGE`
and `--ignored --test-threads=4`; it was executed, not counted as a skipped pass.

Affected daemon/cluster/transport all-target/all-feature Clippy passed with
warnings denied in **20.00 s**. Its prior run caught the installer exceeding the
function-size limit; database-set syncing is now owned by the existing layout
selector and reused at both durability boundaries, preserving sync ordering
without a lint exception. Broader affected library regressions passed **135 unique
tests**: cluster **102/46.26 s**, data plane **6/0.00 s**, protocol **11/0.00 s**,
transport **16/0.63 s**, incremental build **19.22 s**. Rust formatting passed.
The recovered-file milestone closes **task 10: 4 → 3; Stage 10: 82 → 81**.

Registration forwarding review also found that a saved operation's original time
was being reused as its delivery deadline. After a long outage every retry would
already be expired. A deterministic regression reproduced this without sleeping:
with a current time of 60,000,000 µs the deadline was 30,000,100 µs instead of
90,000,000 µs (**0.00 s**, build **19.97 s**). Request preparation now retains the
exact canonical command, actor, operation ID and digest while using a fresh bounded
delivery deadline; overflow remains unavailable. Final focused forwarding checks
passed **5/0.00 s**, build **9.60 s**. Affected all-target/all-feature Clippy passed
with warnings denied in **26.14 s**. The full original-file HTTPS/real-SMB recovery
and storage-restart fixture then passed again in **68.22 s**, build **29.70 s**.
Rust formatting, NVM-default Prettier on the affected design documents and
`git diff --check` passed. The full `pnpm check` integration gate has not been run
for this working-tree candidate; no dependency change was introduced.

The storage path is deliberately still **degraded**, not complete: it withholds
destructive/maintenance RPCs pending live-authority integration, and does not yet
own the full certificate/update/backup service lifecycle for this role. Current
permissions cannot be inferred from its cached history. Broader recovered-file
acceptance and remaining role-transition proofs are open. The earlier unexplained
ordinary HTTPS `503 busy` is not closed by a passing recovery fixture. No full
integration gate, release/tag/package/image publication, GitHub Actions, signing
retry, commit or push was performed. Publication stays prohibited and signing
authentication remains unresolved. Current estimates are **task 10: 3; Stage 10: 81;
Stage 11: 126/not started**.

## Task 10 — automatic non-voting catch-up

Added an owned passive metadata worker over the existing authenticated history
transfer. It automatically selects current-phase voter routes, retries unavailable
connections, continues full pages immediately and resumes from durable application
after restart. It never creates a missing installation or promotes itself.
Committed learner admission returns a distinct handoff outcome; metadata eligibility
alone does not. The composing owner can coalesce wake-ups, observe historical
progress and stop the worker. Cancellation interrupts network IO, while already
started decoding and SQLite application remain owned and are drained.

Local evidence on the uncommitted tree, 2026-09-09, Rust 1.98.0/four test threads:

- The first compile rejected two mistakes in the new group fixture (field name
  and borrowed string), corrected to the existing command contract. The first
  three worker tests then passed in **4.17 s**, build **9.78 s**.
- Adding committed-admission handoff produced **four passing worker tests in
  5.97 s**, build **8.67 s**. Tests use real Quinn, independent SQLite files and
  explicit progress signals, not a simulated transfer or sleep-based readiness.
- The final library run passed **135 unique tests**: cluster **102/46.52 s**,
  data plane **6/0.00 s**, protocol **11/0.00 s**, transport **16/0.64 s**;
  incremental build **6.70 s**. Its five worker tests cover lost response and
  automatic multi-page catch-up (request cursors exactly `0, 0, 64`), restart
  through revision/index 72, stalled-transfer cancellation, missing-state return,
  committed learner handoff at index 6, identity/partition rejection and a closed
  owner channel. Existing hostile-transfer and real leader-loss cases also pass.
- Initial affected Clippy found one collapsible conditional in the source test
  harness; it was corrected without an allowance or limit change.
- Final cluster/daemon all-target/all-feature Clippy passed with warnings denied
  in **24.39 s**. Rust formatting, NVM-default Prettier for the four affected
  design documents and `git diff --check` passed.

Daemon startup still assumes a local consensus member and gateway composition.
This worker does not change that assumption yet, fabricate a follower handle,
grant gateway secrets or turn cached history into current authorisation. Fresh
permission checks, role-appropriate daemon integration and the two-node recovered
file acceptance remain open. Existing unexplained HTTPS `503 busy` evidence is
not closed by these cluster tests. No full integration gate, dependency/schema
change, release, tag, publication, GitHub Actions or signing retry was performed.
The signing-authentication blocker remains; no commit/push was made by this slice.
Estimates stay **task 10: 4; Stage 10: 82; Stage 11: 126/not started** until the
remaining integrated acceptance is demonstrated.

## Task 10 — authenticated bulk metadata history

The [non-voting history wire contract](protocol.md#non-voting-metadata-history-transfer)
now has typed request/header messages and a separately bounded canonical body.
The client checks request/cursor identity, offsets, length, body/entry digests and
EOF, then revalidates its source against the live certificate registry. The daemon
routes source requests through independent admission, current node/certificate
checks and the existing metadata owner. Blocking work is owned and drained;
network cancellation cannot leave an encoder worker detached. No control-frame
limit, consensus membership rule or gateway-key entitlement was widened.

Local evidence on the uncommitted tree, 2026-09-09, Rust 1.98.0/four test threads:

- Initial protocol/cluster focused run: **14 passed** (11 cluster in **16.13 s**,
  three protocol in **0.00 s**), build **25.10 s**. Real Quinn fixtures cover
  authenticated storage-only history application/reopening and a 256 KiB record
  transfer, plus wrong request/cursor, bad body/entry digests, offset substitution,
  truncation, trailing bytes, frame-cap violations and explicit rejection.
- Protocol fixtures also reject duplicate/unknown fields, invalid origins,
  non-contiguous entries and excessive record/byte counts. Outgoing and incoming
  messages use the same validation boundary.
- Initial compile corrected one validator argument mismatch. Clippy identified
  two test `unwrap`s, a large test future and a composition-length tripwire;
  these were fixed without allowances or limit changes. Affected protocol,
  cluster and daemon all-target/all-feature Clippy then passed in **30.03 s**.
- The first broader cluster run had **94 passed/1 failed, 39.01 s**, build
  **14.02 s**. The existing leader-loss test submitted only to one predetermined
  survivor. A forced-other-survivor regression reproduced the timeout in
  **16.75 s**, build **5.95 s**, and captured the contacted node as follower and
  the other as leader. The fixture now discovers a surviving authority and checks
  the exact receipt on both survivors. The forced case passed in **1.79 s**,
  build **4.80 s**, without changing election behaviour or increasing deadlines.
- A subsequent broad run still failed (**95 passed/1 failed, 39.84 s**, build
  **5.69 s**). Its captured follower had one pending caller left over from its
  previous leadership. This was a runtime bug, not resolved by the test fix:
  step-down left pending operations waiting indefinitely. A deterministic
  three-voter regression reproduced the unresolved waiter in **0.33 s**; its
  initial two-voter fixture was unsuitable because that plan permits a one-node
  write quorum and therefore completed instead of leaving pending work.
- The runtime now settles committed effects first and redirects any remaining
  pending/queued callers when its actual role is no longer leader. It does not
  rely on a `RoleChanged` effect, which is not emitted by every vote/append
  step-down path. An initial effect-only correction failed the regression and
  was replaced after inspecting that path. The final regression passed in
  **0.33 s**, build **4.43 s**, including duplicate waiters, retained durable bytes
  and the successor committing the same original operation with an exact receipt.
- The next complete library run passed **130 unique tests**: cluster **97/40.34 s**,
  data plane **6/0.00 s**, protocol **11/0.00 s**, transport **16/0.62 s**, with
  **0.11 s** incremental build. Both real Quinn failover cases passed. The waiter
  regression was subsequently reorganised around an explicit elected-runtime
  fixture; its assertions and production behaviour were unchanged.
- A final transfer regression exposed identity relabelling if the same certificate
  was rebound to a new incarnation during IO (**failed, 2.36 s**, build **6.94 s**).
  The client now compares the entire initial and final authenticated peer binding,
  not only its node ID. The complete hostile-response vector passed afterwards
  (**2.36 s**, build **5.62 s**). No partial result or newly labelled peer is returned.
- Final affected protocol/cluster/daemon all-target/all-feature Clippy passed
  with warnings denied in **37.71 s**. This follows the final identity tightening;
  the 130-test broad run above precedes that tightening and its focused regression.
- The ordinary real daemon HTTPS create/upload/restart acceptance passed in
  **8.26 s**, build **1m 02s**, after the final implementation changes:
  `cargo test -p meshspan-daemon --test headless_process
real_headless_process_creates_mesh_over_https_and_restarts -- --test-threads=4`.
  This is a passing regression, not an explanation of the previously recorded
  intermittent `503 busy`. The unchanged two-node storage-only recovery blocker
  was not rerun or relabelled as complete.

Rust formatting, NVM-default Prettier for the four affected design documents and
`git diff --check` pass. Progress remains local: the existing signing-authentication
blocker was not retried or bypassed, and no commit/push was made by this slice.

The passive runtime worker, fresh permission checks, storage-only composition
and two-node recovered-file acceptance remain open. The earlier ordinary HTTPS
`503 busy` has not been explained by this work. The full integration gate has
not run; source-handler composition is not itself a complete daemon-recovery
proof. No dependency, database schema, release, tag, package/image publication,
GitHub Actions or signing retry was introduced. Task/stage estimates remain
**task 10: 4; Stage 10: 82; Stage 11: 126/not started**.

## Task 10 — non-voting metadata application

Added a separate `MetadataReplica` application adapter and a bounded historical
page read through the existing `MetadataAuthorityHandle`. The adapter does not
construct or weaken `ConsensusCore`, add voter/learner membership, campaign,
accept client mutations or provide fresh permission evidence. It opens already
authenticated metadata installations, checks the supplying voter/incarnation
against its current phase, and uses existing command and membership validators.

Pages bind the exact partition/epoch/plan and previous position/digest, contain
at most 64 records/16 MiB of command bytes, and end at a membership transition.
The source exports only applied history. A source in a later phase can supply
the old phase's committed prefix, but not records beyond its transition. The
consumer applies joint/stable plans before requesting the next phase; if its own
node becomes a learner, passive application stops for a member-runtime handoff.
The durable adapter replaces only unapplied tails and preserves newer terms.
Application failure fences the instance until reopening; retained log bytes alone
never advance its applied cursor. Exact applied-page replay is harmless.

Local evidence, 2026-09-09, Rust 1.98.0, four test threads:

- First focused run: **4 passed, 1 failed, 6.07 s**, build **2m 24s** (uncached
  dependency feature build). The paging fixture reused the administrator's
  principal ID for one generated group. Assigning disjoint fixture IDs corrected
  that test setup; no production validation was relaxed.
- Expanded focused run: **7 passed, 8.89 s**, build **7.31 s**. Final focused
  run including local-member rejection/handoff: **9 passed, 11.62 s**, build
  **5.49 s**. `cargo test -p meshspan-cluster --lib metadata_replica::tests
-- --test-threads=4`. Tests cover live owner-queue reads, exact 64+2 paging,
  restart, stale sources/epochs/digests, malformed/substituted records, replay,
  unapplied-tail replacement, failed-application reopening, joint/stable history
  and refusing to keep operating passively after local learner admission.
- Full consensus library suite: **29 passed, 4.63 s**, build **9.54 s**.
  `cargo test -p meshspan-consensus --lib -- --test-threads=4`.
- Initial affected Clippy found a test helper taking an unconsumed command by
  value; it now borrows the command. No production behaviour changed for lint.
- After that test-only correction, the full cluster library suite passed:
  **93 passed, 33.27 s**, build **4.40 s**. `cargo test -p meshspan-cluster
--lib -- --test-threads=4`. This includes the nine new cases and the existing
  actor, real-Quinn consensus, routing, federation and cancellation regressions.
  Together with consensus, this is **122 unique tests**, not the sum of every
  overlapping focused run.
- Final affected consensus/cluster/daemon Clippy, all targets/features with
  warnings denied: **passed, 22.85 s**.

**Not yet complete:** private bulk framing and authenticated handler/consumer
wiring, current-authority permission checks for the passive runtime, and
storage-only service composition without gateway key/services. The adapter's
maximum page cannot be sent as one existing 64 KiB control message; bulk framing
must preserve that limit. The two-node recovered-file acceptance has not been
rerun because its daemon composition failure is unchanged. The earlier ordinary
HTTPS upload `503 busy` remains unexplained; this change does not claim to fix it.

No task or stage is closed. Estimates remain **task 10: 4; Stage 10: 82;
Stage 11: 126/not started**. No new dependency, schema migration, full integration
gate, signing retry, commit, push or publication.

## Task 10 — admitted roles in private network startup

Private-network startup no longer unconditionally advertises storage, gateway
and metadata-voter roles. The active certificate query now reads admitted service
roles in the same SQLite statement as the active node incarnation and certificate.
Startup derives storage/gateway capabilities from those roles and voter/learner
status from the active stable or joint quorum plan. Metadata eligibility alone
does not grant membership. Contradictory membership/eligibility, missing roles
and an eligible-only node without an admitted service fail closed. This changes
startup presentation, not consensus membership or permission enforcement.

Local evidence, 2026-09-09, Rust 1.98.0, four test threads:

- The initial test fixture had a boxed-plan construction error; after correcting
  the fixture, the regression reproduced the old behaviour: a storage-only node
  returned `[Storage, Gateway, MetadataVoter]` instead of `[Storage]` (**1 failed,
  <0.01 s**, build **30.65 s**).
- Role projection and joint-transition tests: **2 passed, <0.01 s**, build
  **16.70 s**. `cargo test -p meshspan-daemon --lib
private_consensus_runtime::tests -- --test-threads=4`.
- Active-certificate projection tests: **2 passed, 0.89 s**, build **12.97 s**.
  They include changed service roles, missing roles, inactive nodes and restart.
  `cargo test -p meshspan-metadata --lib active_certificate -- --test-threads=4`.
- Certificate selection/rotation tests: **5 passed, 3.07 s**, build **0.10 s**.
  `cargo test -p meshspan-metadata --lib node_certificate -- --test-threads=4`.
  One certificate-selection test overlaps the preceding run: **8 unique unit
  tests**, not 9.
- Ordinary real-process HTTPS create/upload/restart acceptance first **failed
  at upload commit with HTTP 503 `busy`, 6.40 s**, build **36.97 s**. This
  harness previously discarded its failed fixture. It now uses the existing
  test-owned process cleanup and retains private fixture state on returned
  failures, without changing upload expectations, retries or timeouts. With
  those diagnostic changes, the workflow **passed, 8.26 s**, build **6.19 s**:
  `cargo test -p meshspan-daemon --test headless_process
real_headless_process_creates_mesh_over_https_and_restarts -- --test-threads=4`.
  **The intermittent upload failure is unexplained and remains open.** The
  passing rerun is not evidence of a fix; no production upload code changed.
- Affected metadata/daemon Clippy, all targets/features with warnings denied:
  **passed, 30.19 s**.

The storage-only recovery runtime is still not implemented. The existing
`CommittedPrefix` message handles historical membership catch-up for members;
it is not a non-member synchronisation service or fresh authorisation evidence.
The next runtime slice needs a non-voting metadata consumer, current-authority
permission checks, and independently owned storage services without gateway
authentication/certificate workers. It must not construct a fake voter/learner,
report cached observations as linearizable reads, or replace a live SQLite file.
The existing two-node recovered-file workflow remains its acceptance gate and
was not rerun against the unchanged storage-only startup failure.

No task or stage is closed by this change. Estimates remain **task 10: 4;
Stage 10: 82; Stage 11: 126/not started**. No new dependency, schema migration,
public API generation, full integration gate, signing retry, commit, push or
publication.

## Task 10 — role-specific recovery keys

Tracing storage-only startup exposed a second concrete prerequisite: normal
`StorageProviderOpeningService` loads the current permit-MAC key, but recovery
had withheld every secret envelope from storage-only replacements. Recovery now
separates the two control-key recipient sets. The successor online CA private key
goes only to selected gateways and the offline root. The fresh storage-permit key
also goes to selected storage providers. Retained generations, including volume,
authentication, public-TLS and old operational keys, remain gateway/root-only.
Metadata-only nodes receive no secret envelopes. No consensus role is added.

This preserves the content-confidentiality boundary: possession of a permit-MAC
key does not decrypt volume contents or replace current issuer/target/revision
checks. Gateway/storage overlap is deduplicated across the two role sets; duplicate
keys within a supplied set and the offline root masquerading as a node are rejected.
Staging requires exact recipient equality against the independently root-signed
role selection. Missing permit access and excess CA/permit access are rejected.

Key bundles and installation transcripts now use **version 3**. Recipient
verification opens exactly its role-authorised material: all generations for a
gateway, one fresh permit generation for storage-only, zero for metadata-only.
The signed installation transcript binds that count and the exact bundle digest.
Pre-alpha versions 1 and 2 are rejected, not silently reinterpreted. Existing old
preparations require a fresh ceremony; the installer does not overwrite them.

Local evidence, 2026-09-09, Rust 1.98.0, four test threads:

- Before the fix, the storage-recipient test failed with **0 opened generations
  versus the required 1** (**1.90 s**, build **8.18 s**). It then passed in
  **2.25 s**, build **9.68 s**. Its decryptor asserts that the only opened context
  is storage-permit generation 2 and independently counts exactly one call.
- The initial negative-role test fixture failed before its intended assertion:
  it changed gateway selection without refreshing retained recipient envelopes.
  Correcting the fixture's key planning, without weakening production validation,
  made the focused missing/excess-authority cases pass (**5.35 s**, build
  **5.80 s**). The earlier broad run was **49 passed, 1 failed, 51.48 s**.
- Final metadata recovery suite: **51 passed, 53.31 s**, build **8.51 s**.
  `cargo test -p meshspan-metadata --lib recovery_preparation::tests
-- --test-threads=4`. Includes metadata-only zero-key verification, exact
  storage-only key access, missing/excess role authority, malformed/old bundle
  versions, signed installation replay, canonical projection and activation.
- Real command workflow: **failed at the known storage-only runtime boundary,
  53.36 s**, build **34.49 s**. Export, installation, canonical recipient checks,
  interrupted admission and gateway HTTPS startup succeed before the storage-only
  process exits with `PrivateNetworkState`. Both installed replicas contain the
  storage recipient only on the fresh permit generation, never other secrets;
  the storage node verifies its encrypted bundle with its own wrapping key.
  `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4`. Failure fixture retained at
  `/var/folders/xk/vb061tws5wv3z_00cskjqtwr0000gn/T/.tmpfdvTNW`.
- Affected metadata/daemon Clippy, all targets/features with warnings denied:
  **passed, 28.98 s**. `cargo fmt --all -- --check`, NVM-selected Prettier and
  `git diff --check` passed; no generated public API changed.

Storage-only runtime composition and metadata synchronisation remain open;
fixing key distribution alone does not make that daemon a running storage service.
Estimates remain **task 10: 4; Stage 10: 82; Stage 11: 126/not started**. No new
dependency, full integration gate, signing retry, commit, push or publication.

## Task 10 — replacement activation and gateway startup

The node now consumes its exact root-signed consensus permission through
`admit-recovery-state`. Partition schema **117** atomically installs replacement
membership, successor epoch, higher-term empty vote, reserved metadata revision
and an immutable recovery-origin receipt containing the previous plan. This is
not a fabricated Raft command. The applied source log remains intact; only the
unapplied tail is removed. Exact retry preserves later consensus progress.

Normal daemon opening verifies the root-selected identity, existing local keys,
transferred archive and retained filesystem history. A durable permission file
allows restart to resume an interrupted activation transaction. The original
`state.auth` and preparation evidence remain, and no first-boot claim or synthetic
create/join record is produced. Startup verification now runs on an owned blocking
worker rather than the async executor. A configured setup response describes
setup state, not current file availability or restored protection.

The real two-node workflow exposed a membership projection bug: activation had
left old voters as retiring members while retiring their node records. The typed
membership loader correctly rejected that combination. A focused regression
reproduced `CorruptState` before the fix (**1 failed, 2.17 s**). Activation now
replaces the current membership projection while preserving the historical plan
in its immutable receipt. The three focused activation tests then passed in
**4.00 s**, build **6.21 s**.

Local working-tree evidence, 2026-09-09, Rust 1.98.0, four test threads:

- Metadata recovery suite: **49 passed, 51.26 s**, build **0.10 s**.
  Command: `cargo test -p meshspan-metadata --lib recovery_preparation::tests
-- --test-threads=4`. Includes atomic rollback, reopening, corrupted permission
  and origin rejection, unchanged applied history, exact retry after later votes,
  typed membership reads and ordinary-database migrations through schema 117.
- Real backup/replacement process acceptance: **failed, 54.87 s**, build
  **36.14 s**. Both installations admit and reopen without claims; interrupted
  permission publication resumes on ordinary local opening. The gateway reaches
  configured HTTPS startup. The storage-only daemon exits with
  `PrivateNetworkState`, because runtime startup assumes local membership in the
  consensus plan. The earlier attempt failed for both nodes (**67.94 s**); the
  membership fix resolves the gateway failure, not the complete workflow.
  Command: `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4`.
- The process harness now observes child exit while awaiting HTTPS readiness,
  rather than waiting out the deadline after a known process failure. Replacement
  storage folders remain inside the retained failure fixture. The current fixture
  is `/var/folders/xk/vb061tws5wv3z_00cskjqtwr0000gn/T/.tmp5UuKgt`.
- Daemon-local-state regressions: **7 passed, 0.48 s**, build **30.37 s**.
  Command: `cargo test -p meshspan-daemon --lib daemon_local_state_tests
-- --test-threads=4`.
- Appliance composition regressions: **4 passed, 1.27 s**, build **0.14 s**.
  Command: `cargo test -p meshspan-daemon --lib appliance_runtime::tests
-- --test-threads=4`. Includes committed-incarnation authority restart and
  backup snapshot access independent of the storage maintenance lock.
- Affected Clippy (metadata and daemon), all targets/features with warnings denied:
  **passed, 30.31 s**. The final suites above total **60 unique passing tests**;
  the three focused tests are included in the 49-test suite, not added again.
- `cargo fmt --all -- --check`, `git diff --check` and NVM-selected
  `pnpm exec prettier --check` for the three changed design documents passed.

**Open integration defect:** the normal daemon always composes a consensus member
and gateway services. Recovery selection correctly permits storage-only nodes
outside that membership and withholds gateway secret envelopes. Do not work around
this by adding voter/learner roles to a signed selection, copying gateway keys or
removing the failing acceptance. Role-appropriate non-voter startup, metadata
synchronisation and storage service composition need to be completed together.
Fresh all-node/certificate/storage readiness, returning-node fencing and live
recovered HTTPS/SMB file operations remain unproved.

Estimates stay **task 10: 4; Stage 10: 82; Stage 11: 126/not started**. No dependency
was added. No full `pnpm check`, signing retry, Git mutation, release, tag,
package/image publication or GitHub Actions ran. The signing checkpoint and
publication hold remain in force. This is partial integration evidence, not task
or stage completion.

## Task 10 — root-authorised replacement consensus permission

`authorize-recovery-consensus` now produces an explicit offline-root permission
for the exact common state installed by every selected replacement. The manifest,
not a directory listing, selects the bounded package set. The coordinator checks
each expected transfer and retained node signature in one transaction before
persisting a decision. Partition schema **116** adds one immutable decision per
preparation; exact retry returns the original signed bytes, while a competing
state set cannot replace them. A failed output-file publication is recoverable
from that retained decision. Existing output bytes are never overwritten.

The public `RecoveryConsensusAdmission` contract has distinct bounded `MSRCNSNS`
version-one framing, binding the root-authenticated recovery authorisation and
common encrypted-state digest/length. It cannot be substituted with a state
transfer or installation signature. The embedded authorisation binds the source
position/revision, recovery epoch, replacement manifest and inventory. This is
permission to form replacement consensus, not a report of live reachability,
restored protection or HTTPS/SMB readiness. Issuance does not modify installed
nodes, advance the metadata head, clear either startup fence or fabricate setup.

Final local working-tree evidence, 2026-09-09, Rust 1.98.0, four test threads:

- Real encrypted-backup/export/two-node-installation workflow:
  **1 passed, 54.72 s**, build **44.79 s**. The real command rejects zero/partial
  installation sets, recovers after permission-file publication fails, produces
  owner-only root-verifiable permission, replays exact bytes, and refuses to
  overwrite a conflicting output. Installed nodes remain fenced and claim-free.
  Command: `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4`.
- Metadata recovery regressions: **46 passed, 41.24 s**, build **8.04 s**.
  New cases cover missing receipts, exact replay after reopening, competing
  installed state, transactional failure without a surviving decision, immutable
  evidence, unchanged consensus fencing/revision, and populated **115 → 116**
  migration preserving signed installation receipts with foreign keys intact.
  Command: `cargo test -p meshspan-metadata --lib recovery_preparation::tests
-- --test-threads=4`.
- Recovery-bundle regressions: **14 passed, 2.93 s**, build **3.65 s**.
  The new contract checks exact byte positions, every truncation and changed
  byte, trailing/excess data, a foreign root, invalid claims and cross-message
  substitution. Command: `cargo test -p meshspan-recovery-bundle --lib
-- --test-threads=4`.
- Affected Clippy (recovery-bundle, metadata, daemon), all targets/features with
  warnings denied: **23.80 s**, passed. `cargo fmt --all -- --check` passed.

The first Clippy compilation caught comparison of protected `Zeroizing<Vec<u8>>`
output with a byte slice. Comparing its borrowed slice fixed the type error;
no validation or lint was weakened. Initial focused permission tests passed
before broader checks; they are included in the final **61 unique passing tests**,
not additional coverage counts.

The next integration is consumption of this permission: root-authorised local
identity/setup, atomic replacement membership/epoch application, fresh all-node
readiness and returning-node fencing, followed by live recovered HTTPS/SMB.
Those are not implemented by issuing a permission file. Estimates remain
**task 10: 4; Stage 10: 82; Stage 11: 126/not started**. No new dependencies,
full `pnpm check`, signing retry, commit, push, release, tag, package/image
publication or GitHub Actions ran. The signing checkpoint remains unresolved
and the publication hold remains in force.

## Task 10 — runtime layout and interrupted-installation fencing

The external `install-recovery-state` command now installs the normal daemon
layout: `root-authority.sqlite3`, filesystem journals, identity-bound local
metadata, the same node identity/wrapping keys under `secrets/`, fresh local
TOTP/passkey ceremony keys, and the independently supplied public recovery root.
Private keys are persisted only on their owning node, after package/recipient
verification. They are not added to exports or temporary restoration workspaces.
The latter keep their preparation-only layout; no SQLite hard-link alias is
created between preparation and runtime filenames.

The signed `state.auth` transfer is now the first durable installation file.
Normal daemon startup refuses a directory carrying that fence before creating
an identity, claim or setup state, even when installation stopped before any
database or key existed. This is a pending-installation guard, not proof of
authority or admission. No administrator, first-boot claim consumption or
configured setup receipt is fabricated. The existing metadata consensus fence
also remains in place. Root-authorised identity/setup admission must still
replace the first-boot-derived identity assumption for recovered nodes.

Final local working-tree evidence, 2026-09-09, Rust 1.98.0, four test threads:

- Real encrypted-backup/export/install/recovery workflow and normal daemon
  startup attempt: **1 passed, 54.39 s**, build **4.73 s**. Installed key bytes
  equal the originals without printing private material on assertion failure;
  files are owner-only, local metadata has no claim/setup record, and normal
  startup returns `RecoveryAdmissionRequired` without producing a claim.
  Existing corruption, missing-journal and two-node common-state proofs also run
  in this test. Command: `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4`.
- Daemon-local-state focused tests: **7 passed, 0.49 s**, build **26.74 s**.
  The new interrupted-installation case reopens twice without creating local
  metadata, secret keys or a first-boot claim; ordinary first-start, retained
  claims, missing keys, locking and storage-overlap behaviour remain unchanged.
- Final daemon `local_` regressions: **26 passed, 2.71 s**, build **0.14 s**;
  setup API regressions: **5 passed, 0.11 s**, build **0.14 s**.
- Final daemon Clippy, all targets/features with warnings denied: **3.69 s**;
  `cargo fmt --all -- --check` passed. Initial all-target compilation passed in
  **27.92 s**. Clippy's equality-assertion finding was resolved using a named
  boolean so failures cannot print secret byte strings; no lint was suppressed.

The first process attempt failed in **41.19 s**, build **33.55 s**, because the
new startup test omitted the currently mandatory `--storage-path` operand.
A minimal command-line reproducer showed `Configuration(Storage(MissingStoragePath))`;
adding the operand reached `LocalState(RecoveryAdmissionRequired)` immediately.
The test invocation was corrected, retaining the admission expectation and
including unexpected stderr in future failures. The temporary reproducer was
removed after verification. This did not change storage-path requirements.

Runtime file installation is complete; root-authorised identity/setup admission,
replacement membership, fresh all-node storage/certificate checks, returning-node
fencing and live HTTPS/SMB recovery acceptance remain open. Estimates remain
**task 10: 4; Stage 10: 82; Stage 11: 126/not started**. No full `pnpm check`
integration gate, signing retry, commit, push, release, tag, package/image
publication or GitHub Actions ran. Signing remains at its existing unresolved
checkpoint and publication remains prohibited.

## Task 10 — recovered folder and journal attachment

`install-recovery-state` accepts repeated bounded `--storage-target` attachments
for a common state-set package. It verifies the selected node's signed target
report, projected provider/marker/capacity and actual exclusively reopened folder
and existing journal before retaining the mount in node-local schema 16. No user
registration command or administrator identity is fabricated. Recovered bindings
and ordinary registrations cannot claim the same target or folder; changed
retries and foreign-node records fail, and the original binding remains immutable.
Persisted byte lengths are checked before allocating path/identifier copies.

The original target journal remains in place, including its committed WAL state.
It is not copied into a second write history. Its directory is permanent node
state and must be retained alongside the storage folder. Normal startup discovers
the recovered bindings, includes them in folder listings, checks current provider
authority and the required applied revision, and carries the original journal root
into provider opening. New `TargetJournal::reopen` / `FolderShardStore::reopen`
paths refuse missing journals instead of creating empty ones. Only actually opened
providers appear active. Attachment itself never starts a service or admits the
candidate's reserved revision.

Final local working-tree evidence, 2026-09-09, Rust 1.98.0, four test threads:

- Real encrypted-backup/export/install/recovery process workflow:
  `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4`: **1 passed, 55.41 s**, build **35.33 s**. With original
  source media unavailable, the installer saves the exact folder/journal binding;
  reopening reads the restored inventory and scrubs the exact expected shard as
  healthy. Removing the required journal directory causes installation to fail
  without recreating it or publishing `installed.json`. Normal consensus startup
  still reports `RecoveryAdmissionRequired`.
- Metadata `local_` regressions: **30 passed, 3.68 s**, build **7.12 s**.
  Includes exact recovery-binding replay/reopen, ordinary-registration collision,
  foreign-node rejection, immutable rows and populated local schema 15 → 16
  migration; existing setup, claims and local registration tests also pass.
- Complete storage library: **50 passed, 2.09 s**, build **0.05 s**. The new
  required-journal test preserves exact put receipts and capacity across a live
  WAL reader and reopening, verifies physical bytes, and refuses a missing journal.
- Daemon `storage_` regressions: **25 passed, 4.28 s**, build **27.66 s**.
  Includes recovered registration rejecting an unapplied policy and avoiding any
  registration recommit, plus existing provider opening and storage APIs.
- Repeated-option parser boundary test: **1 passed, 0.00 s**, build **0.13 s**;
  accepts optional/repeated attachments through 1,024, rejects overflow, incomplete
  arguments and unknown option names.
- Final storage/metadata/daemon Clippy, all targets/features, warnings denied:
  **21.71 s**. Final `cargo fmt --all -- --check` passed.

The first process run failed in **39.33 s**, build **30.62 s**: the outer daemon
dispatcher still truncated recovery commands to eight arguments. Its bound now
comes from the recovery command owner and retains one overflow item for explicit
rejection; the unchanged process expectation passes. Compile/lint findings were
also corrected: checked SQL integer conversion, cloneable OS-string test vectors,
fixed-size argument chunk parsing and borrowed installation inputs. The installer
was separated into command orchestration and authenticated database restoration/
verification, rather than mechanically extracting a suffix to meet a line ceiling.

This completes the folder/journal attachment slice, not whole runtime admission.
Runtime identity/setup installation, replacement membership, fresh all-node
storage/certificate checks, returning-node fencing and live HTTPS/SMB recovery
acceptance remain open. Estimates stay **task 10: 4; Stage 10: 82; Stage 11:
126/not started**. No full `pnpm check` integration gate, signing retry, commit,
push, release, tag, package/image publication or GitHub Actions ran. Signing is
still at the existing unresolved checkpoint; publication remains prohibited.

## Task 10 — restored provider records with offline-root provenance

`export-recovery-state-set` now projects every collected replacement folder into
normal storage-target, target-generation, provider-component and configuration
records in the same transaction as replacement nodes and keys. It rereads bounded
pages, checks record identity and the selected node's signature against the saved
root-authorised plan, then reuses normal registration validation/persistence.
Provider IDs are deterministic for the recovery and target; paths remain local.
Original targets are retired in the candidate, with immutable marker/generation
history retained. No backing-device or filesystem identity is invented from a
folder report. The source coordinator is unchanged.

Schema 115 makes component creation provenance explicitly either a user/service
principal or the saved offline recovery authority, never both or neither. Root
creation is permitted only during the matching open projection and its origin
cannot later be rewritten. Ordinary component commands retain their real actor;
no administrator is impersonated and no synthetic account is created. The
transactional migration preserves populated component/configuration, assignment,
observation, storage and backup-provider references. Its temporary suspension of
foreign-key enforcement is connection-local and restored on success or failure;
all references are checked before commit. Staging uses transactional on-disk
tables, not an unbounded in-memory copy. The legacy backup fixture now reconstructs
the actual old component schema before testing its forward migration.

This closes **provider-record projection**, not live service admission. The
candidate's policy revision is still reserved above its applied catalogue
revision, and consensus startup is still refused. Node-local runtime installation,
replacement membership, present storage/certificate checks, returning-node fencing
and live HTTPS/SMB recovery acceptance remain required. No scope is deferred.

Local working-tree evidence, 2026-09-09, Rust 1.98.0, four test threads:

- Final actual-process encrypted-backup/recovery test
  `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4`: **1 passed, 51.74 s**, build **13.15 s**. With original
  storage unavailable, real export/install commands deliver the new provider
  records. Normal metadata lookups and `RegisteredFolder::reopen` bind the exact
  restored target, generation, marker and capacity. Source targets remain retired
  only in the candidate, the coordinator is unchanged, sibling bytes survive and
  the consensus fence stays enforced. This is not an admitted running swarm.
- Recovery preparation: **43 passed, 40.56 s**, build **12.08 s**, including
  ordinary schema 114 → 115 migration. After the registration-order correction
  below, the affected recovery-provider tests were rerun: **3 passed, 3.85 s**,
  build **0.09 s**. They cover normal records/provenance, rollback at each write
  boundary and changed node signatures after collection.
- Populated component migration/reference preservation and failed-migration
  rollback: **2 passed, 0.78 s**, build **5.17 s**. Legacy backup-root migration:
  **1 passed, 0.36 s**, build **0.09 s**. The component-filter suite also passed:
  **4 tests, 4.63 s**, build **0.10 s**, including ordinary configuration history.
- Existing storage-target suite: **9 passed, 5.34 s**, build **6.00 s**. It first
  caught a regression (**8 passed/1 failed, 5.55 s**): component insertion had
  moved ahead of the draining-scope guard, changing a normal rejection's error
  path. Both registration origins now share validation-before-write ordering.
  The failing drain case passes with its original expectation unchanged.
- Existing daemon registration: **2 passed, 0.15 s**, build **43.08 s**; provider
  opening/reopening: **2 passed, 0.13 s**, build **0.13 s**.
- Final metadata/daemon Clippy, all targets/features with warnings denied:
  **27.64 s**. Earlier lint findings were resolved by making immutable creation
  provenance a copyable value and asserting provenance predicates directly rather
  than building a complex test tuple. No lint ceiling was weakened.
- Fixture corrections: the populated migration fixture initially used a positional
  insert that omitted an existing backup-destination column; it now names its
  columns. The first new process proof (**39.63 s**, build **31.44 s**) reached
  provider installation/reopening but had the wrong expected sibling string.
  The original fixture's exact bytes were confirmed and the assertion corrected;
  the subsequent proof passed in **51.26 s** before the final rerun above.

Task 10 **5 → 4 points**; Stage 10 **83 → 82**; Stage 11 remains **126/not
started**. These remain rough effort estimates, not hours or an admission claim.
No full `pnpm check` integration gate, signing retry, commit, push, release, tag,
package/image publication or GitHub Actions ran. The signing checkpoint remains
unresolved and publication remains prohibited.

## Task 10 — canonical replacement node and key records

The common `export-recovery-state-set` archive now contains canonical replacement
node, host, role, wrapping-key and certificate records, not just preparation
reports. One transaction retires source-node wrapping authority, replaces each
retained secret's complete recipient set, and installs the prepared successor
online-CA and storage-permit generations. Retained ciphertext stays byte-identical;
old envelopes do not accumulate across recoveries. Storage-only replacements have
registered wrapping identities but receive no secret-decryption envelopes.

Key bundles are exported before this projection changes the source node/key
heads. A fresh SQLite backup captures the resulting exact bytes for encryption
and root authorisation. The original coordinator remains unchanged. Schema 114
permits key retirement and envelope replacement only inside the matching open,
credential-fenced projection transaction; completion seals those exceptions.
Ordinary immutable-secret rules remain in force. Failed writes roll everything
back, including the projection marker. Repeating projection on an already
projected copy is rejected; retry exports a fresh disposable copy.

The source applied revision and consensus fence remain unchanged. The returned
revision is reserved, not committed. Canonical provider installation, replacement
membership, fresh storage/certificate readiness and live service admission still
remain; this is not a recovered running swarm. The single-node
`export-recovery-state` preparation command is unchanged.

Local working-tree evidence, 2026-09-09, Rust 1.98.0, four test threads:

- Real encrypted-backup/recovery process workflow
  `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4`: **1 passed, 48.55 s**, build **0.14 s**. The two-node
  installation checks normal metadata lookups for both replacement wrapping keys,
  successor operational heads, gateway-only decryption recipients, unchanged
  coordinator heads and the retained consensus fence.
- The first run failed before transfer authorisation with cleanup failure
  (**41.35 s**, build **34.34 s**). Reproduction using the existing binary found
  exactly `runtime.sqlite3-wal` (empty) and `runtime.sqlite3-shm` (32 KiB) in the
  owned staging directory. Read-only SQLite verification had created them.
  Cleanup now removes the fixed snapshots' optional WAL/shared-memory/journal
  sidecars after all connections close. It does not recursively delete folders
  or ignore unexpected files. The passing process test verifies staging removal.
- `cargo test -p meshspan-metadata --lib recovery_preparation
-- --test-threads=4`: **40 passed, 37.42 s**, build **8.05 s**. This includes
  ciphertext preservation/decryption after reopen, normal node/key records,
  same-node reincarnation, rollback at each write boundary and ordinary
  schema 113 → 114 migration. The legacy backup-root migration also passed
  separately: **1 test, 0.35 s**, build **0.17 s**.
- Existing secret-generation tests: **7 passed, 6.15 s**, build **0.09 s**;
  existing node-wrapping-key tests: **2 passed, 0.79 s**, build **0.09 s**.
- Metadata/daemon Clippy across all targets/features with warnings denied:
  **19.70 s**. Its initial run identified an oversized test; identity/fencing
  and ciphertext/recipient behaviour now have separate focused tests.
- Workspace Rust formatting, NVM-default Prettier checks for the three changed
  design documents, and `git diff --check` passed.

Next integration boundary: normal storage-target registration creates a provider
component whose provenance currently requires a user/service principal. Recovery
is authorised by the offline root, not by a surviving administrator. Provider
projection must represent that authority accurately; selecting an arbitrary
administrator or inventing a user command is not an acceptable shortcut. No
provider-provenance schema change or provider activation has been made here.

Task 10 remains **5 points**, Stage 10 **83**, Stage 11 **126/not started**,
pending the combined activation workflow. No full `pnpm check` integration gate,
signing retry, commit, push, release, tag, package/image publication or GitHub
Actions ran. Signing remains blocked at the existing 1Password checkpoint;
publication remains prohibited.

## Task 10 — common recovery state across selected nodes

`export-recovery-state-set` now creates all selected nodes' packages from one
isolated coordinator snapshot. Route projection and key exports read only that
snapshot. One encrypted metadata/history archive is wrapped for the selected
nodes, with node-specific key bundles and root-signed transfers. The ordinary
three-file package layout and installer are unchanged. Same-filesystem hard
links share the immutable encrypted archive in the export directory, avoiding N
copies; installation still copies and verifies each signed byte stream. Plaintext
staging is removed before transfer authorisations are published.

`require_recovery_state_installations` now also requires one common encrypted
state digest and length across every selected node. Individually valid collected
signatures from different exports cannot be combined into one accepted set. It
does not implicitly select the newest export or activate an older set merely
because its historical receipts remain valid. The caller must select the intended
candidate. No schema, wire format, dependency or public HTTPS model changed.

The [flow](flows.md#exact-state-package-installation-collection) documents the
headless command, interrupted/partial output and copying packages to other hosts.
This supplies a common **preparation**, not an admitted runtime: provider/key
projection, membership activation, current certificate/storage checks and the
combined service-admission transaction remain open. Subsequent coordinator work
does not alter an existing exported set and may require a newly selected set.

Local working-tree evidence, 2026-09-09, Rust 1.98.0 and four test threads:

- Actual encrypted-backup/recovery process workflow:
  `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4` passed in **47.81 s**, build **5.25 s**. A new two-node
  preparation selects a gateway and a storage-only node, exports one set, checks
  common archive identity and distinct key bundles, and installs/collects each
  through real daemon processes. Both installed metadata/history database sets
  have identical bytes. Missing/duplicate acknowledgements, another identity and
  mixed separately exported packages fail; the matching set passes after reopen.
  The consensus fence remains enforced. This is not live two-node service or a
  hardware failure proof.
- The first run failed during new preparation (**37.58 s**, build **37.26 s**).
  A diagnostic run (**36.71 s**, build **5.21 s**) proved its source pack could no
  longer open. Inspection of the retained fixture found an earlier corruption
  test saved only the 4 KiB SQLite main file while committed pages remained in
  WAL. Its writer checkpointed/removed the WAL, then restoring the old main file
  lost that history. The fixture now saves/restores main and sidecar bytes
  together. An explicit source-pack reopen/read check fails before this correction
  and passes afterwards; no production recovery validation was relaxed.
- Metadata/daemon Clippy, all targets/features with warnings denied: **4.33 s**.
  The first lint run identified unnecessary debug formatting in the new test's
  command-labelled diagnostic; this was corrected before the passing lint run.
- `cargo test -p meshspan-metadata --lib recovery_preparation
-- --test-threads=4`: **36 tests, 33.42 s**, build **5.22 s**.
- `cargo test -p meshspan-backup --lib
two_recovery_recipients_restore_exact_streamed_bytes -- --test-threads=4`:
  **1 test, 0.74 s**, build **3.51 s**. Workspace Rust formatting passed.

Task 10 remains **5 points**, Stage 10 **83**, Stage 11 **126/not started**; the
combined activation workflow is still the acceptance boundary. No full
`pnpm check` integration gate, signing retry, commit, push, release, tag,
package/image publication or GitHub Actions ran. Signing remains blocked at the
existing 1Password checkpoint; publication remains prohibited.

## Task 10 — exact state-package installation collection

`collect-recovery-state` now collects a node's state-installation report against
the coordinator's independently chosen `state.auth`, not a package chosen by
the report. Closed bounded JSON must match the expected displayed node, encrypted
state digest and signing message, then the node signature verifies the exact
reconstructed state-transfer transcript. The repository rechecks the root-signed
transfer, original authorisation, selected node/incarnation and credential fence.

Schema **113** retains immutable per-node/per-state-digest history, including the
complete transfer, signature and first collection time. Exact replay preserves
that time; insert failure rolls back. It does not label any receipt implicitly
"latest". `require_recovery_state_installations` requires an explicitly supplied
package for every selected node, rejecting absent, incomplete, duplicate or
unselected sets and revalidating every retained signature in one read view. The
sealed preparation is validated once for the set; node lookup uses the plan's
validated sorted identities rather than repeatedly validating the entire key
inventory for every node. Key-only proof and an older state digest are insufficient
for an explicitly newer expected package.

The [flow](flows.md#exact-state-package-installation-collection) distinguishes this
installation check from live admission. A receipt is a signed installation claim,
not current physical health. Final activation must select one frozen consistent
runtime candidate across nodes, account for preparation changes, validate current
certificates and required storage, and activate provider/key/membership state.
The collection/check does not clear the consensus fence or advance metadata.

Local evidence on the uncommitted working tree, 2026-09-09, Rust 1.98.0 and four
test threads:

- `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4`: **37.59 s**, build **44.54 s**. The real workflow first
  proves an existing key acknowledgement is insufficient, collects/replays the
  earlier installed state, then rejects it against the newer route-bearing
  package. Changing its displayed fields still fails the signature check. An
  injected insert failure leaves only the earlier receipt. Successful new
  collection/reopen/retry satisfies the explicitly selected new package, while
  preserving old history and refusing consensus startup. Empty and duplicate
  selections fail. This fixture has one selected replacement node; it is not
  the multi-node live-admission or hardware proof.
- `cargo test -p meshspan-api-contract --lib recovery_ -- --test-threads=4`:
  **12 tests, 0.07 s**, build **7.80 s**. New report vectors cover expected-field
  substitution, duplicate/unknown fields, coercion, oversized bodies/scope and
  noncanonical signatures.
- `cargo test -p meshspan-metadata --lib recovery_preparation
-- --test-threads=4`: **36 tests, 33.65 s**, build **16.23 s**, including ordinary
  schema 112 → 113 migration. The separately run legacy backup-root migration
  fixture passed in **0.34 s**, build **0.09 s**.
- API-contract/metadata/daemon Clippy passed across all targets/features with
  warnings denied in **43.54 s**. Workspace Rust formatting, NVM-default document
  formatting and diff checks passed. No dependency or public HTTPS schema changed;
  no full `pnpm check` integration gate ran for this increment.

Task 10 remains **5 points**, Stage 10 **83**, Stage 11 **126/not started**. This
completes the exact-package acknowledgement boundary, not the combined activation
workflow. No signing retry, commit, push, release, tag, package/image publication
or GitHub Actions ran. Signing remains blocked at the existing 1Password checkpoint.

## Task 10 — replacement route preparation and delivery

`export-recovery-state` now includes collected restoration routes in its isolated
catalogue candidate. A bounded metadata visitor verifies each selected node's
complete stored stream before callbacks, in one coherent read transaction. The
exporter resolves each original receipt from the authenticated archive and checks
the exact replacement operation, target, generation, length and digest. A separate
catalogue snapshot receives the routes, leaving original lookup evidence unchanged
for repeated retained references. Conflicting mappings fail instead of overwriting
an earlier selection. The existing encrypted archive/root-signed transfer binds the
result, without another file format or wire message.

The filesystem's explicit `prepare_recovery_shard_route` entry point reuses normal
replay-safe route projection in this isolated candidate. It reserves the checked
`source_revision + 1` for later recovery activation; it does not commit that revision
or advance the metadata head. The daemon's recovery fence still blocks consensus.
Admission must separately adopt the matching revision, current provider/key and
membership state and prove required availability before serving these routes.
The export's `restored_route_references` is a reference count, not a completeness,
current-health or fault-domain-protection claim. Fresh receipts require a fresh
package. [The flow](flows.md#replacement-node-prepared-state-transfer) documents
these boundaries; no running catalogue is modified by the offline command.

Local working-tree evidence, 2026-09-09, Rust 1.98.0 and four test threads:

- Actual encrypted-backup/recovery process workflow: final **38.43 s**, build
  **5.04 s**, using `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4`. It exports again after restoration/collection, installs
  with only the replacement node's keys, checks the exact new receipt and route
  generation, preserves the earlier catalogue bytes, and still rejects consensus
  startup. Original storage remains unavailable. Corrupting a stored receipt
  prevents both encrypted-state output and a signed transfer from being produced;
  the test restores its fixture afterwards. Visitor callbacks also exercise exact
  receipt enumeration and propagated caller failure.
- The first process run **failed in 20.22 s**, build **33.30 s**, at a nested
  transaction: the new visitor called a transaction-owning public validator.
  It now calls the existing validator for an already-open transaction. The same
  workflow then passed in **35.40 s**, build **20.65 s**, before the final added
  corruption refusal. This was a corrected owning-boundary error, not a passing
  retry used to dismiss an unexplained failure.
- `cargo test -p meshspan-filesystem --test protected_content
-- --test-threads=4`: **12 tests, 4.68 s**, build **7.10 s**. The offline
  multi-target test now uses this recovery-specific projection, rejects altered
  receipt lengths, replays exact projections and reads original bytes through
  the normal content reader after reopening and two additional replacement-target
  losses, without the salvage source. These are real local folders/logical
  topologies, not physical-machine/power-loss evidence.
- `cargo test -p meshspan-metadata --lib recovery_preparation
-- --test-threads=4`: **36 tests, 32.82 s**, build **12.77 s**.
- All-target/all-feature Clippy for filesystem, metadata and daemon passed with
  warnings denied in **42.82 s**. Workspace Rust formatting, NVM-default document
  formatting and diff checks passed. No dependency, database migration or public
  HTTPS schema changed. No full `pnpm check` integration gate ran this increment.

Candidate route delivery closes **6 → 5 points**, Stage 10 **84 → 83**; Stage 11
remains **126**, not started. Current authority/provider installation, replacement
membership, all-node readiness, returning-node fencing and recovered live HTTPS/SMB
remain open. No signing retry, commit, push, release, tag, package/image publication
or GitHub Actions ran. The existing 1Password signing checkpoint remains blocked.

## Task 10 — archive-matched restoration receipt collection

The real `collect-recovery-restoration` coordinator command now compares a
selected node's entire signed receipt stream with freshly restored authenticated
archive metadata/history. Each operation, shard, length, digest and destination
must match the independently walked retained layouts; missing/extra receipts and
inconsistent framing, counts or digest fail before persistence. The selected
node's signature and previously collected target are independently verified.
A valid signature cannot authorise a different archived shard operation.

Validated receipts are copied to private scoped work, then consumed in one local
SQLite transaction with one reused prepared statement and bounded memory. Schema
**112** retains the immutable signed claim and its ordered receipt rows. Input or
write failure rolls back the entire collection; exact replay retains the original
timestamp. Reopening rechecks the signature, selected identity, contiguous
ordinals, count and stream hash. No transaction spans network IO. Collected rows
are evidence, not active targets, read routes, present availability or service
admission. The consensus recovery fence remains closed.

The existing 126-byte receipt codec now belongs to the transport-independent
contracts crate, with the data-plane API delegating to it without a format change.
Typed restoration signing messages preserve the node's existing bytes. A closed,
bounded CLI report decoder rejects duplicate/unknown fields, numeric coercion,
noncanonical numbers/hex and service-admitting claims. No dependency or public
HTTPS/OpenAPI shape changed. Command behaviour is documented in
[the recovery flow](flows.md#collecting-restored-shard-evidence).

Local evidence on the uncommitted working tree, 2026-09-09, Rust 1.98.0 and four
test threads:

- `cargo test -p meshspan-daemon --test headless_process
exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes
-- --test-threads=4` passed first in **32.27 s**. The final post-edit run passed
  in **32.15 s**, build **53.81 s**. Original storage and target journals remain
  unavailable during restoration and collection. The fixture injects a stream
  error after one insert and a SQLite insert failure, proves zero retained rows,
  rejects a correctly signed wrong-operation report and truncated receipts, then
  checks exact successful collection/reopen/retry and no active destination route.
- `cargo test -p meshspan-contracts -p meshspan-api-contract --lib
-- --test-threads=4`: **35 contract tests, 0.00 s; 66 API tests, 0.20 s**,
  build **14.05 s**. Independent wire bytes assert every field's layout; truncation,
  trailing bytes, zero required fields and malformed report vectors are rejected.
- `cargo test -p meshspan-metadata --lib recovery_preparation
-- --test-threads=4`: **36 tests, 32.23 s**, build **29.87 s**. Ordinary database
  migration includes schema 111 → 112. The separately run
  `backup_root_migration_retains_surviving_legacy_history` fixture passed in
  **0.34 s**, build **0.09 s**.
- `cargo test -p meshspan-data-plane --test remote_transfer
-- --test-threads=4`: real mTLS shard lifecycle **0.31 s**, build **18.84 s**.
- `cargo test -p meshspan-filesystem --test protected_content
-- --test-threads=4`: **12 tests, 4.69 s**, build **29.44 s**. These are real local
  folder/IO and logical-topology proofs, not six physical machines or power loss.
- Final all-target/all-feature Clippy for contracts, API-contract, data-plane,
  metadata and daemon passed with warnings denied in **5.75 s**. Earlier compile
  checks caught unsupported unsigned SQL decoding, borrowed SQL parameter
  temporaries and an unavailable statement-cache API; the implementation now
  uses checked conversion and an explicitly reused statement. Lint caught test
  unwrap/stack allocation, a complex stored-attestation tuple and an oversized
  workflow test. Named stored fields, fallible fixtures and a separately owned
  signed-forgery fixture resolved these without weakening checks or suppressions.
- Workspace Rust formatting, NVM-default document formatting and diff checks
  passed. No full `pnpm check` integration gate was run for this increment.

Collection/completeness closes **7 → 6 points**, Stage 10 **85 → 84**; Stage 11
remains **126**, not started. Authoritative route installation, replacement
membership, all-node readiness, returning-node fencing and recovered live
HTTPS/SMB acceptance remain open. No signing retry, unsigned commit, push,
release, tag, package/image publication or GitHub Actions ran. Signing remains
blocked at the existing 1Password authentication checkpoint.

## Task 10 — node-side retained-shard restoration

`restore-recovery-target` now executes physical restoration on the selected node
using its existing identity/wrapping keys, root-authorised encrypted state package,
signed prepared target and copied salvage inventory. The offline private root
does not leave the coordinator. Every attempt restores fresh authenticated
metadata/history instead of trusting a previously staged mutable SQLite file.
The existing retained-tree walker selects referenced manifests, then the node
reconstructs and verifies each selected original-target slice and writes it through
the normal capacity-reserving, durable folder provider. Original targets are not
adopted, and no namespace is inferred from pack filenames.

Receipts stream to a synced file with fixed version-one data-plane framing. The
node signs the exact prepared-target message, source target/generation, complete
receipt-stream digest and counts. Stable operations bind the recovery, destination
and original shard receipt; a failed attempt keeps durable provider work, and a
retry recovers identical receipts without duplicate physical shards. Destination
ownership, capacity limits and source/workspace overlap checks remain enforced.
The command does not open network endpoints or publish active permit authority.
Its temporary authenticated plaintext is cleaned before successful stdout.

This composes existing mechanisms rather than inventing another shard store:
the state installer now separates installation from stdout, retained-content
visitors support encrypted restoration without plaintext keys, and the existing
data-plane receipt codec is exported for the offline stream. Its wire format is
unchanged. The new closed, bounded CLI request is not a public HTTPS endpoint.

Working-tree evidence, 2026-09-09:

- The complete real daemon encrypted-backup/recovery workflow passed first in
  **27.68 s**, build **50.82 s**. It checks that a live destination owner refuses
  copying, a successful run writes the expected encrypted shard, the reopened
  replacement pack contains exactly that source ciphertext, the node signature
  covers independently assembled claims, and report/receipt-file loss followed
  by process restart yields identical output without duplicate pack records.
- The strengthened final variant also makes the original storage folder
  unavailable throughout copying and retry; original target journals are already
  unavailable in this workflow. It passed in **27.72 s**, build **17.85 s**.
  The source is the copied inventory and authenticated export, not a live donor.
- All **9 recovery request/report boundary tests passed in 0.07 s**, build
  **9.55 s**, including the new closed restoration request, duplicate/unknown
  fields, numeric coercion and excess input. Final affected API-contract,
  data-plane, filesystem and daemon Clippy passed across all targets/features
  with warnings denied in **12.03 s**. Earlier lint runs found an item declared
  after statements and an inefficient test string formatter; both were corrected
  without suppression. Document formatting passed under NVM.
- All **12 protected-content integration tests passed in 4.68 s**, build
  **7.71 s**, covering normal repair/read/reuse and the existing multi-target
  recovery proof. These are local logical-topology/folder tests, not hardware
  machine-failure evidence. All **3 recovery-workspace tests passed in 0.08 s**,
  build **31.87 s**, preserving locking, exact intent and unknown-file refusal
  after the recognised temporary-file set was extended for authenticated installs.
- The existing real mTLS remote shard lifecycle passed in **0.30 s**, build
  **19.90 s**, exercising the same receipt codec used by recovery output.

This closes node-side physical copying **8 → 7 points**, Stage 10 **86 → 85**;
Stage 11 remains **126**, not started. It is not a claim of active routes, restored
fault-domain protection or a recovered live cluster. Coordinator receipt
validation/completeness, routing, membership and live HTTPS/SMB admission remain.
No dependency, database schema, release, tag or published artefact was added.
No full integration gate, signed commit or push is claimed for this increment.

## Task 10 — replacement target preparation and collection

The node-side `prepare-recovery-target` command now prepares a selected existing
folder through normal exclusive ownership, capability probes and durable marker
installation. It verifies the node's root-authorised recovery package and local
keys, requires the selected storage role, and persists the exact request before
touching the folder. The report binds recovery, node/incarnation, operation,
fresh target, marker fingerprint and capacity ceiling to that node's signature.
An exact retry reopens its pending target; it cannot adopt a different target or
overwrite changed intent. No local path leaves the node in the portable report.

`collect-recovery-target` verifies that signature and scope against the isolated
coordinator preparation and current credential fence. Schema 111 retains immutable
reports with exact replay and indexed target-ID pagination. Existing source target
IDs cannot be reused, and these reports never create active target/provider rows.
This deliberately uses pending recovery state rather than fabricating a consensus
commit to call the live registration service. Neither command stores shards or
claims physical capacity, fault protection or recovered-service admission.

Working-tree evidence, 2026-09-09:

- Both new metadata tests passed in **3.46 s**: reopen, pagination/end, original
  receipt retention on exact replay, forged/substituted reports, changed marker,
  injected insert failure/rollback and every truncated report. Active target
  lookup stays empty.
- The actual encrypted-backup/headless recovery workflow passed in **24.54 s**,
  build **8.14 s**. It prepares a real folder, independently verifies the signed
  report and physical marker, collects it using the real coordinator command,
  reopens SQLite and checks integrity, retries both commands, rejects changed
  request intent and a corrupted report, and preserves an ordinary sibling file.
  Consensus remains `RecoveryAdmissionRequired` throughout. The first test
  compilation used a private field instead of the existing public accessor;
  this was corrected before the successful run, without changing runtime code.
- All **36 recovery-preparation tests passed in 32.93 s**, with four threads,
  including ordinary-database migration from the earlier recovery schemas.
  The separate schema-109 backup-root migration fixture passed in **0.34 s**;
  its setup now removes all post-109 objects before opening the historical state.
- Metadata/daemon Clippy passed across all targets/features with warnings denied
  in **33.58 s**. No dependency or generated public API change was required.
  Rust formatting, NVM-selected document formatting and whitespace checks passed.

The next work is to use these prepared targets for complete physical restoration,
install authoritative routes and replacement membership, then prove live service
admission. This is not that end-to-end recovery proof. Task 10 remains **8 points**,
Stage 10 **86**, Stage 11 **126**, not started. The full integration gate has not
been run for this increment. Signing remains at the existing authentication
checkpoint; no unsigned commit, push, release or other publication was attempted.

## Task 10 — restoring encrypted shards into normal storage

The filesystem now has an offline stripe-restoration operation over the existing
salvage, coding and routed-storage interfaces. It validates the entire bounded
request set before source IO, reconstructs ciphertext once for all requested
slices, checks regenerated bytes against the archive and uses the same durable
reservation/write/receipt implementation as live repair. Neither plaintext keys
nor a live read permit are needed for this offline physical operation. Its caller
must independently authorise the source and destination selection. No old target
is modified or deleted and no storage location alone grants authority.

Returned receipts do not automatically change read routes or claim protection.
Partial failure may leave earlier slices durable; identical operation IDs recover
their receipts on retry. This deliberately composes with the existing separately
authorised catalogue transition instead of fabricating a committed recovery
revision inside the storage operation.

Working-tree evidence, 2026-09-09:

- Two focused real-folder recovery tests passed in **2.07 s**, build **12.30 s**.
  The new case loses two original targets and every original target journal,
  captures only the two surviving encrypted packs, restores all four coded slices
  for a multi-chunk file into fresh normal folder providers, removes access to
  the salvage inventory, reopens the providers and reads the exact original bytes
  through the normal protected filesystem reader. That reader still succeeds
  after two replacement targets are made unavailable.
- Duplicate work is rejected before salvage reads; corrupt candidates produce
  no successful restore. A target outage partway through a batch leaves an exact
  durable prefix, not a complete result. Retrying after its return recovers the
  same receipts without changing immutable shard bytes. Query counts bound the
  implementation to one reconstruction per stripe batch, rather than one per
  destination slice.
- All **12 protected-content integration tests passed in 4.60 s**, build
  **3.10 s**, with four test threads. This includes the unchanged normal repair,
  degraded reads, locality and content-reuse paths. The six-machine-named case
  is a logical topology over local folders, not physical hardware evidence.
- Final all-target/all-feature filesystem/daemon Clippy passed with warnings
  denied in **36.39 s**. Its first run identified an unnecessarily owned error
  argument; the mapping now borrows it, with no lint suppression. After that
  correction all **12 integration tests passed again in 4.69 s**, build
  **6.98 s**. Rust/document formatting and whitespace checks passed.

The test supplies trusted catalogue transitions explicitly. It does **not** prove
that the daemon recovery coordinator selects/adopts replacement targets, records
those transitions authoritatively, admits replacement membership or resumes live
HTTPS/SMB service. That composition remains the next work; this closes the missing
physical write capability without weakening the recovery admission fence. Task 10
remains **8 points**, Stage 10 **86**, Stage 11 **126**, not started. No dependency,
schema change, full integration gate, commit, push or publication is claimed.

## Task 10 — encrypted replacement-state delivery

The headless `export-recovery-state` and `install-recovery-state` commands now
deliver prepared metadata and both filesystem journals to a selected replacement
node. Export uses a consistent preparation snapshot, checks the authenticated
backup history against retained roots/layouts and encrypts all three files to
that node's wrapping key. A separately root-signed, bounded transfer record binds
the original recovery authorisation, node/incarnation and exact lengths/digests
of the encrypted state and key/certificate bundle. There is no new dependency,
private-root export or change to the public HTTPS contract.

Installation verifies both exact streams, the independently trusted root and
the node's existing private identity/wrapping keys. It decrypts only into a new
owner-only workspace, checks SQLite integrity and the persisted source position,
verifies retained history closure and synchronises its files before publishing
a node-signed installation report. The existing admission fence remains intact.
Existing destinations are refused. Interrupted attempts may leave private
partial work, including plaintext; they cannot produce a successful report and
currently require retry into a fresh directory. This command is not a running
daemon-state replacement, physical shard installation or service admission.

Working-tree evidence, 2026-09-09:

- The closed transfer-format test passed in **2.75 s**, including independent
  field encodings, every truncation/changed byte, wrong-root and excess-byte
  rejection. All **13 recovery-bundle tests passed in 2.96 s**.
- The real exported-backup workflow now performs coordinator export and actual
  node-side installation with the original filesystem journals unavailable.
  It checks private file/directory modes, reopened SQLite integrity, the exact
  root-authorised source, the node signature and the still-closed consensus
  admission fence. Corruption of each of `state.msb`, `keys.bundle` and
  `state.auth` is rejected without a successful report or plaintext metadata;
  an existing installed directory is preserved. **Passed in 23.27 s**, build
  **8.27 s**, using the four-thread harness. The first compilation exposed a
  missing explicit test-module path; that harness wiring was corrected before
  the successful run. No runtime test failure was hidden by retry.
- All **34 metadata recovery-preparation tests passed in 31.18 s**, build
  **16.18 s**. New vectors check public-root validation against another valid
  root and changed source revision, and reject a signed transfer paired with a
  different key recipient, incarnation or bundle.
- Affected recovery-bundle/metadata/daemon all-target/all-feature Clippy passed
  with warnings denied in **38.67 s**, before the final two metadata test vectors.
  Final Clippy passed in **5.80 s** after those vectors; Rust formatting passed.

Task 10 remains open: copied shards and restored protection, all-node readiness,
returning-node fencing, replacement membership and live service admission are
not proved by this delivery. No full local integration gate, signed commit, push,
release or publication is claimed. Signing remains at the existing authentication
checkpoint. Current estimates remain task 10 **8**, Stage 10 **86**, Stage 11
**126**, not started.

## Task 10 — successor incarnation through real daemon startup

Tracing recovery admission found a concrete prerequisite failure: replacement
selection requires a successor incarnation, but the daemon supplied incarnation
one to restored consensus, private transport, gateway access and several worker
claims. A node whose committed incarnation was two could not start its core.
The joining-node bootstrap response also omitted peer incarnation, making a
fresh node assume one for every accepting peer.

Normal startup now obtains the local incarnation from restored membership and
the active certificate projection. HTTP gateway sessions, SMB file-operation
contexts, backup/scrub/reconciliation/drain/repair/rebalance claims, certificate
work and notifications use the process's installed identity. A configured node
cannot fall back to first-boot identity when private trust is missing. Fresh,
unclaimed nodes still start at incarnation one. Peer bootstrap responses carry
an exact positive decimal `incarnation`; the Rust source regenerates OpenAPI,
TypeScript, Fetch and Zod artefacts. Joining nodes check the integer before
using it in authenticated QUIC peer bindings. Certificate generation and
incarnation remain distinct.

Working-tree evidence, 2026-09-09:

- The focused consensus restart test first exposed two fixture errors (missing
  storage configuration, then an unsupported legacy bootstrap command). Reusing
  the existing appliance-bootstrap fixture reached the intended defect:
  `Consensus(InvalidConfiguration)` at restart with incarnation two, in **0.46 s**.
  The corrected implementation passed in **0.45 s**. Four runtime tests,
  including exact worker incarnation/claim generation, passed in **1.19 s**.
- The first real two-daemon HTTPS/QUIC successor test passed in **11.40 s**,
  build **35.21 s**. It creates a real swarm, stops the daemon, supplies a
  test-owned successor projection, then restarts through normal startup,
  uploads/reads exact file bytes, enrols a fresh peer and reads through that peer.
- Final real HTTPS/QUIC and SMB successor tests ran concurrently and both
  **passed in 12.50 s**, build **35.99 s**. The SMB variant publishes the real
  embedded share, uploads, downloads and compares exact bytes, deletes the file
  and confirms its absence through HTTPS before enrolling another node.
  It used the inspected, existing immutable local client image
  `sha256:9daac97f82472b031c7bc56e5cdd2446ab01ceafd6dc2a4705cdd20a8ae90d6d`
  with `--pull=never`; no image was built, downloaded or published. The tag lookup
  failed, while the exact image lookup succeeded, as recorded previously.
- Rust bootstrap-peer schema validation passed in **0.02 s**. The 25 generated
  contract tests passed in **0.658 s** after correcting the test's property name
  from `peers` to the actual `bootstrap_peers`. Web type-checking and the full
  configured web/script/tooling ESLint command passed. A direct root-level
  `eslint` invocation was unavailable; the repository-owned lint script was used.

Final all-target/all-feature API/daemon Clippy passed with warnings denied in
**15.05 s**. The final four runtime tests passed in **1.16 s**, build **28.58 s**.
Generated-contract drift, Rust/document formatting and whitespace checks passed.
An earlier Clippy run rejected a test-only `expect`; the fixture now propagates that error
before constructing assignments. No lint suppression, dependency or migration
was added. This is **not** recovery admission evidence: only the test fixture
advances the stored incarnation, with the process stopped. It does not install
replacement metadata/keys/shards or admit an offline preparation. Task 10 stays
at **8 points**, Stage 10 **86**, Stage 11 **126**, not started. No full local
integration gate, signed commit, push or publication is claimed; signing remains
at the existing authentication checkpoint.

## Task 10 — verified inventory commitment before recovery signing

Preparation now derives its inventory commitment rather than accepting a hash
from the operator. The bounded selection supplies source targets and a copy
budget. The coordinator restores the authenticated archive and filesystem
journals, checks historical target identities, captures encrypted packs and
verifies complete selected files before creating replacement keys or signing
the recovery plan. An initial corrupt source cannot produce a prepared database,
root certificate export, node bundle or successful report.

The canonical version-one commitment binds the independent backup digest,
sorted target identities/generations/fingerprints and sorted copied pack members.
Main database, WAL and rollback-journal bytes have explicit presence, length and
digest fields. Original folder paths, local pack allocation order and disposable
SQLite shared memory are excluded. Empty selected targets remain in the scope.
The complete encoding is recorded in [the recovery flow](flows.md#offline-file-content-verification).

Published preparations retain their inventory outside disposable build work.
Retry verifies that inventory against the root-signed commitment without requiring
the original media. Missing or changed retained bytes fail instead of creating
another signature. Independent `verify-recovery-content` also requires the exact
signed commitment after complete-file checks. Both reports now state
`target_inventory_verified: true`; neither claims protection or service admission.

Working-tree evidence, 2026-09-09:

- Six inventory tests passed in **0.44 s**, including path/allocation-order
  independence, WAL binding, disposable SHM and missing-copy rejection. All
  **49 storage library tests passed in 2.07 s**, build **3.41 s**, with four
  test threads. Eight recovery boundary tests passed in **0.07 s**, build
  **12.01 s**; obsolete caller-supplied digest fields are rejected.
- The real HTTPS upload/export/stop/recovery workflow passed in **20.25 s**,
  build **32.30 s**, including interrupted preparation, original-media loss,
  changed/missing retained packs and prevention of signing unverified content.
- A cleanup regression initially passed for the wrong reason: its fixture
  created a non-private build directory. With the required `0700` permissions,
  it **failed in 12.95 s**: preparation reported success when a supplied backup
  occupied an owned temporary filename. Resolved backup/bundle/code/selection
  paths are now rejected inside the work directory before ownership or cleanup.
  The final real workflow **passed in 20.40 s**, build **20.51 s**, verifying
  preservation of that input alongside the existing recovery cases.

Earlier compile/lint corrections fixed a borrowed path, an incorrect fixture
header offset, a large stack buffer and unsupported test digest formatting;
no validation or lint level was weakened. The affected all-target/all-feature
Clippy run before the final cleanup guard passed in **34.88 s**; final Clippy for
API contracts, storage, filesystem, metadata and daemon passed with warnings
denied in **16.01 s**. No full local integration gate, signed commit,
push or publication is claimed. Signing remains at the previously reported
authentication checkpoint.

This closes verified inventory-commitment binding: task 10 **10 → 8 points**,
Stage 10 **88 → 86**. Stage 11 remains **126**, not started. All-node readiness,
physical installation, returning-node recovery-epoch fencing, replacement
membership and live service admission remain open, alongside broader archive
and reclamation acceptance. The tested SIGKILL checkpoint does not prove every
inventory-initialisation crash window. No stage completion is claimed.

## Task 10 — persistent pack inventory and headless file verification

`verify-recovery-content` now composes authenticated archive restoration, exact
retained-tree selection, historical target identity checks, isolated pack inventory
and complete file reconstruction. It uses no original target journal and starts
no listener. The prepared database supplies signed recovery intent only: source
roots, fingerprints and keys are read from a fresh, integrity-checked restore of
the exact encrypted backup, not unsigned preparation rows or folder claims.
The filesystem reconstructs encrypted chunks from independently checked slices,
authenticates/decrypts them, and checks each complete file's length and digest.
Plaintext goes to a verification sink, not ordinary exported files.

The storage owner now retains a private SQLite inventory bound to the selected
backup scope. Copy intent precedes IO; incomplete packs never satisfy reads.
Successful copies are synchronised before their completion transaction. Exact
retries reuse completed copies, while interrupted pending copies can be rebuilt
without deleting unrecognised files. Lookup uses an exact covering index and
tries another copy after corruption or disappearance. Reopening the inventory
does not require original media. The configured budget bounds cumulative source
copies; index/SQLite overhead is explicitly additional, not a claimed total quota.

The CLI's bounded storage-selection model lives beside the existing Rust-authored
offline recovery contracts. It rejects coercion, unknown/duplicate fields, empty
or repeated selections and invalid generations. Fingerprints cannot be supplied
by that input. Work inside selected source storage is rejected before creating
the destination. Recovery command routing now belongs to the recovery owner;
the process entry point only schedules its blocking work. No new dependency,
HTTP route, private protocol message or authoritative schema migration was added.
The new private inventory has its own version-one SQLite schema.

Working-tree evidence, 2026-09-09:

- Four persistent-inventory tests initially passed in **0.24 s**, covering
  restart without original media, exclusive ownership/scope mismatch, interrupted
  copy retry, copy-budget enforcement and corruption fallback. A missing-copy
  extension then failed with `NotFound`; lookup now continues to the surviving
  duplicate. The SQL plan check uses the actual joined lookup and confirms its
  covering index. All **47 storage library tests passed in 1.89 s**, build
  **3.34 s**, on the final storage candidate, with four test threads.
- The real-folder multi-chunk reconstruction test now uses the persistent index,
  closes/reopens it and makes every original source path unavailable. Two target
  losses still leave exact expected plaintext; wrong keys, corrupt candidates,
  missing copies and failed destinations do not report complete recovery.
  All **11 protected-content tests passed in 4.29 s**, build **18.16 s**.
- Eight recovery boundary tests passed in **0.07 s**, build **9.13 s**. The generic
  decoder needed an explicit static validator lifetime; no validation was removed.
  The historical marker test passed in **0.31 s**, build **5.05 s**. Its initial
  fixture attempted to mutate an immutable generation; the test was corrected to
  retire only the target, preserving the generation invariant and live-access fence.
  All **nine metadata storage-target tests passed in 5.34 s**, build **0.09 s**,
  including existing registration, write fencing and machine/fault-group drain cases.
- The initial real HTTPS upload/export/shutdown/recovery workflow passed in
  **19.80 s**, build **63 s**, with complete file-byte verification and rejected
  unknown generations, source-overlapping work and corrupted stored bytes.
  The final process proof additionally removes original target journals and
  compares source pack bytes before/after verification; it passed in **18.96 s**,
  build **30.76 s**. Original filesystem journals were also unavailable.
- All-target/all-feature Clippy for API contracts, metadata, storage, filesystem
  and daemon passed with warnings denied in **26.37 s**. Earlier lint corrections
  used `let...else` for failed candidate opening and consolidated recovery command
  dispatch by responsibility instead of extracting an arbitrary function suffix.
  Rust formatting, documentation formatting and whitespace checks passed.

The command retains private metadata and encrypted pack copies and publishes
`content.json` only after success. It does **not** yet validate the preparation's
canonical inventory commitment, restore protection, record all-node readiness or
admit recovered services. Those report fields remain explicitly false. The
low-level inventory resumes; a whole CLI verification currently requires a new
work directory. No full integration gate, signed commit, push or publication is
claimed. Signing remains at the previously reported authentication checkpoint.
This closes the integrated pack-inventory and selected-file-verification slice:
task 10 **13 → 10 points**, Stage 10 **91 → 88**. Stage 11 remains **126**, not
started. Canonical inventory-commitment binding and recovered-service admission
remain required; no stage completion or publication is claimed.

## Task 10 — exact retained-tree selection in backup and recovery

Backup capture and `stage-recovery-history` now select the immutable object trees
held by their exact authoritative heads/snapshot roots, rather than expanding
every ancestor commit, object revision and file-version parent. An explicitly
selected older snapshot still selects its older files. The ordinary causal
history export used by replication is unchanged.

This reuses the filesystem owner's durable, bounded graph queue and immutable
record verification. Retained-tree requests have a separate digest domain;
their tokens and restartable cursors cannot resume a causal-history export, or
vice versa. They reject a non-empty known-commit set because a partial causal
frontier is not a complete retained-tree selection. Roots are checked against
their volume and root object/revision before traversal. No new queue database,
schema migration, dependency or public HTTP/private protocol message was added.

Working-tree evidence, 2026-09-09:

- The original regression failed before the change: selecting only the current
  root emitted both its current manifest and the superseded ancestor manifest.
  It now emits exactly the current file; separately selecting the older root
  emits exactly the older file.
- Three focused cases passed in **0.44 s**, build **3.92 s**, covering exact
  selection, restart and replay, cross-traversal/scope cursor rejection,
  wrong-volume roots and non-empty known sets. A malformed unselected ancestor
  manifest is not traversed, while selecting it explicitly or requesting its
  causal history still fails. This is a graph-walker claim, not permission to
  skip integrity checking a whole restored database. The corruption fixture
  uses an invalid digest length: an all-zero, correctly sized digest was not a
  malformed encoding and was corrected rather than changing the decoder.
- All **222 filesystem library tests passed in 41.29 s**, build **0.06 s**,
  with four threads. This includes existing history paging/import, snapshot,
  reconciliation and retention checks alongside the new retained-tree mode.
- The real HTTPS upload/automatic archive/export/shutdown/offline verification,
  preparation, key installation and history extraction workflow passed in
  **15.89 s**, build **48.75 s**. Original filesystem journals were unavailable
  during extraction; no physical-shard or service-admission claim was made.
- Final all-target/all-feature filesystem and daemon Clippy passed with warnings
  denied in **49.64 s**. The only implementation lint correction borrowed the
  shared validated paging request instead of unnecessarily taking ownership;
  focused regressions passed afterwards in **0.42 s**, build **3.93 s**.
  Rust formatting, documentation formatting and whitespace checks passed.

Physical inventory, daemon file-byte verification and recovered-service admission
remain open. The previous storage/file reconstruction components remain available
for that integration; this step does not start services or claim shard readiness.
Physical inventory evidence must be independently derived from the authenticated
backup and observed media before satisfying the recovery plan's inventory
commitment; the current preparation's supplied intent digest is not that proof.
Task 10 remains **13 points**, Stage 10 **91**, Stage 11 **126**, not started.
Publication remains prohibited; no commit or push is claimed.

## Task 10 — surviving-pack salvage and verified file reconstruction

The storage owner now exposes an offline recovery reader independent of the
original node/target journal. It takes the normal exclusive target lock and
requires a marker fingerprint supplied from independently verified metadata.
It performs no registration probes, repairs or source-database writes. It copies
one pack and its crash journals into a new private, byte-bounded workspace;
SQLite interprets only that copy. Exact source files remain unchanged, including
a tested crash-left WAL containing acknowledged data with no shared-memory file.
An explicit fallible finish removes only recognised scratch files. Unexpected
files and partial failed work are preserved rather than recursively deleted.

Pack discovery streams directory entries without collecting the whole target.
Bounded primary-key inventory pages include active, tombstoned and unlinked
records without loading ciphertext BLOBs. These are suspect locators, never
proof of integrity, authority or availability. Exact recovery reads verify the
requested identity, length and digest against independent archive evidence.
Tombstoned bytes may be salvaged while physically present without reactivating
their original storage record.

The filesystem owner can now stream a complete protected file from its verified
committed layout, an unwrapped content key, replaceable coding and a read-only
recovery source. It independently checks candidate shards, reconstructs encrypted
chunks, authenticates/decrypts them and verifies the complete plaintext length
and digest. It holds only a bounded stripe/chunk working set and verifies the
catalogue once per file rather than rescanning it per chunk. Plaintext working
buffers have zeroising owners. No live read permit, repair write, reservation,
consensus transition or service admission is minted by this operation. Callers
must keep partial outputs isolated and durably publish only after success.

Working-tree evidence, 2026-09-09:

- All **43 storage library tests passed in 1.61 s**, build **3.84 s**, using four
  threads. Seven new cases cover crash-left WAL, no original journal, live-owner
  rejection, marker substitution, missing/corrupt bytes, retained tombstones,
  bounded/exclusive scratch space, source symlinks, unknown cleanup files,
  keyset pagination and malformed persisted catalogue claims. Storage Clippy
  passed with warnings denied in **10.19 s** at that checkpoint.
- The initial real-folder reconstruction test passed in **1.04 s**, build
  **12.71 s**. It publishes a multi-chunk file normally, copies its closed layout
  catalogue, makes every original target journal and two complete targets
  unavailable, then reconstructs exact expected bytes from the remaining two
  packs. Wrong keys, corrupt candidates, insufficient slices and destination
  failure return errors, not completed recovery. This is local real-folder IO
  with synthetic loss, not a physical power-loss or complete daemon recovery test.
- The final **11 protected-content integration tests passed in 4.20 s**, build
  **3.16 s**, covering normal/degraded reads, repair, deduplication and availability
  scopes as well as offline reconstruction. Lint required separating publication/
  loss fixture preparation from recovery assertions, not arbitrary line extraction.
- All-target/all-feature Clippy for storage, filesystem and daemon passed with
  warnings denied in **52.28 s**. Rust formatting, documentation formatting and
  whitespace checks passed. Initial compile/lint findings included a test SQL
  integer conversion, explicit imports, signed flag representation, a collapsible
  guard and test naming/size; none required weakening checks or adding dependencies.

No dependency, schema migration, HTTP route or private wire message was added.
These composed storage/filesystem capabilities are not yet wired into the
headless recovery workflow. Remaining work includes a bounded durable physical
inventory, selecting the exact retained object graph (not all namespace commit
ancestors), daemon orchestration and all-node recovery/service admission.
Task 10 remains **13 points**, Stage 10 **91**, Stage 11 **126**, not started.
No full integration gate, commit, push or publication is claimed here.

## Task 10 — backup-owned namespace retention

Capture now acquires retained namespace roots in the same replicated transaction
as its first worker claim, before filesystem copying or provider IO. Heads and
active/expiring snapshots are pinned; changes during an unsealed capture retain
revision windows rather than dropping the old root. Catalogue admission trims
those windows to the exact captured source revision and seals the generation.
All later changes leave its selected roots intact.

Committed retirement releases only that backup's ownership. Overlapping backups
deduplicate immutable commits in the retained-root enumeration without losing
their separate ownership. Abandoning an unrecorded run releases temporary pins;
an admitted, incompletely protected generation keeps them until retirement.
Capture never recursively inherits older archives' pins. Producer and offline
history checks cover the archive's source heads and user snapshots, not an
assertion that all older backup generations were themselves restored.

Metadata root pagination and canonical digests now include backup roots. The
filesystem's durable reachability scan accepts the same source kind and refuses
cleanup when a backup-held root reaches the candidate version. These are the
authoritative/root-graph pieces, not yet an assembled physical reclamation proof.

Partition schema **110** adds capture windows and owned root references. Previous
generations without exact capture evidence conservatively retain surviving head
history until retirement; the migration does not reconstruct already-lost bytes.
Filesystem schema **45** extends retained-root records while preserving existing
scans and their digests. No dependency or public HTTP/private wire message was
added. Existing encrypted backup transport and retirement commands remain owners.

Working-tree evidence, 2026-09-09:

- The original capture-race regression failed before the fix: advancing the head
  dropped the earlier root from retention before catalogue admission. It passes
  after the fix. Six focused metadata cases cover source-revision sealing,
  pre-commit rollback, reopen, snapshot removal after capture, legacy migration,
  abandoned captures and overlapping generations without recursive inheritance.
- Two filesystem cases prove backup-root retention across restart, rejection of
  a substituted root identity and migration of a pre-existing schema-44 scan.
- All **84 metadata backup tests passed in 50.13 s**, build **10.69 s**. All
  **219 filesystem library tests passed in 41.43 s**, build **0.06 s**. Both use
  four test threads; these are local library tests, not host power-loss proof.
- Neighbouring metadata tests also passed: **24 snapshot tests in 24.10 s**,
  build **0.09 s**, and **9 version-cleanup tests in 10.05 s**, build **0.10 s**.
  These exercise snapshot scheduling/removal/restore, root digest fences,
  cross-node attestations and transactional finalisation with injected faults.
- All-target/all-feature Clippy for metadata, filesystem and daemon passed with
  warnings denied in **40.44 s**. Initial checks found a test-only SQL integer
  conversion, colliding fixture operation IDs and two needless by-value helper
  arguments; these were corrected without lint suppression or policy changes.
- The real HTTPS upload/automatic archive/export/shutdown/offline preparation/
  key installation/history extraction workflow passed in **16.06 s**, build
  **43.78 s**. Original journals were unavailable during extraction; archived
  history and its content-key envelope were recovered, while changed bytes and
  existing destinations were rejected. It still reports physical shards
  unverified and service admission false.
- Rust and JavaScript licence checks passed under NVM (9 production and 28
  tool-only JavaScript packages). Documentation formatting and whitespace checks
  passed, as did workspace Rust formatting.

Remaining: assembled retained-backup physical reclamation, non-empty multi-gateway
capture/takeover, physical target/file-byte recovery, all-node readiness and
recovered-service admission. Task 10 stays **13 points**, Stage 10 **91**, Stage 11
**126** (not started). No full integration gate, commit, push or publication is
claimed; signing authorisation has not been retried and publication is prohibited.

## Task 10 — automatic filesystem-history archive capture and extraction

Automatic backup preparation now produces one encrypted archive containing the
exact control snapshot, namespace journal and content-layout journal. It captures
the control state first, queries a separate verified restore of that snapshot,
and validates the copied filesystem closure against its retained roots and key
references. The archive is not published from an incomplete capture. A never-used
filesystem may supply an empty private journal pair only if the same closure
check succeeds; missing required history never becomes a fabricated empty backup.

The backup container advances to format **2**. Its header carries optional fixed
namespace/content member evidence alongside the unchanged control-state manifest.
All members share the authenticated header and one increasing nonce counter;
each has its own checked plaintext length and digest. Streaming buffers remain
bounded and plaintext encryption/decryption buffers now have zeroising owners.
Archive input carries no paths. Requested output paths are caller-selected,
created rather than overwritten, and partial output is never success. Even a
metadata-only restore authenticates discarded history members. Format-1 pre-alpha
containers are rejected and need recreation from source state; no old compatibility
promise or published release exists.

Provider/federation transport, scheduling, copy policy and the independent export
digest remain the existing mechanisms over one opaque encrypted object. No new
dependency, SQL migration or HTTP/protocol message was added. The daemon's capture
interface now explicitly supplies its filesystem source instead of deriving that
location from a control-database filename. The existing marked private workspace
also owns the copied journals and recognises their exact SQLite sidecars for
cleanup/rebuild. Original source journals remain read-only.

`stage-recovery-history` now accepts the original encrypted archive as well as a
surviving filesystem directory. For an archive, the required digest comes from
the verified root-signed preparation, not from a newly supplied replacement hash.
It authenticates all members, removes the disposable control member and validates
the recovered history/layouts and actual content-key envelopes as before. Its
report identifies `authenticated_backup` versus `surviving_journals` and still
denies physical shard verification and service admission.

Working-tree evidence, 2026-09-09:

- All **21 backup-library tests passed in 1.09 s**, build **6.38 s**. New archive
  cases remove every original source file before checking exact restored bytes,
  reject reordered members and changed ciphertext even with an updated outer
  digest, authenticate history during metadata-only extraction, refuse existing
  output and reject a history request against a metadata-only container.
- The real HTTPS upload/automatic backup/export/stop/preparation/installation/
  collection/history workflow passed in **16.04 s**, build **56.93 s**. Before
  history staging, it moves the original filesystem directory out of service and
  asserts that the original location stays absent. The archive alone supplies
  the expected root, manifest and decryptable content-key envelope. Existing
  interruption/resume, corruption rejection and installed-certificate QUIC proofs
  remain in that workflow. This does **not** reconstruct physical file bytes.
- All-target/all-feature, warning-denied Clippy for backup, filesystem, metadata
  and daemon passed in **40.46 s** without suppressions or threshold changes.
- **78 metadata backup regressions passed in 45.88 s**, build **18.38 s**;
  **63 daemon backup regressions passed in 5.97 s**, build **31.09 s**, using four
  test threads. They cover snapshot/migration checks, copy admission, retention,
  staging replay, recovery, capacity and the affected API boundaries.
- The real worker lost-source/recovery/original-generation completion regression
  passed in **13.14 s**, build **0.14 s**, including the never-used filesystem case.
- Rust formatting, documentation formatting and whitespace checks passed. Rust
  and JavaScript licence checks passed under NVM (9 production and 28 tool-only
  JavaScript packages). No new dependency was added.

Remaining: retained backups must keep their referenced physical content out of
reclamation; the current live retained-root query covers converged heads and
user snapshots, not backup roots. Archive capture/extraction does not close that
requirement. Multi-gateway capture/takeover with non-empty history also needs
acceptance: a worker without the required local closure currently refuses capture.
Physical target/file-byte recovery, all-node readiness, returning-authority fencing
and recovered-service admission remain open. Task 10 stays **13 points**, Stage 10
**91**, Stage 11 **126** (not started). No full integration gate, independent
hardware proof, commit or push is claimed. Signing authorisation has not been
retried; publication remains prohibited.

## Task 10 — non-empty recovery history and content-key verification

`stage-recovery-history` now takes an isolated prepared database, offline recovery
bundle/code and a surviving gateway's filesystem directory. The filesystem owner
copies its two existing journals through read-only SQLite snapshots into a new
private workspace. Only the copies are opened for migration or history-export
bookkeeping; existing destinations are never overwritten.

The daemon walks the preparation's retained volume/snapshot roots with indexed
pagination and the existing bounded history exporter. Root coordinates must match;
referenced immutable manifests and reconstructed content layouts must agree. Each
referenced content-key envelope is authenticated using its exact retained volume-key
generation recovered through the offline authority. Plaintext keys remain in
zeroising owners and are not printed or retained as plaintext outputs.

`history.json` is published only after these checks and journal synchronisation.
It explicitly denies shard verification, service admission and service startup.
This is a staged donor copy, not authority to serve its additional outage branches.
Partial failed work remains private and requires a new destination for another
attempt. No dependencies, schema or public HTTP contracts changed.

The real backup workflow previously exercised an empty filesystem. It now creates
a volume through HTTPS, selects strong single-node acknowledgement and uploads
known file bytes before taking the encrypted control backup. After stopping the
daemon, the workflow prepares recovery, installs/collects replacement credentials,
stages its surviving history and checks exactly one retained root and one manifest
reference. It verifies the original journal bytes are unchanged, refuses an
existing destination, corrupts only a test copy's content-key ciphertext and
requires rejection without a success report. Existing interruption/resume and
installed-certificate QUIC checks remain in the same assembled workflow.

Working-tree evidence, 2026-09-09:

- The pre-restart process handle was unavailable and no test process remained;
  its missing result was not counted. The non-empty real workflow was rerun and
  passed in **13.25 s**, incremental build **0.13 s**.
- Three filesystem snapshot tests passed in **0.09 s**, build **32.43 s**:
  independent copied databases with SQLite integrity checks, unchanged source
  bytes, no overwrite, missing/corrupt input rejection and symlink rejection.
  The initial command also launched unrelated zero-match integration executables;
  the subsequent focused command uses `--lib` to avoid that startup cost and
  passed in **0.09 s**, build **0.15 s**.
- Initial compilation exposed use of a nonexistent secret accessor; the correct
  protected accessor and a zeroising fixed-size key copy were used. All-target,
  all-feature, warning-denied Clippy then caught similar `content`/`context`
  names. Naming the publication explicitly resolved it without suppressions.
  Final affected filesystem/metadata/daemon Clippy passed in **21.06 s**.
- After that correction, the complete non-empty real workflow passed again in
  **13.26 s**, build **21.47 s**. Rust formatting, documentation formatting and
  whitespace checks passed. Rust and JavaScript licence checks passed under NVM
  (9 production and 28 tool-only JavaScript packages); no full workspace gate was
  run for this focused increment.

**Required gap exposed:** the control-metadata export contains neither filesystem
journal. Raw shards plus that backup do not yet suffice to reconstruct the file
namespace. The new command verifies surviving donor history; it does not replace
automatic backup coverage of the retained immutable history/layout/key references.
That archive coverage must bind the same selected control snapshot, survive loss
of every gateway journal and pass a restored-file-byte proof before full recovery
can be claimed. Physical target/content verification, all-node readiness,
returning-authority fencing and service admission also remain open.

The previous estimate omitted this archive integration: task 10 is corrected
**8 → 13 points**, Stage 10 **86 → 91**. Stage 11 remains **126**, not started.
No full integration gate, commit, push, publication or completed recovery is
claimed. Signing authorisation remains unresolved; publication remains prohibited.

## Task 10 — restartable offline recovery preparation

Preparation now separates unpublished build work from the retained coordinator
database. A private workspace binds the independently verified backup digest,
recovery-bundle digest and normalised selection, with an OS file lock for one
preparer. Interrupted work is rebuilt only inside the owned `build` directory;
unknown files and unsafe paths are rejected rather than recursively removed.
An interrupted initial intent publication can be completed without adopting
an unrelated existing database.

The existing typed SQLite backup operation captures a complete isolated,
credential-fenced preparation into a closed snapshot. That file is made
owner-only, synchronised and atomically linked to `prepared.sqlite3` before
any node bundles are exported. This avoids resuming half-created SQL state or
retaining a separate operator-managed key spool. No active state is published:
the copied database still refuses consensus admission.

Once the database is published, retries revalidate the root-signed exact source
claims, mesh/partition, replacement selection and sealed keys. They preserve its
key material, certificate/fence times and installation receipts. Missing bundles
are deterministically regenerated; existing bundles are checked with bounded
streaming against the reconstructed expected bytes, never silently overwritten.
Report and root-certificate publication also require exact equality on retry.
The new public metadata reader exposes the already-validated recovery
authorisation to this coordinator consumer, without exposing raw SQL or adding
an authority shortcut. No schema or dependency change was needed.

Working-tree evidence, 2026-09-09:

- Three workspace tests passed in **0.08 s**, build **41.94 s**: exclusive ownership,
  interrupted marker/build handling, changed-intent rejection, protected atomic
  publication, no overwrite and preservation of unknown files.
- The first assembled command workflow with successful replay passed in
  **11.22 s**, build **34.33 s**.
- The expanded real command proof passed in **15.79 s**, build **17.73 s**. It
  observes an actual unpublished SQLite restore, sends **SIGKILL** to that
  preparation process, verifies termination by signal 9 with no success output
  or published database, and resumes using the same command/workspace. It then
  removes selected test exports to simulate interrupted output publication and
  verifies exact regeneration, rejects changed inventory intent and corrupted
  existing bundles without overwriting them, and proves a previously collected
  signed installation receipt survives another preparation retry. No production
  fault-injection switch was introduced.
- This extends the existing real HTTPS export/offline verification/installation/
  collection/QUIC-certificate proof. It is process-loss evidence on this host,
  not physical power-loss, remote target completeness or recovered multi-node
  service evidence.
- Initial compilation caught comparison of borrowed versus owned authorisation
  claims and an unused import; both were corrected without contract changes.
  Clippy then required an explicit unit-expression semicolon and passing the
  296-byte manifest by reference. No lint suppression or threshold change was used.
- Final all-target/all-feature, warning-denied Clippy for metadata and daemon
  passed in **16.79 s**. The three workspace regressions passed again in **0.08 s**,
  build **6.71 s**. All **32 recovery-preparation metadata tests passed in 27.22 s**,
  build **11.96 s**, using four test threads.
- Rust formatting, documentation formatting, whitespace and Rust/JavaScript
  licence checks passed. The JavaScript gate used the active NVM toolchain and
  checked 9 production and 28 tool-only packages. No new dependency was added.

Remaining task 10 work is target/content and complete-key-reference verification,
all-node readiness, returning-authority fencing and recovered-service admission.
Task 10 remains **8 points**, Stage 10 **86**, Stage 11 **126** (not started).
Pre-alpha workspaces from the earlier non-restartable layout are not adopted;
they require a new workspace. No full integration gate, commit, push or release
is claimed. The publication hold remains in force.

## Task 10 — headless recovery preparation and receipt collection

`prepare-recovery` now takes the independently saved backup digest, encrypted
setup recovery bundle, owner-only code file and bounded public replacement
selection. It verifies the exact source and recovery identity, plans encrypted
replacement material using a bounded-record spool, signs/stages the replacement
plan, fences copied transient credentials and exports per-node key/certificate
bundles. Its retained report explicitly denies target-inventory verification and
service admission. Normal completion removes the disposable source restore;
the isolated prepared database remains available for subsequent steps.

`collect-recovery-installation` consumes a saved installer report and exact node
ID, then invokes the existing transactional signature-verification journal.
It reconstructs authority from the isolated preparation rather than trusting
reported hashes, messages, counts or certificate fields. A forged signature
cannot insert a receipt. Successful retry after reopening preserves the first
receipt time. Output identifies only that node's verified installation claim;
it does not start services or assert all-node readiness.

The report shape lives in the existing API-contract crate and is shared with the
installer. Original-byte decoding rejects duplicate/unknown fields, coercion,
oversized input and non-canonical signature encoding. These are headless CLI
contracts, not newly registered HTTPS endpoints. No external dependency or
metadata schema change was needed; partition schema remains **109**.

Working-tree evidence, 2026-09-09:

- The prior process handle was unavailable after restart, so its missing final
  result was not counted. The preparation workflow was rerun and passed in
  **11.89 s**, incremental build **0.14 s**. Affected all-target/all-feature
  warning-denied Clippy passed in **17.24 s** before adding collection.
- The preceding preparation implementation caught compact internal IDs where
  the CLI contract expected canonical hyphenated UUIDs. Reports and bundle
  filenames now use canonical UUID formatting; test expectations were retained.
- The first collection compilation exposed a direct Serde import in the daemon,
  which intentionally does not depend on Serde. The shared JSON type was moved
  into the existing API-contract owner; no dependency was added.
- The first collection process proof failed in **9.67 s** because SQLite's
  restored database inherited process-umask permissions and the collector
  correctly required an owner-only file. Preparation now sets and synchronises
  **0600** before handing on the retained database. Its **0700** parent protects
  the restoration interval. The process test asserts the exact file mode.
- The complete real daemon proof then passed in **11.97 s**, build **21.42 s**:
  HTTPS backup export, offline verification, preparation, installation, signed
  receipt collection, reopening/retry and real mutual-TLS QUIC exchange using
  the installed certificate. Wrong saved digest fails before creating work;
  repeated preparation does not overwrite it; forged collection leaves no
  receipt; corrupted transfers preserve the installed bundle. Consensus
  admission remains explicitly blocked. This is not a recovered multi-node
  cluster serving files or physical power-loss proof.
- **32 recovery-preparation metadata tests passed in 28.07 s**, build **15.10 s**,
  with four test threads. The seven focused API-contract recovery tests passed
  in **0.07 s**; these include strict selection and installer-report boundaries.
- Final affected-crate Clippy (API contract, metadata and daemon; all targets and
  features, warnings denied) passed in **34.93 s**. Its earlier fixed-size
  `chunks_exact` warning was corrected using `as_chunks::<2>()`, without a lint
  suppression. The seven contract tests were rerun after that change and passed
  in **0.07 s**, build **5.08 s**.
- Rust formatting, documentation formatting and whitespace checks passed.
  Rust and JavaScript licence gates passed under the active NVM toolchain
  (9 production and 28 tool-only JavaScript packages checked). No full workspace
  integration gate or independent hardware proof was run for this increment.

Remaining: automatic continuation of interrupted preparation, target/content and
complete-key-reference verification, all-node readiness, returning-authority
fencing and actual recovered-service admission. Existing work is not overwritten;
partial private files may remain after failure. Task 10 stays **8 points**,
Stage 10 **86**, Stage 11 **126** (not started). No full integration gate, commit,
push or publication is claimed. Signing authorisation remains unresolved and the
publication hold remains in force.

## Task 10 — replacement certificates in the recovery transfer

Recovery transfer format **2** now includes a deterministic private-transport leaf
issued by the prepared successor online CA for the selected node's existing
public identity. The generation is one above every retained source certificate
for that node. The explicit validity window is 30 days from the fixed credential
fence time, rounded down to Unix seconds. No node private key moves off-node and
no active certificate row or membership changes during export.

The recipient verifies the exact public identity, issuer, private DNS name,
client/server uses, generation serial and interval before publishing the same
bundle that contains its encrypted keys. The node's format-2 acknowledgement
binds the certificate through the full bundle digest, and the coordinator
reconstructs the same expected bytes. Storage-only nodes receive a usable public
certificate for their own private identity without any gateway decryption
envelope. The public validation result exposes the verified leaf/issuer and
validity for the future admission owner; TLS/admission must independently check
current validity. An expired but historically valid transfer is not live readiness.

The existing installer reports the certificate generation and expiry alongside
its signed receipt. There is no extra installer or external CA service. This is
an explicit pre-alpha transfer break: format-1 bundles and acknowledgements are
rejected, not silently upgraded; start a new recovery preparation if old receipts
exist. Partition schema remains **109**.

Local working-tree evidence:

- Initial recovery testing failed seven cases because their synthetic fence time
  was near January 1970, before the fixture CA's 1975 validity start. Issuance
  correctly rejected those intervals. The fixtures now use a fixed time inside
  CA validity; production certificate validation was not relaxed.
- **32 recovery-preparation tests passed in 27.05 s**, build **5.67 s**. These
  cover deterministic leaf replay, exact generation/window, altered certificate
  framing/content, old-format rejection and a storage-only selected node that
  never invokes the gateway decryptor but can acknowledge its installed bundle.
  That node's acknowledgement does not mark the unacknowledged gateway installed.
- Compilation of the new async transport proof caught a borrowed temporary DNS
  name across concurrent handshake futures. The fixture now owns that name for
  the complete exchange; no production contract or timeout was changed.
- Final all-target/all-feature warning-denied Clippy for certificates, metadata
  and the daemon passed in **4.92 s**. All **21 certificate tests passed in
  0.21 s**, build **6.33 s**, including the existing renewal contract regressions.
- The extended **real daemon workflow passed in 10.32 s**, build **50.73 s**.
  It exports a real HTTPS backup, verifies it offline, installs the recovery
  keys/certificate through the daemon command, records and reopens its signed
  acknowledgement, and uses the exact installed leaf/issuer/local key in a real
  bounded mutual-TLS QUIC exchange with independently expected request/response
  bytes and certificate fingerprint checks in both directions. This is an
  isolated loopback test using one replacement identity, not a multi-node
  recovered cluster serving files. Existing corruption/retry checks still pass,
  and consensus service admission remains blocked.
- Rust/JavaScript licence gates, Rust formatting and whitespace checks passed.
  No dependency or licence policy changes were required.

Task 10 remains **8 points**, Stage 10 **86**, Stage 11 **126** (not started).
Operator preparation/export/collection, target/content verification, returning-node
fencing, live membership/transport selection and activation remain unfinished.
No new dependency, full integration gate, commit, push or publication is claimed.
Signing authorisation remains unresolved; the publication hold still applies.

## Task 10 — coordinator key-installation acknowledgements

Partition schema **109** adds a per-selected-node immutable acknowledgement
journal in the isolated recovery copy. `record_recovery_key_installation` takes
the selected node ID and installer signature, independently reconstructs the
expected deterministic encrypted bundle and full transcript, and verifies the
selected public identity. Reported hashes, counts and messages are not accepted
as authority. The export and receipt validation share one local transaction;
encrypted bytes are hashed incrementally, not buffered as a complete bundle.

Exact retries preserve the original receipt and timestamp. The corresponding
read revalidates preparation, digest, signature and fence time after reopening;
missing selected-node evidence returns `None`. Invalid signatures, another node,
changed claims, damaged stored evidence and failed insertions cannot produce a
successful receipt. No live key head, membership or source applied revision
changes, and consensus admission stays blocked. This records a node's key
installation claim, not proof of physical durability, certificate installation
or target readiness. Operator collection and an all-node admission barrier are
still separate unfinished workflow pieces.

Local working-tree evidence:

- **30 recovery-preparation tests passed in 26.70 s**, build **10.80 s**.
  New cases independently assert the transcript layout, exact receipt and source
  revision, reopen/retry behaviour, forged signatures, substituted generation
  count, unselected nodes, malformed signatures, time before fencing, insertion
  rollback and corruption of persisted proof. Migration coverage now includes
  an ordinary schema-108 database advancing without gaining a recovery barrier.
- Initial Clippy identified an inconsistent field order in the shared test
  fixture's constructor. Correcting that order required no lint suppression.
  All-target/all-feature warning-denied metadata/daemon Clippy then passed in
  **21.16 s**. Document formatting and JavaScript licence checks passed.
- The extended **real daemon workflow passed in 10.27 s**, build **39.08 s**:
  actual HTTPS backup export, offline verification, encrypted replacement-key
  installation, installer-signature collection by the coordinator, durable
  receipt reopening/retry and confirmation that consensus admission remains
  blocked. Existing installer corruption and live-state preservation checks
  still pass. This is not a recovered cluster serving file data.
- Rust and JavaScript licence gates, Rust/document formatting and whitespace
  checks passed. No full workspace integration gate is claimed for this increment.

Task 10 remains **8 points**, Stage 10 **86 points** and Stage 11 **126 points**
(not started). The complete operator workflow, certificates, content/target
verification, returning-node fencing and live activation are not complete.
No new dependency, service or publication was introduced. No full integration
gate, commit or push is claimed; signing authorisation remains unresolved.

## Task 10 — node-side recovery key installation

`export_recovery_key_bundle` now streams the exact prepared encrypted key set for
one selected replacement node. Export requires the root-authorised selection,
sealed inventory and matching credential fence. It preserves source metadata and
refuses unfenced or unselected recipients before writing output. The transfer is
deterministic across reopening, with bounded frames and indexed source paging.

The recipient verifies the independently trusted public root, exact plan and
complete-key commitment, and its existing local public identity/wrapping keys.
Gateways open each assigned encrypted generation, checking the fresh CA private
key against its certificate and the permit-key shape. Historical encrypted
generations remain archival. Storage-only recipients must have no usable key
envelopes; the verifier does not ask them to decrypt gateway keys.

The actual daemon command `install-recovery-keys` copies and validates the stream
before owner-only atomic local publication. It synchronises the file and parent
directory before signing a domain-separated installation transcript. Exact retry
reopens, revalidates and synchronises the same bytes; changed/unsafe existing
destinations are never overwritten. Root/node private keys do not enter the
transfer or report, and the node never needs the offline private authority.
The transcript binds node/incarnation, mesh/partition/recovery/epoch, plan and
bundle digests, and verified generation count. It is an installation attestation,
not proof of physical hardware health or service admission.

Local working-tree evidence:

- The extended **real daemon export/stop/offline verification/key-installation
  workflow passed in 9.63 s**, build **52.13 s**. It uses the actual setup recovery
  download and encrypted HTTPS backup; prepares/fences a separate recovery copy;
  exports replacement keys; invokes the installer subprocess; verifies exact
  saved bytes, mode `0600`, generation count and node signature; replays the
  command with an identical report; then corrupts the input and proves rejection
  without a published destination or changes to the prior installation/live state.
  This is not a recovered file-service or replacement-cluster admission test.
- Initial lint found a collapsible condition and one test combining too many
  distinct scenarios. Export authority, deterministic replay and hostile framing
  now have separate tests using one shared transfer fixture; no limit was raised.
  Integration compilation also corrected the fixture's boxed quorum variant.
  Inspection caught the setup bundle's text-download encoding before running the
  real process case; the fixture decodes that exact existing format.
- **27 recovery-preparation tests passed in 23.10 s**, build **8.34 s**, including
  unfenced/unselected export rejection, deterministic encrypted replay, node-only
  decryption, wrong-key refusal, truncated/oversized frames and trailing bytes.
  Storage-only transfer policy is implemented but has no dedicated node-side
  installation case in this proof yet.
- Final all-target/all-feature warning-denied Clippy through metadata and the
  daemon passed in **5.56 s**. Its final corrections used current slice/integer
  helpers in the test's hex decoder without changing the validation contract.
  The actual process workflow passed again in **9.51 s**, build **4.17 s**.
  Rust/JavaScript licence gates and Rust/document/whitespace formatting checks
  passed. No full integration gate is claimed for this increment.

Partition schema remains **108**. No new dependency, service, GitHub Action or
publication is introduced. The exporter is currently a typed repository API;
the complete operator preparation/export command, certificate installation,
target/content verification, collection of node acknowledgements, new live
membership and recovery activation remain outstanding. Task 10 remains **8
points**, Stage 10 **86 points**, Stage 11 **126 points** (not started). No full
integration gate, commit or push is claimed; signing authorisation is unresolved
and publication remains prohibited.

## Task 10 — isolated recovery credential fencing

Partition schema **108** and `fence_recovery_credentials` now atomically revoke
copied sessions and join grants, retire old node certificates and pending
rotations, cancel pending federation pairing invitations and retain an immutable
offline-root receipt. The operation requires the exact signed replacement plan
and independently verified, sealed key inventory. It rejects times preceding
staging or source credential issuance and source credentials newer than the
signed backup revision. Exact retries retain the original receipt and time.

Temporary group/grant and federated-assignment activations at or below the
selected source revision are excluded by their authority readers. Their original
user evidence is preserved: an offline root action is not falsely attributed to
an administrator. Later committed activation revisions remain usable. Accounts,
authentication methods, permanent permissions, established federation
relationships and source ciphertext are retained; the original database and
encrypted backup are not modified.

The daemon's authoritative secret adapter now uses `runtime_secret_generation`.
It refuses retained CA/permit generations below the recovery floors while
archival `secret_generation` still supplies historical ciphertext to offline
verification. A staged successor is not returned as installed key material.
The source applied revision and active key heads do not advance, and normal
consensus startup remains blocked. This cannot revoke material on an unreachable
old node before that node learns the new recovery authority.

Local working-tree evidence:

- **24 recovery-preparation tests passed in 22.16 s**, build **6.96 s**.
  Added cases exercise real encrypted backup/restore and database reopening,
  session denial, node-certificate retirement, join/pairing revocation, old group
  activation exclusion and later activation eligibility, preserved account and
  source records, retained versus runtime key loading, missing selection,
  issuance/staging time rejection, immutable receipts and atomic rollback after
  an injected final receipt-write failure. Migration coverage now includes
  **103/104/105/106/107 → 108**. Credential rows in these persistence fixtures
  are explicitly synthetic; this is not live HTTPS/SMB disaster-recovery proof.
  Federated activation exclusion and pending rotation retirement are implemented
  but do not yet have a dedicated recovered-copy scenario in this test set.
- The first compile exposed unsupported SQLite `u64` conversions and a test
  reading a field not present in the public join-grant projection. Checked
  signed/unsigned conversions and an explicit persistence assertion corrected
  those issues; the subsequent focused runs passed.
- **18 access regressions passed in 10.89 s** and **94 federation regressions
  passed in 55.55 s**, each with four test workers and **0.09 s** incremental
  build time. These cover the existing ordinary authority paths, not a claim of
  dedicated recovered-federation activation acceptance.
- All-target/all-feature warning-denied Clippy through metadata and the daemon
  passed in **1 m 54 s**; the final test-only update passed again in **5.53 s**.
  Rust/JavaScript licence gates passed (9 production and 28 tool-only JavaScript
  dependencies). No new third-party dependency or lint suppression was added.

Task 10 remains **8 points**, Stage 10 **86 points**, Stage 11 **126 points**
(not started). Replacement installation, target/content completeness, recovery
authority activation, returning-node fencing and the assembled product workflow
still require acceptance. No full integration gate, new daemon-process test,
commit, push or publication is claimed. Signing authorisation remains unresolved;
the publication hold remains in force.

## Task 10 — root-authorised replacement selection

`RecoveryReplacementPlan` now provides the canonical public manifest behind the
authorisation's replacement digest. It binds mesh/partition/recovery identities,
the recovery epoch, complete prepared-key commitment, stable replacement quorum
specification and exact node/host identities, names, incarnations, roles, public
identity/wrapping keys and private endpoints. Decoding independently recompiles
the existing election/write/read quorum proof; duplicate identities, keys,
endpoints, names, ambiguous host mappings, absent metadata-eligible quorum
members, malformed public keys and noncanonical framing are rejected.

`RecoverySecretInventoryBuilder` computes the exact streaming key commitment
**before** authorisation is signed. The source remains read-only during planning;
the exact encrypted outputs are retained for staging, not regenerated after
signing. The builder enforces ordered, unique generations but does not itself
prove source completeness. Repository sealing independently verifies that.

Partition schema **107** persists the exact root-authorised replacement manifest.
Staging rechecks the saved authorisation, independently verified secret set and
completion record, exact gateway recipients, successor membership epoch, source
incarnations and name collisions. Identical retries preserve the original record;
reopening revalidates it. A valid root signature alone cannot bypass those checks.
The normal join/quorum-transition paths are not misused as a catastrophic reset.

This remains selection **before activation**: no private node key is accepted,
no claim of possession/reachability/installation is inferred from public keys,
no credentials or active memberships change, and consensus remains blocked.
Target/content inventory validation, node installation, credential fencing,
explicit recovery activation and the product workflow are still required.

Local working-tree evidence:

- **19 recovery-preparation tests passed in 18.30 s**, build **7.60 s**.
  The new sequence plans keys, signs the exact manifest, restores the encrypted
  source, stages/seals the same keys and retains/reopens the authenticated plan.
  Cases cover unsigned endpoint substitution, incomplete key completion,
  root-signed wrong recipients/stale quorum epoch, stale versus newer node
  incarnations, malformed/duplicate nodes, every framing truncation, trailing
  bytes, oversized input and rejected duplicate/reversed inventory-builder input.
  Ordinary-database migration coverage includes **103/104/105/106 → 107**.
- All-target/all-feature warning-denied Clippy through metadata and the daemon
  passed in **34.33 s**. The first compile exposed a too-narrow visibility on the
  reused endpoint validator; only its crate-internal visibility was corrected.
  No new third-party dependency or lint suppression was introduced.
- Rust/JavaScript licence gates, workspace Rust formatting, NVM-backed document
  formatting and whitespace checks passed.

Task 10 remains **8 points**, Stage 10 **86 points**, Stage 11 **126 points**
(not started). No full integration gate, new daemon-process test, commit, push or
publication is claimed. Signing authorisation remains unresolved and the
publication hold remains in force.

## Task 10 — restartable retained-secret inventory

Partition schema **106** adds immutable, per-generation prepared secret records
and a complete-inventory commitment in the isolated recovery copy.
`stage_recovery_secret` requires the already prepared control-key recipient set,
preserves exact source ciphertext/context/generation, verifies offline decryption
and makes exact retries idempotent. It rejects changed ciphertext, different
recipients and regenerated envelopes conflicting with an existing record.
`staged_recovery_secret` revalidates the saved bytes after reopening.

`seal_recovery_secret_inventory` walks the source's indexed, bounded generation
pages, verifies every corresponding prepared record and refuses missing or extra
generations. Its ordered digest binds the recovery ID, prepared control pair,
every retained generation and the exact count. The completion record is atomic
and immutable; after sealing, additional inserts are refused. Replaying a seal
rechecks the inventory rather than trusting the saved digest. No active key head,
source revision, recipient grant or consensus admission changes.

This is a complete commitment to **secret rows present in the selected backup**,
not proof that every file-content reference exists, that remote recipients have
installed/decrypted their envelopes, or that replacement membership is valid.
It is an input to the signed replacement manifest, not that manifest itself.
Old operational generations are preserved as retained encrypted material; they
are not reactivated. Credential fencing and service admission remain required.

Local working-tree evidence:

- **13 recovery-preparation tests passed in 12.20 s**, build **7.93 s**.
  New cases use real encrypted backups and reopened SQLite copies to prove
  partial-inventory resume, refusal to seal missing generations, exact replay,
  unchanged source ciphertext/revision, replacement-recipient decryption,
  mismatched ciphertext/recipients, conflicting regeneration, failed seal-write
  rollback/retry, immutable rows and corrupted completion-digest rejection.
  Existing ordinary-database migration coverage now includes **103/104/105 → 106**.
- All-target/all-feature warning-denied Clippy through metadata and the daemon
  passed in **35.40 s**. No lint was weakened and no third-party dependency was added.
- Rust/JavaScript licence gates, workspace Rust formatting, NVM-backed document
  formatting and whitespace checks passed.

Task 10 remains **8 points**, Stage 10 **86 points** and Stage 11 **126 points**
(not started). Remaining recovery work is complete replacement-manifest and
content-inventory validation, recipient installation, new membership/authority,
credential fencing and the assembled product workflow. No full integration gate,
new daemon-process test, commit, push or publication is claimed for this slice.
Signing authorisation remains unresolved; the publication hold remains in force.

## Task 10 — durable control-key preparation

Partition schema **105** now retains the exact encrypted replacement online-CA
and storage-permit keys in the isolated recovery database. Staging validates
the signed preparation against the saved offline root, exact source position,
revision and identities inside one immediate transaction. It checks successor
generations, matching recipient sets, offline decryption, the permit-key shape,
the online private/public key match and the certificate's root signature/profile.
No active key head, credential, source revision or consensus admission changes.

Identical retries retain the original timestamp and return the same
recovery-ID-bound material digest. Regenerated material conflicts. Reopening
rechecks the bounded canonical ciphertext record and decryptability through the
offline authority; an injected post-insert database failure rolls back and can
be retried. The prepared database still refuses normal consensus startup.
This digest is **not** the complete signed replacement-manifest digest. Complete
retained-secret installation, membership/inventory validation, credential fencing
and the assembled recovery/admission workflow remain outstanding.

This work also found a real defect in
`OnlineCertificateAuthority::from_pkcs8_and_certificate`: it accepted a valid
private key paired with a different certificate. The new mismatch regression
failed before the fix. Reload now checks the key match, exact DER, CA signing
usage and the online path-length constraint. Separate root validation checks
issuer, signature and validity containment. It does not infer current trusted
time or service authority. The earlier successful-constructor test in the
replacement-key evidence below did **not** prove matching; the negative
regression and corrected boundary now provide that evidence.

Local working-tree evidence:

- **21 certificate tests passed in 0.22 s**, including wrong-key, wrong-root,
  root-as-online, leaf, malformed and oversized certificate rejection.
- **12 recovery-bundle tests passed in 0.95 s**; combined build **10.79 s**.
- **10 metadata recovery-preparation tests passed in 8.35 s**, build **7.42 s**.
  These use real SQLite/encrypted copies and reopening, exact replay/conflict,
  denied material with no writes, transactional fault/retry, every framing
  truncation, trailing/corrupt/oversized input and schema **103/104 → 105**.
  The injected SQLite failure is not a hardware power-loss claim.
- Initial compilation caught SQL bindings requiring checked `u64 → i64`
  conversion and the migration fixture's `u32 → usize` parameter. Both were
  corrected; no lint or validation rule was relaxed.
- All-target/all-feature, warning-denied Clippy through certificates, recovery
  bundles, metadata and the daemon passed in **45.16 s**. Rust and JavaScript
  licence checks passed; no new third-party dependency or allow-list change.
  Workspace Rust formatting, NVM-backed selected-document formatting and
  whitespace checks passed.
- The real-daemon
  `exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes`
  test passed in **8.09 s**, build **55.03 s**, under the changed certificate
  loader and schema. It proves the existing export/stop/verify workflow, not
  completed replacement-cluster admission.

Task 10 remains **8 points**, Stage 10 **86 points**, Stage 11 **126 points**
(not started). This is a completed persistence slice, not completed recovery.
No full integration gate, commit, push or publication is claimed.
Signing authorisation remains unresolved from the earlier checkpoint; no
unsigned commit or repeated authentication attempt was made.

## Task 10 — replacement key preparation

The offline recovery authority now prepares complete replacement recipient
envelopes for retained secret generations. It validates the exact offline
envelope and ciphertext, preserves the original ciphertext/context/generation,
and includes only explicitly selected replacement gateways plus the offline
recipient. Batch rewrapping authenticates the secret once before wrapping its
data key for the bounded replacement set. It does not return plaintext keys or
partially completed output. Removing an old recipient from the new envelope set
does **not** erase keys or old envelopes that recipient already possessed.

Metadata's `prepare_recovery_control_keys` validates the source mesh and offline
identity and prepares fresh online-CA and storage-permit key generations. The
online generation succeeds both the public CA head and the maximum retained
encrypted-key generation; neither can be accidentally reused. Its new online
private key is returned only as ciphertext and exact recipient envelopes,
alongside the root-signed public certificate. `prepare_recovery_secret` uses the
existing bounded inventory and exact-generation loader for retained material.
Historical content and authentication secrets can therefore be recovered without
changing their ciphertext or silently breaking generation-bound consumers.

These APIs **do not mutate source metadata, persist a replacement plan, revoke
credentials or admit service**. Fresh-key preparation is deliberately not called
an idempotent operation: its exact output must be durably retained and bound into
the signed replacement manifest before installation. Session/join-grant/node
certificate invalidation, key installation, replacement membership, complete
content-key/inventory validation and the product recovery workflow remain open.
Envelope preparation does not itself authorise node or user access to a running service.
Credential recovery is not a claim that material learned by a compromised node
can be forgotten or that an older backup proves later revocation state.

Local working-tree evidence:

- **12 recovery-bundle tests passed in 0.93 s** and **7 secret-envelope tests in
  0.01 s**, build **10.73 s**. New cases cover exact ciphertext preservation,
  selected/offline-recipient decryption, missing/duplicate/substituted evidence,
  bounds, bad entropy, mesh binding and a decryptable CA private key matching its
  public certificate.
- **6 metadata recovery-preparation tests passed in 4.64 s**, build **28.21 s**.
  The new cases use the existing real SQLite/encrypted-backup fixture. They prove
  generation **1 → 2**, replacement/offline decryption, no envelope for the
  excluded gateway, unchanged authentication ciphertext and plaintext, unchanged
  source heads/revision, wrong-authority rejection and invalid-recipient rejection.
  This is not a claim that an actual TOTP/SMB login has been tested after disaster
  recovery; the assembled admission workflow still needs that proof.
- All-target/all-feature warning-denied Clippy through secret envelopes, recovery
  bundles, metadata and the daemon passed in **39.78 s**. The licence gate passed;
  no dependency, licence rule or schema version changed in this slice.

Task 10 remains **8 points**, Stage 10 **86 points**, Stage 11 **126 points**
(not started). No full integration gate, commit, push or publication is claimed.
Next is durable retention of the exact replacement material and its authenticated
transition into credential fencing and service admission, not further speculative
hardening of the preparation helpers.

## Task 10 — signed offline recovery preparation

Recovery-bundle authority now signs a domain-separated, fixed-width proposal
binding the exact mesh, partition, recovery/backup IDs, encrypted-container
digest, committed source position/revision, successor recovery epoch,
replacement-manifest digest and target-inventory digest. Its portable container
is at most **284 bytes**, carries no trust anchor or private key, and is verified
against the independently trusted offline root. Changed claims, other operation
domains, malformed roots/signatures, every truncation, trailing bytes and
single-byte substitutions are rejected in the focused fixtures.

`prepare_authorized_partition_recovery` composes this with the real encrypted
restore boundary. It checks the source claims and signature before restore,
then compares the root and wrapping recipient with the restored authoritative
identity. Partition schema **104** retains the exact signed proposal in an
immutable offline preparation record. Consensus state loading, vote/log mutation
and quorum bootstrap refuse a prepared database, including after reopening.
An ordinary schema-103 database migrates with no preparation barrier.
The source backup does not contain its own later catalogue publication, so the
record binds its signed source ID rather than inventing a `metadata_backups` row.

This is **preparation, not recovery completion or a new CLI workflow**. It does
not install replacement membership/keys, fence old credentials, prove content-key
completeness or storage availability, or admit service. Replacement and inventory
digests bind caller-validated manifests; their validators and product workflow
remain outstanding. Until activated recovery lineage exists, this preparation
path accepts only epoch **0 → 1**, never an inferred later epoch. A signature
does not prove the selected backup is latest or revoke unheard-of offline peers.
Staging belongs in a new private workspace; failure does not authorise reuse or
activation of partial output.

Local evidence on the working-tree candidate:

- **19 certificate tests passed in 0.17 s** and **9 recovery-bundle tests in
  0.90 s**, build **10.41 s**.
- **4 real encrypted-backup/preparation tests passed in 3.51 s**, build
  **15.81 s**: exact reopened receipt and unchanged revision, consensus refusal,
  source substitution, another signing root, existing-destination preservation
  and genuine schema-103 migration.
- **6 existing consensus durability tests passed in 3.32 s** and **3 existing
  older-backup restore tests in 2.41 s**; incremental builds **0.10/0.09 s**.
- `cargo deny check licenses` passed. Metadata reuses the existing MeshSpan
  recovery-bundle crate; no third-party dependency or licence allow-list changed.

Initial fixture compilation caught two incorrect repository method names and
the distinction between metadata and consensus log-position types. They were
corrected to use the existing APIs. Warning-denied Clippy then identified a
needless large value argument in the source-claim validator; it now borrows the
manifest. Final all-target/all-feature warning-denied Clippy, including the
daemon consumer, passed in **37.79 s**. The four preparation tests passed again
after that borrow-only edit in **3.59 s**, build **5.17 s**. Workspace Rust
formatting, NVM-backed selected-document formatting and whitespace checks passed.
The existing real-daemon
`exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes`
workflow also passed in **8.09 s**, build **1m 03s**. It exercises normal daemon
startup, encrypted export, stop and offline verification under the changed
schema; it is not an acceptance test for live disaster-recovery admission.
No full-workspace integration gate, commit, push or publication is
claimed. Task 10 remains **8 points**, Stage 10 **86 points**; Stage 11 remains
**126 points**, not started. Signing authorisation remains unresolved from the
earlier checkpoint.

## Task 9 — real-process worker takeover

The three-daemon acceptance test
`surviving_daemon_retires_unadmitted_upload_after_worker_sigkill` passed in
**325.81 s**, build **5.95 s**. All daemons use the normal executable and actual
HTTPS create/join/recovery-save flows, converge to three voters and produce an
initial protected backup. Test-owned SQLite `BEGIN IMMEDIATE` locks then hold
the three provider catalogues without modifying their records. A fresh backup
reaches durable upload intent and a published provider file; independent length
and SHA-256 checks match the intent while both provider inventory and replicated
backup admission remain absent. The test kills that exact publishing process.

The two surviving nodes keep their actual production clocks and five-minute
claim lease. After expiry, a surviving daemon commits abandonment and claims
a new generation; retained claim history independently identifies a different
worker, including if the new run completes between polls. Restarting the killed
node restores its provider. Exact receipt-backed orphan retirement completes,
the observed object disappears and cleanup debt clears. The replacement reaches
protected state and passes the existing real HTTPS encrypted export and restore
check. Operator sibling files remain unchanged. No authoritative records, clock,
lease, production hook or external service was introduced for the proof.

The test is deliberately separate from the fast gate; its explicit `--ignored`
command is recorded in [verification.md](verification.md#10-hardware-and-destructive-fault-laboratory).
An ignored default run is not evidence of this acceptance. This was an explicit
executed pass, not physical power removal, independent hardware, a partition
laboratory or the Stage 11 soak. The existing provider/consensus and federated
receipt tests remain complementary evidence, not a claim that this new process
scenario itself crosses independent swarms.

An initial compile caught a missing test SHA-256 import. Final test-target,
all-feature warning-denied Clippy passed in **3.78 s** after changing an unused
owned path to a borrow and documenting the test's two non-secret phase markers.
Those lint-only test edits did not change the already-running fault sequence or
production executable. Rust formatting, NVM-backed document formatting and
whitespace checks passed. No production implementation or dependency changed in
this slice, and no full-workspace integration gate, commit, push or publication
is claimed. Task 9 closes **1 → 0 points**, Stage 10 **87 → 86**; Stage 11 remains
**126 points**, not started. Next is task 10 recovery authority and service admission.

## Task 9 — automatic exact receipt discovery

The provider contract now exposes metadata-only `lookup_exact`: exact object in,
operation-bound retained catalogue receipt out, without requiring the lost opaque
reference. It does not newly verify bytes or grant deletion authority. The folder,
shared, namespaced, same-swarm QUIC and federated implementations support it.
Private envelope tags **62–63**, federated action **5** and result outcome **15**
carry the operation through existing authenticated boundaries. Current identity,
intent/claim or terminal-abandonment authority, target incarnation and bilateral
federation restrictions remain required. No schema or closed metadata-command
version change is needed beyond schema **103** / command version **17**.

The existing cleanup worker now pages retained intents for terminal unadmitted
runs, resolves exact provider evidence, commits immutable receipt-backed
retirement, then deletes and records completion. Lookup absence, timeout or
rejection stays pending; an older upload may still finish. The worker never
guesses references, invents admitted copies or equates abandonment with removal.

The real consensus/folder worker proof passed in **1.00 s**, build **48.72 s**:
an injected empty provider leaves authority unchanged and the intent pending;
the actual provider then permits automatic discovery and retirement. Physical
deletion succeeds while completion commit is unavailable. A reopened provider
and fresh worker recover the exact deletion receipt and clear debt; another
fresh worker is idle. The test's original store receipt is an independent oracle,
not an input to discovery. This is boundary fault injection and worker/provider
reopening, not a claim of physical power-loss or cross-process takeover proof.

The real pinned-TLS federation workflow passed in **6.51 s**, recovering a lost
upload reply through the consumer provider API instead of its former guessed
folder reference. The signed federation stream lifecycle also passed in
**1.19 s**, build **38.12 s**, including lookup between verify and delete.
All **18 backup tests passed in 0.96 s**, build **6.03 s**; all **36 backup
catalogue tests passed in 23.06 s**, build **22.38 s**. They cover changed object
identity, expiry, missing/deleted lookup, reopen, retained discovery and handoff
only after retirement. **15 private/federated wire tests passed in 0.00 s each
suite**, build **10.34 s**, including missing-authority and false-success vectors.

Five focused discovery tests passed in **2.80 s**, build **13.04 s**, including
the actual production SQL query plan. Its first assertion failed because it
expected WITHOUT ROWID primary-key wording for two existing rowid tables;
inspection showed their intended indexed equality searches. The assertion now
checks those existing indexes and absence of temporary sorting. No query/schema
change was made to disguise that test-expectation error. A mistaken daemon test
filter initially ran zero tests; only the corrected named workflow counts above.

All-target, all-feature warning-denied Clippy across contracts, protocol, backup,
data-plane, transport, metadata, cluster and daemon passed in **42.17 s** after
updating exhaustive test fixtures and separating upload/receipt recovery from
read/retirement assertions in the node lifecycle proof. This closes task 9
**2 → 1 point**, Stage 10 **88 → 87**. Full process-loss takeover remains open;
Stage 11 remains **126 points**, not started. No dependencies, commits, pushes,
releases or publications were added, and no full-workspace integration gate is
claimed. Signing authorisation remains unresolved from the earlier checkpoint.

Final focused node lifecycle passed after the responsibility split in **0.30 s**,
build **8.75 s**. The lookup-permit action/object substitution regression passed
in **0.00 s**, build **8.99 s**. The real federation transport conversation proof,
including all lookup response phases, passed in **0.33 s**, build **9.67 s**.
Workspace Rust formatting, selected document
Prettier under NVM and whitespace checks passed.

## Task 9 — pre-IO upload intent

The publication path now commits `BindBackupPublicationIntent` before provider
storage: partition schema **103**, closed metadata command version **17**, kind
**125**. It binds the exact encrypted object, store operation, live run claim and
active destination revision. The first object/store identity is immutable across
retries; different destinations of one generation must describe the same bytes.
Admission and orphan retirement check these retained byte identities. No backup
or copy is reported stored, verified or retired merely because an intent exists.

The unavailable-intent regression failed against the previous publication order:
the provider wrote **1** object when **0** was required (**0.00 s**, build
**42.38 s**). After the guard, all **9 publication tests passed in 0.09 s**, build
**16.71 s**. Intent/reopen/abandonment and canonical round-trip/every-truncation
tests passed with all **34 backup catalogue tests in 21.26 s**, build **16.41 s**.

Stable store-operation IDs now use the immutable source creation instant rather
than attempt time. This exposed the provider's deadline-bound store digest:
the renewed-attempt regression returned `Conflict`. Store digests now exclude
attempt timing and current upload-authority revision, retaining immutable object
and operation bindings; fresh request/transport authority checks still apply.
Delete digests retain their retirement revision. The new store domain does not
reinterpret old pre-alpha digests or claim old store-operation replay compatibility.

A second concrete regression found that replaying a completed store after its
object was deleted returned a stale success receipt. The provider now requires
the object still be live before returning that receipt, before changing capacity
accounting. That regression failed before the fix (**0.04 s**, build **6.17 s**).
All **17 backup-library tests passed in 0.92 s**, build **2.89 s**; the focused
renewal test also covers changed bytes, elapsed deadlines and deletion followed
by store replay. The latter assertions were grouped with retry lifecycle coverage
after the original broad lifecycle test exceeded the function-size ceiling.

The real three-daemon consumer/gateway/storage-owner workflow passed in
**29.18 s**, build **36.07 s**, with explicit intent/object agreement and intent
revision preceding the admitted/verified remote copy. It still exercises storage
owner process restart, exact encrypted export, grant replacement and revocation.
This is a working pre-IO integration slice, not completed automatic orphan
discovery or full takeover acceptance. Task 9 remains **2 points**, Stage 10
**88 points**, Stage 11 **126 points** and not started. No dependencies, commits,
pushes or publications were added.

Final static checks: backup/metadata/cluster/daemon all-target, all-feature
warning-denied Clippy passed in **43.90 s**. Workspace Rust formatting, selected
document Prettier under NVM and whitespace checks passed. The three intent tests,
including actual **102 → 103** migration without inferred historical uploads,
passed in **1.56 s**, build **10.57 s**. No full-workspace integration gate is claimed.

Next: page retained intents for terminal unadmitted runs and recover exact provider
receipts through the replaceable provider, same-swarm QUIC and federated paths.
The current provider interface still requires an opaque reference for verification;
do not substitute a folder-specific reference formula to claim generic recovery.
Lookup absence or timeout must not complete cleanup or authorise deletion: an
already-admitted old upload could still finish. Returned exact evidence must pass
current authority before the existing retirement/completion worker can consume it.

## Task 9 — receipt-backed abandoned-object cleanup

The existing retirement test failed against the old queue: one committed orphan
retirement produced **0** pending objects instead of **1** (**0.30 s**, build
**5.47 s**). The queue now merges admitted retired copies and unadmitted orphan
retirements into one typed exact-object projection. Both branches use indexed
keyset scans; the query-plan test checks the actual production SQL, including
the ordered merge and absence of temporary sorting. Related authority rows are
loaded inside one short read view, never across provider IO.

Partition schema **102** adds `abandoned_backup_reclamations`, foreign-key bound
to immutable orphan retirement. Closed metadata command version **16** extends
the existing kind **74** completion command without changing its payload. Exact
object identity, provider operation and retirement revision are checked; changed
generation, length, digest, revision or replacement receipt cannot clear debt or
overwrite completion. No admitted backup/copy record is fabricated. Current
same-swarm remote deletion checks recognise this retirement projection; ordinary
read/verify still require admitted copies. This is not a new remote wire proof.

The live consensus dispatcher test now composes the production cleanup worker
with a real encrypted-folder provider. Physical deletion succeeds while the
completion-commit boundary returns unavailable. The object is absent but the
queue remains pending. After dropping/reopening the provider and constructing a
fresh worker, the same stable deletion operation recovers its receipt, commits
completion and empties the queue. Another fresh worker finds no work. The final
test passed in **0.99 s**, build **13.94 s**. An earlier mistyped test filter
matched zero tests; it was corrected and is not counted as evidence.

All **32 backup catalogue tests passed in 20.41 s**, build **7.85 s**, including
the original regression, exact receipt rejection, database reopen and indexed
queue checks. Both schema **100/101 → 102** migration checks passed in **0.79 s**
without inventing retirement/completion. Both existing worker retry/fairness
tests passed in **0.06 s**. These are focused checks, not a full-workspace gate
or abrupt host-power-loss proof.

Metadata/cluster/daemon all-target, all-feature warning-denied Clippy passed in
**12.98 s** after correcting one test-only unnecessary value transfer. Workspace
Rust formatting passed. The retirement/reclamation codec round-trip and every
truncation test passed (**0.00 s**, build **0.18 s**).

This closes the automatic consumption/completion slice **3 → 2 points**, Stage
10 **89 → 88**. Automatic discovery and receipt recovery when admission evidence
is lost, plus full process-loss takeover acceptance, remain open. Stage 11 has
not started. No dependencies, commits, pushes or publications were added.

## Task 9 — exact abandoned-object retirement authority

Partition schema **101** retains `abandoned_backup_retirements`; closed metadata
command version **15**, kind **124**, adds `RetireAbandonedBackupCopy`. The command
requires the exact committed incomplete run revision, terminal evidence, no live
claim and no admitted backup. It binds the provider receipt's operation, backup,
destination, generation, byte length, digest and opaque reference. Federated
objects must also match their retained pre-IO route. Lease expiry or catalogue
absence alone cannot authorise deletion. The first retirement revision is retained
across retries; this record is neither a recoverable generation nor a provider
deletion acknowledgement.

The repository tests reject active/merely expired claims, admitted generations,
stale run/provider revisions and substituted retained digest/reference. Reopening
and exact operation replay preserve the original retirement. Canonical codec
tests cover round-trip and every truncation; migration from real schema **100**
creates no inferred retirement records. All **484 metadata tests passed in
308.59 s**, build **9.75 s**.

The existing live consensus-dispatcher proof now stores a real encrypted object
before replicated admission, commits run abandonment, admits/replays its exact
retirement command and uses that revision for idempotent folder-provider deletion.
It passed in **1.01 s**, build **43.97 s**. This is real consensus/provider
composition, not automatic orphan discovery or cross-swarm cleanup. A test-only
responsibility split followed a lint length finding; the final rerun passed in
**0.96 s**, build **13.40 s**.

Metadata/cluster/daemon all-target, all-feature warning-denied Clippy passed on
the final tree in **6.05 s**; Rust formatting and whitespace checks passed. This
closes the retirement-authority slice **4 → 3 points**, Stage 10 **90 → 89**,
not task 9 as a whole. No full-workspace integration gate is claimed.

Remaining: automatic discovery/receipt recovery when local admission evidence is
lost, durable cleanup completion, provider-worker integration and full process-loss
takeover acceptance. Task 9 remains open. Task 7 also remains open; a non-blocking
question asks which initial external backup backend to implement because the
accepted replaceable-provider contract does not select one. No external backend
has been substituted with a folder adapter to claim completion. No dependencies,
Git commits/pushes or publications were added by this work.

## Task 7 — gateway forwarding and setup gap

### Control-stream failure isolation

Follow-up: a deterministic two-connection repository regression now demonstrates
the suspected read race. While reading one valid backup allocation, a second
connection commits another allocation: separate reads observe revision **5** then
**6**, the exact condition rejected by the relayed owner's old revision guard.
A second regression shows how a grant revocation can likewise split a multi-read
check. Both failed before the scoped view in **0.85 s**, build **9.36 s**.

`AuthoritativeRepository::with_read_view` now composes synchronous read-only
checks in one local database transaction. Gateway and relayed-owner backup checks
use it, retaining exact grant/allocation, peer, certificate, epoch and expiry
validation. The owner no longer rejects an unrelated global revision change.
The transaction ends before provider/network IO; the next view sees the newly
committed revocation. All **41 allocation tests passed in 29.94 s**, build
**6.45 s**, including both regressions.
This establishes and fixes the read race, but the earlier truncated export did
not retain an error identifying it as the cause. No additional completion points
or claim that every historical interruption is explained.

Verification of this scoped correction: the real TLS pairing/backup/owner
workflow passed in **6.51 s**, build **35.94 s**. The three-daemon remote backup,
storage-owner restart, grant replacement, exact export and revocation workflow
passed in **30.54 s**, build **19.96 s**. Metadata/cluster/daemon all-target,
all-feature warning-denied Clippy passed in **35.74 s**. Rust formatting,
selected-document Prettier and whitespace checks passed. These are focused
checks, not a new full-workspace gate. No dependencies or wire/schema formats
changed. No commits, pushes or publications were made.

The retained reconciliation failure led to a reproducible shared-connection
defect. A fully decoded, authenticated control request whose application handler
did not return a reply was treated as invalid peer traffic. The server closed
the entire QUIC connection, interrupting other valid requests on it. This can
multiply failures across the concurrent immutable-history fetch batch.

`failed_control_handler_does_not_cancel_another_request_on_the_connection`
failed before the correction in **0.14 s**, build **5.64 s**: the unrelated
request received connection closure code **2**, “invalid peer traffic”. The
server now resets only the affected response stream when its application
handler is unavailable or expires. Framing and peer-identity violations retain
their existing rejection path. No failed request becomes an acknowledgement.
All **14 private-network tests passed in 2.40 s**, build **5.15 s**. The parallel
process suite is being rechecked; no full-suite success is claimed yet.

The parallel run with only the handler-failure correction passed both namespace
reconciliation tests but was still **30 passed, 1 failed, 8 ignored** in
**137.44 s**, build **28.49 s**. The separate failure was a truncated backup
export during permission succession: **327,680 of 2,831,053 declared body bytes**
arrived before TLS closed. Storage remained leader at term **3**, position **50**,
with no pending/queued operations. This is not counted as successful export or
as proof of its cause; the exact private fixtures were retained.

A second isolation regression proved that sending a late response after caller
cancellation also closed the shared connection. It failed in **0.24 s**, build
**6.08 s**. QUIC stream cancellation/closed-stream errors are now classified as
stream-local; malformed frames and stale identities still reject the connection.
The control-pair test fixture also now discovers addresses from live port-zero
sockets instead of releasing ephemeral reservations before binding, after an
actual parallel `AddrInUse` failure. No tests were serialised and no new API was
needed for this fixture correction.

Two framing regressions then demonstrated premature request admission and
accepted trailing bytes, each failing in **0.14 s** (builds **5.49 s** and
**5.35 s**). The metadata-control request lifecycle now owns decoding, complete
stream admission, handler response and request-local failure. It requires FIN
before dispatch, rejects trailing bytes and bounds an unfinished request without
closing unrelated streams. This also avoids normal receive-stream disposal
producing STOP_SENDING before the client's delivery confirmation. All **17
private-network tests passed in 2.56 s**, build **5.70 s**, after these changes.
The truncated-export observation remains open; latest lint and process checks
are pending. No additional task-completion points or Git/publication claims.

Final verification of this transport correction: cluster/daemon all-target,
all-feature warning-denied Clippy passed in **30.64 s** after style-only pattern
corrections. Rust formatting and whitespace checks passed. The parallel headless
suite then passed **31 tests, 0 failed, 8 ignored in 131.02 s**, build **32.34 s**,
including both reconciliation workflows, remote backup/restart/permission changes
and every updater process test. This is not the full workspace integration gate
and does not replace the ignored environment-dependent acceptance. It also does
not establish the cause of the earlier truncated export.

Next investigation for that export is its per-frame authority read: the relayed
owner currently reads several related records and rejects any intervening root
revision, including unrelated metadata changes. A coherent short-lived metadata
read view could address that race without weakening revocation, but this remains
an unproven causal hypothesis and has not been implemented. No snapshot may span
network/provider IO or permit subsequent frames to bypass current authority.

### Three-daemon delivery and storage-owner restart

The real-process test
`remote_backup_forwards_through_gateway_to_distinct_storage_process` passed in
**22.94 s**, build **25.47 s**, on the uncommitted working tree. It creates two
independent swarms using HTTPS setup and offline-recovery verification, joins a
second provider node, drains the gateway's storage folder, pairs the swarms and
issues the provider storage offer through the production APIs. Only the remote
backup destination remains active for the new schedule. The persisted route must
name the other storage node, not the gateway; there must be exactly one verified
copy, with no local duplicate available to make export pass accidentally.

Automatic encrypted publication/verification, HTTPS export and restore-readiness
then succeed. Killing and restarting the storage-owner process preserves exactly
the same exported encrypted bytes and digest. This is process-crash evidence,
not host power-loss, loss during upload, or remote failure-overlap evidence.

The workflow exposed incompatible production deadline assumptions. Backup attempts
used a two-minute deadline against a thirty-second replay guard. Export allowed
an hour but initially copied that entire lifetime into individual envelopes.
Clamping envelopes alone then conflicted with a wire rule requiring exact equality
to the nested operation deadline. The final contract keeps the signed operation
unchanged, bounds exchanges by the existing five-minute maximum, and requires
permit expiry no later than the exchange, operation or allocation lease. Replay
entry capacity, current-authority checks and response correlation are unchanged.

The new wire regression failed before the nested-deadline correction with
`InvalidMessage`; all **11** backup wire tests then passed in **0.00 s**, build
**6.20 s**. Earlier process failures progressed from no route to a verified copy
but zero export bytes; they are not counted as passing evidence. Failed fixtures
remain in private temporary directories, not in the repository.

This closes task 7 **5 → 3 points**, Stage 10 **92 → 90**. Affected regression
and warning-denied lint are running; no final integration result or publication
is claimed. No signing retry, commit or push has been made.

Follow-up validation: the existing native pairing/backup/owner regression,
including a production-client read with an hour-long operation deadline, passed
in **6.52 s**, build **20.26 s**. Protocol/transport/data-plane/cluster/daemon
all-target/all-feature warning-denied Clippy passed in **59.41 s**. These results
precede the owner catch-up addition described below.

The extended process workflow now also replaces the provider grant with a lower
quota, reads identical retained bytes through the successor, revokes it and
requires an HTTP **503 / `busy`** restore-readiness response. The first replacement
read failed: retained databases showed provider revision **42**, storage-owner
revision **41**. The authenticated owner now waits for the signed provider grant/
allocation revisions before performing its complete authorisation, within a
monotonic permit-bound deadline. This wait holds neither a SQL transaction nor a
provider lock, consumes the existing bulk-worker slot, and polls only local state
with bounded backoff. It never treats a consumer revision or expiry as authority.

The extended workflow passed in **27.22 s**, build **4.22 s**. The test client
handles explicit metadata-CAS rejection by re-observing a revision and retrying;
background topology/backup work is allowed to advance that revision. Unknown IO
outcomes are not retried by this helper. No production CAS check was removed.

**Unresolved observation:** other runs timed out submitting a new grant mutation
after restart. Live diagnostics showed a follower gateway at term **3**, commit
and applied index **45**, with no pending/queued operations or persistence fence.
This does not establish why the forwarded mutation stalled. A subsequent pass
does not close that observation; the expanded failure diagnostics now include the
storage node, and broader parallel headless acceptance is running. No additional
completion points are taken. Latest daemon lint found one test-only
`single_match_else` issue, corrected without changing behaviour; recheck pending.

The subsequent daemon all-target/all-feature warning-denied Clippy passed in
**3.40 s**. Broader parallel headless acceptance then returned **29 passed,
1 failed, 8 ignored** in **130.74 s**. The failure was the updater evidence reader:
it enumerated an atomic publisher's temporary file, which could disappear before
the reader opened it. The completed reports were intact. Test readers now inspect
only published `.json` reports; production publication is unchanged. A regression
with an incomplete temporary report failed before that filter and passed after it.
All **8 updater process tests** subsequently passed in **52.35 s**, build
**0.14 s**, including executable staging, handoff and cold restart. The generated
federation client suites also passed **11 tests in 372 ms**. These are focused
results, not a full integration gate or closure of the separate restart timeout.

The next parallel process run returned **30 passed, 1 failed, 8 ignored** in
**132.82 s**. The updater correction passed. The backup failure again timed out
on a forwarded storage-grant mutation; this time both gateway and storage-owner
diagnostics showed term **3**, committed/applied index **46**, no pending/queued
operations and no persistence fence. The storage owner was the valid leader.
The native pairing/backup regression separately passed in **6.51 s**, build
**17.76 s**. Rust formatting and whitespace checks passed at that point.

A focused real-UDP-loss regression established a transport defect: `finish()`
queued a metadata request on a cached connection without proving delivery, so a
dead path consumed the long authority-response deadline. The baseline failed
the four-second outer test bound, while a genuinely slow delivered request passed.
Control-stream opening/writing and delivery now use the existing two-second peer
budget. A valid response races the delivery acknowledgement to avoid adding ACK
latency; delivered requests retain the sixty-second authority-response budget.
Unconfirmed delivery uses the existing exact-connection eviction guard and leaves
the mutation outcome unknown. Transport itself never retries the mutation.
All **13 private-network tests passed in 2.39 s**, build **5.91 s**, including
loss, slow authority execution, cancellation, concurrent streams and identity
rotation. The independent-daemon failure is being rechecked against this fix;
the local reproducer alone does not establish that every restart stall is closed.

With the delivery correction, the three-daemon backup workflow passed in
**23.51 s**, build **33.76 s**, and then passed in the parallel headless suite
that had reproduced the stall. Cluster/daemon all-target/all-feature
warning-denied Clippy passed in **28.67 s**. Rust formatting, whitespace,
selected design-document formatting and generated-contract drift checks passed.
No dependency, schema or wire-field change was introduced by the delivery fix.

The final parallel run is **not green**: **30 passed, 1 failed, 8 ignored** in
**137.00 s**, build **0.22 s**. Its different failure was
`disconnected_gateways_accept_distinct_writes_and_reconcile_after_reconnect`:
the returning gateway still answered **404** for `office.txt` at the bounded
reconciliation deadline. Private retained stores showed both metadata replicas
at term **5**, committed/applied position **48**, state revision **44**. The peer
had published a merged history; the root had retained the imported office
history but had not adopted that merged head. These facts do not yet identify
the stalled boundary or prove whether the transport change contributed.
The two namespace-delivery tests subsequently passed in isolation in **35.96 s**,
build **0.13 s**. That pass does not close the parallel failure, and the test
deadline has not been increased. Full integration acceptance remains open.

The reconciliation harness now labels first reconnect versus full restart and
captures bounded live diagnostics on failure. Its two focused tests passed in
**28.96 s**, build **4.59 s**. Further read-only inspection of the original
failure shows partial immutable-history import sessions for the merged head;
the merged head was not merely absent from the delivery queue. Several earlier
imports also had incomplete object batches. No namespace implementation change
has been made on the strength of these observations. The final strengthened
private-network assertions passed all **13 tests in 2.39 s**, build **4.93 s**.

The eight ignored tests require dedicated offline DNS-provider containers,
real five-minute ACME lease/backoff waits, or the pinned SMB-client container;
none is counted as passing here. Task 7 remains **3 points**, Stage 10 **90**.
Signing authentication is still unresolved; no Git writes, commit, push,
release, tag, package/image publication or workflow execution occurred.

### Provider storage-offer administration

The production pairing router now exposes authenticated exact lookup and
issue/replace/revoke operations at `/api/latest/admin/federation/storage-grants`.
Mutations require current manager authority, CSRF where applicable, a stable
operation ID and the observed root-metadata revision. Exact retries reconstruct
the original command time and immutable epoch, check the original actor and
command digest, and retain their receipt after service reopen or later grant
replacement/revocation. Lookups reject a concurrent metadata revision change.
Foreign, namespace and downstream grants cannot be edited through this provider
surface. Replacement retains peer restrictions and existing allocation lineage;
revocation does not erase retained encrypted bytes.

An initial provider offer has a neutral recipient ceiling, not a claim that the
recipient approved a backup configuration or delegated access to its files.
Consumer-local restrictions remain independent. The endpoint is an exact lookup,
not a complete paginated offer inventory; inventory and panel controls remain
open under task 12. Missing lifetime means 30 days; explicit null means indefinite.

Rust boundary models generate OpenAPI, native Fetch, TypeScript and Zod; query
constraints reference the Rust schema rather than a separately authored pattern.
No dependency or database migration was added. Local uncommitted-tree evidence:

- Three Rust request/response contract tests passed in **0.02 s**; the initial
  build took **1m52s**. Missing/null/value distinctions, unknown input, unsafe
  integers and outgoing receipt constraints are covered.
- Two real-router/consensus API tests passed in **1.27 s**, build **43.00 s**:
  issue, replace, revoke, exact receipts after reopen, changed retries, stale
  revisions and authentication before body parsing. After the borrow-only lint
  corrections, the broader focused filter passed three daemon tests in
  **2.13 s** and three contract tests in **0.02 s**, build **14.44 s**.
- Eleven generated-client/federation tests passed in **336 ms** total Vitest
  duration. An initial test incorrectly compared JSON property order; it now
  checks decoded content. No production validation was weakened.
- Web TypeScript and warning-denied ESLint passed. API-contract/daemon
  all-target/all-feature Clippy passed in **20.66 s** after borrowing two
  unnecessarily owned arguments. API generation completed under NVM.

This closes **2 points** of the added API implementation: task 7 **7 → 5**,
Stage 10 **94 → 92**. The new three-process workflow is being exercised; no
success is yet claimed for distinct-owner gateway forwarding, failure recovery,
the full integration gate or publication. Signing authentication remains
unconfirmed; no commit or push is claimed.

`FederationBackupCapabilityService` can issue capabilities for a different
same-swarm storage owner. Its explicit gateway authorisation validates the local
MAC and current bilateral authority; direct provider authorisation additionally
requires the service's own node. The daemon now branches to its existing private
network for non-local owners, connects within the permit deadline and invokes
the forwarding service on the same owned bulk worker.

Forwarding preserves the original canonical signed consumer envelope. The owner
connection is checked against current certificate metadata at admission and at
IO/reply boundaries. A bounded readiness/result state machine validates full
forwarding digest, permit, frame offer, operation, action, object and receipt
time before the gateway signs an external response. Upload/download bytes are
forwarded one frame at a time with exact offsets, length and SHA-256. Upload FIN
is checked before finishing the owner stream. Owner FIN is checked before the
final external receipt. Errors do not invent success or move an uncertain upload
to another storage location. No private keys are forwarded and no dependencies
were added.

Local evidence on the uncommitted working tree:

- Production daemon check passed **19.16 s**.
- Transport/cluster/daemon all-target/all-feature warning-denied Clippy passed
  **19.46 s**. Earlier lint caught an oversized test combining admission/result
  vectors, the appliance composition crossing its size limit after expanded
  argument passing, and an ignored unit pattern. The test now separates admission
  vectors, federation composition borrows its existing node owner directly, and
  the unit error is explicit; no lint was weakened.
- Transport: **16 tests**, **0.62 s**, build **4.25 s**. The real relay harness
  now tests altered request/permit/frame offers, wrong operation/object, future
  and pre-issuance receipts, wrong phase, duplicate completion and expiry.
  Rejected responses do not advance the expected phase.
- Direct backup regressions: **3 tests**, **14.13 s**, build **28.51 s**.
- Existing native-owner/pairing proof: **1 test**, **6.50 s**, build **39.05 s**.

These tests do **not** prove the complete new consumer/gateway/different-owner
forwarding branch. That native workflow and independent-daemon failure acceptance
remain open; no completion credit is taken for the unverified integration.

Preparing the real-process workflow also exposed a required setup gap:
`IssueFederationGrant` is currently invoked by daemon tests, not a production
administrator route. The allocation provisioner consumes an already-issued grant;
pairing does not grant storage authority. Implement storage-offer/grant
administration with authenticated, revision-bound issuance/restriction/revocation
and prove its native setup flow. Panel controls belong to task 12. This adds
**3 points** of previously unaccounted API work: task 7 **4 → 7**, Stage 10
**91 → 94**. It does not weaken the required end state or treat test seeding as
user functionality.

Stage 11 has not started. Full local integration gate and complete new gateway
workflow are unrun. No commit/push or publication is claimed; the prior signing
authentication blocker has not been confirmed resolved.

## Task 7 — native storage-owner dispatch

The daemon's private data dispatcher now routes forwarded backup executions to
`FederationBackupOwner`. Listener binding supplies a weak reference to the actual
federation runtime; it cannot keep a stopped listener alive or open a competing
provider catalogue. The owner authenticates the original consumer against current
federation metadata, then rechecks enrolled relay identity, owner and authority
before opening the provider. `PeerDataStream` carries the locally configured route
epoch, rather than trusting the epoch in the request.

Direct and forwarded requests share one native bulk semaphore, replay window,
reader pool and provider catalogue. Allocation and physical-folder limits use the
existing intersected budgets. No maintenance lock spans transfer IO. The data
cycle observes the deadline-bounded worker to completion during shutdown rather
than dropping a blocking-write handle and assuming cancellation undid its work.

The native pairing proof now sends the original signed frame over real node-mTLS
and invokes the production owner ingress against a real registered folder. It
exercises short upload, exact retry, stored replay, exact readback, verify and
delete. A direct federation verification succeeds against the same live catalogue.
Ledger assertions verify **0 committed / 1,024 reserved** after truncation,
**1,024 committed / 0 reserved** after retry and **0 / 0** after deletion.
The first test incorrectly expected the interrupted reservation to be released;
the observed **0 / 1,024** is the existing conservative recovery contract. The
assertion was corrected without weakening production accounting. The expanded
proof then passed in **6.50 s**, build **12.62 s**.

The production daemon check passed in **22.89 s**. Clippy identified a 106-line
test conversation combining control exchange with bulk transfer. Upload/download
framing now has its own responsibility; correlation and worker ownership remain
in the conversation. Cluster/daemon all-target/all-feature warning-denied Clippy
passed in **8.94 s**, without exceptions. Final private-network regressions
passed **11 tests in 0.48 s** (build **8.90 s**); the expanded daemon proof passed
again in **6.52 s** (build **21.26 s**). NVM-selected Prettier, Rust formatting
and whitespace checks passed. No dependencies were added.

This closes the native owner composition slice: task 7 **5 → 4 points**, Stage 10
**92 → 91**. Gateway reply validation/forwarding and independent-daemon failure
acceptance remain open. The test dispatches after real frame reception; it does
not claim complete three-role consumer/gateway/storage-owner daemon delivery.
Stage 11 has not started. No full local gate, commit/push or publication is claimed;
the previous signing-authentication blocker has not been confirmed resolved.

## Task 7 — shared storage-owner transfer service

`FederationBackupOwnerService` now executes authenticated relay requests through
the same provider/byte/completion state machine as direct federation requests.
A private conversation boundary selects current-authority checks and reply
delivery; it does not duplicate store/read/verify/delete logic. Direct execution
retains its gateway signature/MAC checks. Owner execution uses current node and
bilateral authority without holding or copying gateway private keys.

The owner narrows its data-frame size to the relay offer, rechecks authority
during IO and completion, and applies a monotonic deadline no later than either
the relay deadline or permit expiry. Readiness still follows the provider asking
for source bytes, after capacity admission. Exact upload length, digest and clean
FIN remain necessary before publication, including exact stored retries. Internal
replies carry a domain-separated digest of the complete forwarding request.

The existing daemon pairing proof now also calls the owner service over a real
internal QUIC stream with a real, exclusively owned directory catalogue. A
**512-byte** catalogue rejects the **1,024-byte** operation with `Exhausted`
before any upload data. A **5-byte** truncated upload returns `Unavailable`;
the catalogue is closed/reopened before successful upload. An exact retry returns
the same stored receipt, and direct provider readback equals all **1,024** expected
bytes. The fixture now uses an independently reproducible payload digest instead
of an arbitrary digest placeholder. These are already-authenticated service-level
streams, not proof that native gateway dispatch forwards the complete operation.

The first build caught the test using the domain error name `ResourceExhausted`
instead of its existing wire name `Exhausted`. After correcting the fixture, the
expanded daemon proof passed in **6.50 s**, build **21.21 s**. A redundant mutable
binding was removed. Clippy then identified that the immutable borrowed IO context
should be copyable; it now derives `Clone, Copy`, without a lint exception.
Final affected transport/cluster/daemon all-target/all-feature warning-denied
Clippy passed in **29.21 s**. The production cluster check passed in **11.20 s**.

Gateway reply validation/forwarding, owner dispatch with the native registered
folder and shared allocation budgets, and independent-daemon failure acceptance
remain open. This test's directory capacity is not a physical disk-full or
registered-folder quota proof. Task 7 stays **5 points**, Stage 10 **92**;
Stage 11 has not started. No full integration gate, commit/push or publication
is claimed. The final direct-path regressions subsequently passed **3 tests in
20.54 s**, and the expanded daemon proof passed **1 test in 6.49 s**. These were
rerun after the earlier terminal session became unavailable; no result was inferred
from that lost session.

## Task 7 — storage-owner relay framing and authentication

Private data-control tags **90–92** now define a same-swarm owner relay. Its
request retains the consumer's original bounded signed federation frame;
structural validation rejects other message families, substituted owner/mesh or
correlation fields, and deadlines exceeding the original request or permit.
Internal ready/results have empty signature fields because their authority is
the owner's node-mTLS connection; external responses still require signatures.
The data-control container moved to a composition schema without changing its
existing tags. No dependency or public API schema changed.

The initial typed nesting inflated every data-control enum to 968 bytes, and
warning-denied Clippy rejected it. Retaining the original bounded encoded frame
avoids that inflation while preserving the signed input unchanged. Both frames
are validated independently; no lint allowance or generated-code edit was used.

Transport binds the forwarding node/incarnation to real node-mTLS, then checks
the original consumer's current registered signature, identity lifetime and
replay nonce independently. The real QUIC test rejects sender/incarnation,
signature, allocation and expiry substitutions; rejected attempts do not burn
the original valid nonce. A second acceptance returns an explicit replay error.

`authorise_forwarded_backup` adds receiving-owner, active relay certificate,
mesh/partition/routing-epoch, current bilateral grant/allocation and permit-lifetime
checks. A revision fence rejects metadata changed during admission. Direct
execution keeps its existing own-node and local signing-identity checks; both
paths reuse the same bilateral-authority decision. The owner has no gateway
private signing or permit-MAC key. This authority call does not reserve capacity.

The first cluster fixture failed with `InvalidCommand` because its minimal
bootstrap had no verified recovery bundle and therefore correctly could not
enrol another node. That new unfinished test was moved to the existing daemon
bootstrap/paired-session proof, which already confirms the recovery bundle.
It now uses an independent real internal TLS connection, commits gateway
enrolment/activation through consensus, proves rejection before enrolment and
exact permit admission afterwards, and rejects another owner, route epoch and
expired request. It does not bypass enrolment or seed authority rows with SQL.

Local evidence on the uncommitted working tree:

- Complete protocol/transport suites: **66 passed**; test build **24.00 s**,
  protocol suites each **0.00 s**, transport suite **0.62 s**. Includes the
  final encoded-frame representation and real internal QUIC relay.
- Protocol/transport all-target/all-feature warning-denied Clippy passed in
  **3.41 s** after the size correction. The peer-negotiation assertions now
  have their own coherent test helper; no function-length ceiling changed.
- Cluster production check passed in **32.23 s**. Its three existing direct
  backup capability/execution/rotation tests passed alongside the rejected
  minimal-fixture attempt; this was not a passing four-test run.
- Expanded daemon paired-session/owner-admission proof: **1 passed, 6.49 s**,
  build **1m 04s**. This includes normal local backup store/read/verify/delete
  and interruption coverage, not storage bytes forwarded to another owner.
- Final protocol/transport/cluster/daemon all-target/all-feature warning-denied
  Clippy passed in **56.53 s**. Rust formatting, NVM-selected Markdown formatting
  and `git diff --check` passed. Signing authentication remains unresolved; no
  signing prompt was retried and no unsigned commit was made.

Reply correlation, physical capacity admission through the relay, byte forwarding
and runtime dispatch remain open; the existing data router still rejects this
new execution family. Independent-daemon delivery/restart/failure acceptance
also remains open. Task 7 stays **5 points**, Stage 10 **92**; Stage 11 has not
started. No full integration gate, commit/push or publication is claimed.

## Task 7 — automatic provider sealing and recovery

The production storage-maintenance owner now runs a bounded provider sealing
worker before allocation provisioning. Each tick examines at most one allocation
on its own node, intersecting current authority with local committed/reserved
charges and freshly observed folder headroom. Unavailable folders or reduced
write ceilings trigger permanent sealing; healthy, adequately backed allocations
do not. An unavailable _different node_ is never assumed to have unused capacity.

The worker loads the existing protected node-local federation signing identity,
registers its public attestation key through consensus when absent, seals the
local ledger, and submits the signed ceiling through the same consensus adapter.
It verifies the committed receipt. A different registered key is rejected rather
than silently overwritten. Local fences survive submission failure; a restart
rescan submits pending evidence and later lower ceilings. Accepted seals with
missing local fence evidence fail closed rather than manufacture zero usage.

The real consensus/folder acceptance now requires no test-side key registration
or seal submission for its ordinary withdrawal path. With **128 reserved bytes**
inside a **1,024-byte** allocation, it verifies healthy no-op maintenance, folder
withdrawal, automatic key registration/sealing, retained read authority, and a
distinct **896-byte** successor. Reopening the signing identity and restarting
the maintenance cursor produce no duplicate revisions. A second case explicitly
injects the window after local sealing but before consensus submission, reopens
the SQLite ledger and recovers through the production worker. It commits exactly
one missing seal and reuses the released allowance once. A mismatched local
signing identity cannot change the registered key or revision.

These are opened-folder snapshot withdrawal and a precisely constructed durable
interruption state, not physical unplugging, a killed daemon or host power loss.
Independent-daemon failure-overlap acceptance remains separate.

The query-plan regression exposed temporary sorting behind the older allocation
index. Partition schema **100** adds an active-provider keyset index; the final
plan uses it without a scan or temporary sorting. The first production build
passed in **19.64 s**, and the initial automatic test passed in **0.55 s**, build
**1m 01s**. Lint identified a 109-line runtime coordinator; the complete ordered
seal/provision pair now has one capacity-reconciliation owner without weakening
the lint limit. The final nine signed-seal/maintenance tests passed in **5.61 s**,
build **5.14 s**. The expanded native automatic/restart/key-mismatch proof passed
in **0.65 s**, build **36.21 s**.

Final local checks on this candidate:

- Allocation suite: **39 passed, 29.04 s**, build **4.66 s**.
- Database/migration suite: **50 passed, 10.19 s**, warm build **0.09 s**.
- Expanded automatic/recovery proof: **1 passed, 0.69 s**, build **25.72 s**;
  this also rejects a blank replacement ledger for an allocation whose accepted
  seal retains 128 bytes, without changing the authoritative revision.
- Native QUIC backup/authority regression: **1 passed, 6.50 s**, warm build
  **0.14 s**.
- Metadata/cluster/daemon all-target/all-feature warning-denied Clippy passed in
  **37.09 s**. Rust formatting, NVM-selected Markdown formatting and diff checks
  passed. No dependency or generated public-API contract changed.

Automatic provider-local seal selection/submission and allowance reassignment are
now implemented. Other-provider-node forwarding and independent-daemon automatic
delivery/restart/failure-overlap proof remain open; task 7 remains **5 points**,
Stage 10 **92**. Stage 11 has not started. No full integration gate, signed
commit/push or publication is claimed; signing authentication remains unresolved.
The next routing boundary is explicit: `FederationBackupCapabilityService`
requires the target's provider node to equal its execution node, and native
provider resolution requires that node's opened folder. Cross-node forwarding
must preserve those ownership checks and the authenticated request/receipt
binding rather than relabel another node's storage as locally owned.

## Task 7 — authenticated provider quota handoff

Partition schema **99** and metadata command capability **14** add signed
capacity-seal acceptance (kind **122**) and consensus encoding for the existing
node attestation-key registration (kind **123**). No dependency was added. The
provider signs the exact permanent local seal, including unresolved reservations,
under a distinct Ed25519 signature domain. Acceptance checks the mesh, immutable
allocation/node/target, generation, current node incarnation and active key.
The node-private signing capability is reused; no private key enters consensus.

Sealed allocations retain their immutable identity and read authority, but no
longer admit new writes. Authoritative quota accounting charges their retained
ceilings instead of their original maxima. Renewal reserves all sealed charges
before distributing new-write allowances, independent of allocation-ID ordering.
Historical seals remain verifiable after key rotation, while retired keys cannot
sign newly accepted seals. Failed authoritative insertion rolls back the revision
and cannot free quota.

A regression first demonstrated that validly shaped database corruption could
lower a stored ceiling without a matching signature and avoid corruption rejection.
Allocation issuance and grant renewal now reverify stored evidence in bounded,
indexed reads before using its credit. The regression passes and checks that the
metadata revision stays unchanged on rejection.

The assembled maintenance test also first failed because planning skipped a
target even after its allocation was sealed. Planning now permits a successor
only when every existing allocation for that target incarnation is sealed.
Its deterministic ID includes the retained target-allocation sequence; the first
allocation keeps its existing ID derivation. Current-revision fencing prevents
concurrent stale plans from issuing duplicate budgets. The real consensus/folder
test now lets the production maintenance worker assign the released **1,024
bytes**, proves that the old allocation is unchanged, and restarts its cursor
without producing another allocation or metadata revision.

Local evidence on the uncommitted `codex/stage10-update-handoff` tree:

- All **36** allocation tests passed in **26.34 s**, build **6.96 s**, before the
  successor-planning addition. Metadata/cluster/daemon all-target/all-feature,
  warning-denied Clippy then passed in **33.00 s**.
- All **7** signed-seal tests, including historical key rotation, passed in
  **4.27 s**, build **6.35 s**, after the planning addition.
- All **50** database/migration tests passed in **10.17 s**, warm build **0.09 s**.
- Real consensus/folder automatic reassignment passed in **0.51 s**, build
  **30.15 s**. The earlier red test failed at the exact missing successor proposal
  in **0.46 s**, build **32.25 s**.
- Final allocation suite: **38 passed, 27.31 s**, build **11.28 s**. This includes
  an actual query-plan check using the grant index, without scans or temporary
  sorting, and exact corruption-error assertions for allocation and renewal.
- Existing command-codec suite: **43 passed, 0.21 s**, warm build **0.41 s**.
- Assembled native QUIC backup/authority regression: **1 passed, 6.75 s**,
  build **33.96 s**. Final metadata/cluster/daemon all-target/all-feature,
  warning-denied Clippy passed in **41.67 s**. Rust formatting, NVM-selected
  Markdown formatting and `git diff --check` passed.

The fixture still explicitly registers the key and seals the provider before
running maintenance. Automatic selection of allocations to seal and production
key-registration/seal submission are **not** complete. Other-provider-node
forwarding and independent-daemon automatic delivery/restart/failure-overlap proof
also remain. Task 7 stays **5 points**, Stage 10 **92**; Stage 11 has not started.
No full integration gate, signed commit/push or publication is claimed. The prior
signing-authentication blocker has not been confirmed resolved.

## Task 7 — durable provider capacity seals

Local schema **15** adds a permanent per-allocation admission seal. The provider
owner seals an exact local allocation and snapshots **committed plus reserved**
bytes in one immediate SQLite transaction. Both shard and backup admission use
the existing shared reservation path and refuse new holds after sealing, including
with authority obtained before the seal. Already admitted operations can replay,
finish or reconcile without another charge. Later sealing may lower, but never
raise, the retained ceiling; a local sequence advances only on a reduction.

Database constraints also reject deleting the seal or increasing a sealed
allocation's aggregate charge. The original allocation identity and maximum are
unchanged. The seal is not a grant revocation, deletion permit, remote attestation
or consensus quota credit. It is deliberately not activated by maintenance yet:
authenticated provider evidence and authoritative reassignment must be connected
before an automatic worker freezes usable allocations. An unavailable provider's
allowance cannot simply be assumed unused.

Focused acceptance:

- Mixed backup/shard holds total **40 bytes**. Sealing rejects new reservations
  but accepts exact held retries. Completion reduces charges to **35**, provider
  database reopening preserves the seal, and confirmed backup release permits
  narrowing to **15**. Sequence values are exactly **1, 2, 3**.
- Concurrent independent SQLite connections race admission and sealing. Either
  the 20-byte reservation is included in the seal or admission is rejected; it
  cannot escape the retained ceiling.
- Empty allocations seal at zero; deletion, attempted ceiling increases and
  direct accounting increases fail. An injected insertion failure rolls back
  even newly installed usage identity, and a different node cannot seal it.
- An actual schema-14 database with a pending backup charge migrates to 15,
  retains its 20-byte reservation, accepts its exact retry and completes it
  without changing the seal or double charging. This proves schema migration,
  not an old executable or host power loss.

The initial three fence tests passed in **1.71 s**, build **13.57 s**. All **30**
allocation tests, including five seal cases, passed in **22.50 s**, build **6.55 s**.
All **50** database/migration tests passed in **10.23 s**, warm build **0.09 s**.
Metadata all-target/all-feature warning-denied Clippy passed in **5.12 s** after
the final seal-specific tests. The real folder-provider cycle now seals stored
bytes before replay, reopening and owner read/verify/delete: **1 passed, 0.38 s**,
build **5.46 s**. The assembled native QUIC regression passed in **6.51 s**, build
**54.01 s**; it exercises normal unsealed operation after the schema change, not
automatic remote seal acceptance. Final metadata/daemon all-target/all-feature
warning-denied Clippy passed in **37.99 s**.

Remaining: authenticate and commit these local ceilings before redistributing
quota; wire the maintenance reconciliation/placement loop; other-provider-node
forwarding; independent-daemon automatic delivery/restart/failure-overlap proof.
Task 7 remains **5 points**, Stage 10 **92**. No full gate, signed commit/push or
publication is claimed; the signing-authentication blocker remains unconfirmed.

## Task 7 — native interrupted-upload and withheld-receipt recovery

The native fixture previously stored its object during route selection before
exercising a short upload. That proved malformed replay rejection, not recovery
of a genuinely unpublished object. Route selection now commits its admitted
route and deliberately fails the source after five bytes through the production
consumer facade. The subsequent independent wire short-upload check observes
exactly zero committed bytes and one object-sized reservation, before and after
its rejection. An interrupted attempt neither publishes incomplete data nor
silently frees its uncertain charge.

A client-boundary fault then consumes but withholds the final store response:
no authenticated receipt or returned reference reaches the consumer. Reading that
frame synchronises the test with provider completion; this is deliberately not
claimed as a process crash, physical network partition or TCP/QUIC connection
loss. A newly resolved production consumer facade discovers current permission,
retries the same object through its immutable saved route and reads/verifies the
exact expected bytes. The provider retains exactly one object-sized committed
charge with no reservation debt, and the consumer's route is unchanged. The
existing renewal and deletion checks run afterwards and return accounting to zero.

Inspection also confirmed that publication already derives distinct attempt IDs
from its attempt time. A fresh attempt therefore does not reuse a store operation
ID with a different deadline; no production digest rule or compatibility contract
needed changing. Test operation IDs are now explicitly separated between the
failure-recovery and grant-renewal cycles.

Initial focused native proof: **1 passed, 6.50 s**, build **54.59 s**. Daemon
all-target/all-feature warning-denied Clippy passed in **8.28 s**. The final native
run also asserts the exact existing short-stream rejection code rather than any
rejection: **1 passed, 6.49 s**, build **9.82 s**. All **7** publication tests passed
in **0.08 s** (warm build **0.13 s**), including provider success followed by
authority failure and replay. Rust formatting, NVM-selected Markdown formatting
and `git diff --check` passed.

This corrects and extends native acceptance evidence; it introduces no production
runtime, dependency, schema or wire change. Safe redistribution of assigned quota
still needs provider-side fencing before authoritative reassignment: object
cleanup releases occupied bytes but does not erase an allocation's reserved
ceiling. Other-provider-node forwarding and independent-process automatic backup
delivery/restart/failure-overlap remain open. Estimates remain task 7 **5 points**,
Stage 10 **92**. No full gate, signed commit, push or publication is claimed.

## Task 7 — provider-owned automatic allocation provisioning

Approved local storage grants now feed a provider-owned reconciler in the normal
storage maintenance cycle. Discovery remains read-only. The reconciler examines
one grant/target pair per tick, probes the live folder and intersects its measured
filesystem availability with configured headroom, committed bytes and outstanding
reservations. It proposes up to the unallocated bilateral grant quota and commits
through the existing `IssueFederationStorageAllocation` command and consensus
forwarding path. No external service, dependency, schema or wire message was added.

Grant scanning uses the existing resource index. Proposals capture a complete
metadata revision and require it in command context, so concurrent target, grant
or quota changes reject the stale plan. Existing allocation ceilings remain
charged, including revoked/expired allocations; current successor-grant authority
is used when counting them. An existing target incarnation is not allocated twice.
Allocation IDs are deterministic from grant, target and incarnation. Losing the
transient scan cursor restarts discovery without creating another allocation.
Failures are reported through maintenance observations without preventing the
remaining maintenance phases from running.

The runtime packs remaining quota into eligible targets as they are visited;
these ceilings are not reserved physical bytes or protection acknowledgements.
Actual transfer admission still intersects allocation and folder accounting.
Moving quota already assigned to a full/lost target requires fenced accounting
reconciliation; this implementation deliberately does not erase old charges or
revive revoked allocations to claim additional room. Automatic rebalancing of
assigned quota remains part of task 7's capacity/recovery work.

Evidence:

- The consensus/folder integration test automatically creates an exact **1,024-byte**
  allocation from an approved grant, rejects an older competing proposal, and
  rescans after dropping its transient worker state without another allocation or
  metadata revision. It also excludes expired grants. Final focused run:
  **1 passed, 0.51 s**, build **17.48 s**. This is not a process-restart proof.
- The capacity intersection test covers actual-free-space versus configured quota,
  repair headroom, occupied/reserved-byte overflow, missing measurements and
  impossible filesystem reports. The initial broader `provisioning_` filter ran
  these two new tests plus three existing certificate/TOTP tests:
  **5 passed, 0.44 s**, build **20.79 s**.
- Metadata grant seek/expiry test: **1 passed, 0.29 s**, build **12.38 s**. Its
  `EXPLAIN QUERY PLAN` confirms the existing covering resource index and no
  temporary sort.
- Final metadata/daemon all-target/all-feature warning-denied Clippy passed in
  **21.96 s**. All **25** allocation/accounting tests then passed in **19.43 s**
  (warm build **0.18 s**), and the real native QUIC backup/renewal cycle passed in
  **6.58 s** (warm build **0.13 s**). Rust formatting, NVM-selected Markdown
  formatting and `git diff --check` passed. These are focused local checks, not
  the full integration gate or independent-process acceptance.

The first compile rejected a `usize` SQL parameter; it now uses checked `i64`
conversion. The first integration assertion expected the wrong public error:
stale metadata preconditions map to `Rejected`, not operation-ID `Conflict`.
The assertion now matches the existing authority mapping exactly; no runtime
error handling was weakened. Clippy then identified a 104-line test orchestration;
approved-grant fixture setup is now a separate named responsibility.

Task 7 remains open for assigned-quota reconciliation, uncertain/post-admission
upload recovery, other-provider-node forwarding and independent-daemon automatic
delivery/failure-overlap acceptance. Estimates remain **5 points**, Stage 10 **92**.
The full integration gate has not run. No signed commit/push is claimed while the
signing-authentication blocker remains unconfirmed; publication is still prohibited.

## Task 7 — stable backup namespace and native permission renewal

The approved renewal correction now reaches the native consumer/provider flow.
`FederatedBackupScope` separates current `grant_id` from immutable
`namespace_grant_id`. Physical backup hashing keeps the original namespace bytes;
signed messages and provider MACs bind both identifiers. Provider admission checks
the origin against its immutable allocation and the permission against current
lease authority. Mandatory Protobuf field **12** rejects omitted/malformed origins.

Allocation discovery follows the indexed current grant/lease projection, including
renewed intervals. It keeps retained larger objects discoverable after quota
narrowing without relaxing new-write admission. Consumer route format **2** and
command kind **121** carry both identifiers; format **1** and kind **120** keep their
old decoding, deriving the origin from their original sole grant. Metadata command
capability version is **13**. No physical route is rewritten on renewal.

The consumer now refreshes permission from complete signed grant discovery and
bounded signed allocation pages, accepting only the exact retained allocation,
origin, node, target and incarnation. It verifies response correlation and stream
completion under the operation deadline. Initial prepared uploads retain their
already admitted stream; refresh never silently selects another storage location.

The physical-location regression first failed with two distinct destination IDs
after changing only permission. With the split, all **7** contract tests passed
in **0.00 s**, build **3.70 s**. All **24** allocation tests passed in **18.62 s**,
build **19.61 s**, including renewed discovery past original expiry, lower-quota
recovery discovery, forged-origin rejection and an indexed seek without sorting.
Affected all-target/all-feature warning-denied Clippy passed in **4m 00s** after
the shared protocol rebuild; later fixture changes receive a separate final check.

The extended real Quinn/mTLS native test stores bytes, retires/reopens the provider
catalogue, renews the grant, then uses the production blocking consumer facade to
store/read/verify the same bytes and reference through its unchanged saved route.
Allocation usage remains exactly the payload length with no reservation debt;
deletion under successor authority returns both allocation counters to zero.
Fresh capability requests prove the successor works before revocation, the retired
predecessor fails, and the revoked successor fails. The denial proof explicitly
checks its fresh deadline has not expired. Final native run: **1 passed, 6.50 s**,
build **13.84 s**. This is real native session/folder IO, not independent daemon
process restart or host power-loss evidence.

The first native attempt failed `Conflict` (**2.83 s**). A diagnostic rerun
identified consumer access after renewal (**2.77 s**): the test called the same
operation-ID sequence twice with newly constructed deadlines. The provider's
existing canonical idempotency check correctly rejected that different request.
The duplicate facade call was removed: the independent wire client retains its
pre-renewal proof, and the facade proves post-renewal access once. No runtime
idempotency rule was weakened. That correction passed in **6.49 s**, followed by
the stronger fresh-deadline revocation proof above.

Final focused checks on this working tree:

- Contract backup tests: **7 passed, 0.00 s**, build **2.85 s**.
- Protocol `federation_backup` target: **6 passed, 0.00 s**, build **15.18 s**.
- Allocation/renewal tests: **24 passed, 18.62 s** as recorded above; subsequent
  changes affected route-codec tests and the daemon fixture, not allocation logic.
- Metadata `federated_routes` filter: **3 passed, 1.70 s**, build **4.82 s**.
  This includes actual schema-96 route migration, route backup/restore and
  independently assembled kind-120/kind-121 command bytes. The first filter used
  the source filename rather than registered module name and selected **zero**;
  that empty run was not accepted as verification.
- Transport allocation response tests: **1 passed, 0.00 s**, build **15.85 s**.
- Cluster backup-capability integration: **3 passed, 14.01 s**, build **53.43 s**;
  includes identity rollover and real signed byte-transfer execution.
- Final native renewal test: **1 passed, 6.50 s**, rebuild **16.47 s** after the
  fixture responsibility correction.
- Final metadata/daemon all-target/all-feature warning-denied Clippy:
  **passed, 11.34 s**. It first identified three large test arguments and a
  101-line orchestration function. The arguments now borrow their records;
  retained-byte verification is a named test phase, separate from lifecycle,
  renewal and accounting orchestration. No lint limit was relaxed.

Commands used Rust **1.98.0**, `CARGO_BUILD_JOBS=4`, `--all-features` and
`--test-threads=4`; Cargo invocations were sequential. Markdown formatting used
Prettier through the repository-selected NVM runtime. Formatting/diff checks
are separate from the still-unrun full integration gate.

Task 7 remains open: automatic allocation provisioning, post-admission/unknown
outcome recovery, other-provider-node forwarding and independent-process
delivery/restart/failure-overlap acceptance remain. Estimates remain task **5**,
Stage 10 **92**; closing permission refresh does not establish those broader
integration gates. No full integration gate, signed commit, push or publication
is claimed. Signing authentication remains unconfirmed; publication is prohibited.

## Task 7 — approved renewal correction, metadata authority and accounting

The owner approved the cross-contract correction (D-084); the earlier approval
blocker is resolved and the goal is active. This is implementation in progress,
not a claim that the complete native renewal flow is finished.

Two new regressions first reproduced the defects: successor permission could not
use the retained allocation, and renewal allowed a second fresh quota budget.
Both failed before the fix (**0.82 s**). Partition schema **98** now adds a
renewable authority projection keyed by the unchanged allocation identity.
Grant replacement advances it atomically through the explicit succession edge.
New allocation admission counts predecessor allocations against the successor
budget, including retained revoked allocations whose capacity is not yet proved
reclaimable. No usage counters or physical allocation identities are replaced.

Quota narrowing assigns bounded write ceilings within the successor's limit;
already stored/reserved bytes remain charged. Local reservation accounting
accepts newer authority fences over the same exact physical identity without
resetting counters. Both shard and backup reservation paths use the current
ceiling and validity interval. Only an expiry originally tied to the grant follows
renewal; independent allocation deadlines remain fixed.

The initial **21** allocation/accounting tests passed in **16.84 s**, build
**7.03 s**. Six focused renewal tests subsequently passed in **3.49 s**, build
**6.83 s**: retained identity, no second budget, lower-quota rejection with
retained charges across reopen, independent expiry, rollback at all four apply
boundaries, and backfilling the new projection from existing succession history.
The backfill case rebuilds the new projection; it is not an older-binary upgrade
or a real-byte/QUIC renewal proof. Successor revocation is also checked.

Affected Clippy initially rejected use of a fixture's underscore-prefixed field;
the test now derives its local database path from the existing explicit path.
Final metadata/cluster all-target/all-feature warning-denied Clippy passed in
**15.46 s**; all **23** allocation tests passed in **18.50 s**, build **5.43 s**;
all **6** grant tests passed in **5.17 s**, build **0.09 s**. No full integration
gate, commit, push or publication is claimed. Still required for this correction: separate renewable
permission from stable namespace fields on the wire, current-authority discovery
and consumer refresh, real-byte/provider and native QUIC renewal acceptance.
Automatic allocation provisioning, post-admission recovery, other-node forwarding
and independent-process failure-overlap acceptance also remain task-7 work.

## Task 7 — renewal requires separating storage identity from grant authority

Inspection after capacity-admission integration found that the previously named
“remote revision refresh” is not a revision-only change:

- `repository/federation_grant.rs::replace` requires a **different grant ID**,
  retires the predecessor and records explicit succession.
- `repository/federation_storage_allocation.rs::active_authority` requires that
  exact grant to remain active and match the allocation's immutable grant ID.
- `federated_provider_backup_identity` includes the grant ID in the physical
  backup namespace. Substituting a successor ID would address another namespace.
- `prove_disjoint_capacity` groups allocation ceilings by grant ID. Renewal
  cannot be treated as fresh capacity while predecessor allocations retain bytes.

Consequently, updating an observed revision alone cannot restore retained-backup
access after renewal. Automatically creating replacement allocations is not an
adequate fix either: it must preserve both stored-object routing and existing
capacity charges, without reviving revoked authority.

Proposed correction, awaiting approval because it crosses the storage contract:
separate stable storage/allocation identity and accounting from renewable grant
authority. Follow only authoritative, explicit grant succession; preserve exact
object locations and charges; enforce current restrictions and revocations on
every operation. Lowered quotas must not silently erase bytes or mint capacity.
This affects records/schema, private contracts, discovery and provider admission,
not just the consumer facade. Required acceptance includes renewal over retained
bytes, narrowing/revocation, restart and no double-spending of allocation budgets.

No runtime/schema/protocol change has been made for this proposal. The existing
`bilateral_grant_intersection_replacement_and_revocation_survive_restart` test
passed in **0.48 s** and `bilateral_quota_is_disjoint_fenced_and_durable` passed in
**0.31 s** under Rust 1.98.0, all features, four test threads. These verify their
separate grant/ledger contracts, not retained-backup recovery through renewal;
that cross-contract acceptance is still missing. The earlier passing capacity
admission evidence remains valid. Task 7 is not complete; its estimate must be
revisited once this boundary is agreed rather than pretending the change is a
small revision refresh.

## Task 7 — capacity admission before route commitment

The native client now exposes an owned, deadline-bound admitted upload. It has
received the signed `BackupReady` response but has no source stream and has sent
no object bytes. The consumer commits that exact route, then the resolved
provider finishes the same operation on the same connection. Changed operation,
scope, connection or framing bounds are rejected. No new wire message, schema
or dependency is needed.

The existing provider reserves allocation and folder capacity before requesting
source bytes, which is when it sends `BackupReady`. A confirmed capacity refusal
therefore permits trying the next allocation without persisting the refused
route. Transport/authority errors remain errors rather than false capacity
reports. After commitment, retries retain the immutable route; this does not
authorise rerouting an unknown store or claim that physical IO cannot fail after
admission.

The native QUIC fixture fills the first allocation with **2048 bytes**, then
requires selection of the second allocation and completion through the admitted
production provider. Exact route replay, source independence during preparation,
read-back, target withdrawal/reopen, deletion and zero final reserved/committed
usage on both allocations are checked. Seven publication regressions passed in
**0.07 s**. Native runs passed in **6.48 s**, **6.50 s**, and **6.81 s**;
builds took **46.65 s**, **18.45 s**, and **23.86 s** respectively.

Lint found a redundant continue, mixed test responsibilities and oversized test
futures. Capacity-refusal and permit-assertion checks now have their own focused
test helpers; the bulk fixture future is heap-owned. No lint limits were relaxed.
Final affected data-plane/daemon all-target/all-feature warning-denied Clippy
passed in **8.61 s**. The final native regression passed in **6.95 s**, build
**19.14 s**. NVM-selected document formatting and `git diff --check` also passed.

Still required: automatic allocation provisioning, safe recovery after
post-admission failures, current remote-revision refresh, other-node forwarding,
and independent-process scheduled delivery/restart/failure-overlap acceptance.
Task 7 remains **5 points**, Stage 10 **92**, Stage 11 **126**. No full integration
gate, commit, push, release or publication is claimed for this increment.

## Task 7 — automatic selection from existing allocations

Publication now asks its provider resolver to prepare durable routing before
opening/sending the source. Local providers keep their existing resolution path;
the native federated resolver selects and commits a route through the supplied
publication authority. It verifies the active destination and exact committed
receipt. Existing intent is checked and reused rather than selecting again.

Initial selection fetches a complete bounded signed grant snapshot, then signed
allocation pages over the lifecycle-owned session. It filters active, currently
valid storage grants for the exact two swarms, checks object size and verifies
the selected scope against the signed grant revision and exact object. One
request deadline bounds the exchange; unavailable sessions remain unavailable,
not a false capacity report. No new wire message, schema or dependency is added.

The native real-QUIC fixture now discovers and commits its own initial route,
instead of inserting the successful route directly. It retains the prior
stale-claim/destination checks, wire encoding checks, reopen proof and exact retry.
A request exceeding all granted capacity must leave no route behind. The source
path deliberately does not exist during route preparation, proving this phase
does not publish bytes. Its source-manifest values are fixture inputs, not proof
of encrypted database capture or autonomous daemon scheduling.

The seven publication regressions passed **0.08 s**, build **14.06 s**. The first
native selection run passed **6.49 s**, build **25.01 s**. A fixture field-name
error was corrected before that run. Lint identified a redundant clone and mixed
codec/lifecycle responsibilities in the test; those responsibilities are now
separate without raising limits. The capacity rejection check uses the public
preparation boundary, not widened visibility on a private selector. Final native
selection/capacity-refusal proof passed **6.50 s**, build **13.16 s**. Affected
data-plane/daemon all-target/all-feature warning-denied Clippy passed **17.18 s**.

Still required: provider-side capacity-aware allocation provisioning, safe
recovery when a selected allocation cannot admit bytes, current remote-revision
refresh, forwarding to another provider node, and independent-process scheduled
delivery/restart/failure-overlap proof. Discovery advertises allocation ceilings,
not reserved free bytes: selecting the first suitable ceiling is not sufficient
to close capacity-aware automatic placement. An unknown store cannot be resolved
by blindly changing the immutable route. Task 7 remains **5 points**, Stage 10
**92**; no full integration gate, commit, push or publication is claimed.

## Task 7 — durable consumer routes and native client

The consumer now has an immutable consensus-backed allocation route for each
backup/destination. Binding checks the live run claim and destination revision
before any store. An unknown outcome retains the original allocation and object;
changed identity cannot silently reroute a retry. A route is intent only: neither
the backup catalogue nor a stored/verified copy is fabricated before provider IO.
Later catalogue/copy commands reject disagreement with an existing route.

The new signed streaming client performs capability issuance and exact
store/read/verify/delete over an existing negotiated federation connection.
Request deadlines and the shorter permit lifetime bound network waits; source
and downloaded bytes are checked incrementally with frame-sized memory. Signed
responses retain the existing exact operation, object, phase, peer and replay
checks. End-of-stream is required after a capability/result; a lost response is
an unknown outcome, not evidence of rollback. Deadline errors retain that class
through the synchronous provider facade.

The backup worker, retention resolver and export service now use that facade
for federated destinations with a persisted route. It reads current local pairing,
checks the immutable object and reuses the lifecycle-owned connection with its
negotiated limits. SQL and live-session guards are released before network IO.
A weak startup handoff connects providers to the listener after binding; it
cannot create a reference cycle or dial a competing session. Missing routing
intent fails before sending bytes. Remote grant revisions are not yet refreshed
automatically: a changed grant must reject the old scope, not silently relocate it.

The native paired-session fixture now also proves the production client’s exact
store/read/verify/delete and the daemon facade’s persisted-route store/read/verify.
It checks missing startup handoff, duplicate attachment and changed-object refusal.
The existing independent wire client still checks returned fields, retry,
withdrawal/reopen, absence and zero final capacity accounting. These are real
QUIC, SQL and folder operations within one test process, not autonomous scheduled
delivery between independently restarted daemon processes.

Partition schema **97** adds `federated_backup_routes`; command admission version
**12** adds kind **120**, audit kind **159**, entity kind **64**. Existing record
encodings are unchanged. The real schema-96 fixture migrates twice without
changing its existing principal and finishes with no foreign-key violations.
Exact canonical bytes, malformed fields, every injected apply-transaction failure
and backup/restore preservation are covered. This proves the schema transition,
not mixed-version consensus-log replay. No dependency or external service was added.

Final affected local results, Rust **1.98.0**, four workers:

- Route/migration suite: **3 passed, 1.74 s**, build **6.77 s**.
- Federation suite including the native facade: **10 passed, 11.71 s**, build
  **27.05 s**, including the command-version and listener-composition changes.
- Provider routing/deadline mapping: **2 passed, <0.01 s**, build **0.16 s**.
- Real daemon HTTPS create/restart: **passed, 7.79 s**, build **37.95 s**.
- Broader metadata-backup suite: **64 passed, 37.08 s**, build **0.68 s**.
- Affected metadata/data-plane/daemon all-target/all-feature Clippy:
  **passed 38.48 s**.

Initial compile checks caught a QUIC-read error conversion and incorrect mutable
receivers on the read-only provider methods; both were corrected. Lint identified
an oversized test future and listener composition function. The bounded round-trip
fixture now heap-owns its future; listener binding and consumer handoff form one
startup operation. No lint ceiling or exception was added. Rust formatting,
NVM-managed document formatting and `git diff --check` pass. No fresh full
integration gate or Git publication is claimed here; signing is still awaiting
re-authentication after the previously recorded failure, and unsigned commits
have not been substituted.

Task 7 remains **5 points**, Stage 10 **92**. Automatic first-allocation
provisioning/selection and route binding, remote revision refresh, non-local
provider forwarding and independent-process restart/failure-overlap acceptance
remain required. The signed client and facade are not a claim those gaps are done.

## Task 7 — native allocated-folder backup execution

The native federation dispatcher now serves signed backup execution for an
allocation hosted on its own node. It composes current peer/grant/allocation/MAC
admission with the existing bounded stream executor and real directory provider.
Store readiness follows allocation and shared physical-folder capacity admission;
read, verify and delete retain current authority checks. No provider keys or
volume decryption material leave the node.

Bulk transfers have their own CPU-derived semaphore and reused metadata-reader
pool, separate from control preparation. Every spawned blocking job has an
observed completion and the signed permit deadline bounds network waits. A
maintenance-published target snapshot supplies exact live folder handles without
holding the maintenance runtime lock during transfers.

One catalogue owner is retained per allocation-isolated physical destination.
The resident cache is bounded relative to host workers, not the number of
configured destinations. Busy namespaces reject admission instead of waiting
behind another transfer. Permission revisions reopen the same namespace under
exclusive ownership, not a new directory. Target withdrawal retires idle cached
catalogues, and active owners are revisited on the next lifecycle pass. Closing
evicted catalogues happens outside the inventory guard.

The native real-QUIC test now proves:

- control capability issuance completes while a bulk upload waits for bytes;
- a short upload fails and an exact retry stores the expected object;
- repeated storage returns the same receipt without a duplicate charge;
- withdrawing the target releases its cached catalogue lock, demonstrated by
  an independent exclusive open; returning it recovers the same bytes;
- readback matches the expected payload byte for byte, verification returns the
  exact reference, deletion replays exactly and subsequent verification returns
  `NotFound`;
- the allocation finishes with exactly zero committed and reserved bytes.

This is the production native dispatcher with actual folders, independent
consensus authorities and a test-process wire client. It is not independent
daemon-to-daemon automatic backup delivery, a physical unplug proof or a proof
that the opaque test payload was produced by encrypted backup preparation.

Final local dirty-tree checks, Rust **1.98.0**, four workers:

- Daemon all-target/all-feature warning-denied Clippy: **passed 5.74 s**.
- Daemon federation suite: **10 passed 11.69 s**, build **13.71 s**.
- Real-process HTTPS create/restart smoke test: **passed 7.95 s**, build
  **36.56 s**. This verifies the changed daemon composition, not cross-swarm
  delivery.

The initial native execution flow passed **6.49 s**. Subsequent review identified
the idle catalogue retaining a withdrawn folder owner; lifecycle retirement and
the independent-open/readback proof address that issue. Lint findings were fixed
without exemptions: borrow the target, heap-own the large daemon-cycle future,
and separate deletion/retry/absence assertions into one lifecycle operation.
No external dependency, new wire tag or schema migration was added by this slice.

This closes native local-provider execution: task 7 **6 → 5 points**, Stage 10
**93 → 92**. Still required: automatic grant/allocation provisioning and consumer
selection, native destination/retained-copy resolution, other-node forwarding,
automatic delivery and independent-process restart/failure-overlap acceptance.
Quorum-derived native time and identity rollover remain explicit integration
gaps. The full integration gate has not been rerun. Signing authentication remains
uncleared; no commit, push, release, tag or publication was attempted.

## Task 7 — native backup-allocation discovery

Native paired sessions now serve signed allocation pages before capability
issuance. Requests bind the grant, required object size and optional canonical
cursor; replies bind the exact request digest and metadata revision. Current
bilateral authority, page order, continuation progress and negotiated frame
bounds are checked. These are allocation observations, not reservations or
proof that bytes are stored. The private protocol adds envelope tags **55–56**;
there is no new dependency or database migration.

The real native-session proof pages two allocations, checks their exact IDs and
quotas, rejects replay and uses the returned scope to request a capability.
Metadata tests exercise filtering, expiry, wrong authority, changed revisions and
the existing indexed query without a temporary sort. Protocol vectors independently
check canonical cursor bytes and signature/digest boundaries; transport vectors
reject substituted, undersized, unordered and stale pages.

Local dirty-tree evidence, Rust **1.98.0**, four workers:

- Protocol: **45 tests passed**; new cursor/query vectors: **2 passed**.
- Metadata allocation suite: **17 passed, 13.93 s**.
- Transport federation suite: **6 passed, 0.32 s**.
- Native daemon federation suite: **10 passed, 12.10 s**.
- Cluster federation sessions: **5 passed, 22.73 s**.
- Affected protocol/metadata/transport/daemon all-target/all-feature Clippy:
  **passed, 40.10 s**, warnings denied.

The last two suites were rerun because the previous execution handle and final
output were unavailable after resumption; no result was inferred from silence.
Clippy's oversized-test finding was resolved by separating paging/filtering from
authority/revision behaviour, retaining the shared fixture.

Still required: native grant/allocation provisioning and consumer selection,
backup execution, destination/retained-copy resolution, non-local provider routing
and independent-process restart/failure-overlap proof. Existing consensus command
tests do not establish automatic native provisioning. Task 7 remains **6 points**,
Stage 10 **93**. No fresh full integration gate, signed commit or publication is
claimed by this incremental evidence.

## Task 7 — native backup-capability dispatch

The native application dispatcher now handles the existing signed backup
capability request, not just authority pages. The same metadata-worker budget,
negotiated framing bounds, replay window and current pairing authority apply.
Issuance revalidates the complete bilateral grant/allocation and exact provider
node before signing. Expiry is the earliest of the request deadline, allocation
expiry and the five-minute capability ceiling. No capacity is reserved and no
stored-byte receipt is fabricated by this operation.

The capability MAC key is node-local process material, never sent to peers.
Restart retires outstanding permits; an exact operation retry must obtain a new
permit. Durable provider receipts are not tied to that transient key. This does
not establish native execution/restart acceptance, which is still outstanding.

The real paired-session test commits a storage grant/allocation, requests a
capability over QUIC, authenticates the exact signed reply, checks its scope,
operation and expiry, then proves replay and committed grant revocation reject
issuance. Harness timeouts are kept separate from protocol errors so silence
cannot pass as rejection. The initial successful run passed **6.52 s**, build
**12.71 s**. Initial fixture field mismatches and a missing required consumer
revision were corrected without relaxing production validation; Clippy also
caught a redundant test `Ok`/`?` wrapper, which was removed.

A further regression reproduced acceptance of a signed `1.1` request on the
native runtime's exact `1.0` session (**1.52 s** failing run, build **19.75 s**).
The native handshake offer and application gate now share one exact version
constant, rejecting a different minor version before metadata preparation.
Final dirty-tree checks on Rust **1.98.0**, four workers:

- Cluster/daemon all-target/all-feature warning-denied Clippy: **passed 13.57 s**.
- All **10 daemon federation-filtered tests passed 12.07 s**, build **15.19 s**,
  including the native capability/version/limits/replay/revocation flow.
- All **5 cluster federation-session tests passed 27.39 s**, build **12.01 s**,
  including signed backup byte operations, identity rotation and disconnected
  file-edit reconciliation. These are in-process real-network proofs, not the
  outstanding independently launched-daemon acceptance.
- NVM-selected Node **26.8.1** documentation formatting and `git diff --check`
  passed. No full workspace gate was run for this incremental feature slice.

Still open: allocation-route discovery, backup execution/byte dispatch, native
destination resolution, retained-copy routing, non-local provider nodes and
multi-process delivery/restart/failure overlap. Task 7 stays **6 points**; Stage
10 stays **93**. There is no new dependency, wire tag or persisted schema.
Signing remains blocked, the full integration gate has not been rerun, and no
publication is authorised.

## Task 7 — native application-stream dispatch

Live native federation sessions now own application-stream dispatch, initially
for the existing signed authority fetch/page exchange. The lifecycle attaches
the dispatcher to authenticated connections reached through either handshake
direction. Unsupported application families still fail closed; this does not
claim that native backup capability or byte delivery is complete.

Stream acceptance and kind parsing are separate so a stalled prefix/control
frame cannot serialise all requests on its connection. Idle connections hold no
application permit. A CPU-derived metadata-worker budget is separate from the
bounded asynchronous stream budget (eight stream slots per metadata worker).
Metadata readers are opened lazily and reused up to that worker budget; neither
their pool guard nor the shared replay guard is held during database/network IO.
Control exchanges have a ten-second monotonic ceiling and honour an earlier
signed request deadline. Deadline checks bracket metadata preparation, including
when an already-ready future would otherwise complete after timeout.

The native handshake now retains negotiated bounds alongside the connection,
rather than discarding them and using local advertised maxima for application
work. Both handshake directions preserve the agreed control/data limits and
stream count. Readers, signed response preparation and writers use those bounds;
per-session request permits intersect the host-wide budget. Metadata/text item
bounds remain local decode ceilings, not peer-controlled expansions.

The cluster authority-page operation now separates authenticated preparation
from sending. Preparation reloads current authority, fences a changed complete
peer binding and validates the retained local signing/TLS identity. Native fetches
use the same bounded replay window as handshakes. Endpoint closure wakes stream
IO; the lifecycle drains and observes admitted application jobs and their blocking
metadata work instead of dropping those owners on shutdown. Outcomes contribute
to the existing bounded federation-lifecycle observations without logging records.

Current local dirty-tree evidence, Rust **1.98.0**, four build/test workers:

- All-target/all-feature daemon compilation passed **48.19 s**.
- The extended native paired-session proof passed **6.54 s**, build **30.65 s**.
  It obtains a signed authority record through the production dispatcher while
  another control stream is stalled, verifies exact relationship direction/state,
  rejects replay on a separate stream, then exercises committed revocation and
  orderly shutdown. This is real pinned HTTPS/QUIC and independent consensus
  authorities within the test process, not two independently launched daemons.
- The expanded proof additionally verifies a fresh signed fetch succeeds after
  replay rejection and returns unchanged exact records. It passed **6.55 s**,
  build **24.49 s**. All **5 cluster federation-session tests passed in 21.45 s**,
  build **22.61 s**, including signed backup operations, peer/local identity
  rotation and disconnected edit reconciliation.
- Affected transport/cluster/daemon all-target/all-feature warning-denied Clippy
  passed **32.99 s**; after formatting and explicit control-deadline checks it
  passed **13.72 s**. No new external dependency, wire tag, persisted schema,
  generated public API or private-key export was introduced.
- The final deadline regression passed **6.53 s**, build **15.37 s**; the five
  federation-filtered transport unit tests passed **0.32 s**, build **8.89 s**.
- An asymmetric real-session regression reproduced the discarded-limit defect:
  an 8,193-byte control length below the server's local 64 KiB ceiling but above
  the negotiated 8 KiB ceiling stalled awaiting payload instead of rejecting
  admission. The pre-fix test failed **3.61 s**, build **21.01 s**, at the explicit
  two-second rejection deadline. With negotiated limits retained it passed
  **6.54 s**, build **21.64 s**. Both handshake participants assert exactly
  8 KiB control, 16 KiB data and three streams; normal signed page fetches remain
  successful. Daemon all-target/all-feature warning-denied Clippy passed
  **19.23 s**. The subsequent ten-test daemon federation filter passed
  **12.20 s**, build **13.23 s**, including exact reset of an excess fourth
  stream while the three negotiated slots are occupied. This is not a backup
  byte-transfer proof.

Next: complete authenticated allocation-route discovery, then attach backup
capability/execution dispatch and the consumer resolver to the allocated provider
owner. Retained copies, non-local provider nodes and failure overlap must be
handled explicitly; a remote swarm ID alone is not an allocation route.
The signed backup library proof below does not close that integration gap.
Task 7 remains **6 points**, Stage 10 **93 points**. The latest full gate remains
the failed run recorded below; a new completed candidate needs fresh integration
evidence before merge. Signing authentication remains uncleared and publication
remains prohibited.

## Task 7 — signed backup transfer and current authority

Federation envelope tags **50–54** now carry explicit backup capability request,
capability, execution, readiness and result records. The wire path binds the
complete operation and scope, uses domain-separated Ed25519 signatures and
retains the provider-only BLAKE3 MAC. The consumer authenticates the provider's
response against its exact request; a result cannot bypass successful readiness.
The [wire contract](protocol.md#signed-backup-conversation) records the domains,
canonical encodings, byte-stream phases and remaining native integration.

The capability service composes signature/mTLS admission with the same current
metadata query used by the allocation budget. It rechecks MAC, node, target,
relationship, grant/allocation revisions and lifetime for execution, including
read, verify and delete. A recovery-only allocation can serve encrypted backup
recovery without granting ordinary file/shard reads. Issuance itself reserves no
bytes; the composed provider admits capacity before inviting an upload.

The execution adapter runs synchronously inside an owned blocking worker and
awaits bounded QUIC frames through that worker's runtime handle. It rechecks
authority during transfer and before the result. Stores require exact length,
digest and clean upload FIN before exposing end-of-input to the provider. Exact
retries can avoid another disk write but still validate their incoming stream.
Reads measure the actual outgoing bytes; all actions check exact provider
receipts before signing success. Network waits also have a monotonic deadline,
independent of an injected clock advancing. No provider folder becomes a normal
user-visible filesystem, and no private key or plaintext is sent to the partner.

Current local dirty-tree evidence, Rust **1.98.0**, four build/test workers:

- The preceding wire/transport continuation passed **5 protocol tests**, including
  all four actions through all five phases, malformed fields and the aggregate
  nested-field budget. The real QUIC conversation test passed **0.32 s**. Its
  correctly signed mismatched result, replay, premature result and expired permit
  vectors are transport evidence, not provider MAC verification.
- The new metadata-backed capability test passed **1.59 s**, build **37.03 s**;
  after adding consumer-side response authentication it passed **1.71 s**, build
  **3.74 s**. It proves all four actions, exact wire/contract/MAC round trips,
  tampered MAC rejection and committed revocation fencing requests which were
  authenticated before revocation. Issuance leaves no capacity reservation.
- The first real namespaced directory-provider/QUIC execution test passed
  **1.39 s**, build **13.64 s**. The expanded pair of capability/execution tests
  passed **4.10 s**, build **3.45 s**. They cover store, exact retry, exact
  downloaded bytes, verification, deletion confirmed by a local absence check,
  short upload, wrong digest, excess bytes and a full provider rejecting ready
  before any upload frame is sent. This provider-level network proof is not a
  pair of independently running native daemons or a host power-loss test. The
  network fixture uses deterministic opaque payload bytes; cryptographic container
  creation/decryption remains covered by the existing backup-crate proofs, not
  inferred from this byte-transfer test.
- Resumed Clippy found a needless owned issuance argument; it now borrows its
  inputs. The larger federation envelope also exposed three existing test-future
  size violations; the named content-layout/history proof boundaries are boxed
  without raising limits. The new tests' unit-pattern and copy lint findings
  were corrected. A missing fixture module path and QUIC read-error conversion
  were corrected before the execution proof passed; no runtime test failure was
  hidden by changing an expected successful outcome or retrying unchanged code.
- The execution proof adds only a dev-dependency on the existing workspace
  `meshspan-backup` crate; no external package/version or runtime feature changed.
  A fresh `pnpm check:dependency-update` under NVM **Node 26.8.1 / pnpm 11.19.0**
  **failed in 814.10 s**. Advisories, generated drift, embedded web bundle, Rust
  formatting, workspace-wide warning-denied Rust lint (**78.31 s**), both
  dependency licence checks, web format/lint/typecheck, tooling and web tests
  (**5.68 s**) passed. All **415 daemon unit tests passed in 30.72 s**; headless
  acceptance finished **26 passed, 3 failed, 8 ignored in 117.63 s**. The Rust
  lane's reported **709.34 s** includes blocked output collection from orphaned
  test daemons, not 709 seconds of executing headless test cases.
- The failures were `backup_worker_recovers_lost_source_and_completes_original_generation`
  (TLS export closed after headers declaring **2,777,805 bytes**, with zero body
  bytes), `exporter_policy_survives_restart_and_reaches_another_gateway`
  (`completed > 0`) and
  `private_node_renewal_runs_automatically_and_survives_restart_and_join`
  (`reconciliation_cycles > 0`). Backup failure state is retained in the reported
  temporary fixture `.tmpUXMuRC`. These functional failures remain open; a focused
  passing retry alone must not erase them.
- After parent termination, three surviving test daemons held inherited stderr
  open. Their temporary-state identities were checked before sending SIGTERM to
  only those three processes; no test-state directory was deleted. The metrics
  and private-certificate tests now use the existing `ProcessCleanup` owner so
  assertion unwinding cannot bypass child termination/reaping. This is a cleanup
  correction, not a fix for either metrics assertion.
- Review exposed an identity-rotation gap separate from grant revocation. The
  new regression first **failed in 0.69 s**: a retired remote signing/TLS identity
  still authorised a previously authenticated request. Admission now reloads and
  compares the complete peer and local identity bindings as well as allocation
  authority. The expanded **3 backup tests passed in 13.78 s**, build **14.25 s**,
  covering rotation on either side. Affected transport/cluster warning-denied
  all-target/all-feature Clippy passed **23.13 s**. These post-gate edits require
  fresh integration evidence before merge; the full gate remains failed.
- The metrics failure reproduced in isolation **before** changing its completion
  check: **7.62 s**, build **48.84 s**. The previous startup correction intentionally
  opened listeners before maintenance, but metrics/diagnostics asserted a positive
  cycle count on the first readable sample. They now await an actual positive
  observation within the existing deadline; null/zero are not treated as success,
  malformed responses still fail, and reads never trigger maintenance. Metrics
  restart/peer acceptance then passed **11.92 s**, build **4.38 s**; private
  certificate renewal/restart/join passed **15.60 s**, cached build **0.13 s**.
  Affected all-target/all-feature warning-denied daemon Clippy passed **8.17 s**.
  This resolves the diagnosed startup-observation assumptions, not the backup
  export failure or the need for a fresh full gate.
- The remaining backup failure also reproduced in its focused real-process test
  (**10.76 s**, build **3.97 s**). A phase annotation now establishes that the
  exact original bytes export successfully **before restart**, but the first
  export immediately **after restart** returns headers and no body. Failure
  state is retained at `.tmpBLtQza`; its test also now owns cleanup during panic.
  The next diagnosis is the startup provider-availability boundary: the native
  export preparation reads persisted metadata, while the provider catalogue is
  initially empty and populated by later storage work. Confirm that boundary
  before changing admission. Do not accept the premature headers as success,
  add an arbitrary sleep, retry incomplete byte streams as if nothing escaped,
  or weaken exact recovered-byte equality.
  Final affected daemon Clippy passed **3.01 s** after adding the phase evidence
  and cleanup owner. Rust formatting, document formatting and whitespace checks
  pass. No test daemon or Cargo process remains running from these checks.

- The restart export failure is now resolved at the provider lifecycle boundary.
  Local backup routes are restored before return-scan/repair admission, and export
  waits for that first scan through a separate deadline-bounded completion signal.
  Listener startup remains independent; no maintenance or authority mutex is held
  while waiting, and the backup worker's own catalogue snapshot remains non-blocking.
  The unchanged real-process recovery test now passes **11.68 s**, build **45.91 s**,
  returning the exact original encrypted container on its first post-restart export.
  Two startup/snapshot regressions pass **0.58 s**, build **35.48 s**; they cover
  expired waits, retained completion and admission while the real maintenance mutex
  is held. Affected daemon all-target/all-feature warning-denied Clippy passes
  **20.21 s**. No download retry, fixed startup sleep or relaxed byte assertion was
  added. The earlier failed full gate still requires a fresh integration run.

- A fresh NVM dependency-update gate finished **failed in 1,000.19 s** (Rust
  test lane **930.97 s**). Advisory, generation, embedded bundle, formatting,
  workspace Rust lint (**42.38 s**), both licence checks, web lint/typecheck,
  tooling and web tests (**5.06 s**) passed. All **416 daemon unit tests passed
  in 30.65 s**, and all **29 enabled headless tests passed in 119.46 s** with
  **8 ignored**. This integration run confirms the three preceding headless
  failures are resolved; no orphan test daemons remained from that suite.
  The later metadata suite finished **450 passed, 1 failed in 280.18 s**:
  `schema_86_indexes_existing_publication_without_changing_its_checkpoint` rewound
  migration history to 85 while retaining later tables, then failed creating
  `node_certificate_rotations` again. Subsequent workspace suites were not proved
  by this failed run. It is not a fast or successful full gate.
- The HTTP-01 migration fixture now creates the genuine schema-85 structure
  with the existing historical migration helper, projects seeded ACME state into
  its historical columns, restores its original triggers, and checks SQLite and
  foreign-key integrity before upgrading. No production migration changed. The
  first focused run exposed a seed-copy collision with default fault-group rows
  (**3 passed, 2 failed in 3.50 s**); replacing only those temporary fixture-table
  contents resolved it. All **5 HTTP-01 projection/migration tests passed in
  3.58 s**, build **4.45 s**, including exact checkpoint preservation and corrupt
  migration rollback. No ever-growing reverse-migration drop list, ignored test
  or relaxed expected output was introduced. A fresh full gate is still required
  before integration; do not repeat it unchanged for each small edit.
  Affected all-target/all-feature warning-denied metadata Clippy passed **10.80 s**.

This supersedes the earlier missing signed-wire and provider-execution statements,
not the native delivery gap. Task 7 remains **6 points**, Stage 10 **93 points**.
Next, compose the current paired session with bounded application-stream dispatch,
an allocation/target-bound provider owner and the native destination resolver;
then prove automatic backup/recovery between real daemon processes, interruption,
restart and remote failure overlap. Reuse these tested contracts rather than
inventing shard identities or reopening a provider per request. Use dedicated
metadata reader ownership for long-lived IO: never hold the shared session-authority
mutex or the storage-maintenance runtime mutex across a network transfer. Quorum-derived
clock composition and post-expiry pairing recovery remain explicit gaps.

The native wiring review identifies three concrete composition requirements:

- `ClusterBackupProviderResolver` currently resolves only registered targets.
  A `FederatedMesh` binding supplies a remote mesh and generation, not the exact
  provider allocation required by the signed capability request. Existing
  `FederationAuthorityPageSource` publishes relationship/grant records, not
  allocation routes. Complete authenticated route discovery before calling the
  capability service; do not invent allocation IDs or assume both swarms share
  a metadata database. Retained copy references must still resolve after restart.
- The provider catalogue must retain one exclusive directory-provider owner per
  physical destination namespace, composing the allocation budget with the
  already-open target's physical budget. Permission-revision changes must refresh
  authority without renaming retained bytes; an in-flight older owner cannot be
  bypassed by reopening its files. Network IO must not hold the catalogue guard.
- The existing lifecycle currently owns handshakes, not application streams.
  Add bounded, observed application workers and dedicated metadata-reader
  ownership, then connect dispatch and the consumer resolver. Reuse the existing
  signed backup execution adapter and prove native delivery, rather than adding
  another parallel byte protocol or counting the library proof as daemon support.

Signing authentication has not been cleared. No unsigned commit, repeated signing
attempt, push, release, tag, package/image publication or GitHub Actions was run.

## Task 7 — backup authority and provider composition

The backup boundary now uses exact store/read/verify/delete requests rather than
inventing shard identities or admitting a foreign swarm as a local node.
Capabilities bind the complete request, both swarm identities, relationship,
allocation/grant, target/node, revisions, deadline, nonce and expiry. Independent
canonical-byte fixtures cover the request digest, and mutation vectors cover the
provider-only MAC. MACs do not replace signed federation messages or current
authority checks.

Local schema **14** adds backup capacity to the existing shard allocation counters.
Exact retries charge once; holds cannot disappear because a timer expires. The
provider budget checks live allocation authority before every reservation and
composes with the actual folder's physical capacity policy. If the second budget
rejects admission, no upload bytes are read and the first hold remains until
exclusive provider recovery proves absence. Recovery merges bounded pages from
both budgets, rather than losing a hold which exists in only one database.

Logical consumer destinations map to allocation-isolated physical namespaces.
Logical generation and physical target generation remain distinct; permission
revision changes do not rename the stored objects. Store/read/verify/delete
receipts are checked before returning the consumer identity. The namespace
adapter is not remote authorisation; the still-unimplemented federation dispatcher
must enforce current authority for every action.

Local dirty-tree evidence, using Rust **1.98.0**, four build/test workers and
`--all-features`; no dependency was added:

- The earlier foundation checks passed **32 contract tests (0.00 s)**,
  **12 allocation tests** and **49 database tests (9.53 s)**. Contract/metadata
  warning-denied all-target/all-feature Clippy passed **19.57 s** after the
  namespace fixtures. These results cover the preceding contract/schema changes,
  not native transport.
- Three new real directory-provider/allocation tests passed **1.82 s**, build
  **16.48 s**: exact bytes/replay/reopen, admission denial after committed
  revocation, short-upload recovery after allocation expiry, quota exhaustion
  and destination/revision substitution. Reads/retirement after revocation in
  that test are explicitly trusted local provider-owner calls, not permitted
  remote operations.
- The combined consensus-created allocation plus actual folder-journal/provider
  proof passed **0.51 s**, build **57.43 s**. Its expanded run through logical
  namespace translation and eight existing folder-capacity regressions passed
  **9 tests in 0.95 s**, build **21.31 s**. The full folder rejects the second
  upload before reading its source, recovery settles only the unused allocation
  hold, and exact deletion makes both budgets available again.
- The expanded allocation suite passed **15 tests in 12.70 s**, build **12.53 s**;
  all backup-crate tests passed **16 in 0.91 s**, build **10.09 s**. These include
  encrypted backup restore, wrong-recipient and corruption regressions.
- Affected backup/metadata/daemon all-target/all-feature warning-denied Clippy
  passed **46.40 s** before the final additional logical-receipt assertions.
  The final combined test, now checking logical store/verify/delete receipts and
  exact deletion replay, passed **0.50 s**, build **11.99 s**; final affected
  Clippy passed **10.49 s**. Rust formatting and whitespace checks pass.

This supersedes the earlier statement that provider composition was unimplemented.
It **does not** complete task 7: signed federation wire capability issuance and
dispatch, native provider resolution/delivery, process restart and remote
failure-overlap acceptance still remain. Stage 10 remains **93 points**, task 7
**6 points**. The last full local gate remains failed as recorded below; these
focused results are not a substitute for a fresh integration gate. Signing
authentication has not been cleared, so no unsigned commit or repeated signing
attempt was made. No push, release, tag, publication or GitHub Actions was run.

## Task 7 — native QUIC session lifecycle

### Follow-up: metadata forwarding during leader election

The retained failover state led to a concrete discovery failure: a live voter
could reply `NotLeader` just before winning the election, but the forwarding
gateway tried it only once. An unreachable voter could then occupy the entire
30-second discovery deadline. The final local-only fallback did not discover a
different surviving leader.

Discovery now owns one sequential request per candidate and retries only
`Unavailable`, with 250 ms exponential backoff capped at one second inside the
existing overall deadline. The local authority participates too, so promotion
of the forwarding gateway does not wait for dead peers. Each retry keeps the
same operation, command, request digest and deadline. Terminal errors are not
retried; success still requires the exact locally applied durable receipt.
Owned pending tasks are cancelled and drained. No consensus/quorum rule or
wire/schema format changed.

- The controlled newly-elected-peer/dead-peer regression failed before the fix
  with a **2.00 s timeout**, then the six forwarding tests passed in **0.51 s**
  (build **15.39 s**). Coverage includes terminal rejection and cancellation of
  the pending peer before discovery returns.
- The previously failing real three-daemon notification/credential failover
  proof passed in **20.18 s** (build **26.84 s**) after killing the original
  node, committing user creation through a survivor and delivering the exact
  notification retry with replicated credentials. Its timeout was not changed.
- Affected all-target/all-feature warning-denied daemon Clippy passed in
  **13.28 s**. The fresh full dependency-update gate under NVM
  **Node 26.8.1 / pnpm 11.19.0** failed in **417.10 s**. Advisory, static and
  licence lanes passed, as did all **414 daemon unit tests (29.87 s)** and the
  web lane (**5.29 s**). Headless acceptance finished **27 passed, 2 failed,
  8 ignored in 122.74 s**; notification failover passed. The other failures were
  an isolated peer restart which never reopened HTTPS and an update observation
  whose live sequence advanced **2 → 3** between pre/post-restart reads.
- The new restart failure differs from the earlier immutable-history deadlock.
  The retained peer has only the common namespace commit: it had not accepted
  the office write yet. Composition started storage maintenance before building
  routes; those routes synchronously borrowed the target mutex which maintenance
  could hold while waiting on the offline authority. Maintenance now starts
  after listeners bind, and existing filesystem opening precedes return-scan
  admission. These changes do not grant disconnected consensus authority.
- Update preparation legitimately preserves staged progress while incrementing
  the rollout sequence. The test now allows only the existing staged/prepared
  sequence transition, compares every other rollout field exactly and rechecks
  the unchanged staging evidence after restart. It does not accept arbitrary
  rollout changes. Affected Clippy passes (**13.83 s**). Both real namespace
  restart/reconciliation tests pass (**21.68 s**, build **23.30 s**), including
  starting the isolated peer before accepting its office write. The real signed
  executable staging/restart proof passes (**35.60 s**, cached build **0.13 s**).
  The full gate remains failed; these are focused post-fix results, not a
  replacement claim of a complete passing workspace gate.

Stage 10 remains **93 points**; task 7 remains partial. This correction closes
the diagnosed forwarding defect, not the remaining cross-swarm backup work.
No commit or push was attempted: the previously reported signing authentication
blocker has not been cleared. Publication remains prohibited.

Next implementation work is task 7's native cross-swarm backup delivery. Existing
same-swarm backup streams assume local replicated backup-run authority; existing
federated storage permits/ledgers bind shard identities. Neither is a licence to
treat an external swarm as an enrolled node or a metadata backup as a fabricated
file/shard. Compose explicit backup-object authority with the existing bilateral
grant/allocation and encrypted streaming/provider boundaries. Preserve exact
receipts, quota ownership and current revocation checks. Run focused local checks
while completing that coherent feature; a new full gate remains required before
integration, not after each edit.

The resumed work composes a federation-only UDP endpoint at the actual HTTPS
address/port with committed, node-hosted pairing records and locally protected
identity material. Admission starts closed; trust refresh does not rebind the
socket. A separate `meshspan-federation/1` ALPN prevents within-swarm protocol
connections from crossing this boundary. Shared replay admission does not hold
its lock over network IO. One owner handles bounded concurrent handshakes,
periodic retry, trust withdrawal, connection retirement and shutdown. Startup
configuration and SMB task ownership have separate focused operations; the
configuration is boxed to avoid inflating the enclosing startup future.

Local evidence on the dirty working tree:

- Real pairing/QUIC proof first passed **2 tests in 1.94 s**. It establishes
  reciprocal peers, reconnects after a closed connection, then rejects a revoked
  relationship. The expanded production-lifecycle proof passed **2 tests in
  7.03 s**, build **16.49 s**: no manual dial or refresh is used for reconnection
  and revocation; the peer receives the exact authority-change closure, and the
  worker's cancellation/result is observed. This remains independent in-process
  consensus/SQLite with real HTTPS/QUIC, not two OS daemon processes.
- Dedicated transport checks passed **2 tests in 0.19 s**, build **7.91 s**:
  starts closed, replaceable trust without rebinding, and rejection of the node
  ALPN with the exact TLS `no_application_protocol` error despite a trusted
  certificate. Existing live connections are deliberately retired by the domain
  owner, not silently by TLS configuration replacement.
- Warning-denied all-target/all-feature Clippy for contracts, transport,
  metadata, cluster and daemon passed in **36.11 s** before the metric-bound
  correction. It caught conditional simplifications, startup function size and
  future size; the fixes did not suppress or relax the lints.
- The all-family metrics regression failed with `InvalidInput`: eight newly
  observed federation lifecycle families exceeded the old 242-family limit.
  Rust and API history bounds now admit exactly **250** families; OpenAPI and
  client validators were regenerated. All **25 observation tests passed in
  0.03 s**, including full exporter/history encoding and exact federation counter
  text. The broader daemon federation regression passed **8 tests in 11.70 s**.
- The daemon now directly references the already-used workspace Quinn package.
  `Cargo.lock` adds only that dependency edge; no package version or feature
  declaration changed. Post-change licence checks pass. Final all-target,
  all-feature warning-denied Clippy (including API contract) passed in **55.77 s**;
  Rust formatting, TypeScript and ESLint pass.
- Shared cluster regressions passed **2 tests in 16.81 s**, build **41.90 s**,
  covering metadata-authorised session rotation/revocation and signed disconnected
  edit reconciliation. These library proofs do not imply native data dispatch.
- The full local dependency-update gate **failed in 783.55 s**. Both advisory
  scans and all static/tooling lanes passed. All **410 daemon unit tests passed
  in 29.77 s**, but headless acceptance had **27 passed, 2 failed, 8 ignored**
  in **125.54 s**: disconnected reconciliation returned 404 for acknowledged
  `home.txt`, and update staging found two evidence files rather than the
  test's expected one. The update assertion panicked before cleanup, leaving
  test daemon PID 34884 in this run's process group 31173 holding inherited
  stderr open. After verifying that provenance, it was terminated with SIGTERM;
  this recovered the failing result, not a passing retry. The Rust lane's
  **674.38 s** includes that orphaned-pipe wait.
- The web lane had **234 passed, 1 failed**: the generated metrics test retained
  the old 242-family boundary. Its fixture is being corrected to 250. Review
  also identified retry starvation when the earliest unreachable peers consume
  all handshake slots; a deterministic ordering regression is being added.
  These failures are unresolved until their focused evidence is recorded.
- Follow-up corrections: the retry-order regression first reproduced starvation
  (peers 1/2 selected again instead of 3/4), then passed after rotating from the
  last attempted peer, **0.00 s**, build **15.08 s**. The corrected metric client
  fixture passed **4 tests, 21 ms; runner 364 ms**.
- The executable update test now selects the unique staging report by its
  schema/binding instead of assuming the shared evidence directory contains one
  file. Coordination legitimately writes separate evidence there. A scope-owned
  process guard also reaps this test's children during assertion unwinding.
  The real signed-executable/restart proof passed **37.88 s**, build **34.43 s**.
- Read-only inspection of the retained reconciliation databases established an
  ordering deadlock: the peer had the common, home and office commits, but its
  replicated head already named the root's fourth, merged commit. Delivery of
  the earlier home commit was refused because that newer immutable head was
  absent; the sender's durable cursor therefore never reached the merge. Receipt
  now acknowledges retained immutable history without activating a live head
  when current authority history is missing. Corrupt/wrong-volume history still
  fails closed and restore ancestry remains required for adoption. The new
  missing-versus-corrupt root regression passed **0.07 s**. The real-process
  reconciliation/restart proof then passed **31.66 s** without changing its
  timeouts. Final affected Clippy passed **34.89 s**. All **235 web tests passed
  in 4.73 s**, and ESLint passes.
- The broader headless suite finished **28 passed, 1 failed, 8 ignored in
  125.36 s**. Both corrected workflows pass, but
  `notification_credentials_reach_joined_gateways_and_deliver_after_source_loss`
  failed: both survivors durably recorded the same term-2 vote, with log/applied
  index 43 from term 1, while the attempted metadata write remained uncommitted
  and returned 503. The three private fixture directories were retained. This
  failure has not been diagnosed or dismissed as a flake; no timeout was changed
  and no blind retry was run. The failed full gate has not been replaced by a
  successful full gate. Next validation work is the retained failover state,
  followed by a focused proof and then the remaining integration gate.

Task 7 remains partial: native backup grant/capability dispatch, cross-swarm
provider delivery, post-expiry pairing recovery, automatic lifecycle restart and
remote failure overlap still need implementation/proof. Identity chaining and
rollover remain task 3; quorum-derived time is not proved here. Scope closed:
task 7 **8 → 6 points**, Stage 10 **95 → 93**; Stage 11 remains **126**.
The full local integration gate is not green. No commit, push, signing
retry, GitHub Actions, release or publication has run. The previous 1Password
signing blocker has not been re-tested; publication remains prohibited.

## Task 7 — two-swarm pairing over pinned HTTPS

The owner resumed work. Native `POST /api/latest/federation/pairings/accept`
and `POST /api/latest/admin/federation/connections` now compose invitation
consumption, public peer retention and separate relationship approval. Both
operations are generated from Rust into OpenAPI, TypeScript, Fetch and Zod.
The receiving endpoint admits invitation authority before reading its body.
The initiating endpoint admits current manager authority before its body and
again after network IO. It retains an immutable public intent in partition
schema **96**, command version **11**, kind **119**, before contacting its peer;
no invitation secret or private identity key enters that record. This is not
background connection recovery or a data grant.

Local evidence on the dirty working tree:

- Acceptance router/consensus checks passed, including exact retained peers,
  separate preparation/approval revisions, malformed signature/certificate
  rejection, changed-retry rejection, reopening and no node enrolment.
  Expanded federation run: **3 API-contract tests, 0.02 s; 6 daemon tests,
  4.11 s; build 7.99 s**. These preceded outbound intent integration.
- Two independent swarm authorities through the real TLS 1.3 listener and
  certificate-pinned client: **2 focused tests passed, 1.91 s**, build **61 s**.
  The first remote approval is committed but its usable reply is withheld.
  Local state retains intent revision 2 with no local relationship, while the
  remote relationship is active. Reopening the local service and retrying commits
  local preparation/approval at revisions 3/4. Another retry returns identical
  response bytes. Peers match reciprocally; changed intent causes no additional
  network request; each swarm still has exactly one node. A separate test proves
  unauthenticated rejection before oversized-body parsing. This is in-process
  independent consensus/SQLite and real TLS, not separate OS daemon processes.
- Generated client: **6 tests passed, 20 ms; runner 422 ms**. TypeScript and
  ESLint pass. The acceptance credential replaces an existing client API key and
  omits cookies; local connection uses normal manager/CSRF authentication.
- Compile errors in new test imports and a missing public record export were
  corrected before passing runs. Lint caught crowded test scenario grouping;
  acceptance and invitation administration now have separate suites. The TLS
  test's redundant `drop` of a copyable shutdown result was corrected after its
  first passing run. No lint suppression was added.
- The caller's operation ID now resolves only to final local relationship
  approval. Internal intent/preparation IDs are separate, and a repeated client
  operation cannot switch invitations before a remote side effect. The TLS test
  asserts no public success receipt after the withheld reply and final receipt
  kind/revision after retry. Retained destination, pin, inviter and deadline are
  compared against the presented invitation again before network IO.
- Broader focused regression: **62 metadata tests, 34.91 s; 8 daemon tests,
  6.54 s; 3 API tests, 0.02 s**, build **24.99 s**. After the receipt correction,
  final affected regression: **8 daemon tests, 6.72 s; 3 API tests, 0.01 s**,
  build **15.54 s**. All-target/all-feature warning-denied Clippy for metadata,
  daemon and API contract passed in **9.58 s**. Test responsibilities now
  distinguish interrupted-state verification from successful mutual approval.
- Final generated-contract drift, workspace Rust formatting and `git diff --check`
  pass. No new dependency was added. The next task 7 implementation is the
  dedicated QUIC endpoint/session lifecycle using these committed paired identities,
  then native other-swarm backup provider composition. Existing library-level
  session/exchange tests do not establish that daemon lifecycle.

Task 7 is still partial: native QUIC endpoint/session lifecycle, identity
chaining/rotation, post-expiry recovery and cross-swarm backup delivery are not
proved or complete. Remaining estimate: **task 7: 8 points; Stage 10: 95;
Stage 11: 126**. No full local gate, commit, push, signing retry, GitHub Actions,
release or publication has run in this resumed work. Signing was previously
blocked by 1Password authentication; that status has not been re-tested.

## Task 7 — connection integration paused at the owner's request

The owner asked to wrap up current work before continuing. The previous turn
was progress: native invitation issuance/cancellation was implemented and tested.
This turn adds an **unfinished, unverified connection candidate**; it does not
close task 7 or establish that two swarms can connect.

Work retained in the existing dirty branch:

- Canonical signed public peer records (`MSFP` version 1), a domain-separated
  pairing proof and the existing Ed25519 dependency behind a node-local signing
  capability. No new dependency was added.
- Protected, atomically stored federation signing/TLS material under the local
  secrets directory. The provisional 90-day identity lifetime still needs the
  required rotation lifecycle; this is not completed PKI integration.
- Partition schema **95**, metadata command version **10**, kind **118**:
  preparation retains both signed peers and creates a horizontal relationship
  proposal in the same transaction as invitation consumption. Approval remains
  a separate existing relationship revision. Consumed invitations cannot be
  cancelled or reissued. This new behaviour still needs focused tests.
- Rust connection/acceptance DTOs and bounded validators, plus optional
  authorisation headers on the existing certificate-pinned HTTPS client.
  These DTOs are **not yet registered in OpenAPI or connected to HTTP handlers**.

Next implementation work, when resumed: complete the local manager connection
operation and remote invitation-authenticated acceptance handler, retain exact
retry context, perform separate approval on both sides, then compose the actual
dedicated QUIC endpoint/session lifecycle and remote backup provider. The current
candidate does not implement native governance pairing, automatic identity
rotation, background connection recovery or other-swarm backup delivery. Do not
count those existing library components as daemon integration.

The first compile found a missing borrow and a private canonical-digest helper;
both were fixed. The wrap-up compile found missing static lifetimes on schema
validator references and an inapplicable `const` constructor; fixed before the
final check. `cargo check -p meshspan-daemon` passes in **10.20 s**, with **two
dead-code warnings** for identity fields awaiting connection integration. Those
warnings remain visible; no lint suppression was added. Rust formatting and
`git diff --check` pass. No new connection test,
full gate, signing retry, commit, push, release or publication has run. Previous
invitation test evidence below predates these changes and is not proof of the
new connection candidate. Task 7 remains **13 points**, Stage 10 **100 points**,
Stage 11 **126 points**.

## Task 7 — native federation invitation API

The daemon now composes authenticated native issuance/cancellation routes into
its HTTPS router. Invitation material is distinct from node join grants, pins
the issuing HTTPS origin/certificate and expires after at most one hour. A
domain-separated protected-root key reproduces exact committed retries without
persisting the secret or moving node identity keys. Public issuance evidence,
withdrawal and receipts use partition schema **94**, metadata command version
**9**, kinds **116/117**. Both endpoints reject unauthenticated callers before
reading bodies and recheck current manager authority before committing.

Local evidence on the working tree:

- Domain material tests: **3 passed, 0.00 s**, build **3.35 s**. Round-trip,
  expiry boundaries, deterministic retries, node-grant separation and malformed
  material are covered.
- Native API through real consensus and protected local keys: **2 passed,
  1.55 s**, incremental build **53.46 s**. Assertions include exact revisions,
  verifier persistence, no implicit relationship, `no-store`, unchanged retries,
  changed-intent rejection, cancellation and reopened service/database state.
  These use the actual HTTP router and reactor, not an independent process/TLS
  handshake. The first narrower test passed in **0.73 s**, build **81 s**.
- All-target/all-feature Clippy for domain, metadata, API contract and daemon
  passed in **88 s**. The initial compile found an incorrect API error enum name;
  it was corrected before the passing tests, with no lint suppression.

- Rust request/response contract tests: **2 passed, 0.02 s**, build **20.52 s**.
  Unknown fields, coercion, unsafe origin shape, lifetime bounds, missing/null
  revision and invalid outgoing receipts reject.
- NVM-default API generation and generated-drift verification passed. The
  generated Fetch/TypeScript/Zod client exposes both operations. Focused web
  tests: **3 passed, 20 ms**, runner **357 ms**. TypeScript, ESLint and focused
  Prettier pass. The first client assertion wrongly depended on JSON key order;
  it now compares the exact decoded request fields. ESLint identified a redundant
  optional chain and the crowded administration route collector; federation
  route discovery now has its own responsibility alongside the other families.
- The focused invitation command-codec test passed **1 test, 0.00 s**, build
  **49.72 s**, checking exact kind bytes, field preservation and malformed wire.
  Final metadata all-target/all-feature Clippy passed in **51.14 s**; Rust
  formatting and `git diff --check` pass. No broad test gate was repeated.

This is not a federation connection:
consuming material, mutual identity approval, native session lifecycle and
cross-swarm backup delivery still need implementation. Task 7 remains **13
points**, Stage 10 **100 points**, Stage 11 **126 points**. No full gate,
signing retry, commit, push, GitHub Actions or publication ran. Signing remains
blocked by the previously reported 1Password authentication failure.

Next task 7 integration is the actual two-swarm acceptance/session flow. Keep
code possession scoped to pairing, atomically consume it in committed state,
retain exact retry/outcome evidence and keep federation identity keys node-local.
The existing relationship event validator requires proposal and approval at
distinct increasing committed revisions; do not weaken it by combining those
events at one revision. Existing cluster federation transport/provider machinery
must be composed without admitting external swarms as local consensus members.

## Task 7 — federation consensus command integration

Inspection of native destination delivery found that the daemon's provider
resolver supports registered targets only. Federation's library-level authority,
Quinn sessions and storage providers exist, but native pairing/runtime composition
is absent. The existing 25 federation commands also lacked consensus codec
support; direct repository tests had not exposed that integration gap.

All 25 now have bounded canonical consensus encoding/decoding, grouped by their
existing responsibilities: relationships, grants, local assignments/activation,
storage allocations, signed actors, recovery succession and mutation admission/
quarantine. Private command forwarding advances to version 8 (kinds 91–115).
The grant-definition codec shares the retained record's grant/policy encoding
without inventing lifecycle evidence. Database schemas are unchanged; no new
dependency or authorisation shortcut was introduced.

Local evidence on the dirty working tree:

- All metadata federation tests: **65 passed, 34.50 s**, build **6.06 s**.
  New command fixtures preserve every typed field, command kind, original actor
  versus relay, optional activation fields, signed evidence and recovery choices;
  truncation/trailing bytes reject. A manually assembled relationship vector
  checks exact bytes. Existing authority/quota/recovery tests remain passing.
- Final metadata/daemon all-target/all-feature Clippy: **22.21 s**. Earlier
  failures were test type complexity/needless ownership, a large borrowed
  acknowledgement and missing semicolons; fixed without weakening lint rules.
- Final real consensus relationship and storage-grant/allocation lifecycle
  tests: **2 passed, 0.97 s**, build **21.68 s**. They check committed revisions,
  exact request digests, current records, narrowing, revocation and replay. This
  exercises the first 12 command kinds through the reactor, not a direct SQL
  apply. The other 13 have wire coverage and existing state-machine coverage,
  not an additional real-reactor lifecycle claim.
- An earlier overly specific test filter selected zero tests; it is not evidence.
  The subsequent 65-test run includes the actual grant-record round-trip test.
- After the final borrowed-argument lint fix, the focused wire suite passes:
  **7 tests, 0.02 s**, build **9.40 s**. Formatting and `git diff --check` pass.

Task 7 remains **13 points**, Stage 10 **100 points**: native pairing, persisted
endpoint/identity composition, cross-swarm backup delivery and installed external
provider delivery remain. Unknown failure overlap remains unknown. This is a
required integration prerequisite, not completed remote backup functionality.
No full workspace gate, signing retry, commit, push, release or publication ran.

## Task 9 — local abandoned-staging cleanup

The existing maintenance worker now reclaims local staging only after reading a
committed incomplete run in the matching partition, no remaining active claim,
no admitted backup and an exact local ownership record. Active, recorded and
unknown runs are not cleanup candidates. Provider objects are not touched.

An indexed backup-ID seek reads at most 16 records per worker pass. The retained
cursor wraps after the last page; a local file-removal failure retains its journal
entry for retry and does not starve later entries. Cleanup removes the private file,
synchronises its directory, then removes the exact journal record, using the
existing preparation service. It adds no consensus writes or database migration.

Focused evidence on the working tree:

- Staging page order, continuation after deletion, reopen and invalid bounds,
  alongside the existing ownership/replay checks: **3 tests, 0.15 s**, build
  **7.64 s**. The first compile caught an incorrect `usize` SQL parameter;
  the bounded limit now converts explicitly to the signed database domain.
- Production preparation, real encrypted file, live-run preservation, committed
  abandonment, physical removal, journal reopen, replay and fresh backup claim
  through real consensus: **1 test, 1.07 s**, build **37.90 s**.
- Metadata/daemon all-target/all-feature Clippy: **25.11 s**; formatting passes.
- On the final runtime tree, the real-daemon recorded-backup source-loss,
  exact-ciphertext recovery, completion and restart workflow passes:
  **1 test, 12.12 s**, build **31.81 s**. Admitted ciphertext retains its
  original identity and remains exportable after restart.
- Before the cleanup addition, the three-real-daemon original-node-loss
  regression passed in **42.71 s**, build **12.44 s**. This is node-loss evidence,
  not a test of remote abandoned-object retirement.

This completes the local cleanup part of task 9's current slice; no additional
point reduction is claimed. Task 9 remains **4 points**, Stage 10 **100 points**.
Remote orphan retirement, lost admission evidence and whole-process unadmitted
worker takeover remain. No full workspace gate, signing retry, commit, push or
publication ran.

## Task 9 — unrecorded-generation abandonment

An expired producer which never admitted its encrypted container is now fenced by
an explicit replicated command. The transition requires the exact expired claim,
a claimed run and no admitted backup; renewal, replacement and admission races
reject a stale attempt. In one transaction it supersedes the claim, marks the run
incomplete and makes a fresh occurrence due immediately. The next bounded worker
pass allocates a new backup identity. Recorded generations still recover their
original ciphertext and identity. This does not authorise deletion of provider
objects or local staging.

Private metadata forwarding advances to command version 7, adding canonical kind 90. Existing canonical command layouts and database schemas are unchanged.

The real-consensus dispatcher test exposed a separate existing runtime defect:
random claim fences used the full unsigned 64-bit range despite being persisted
as positive SQLite integers. A deterministic high-bit entropy fixture reproduced
the rejected initial claim in **0.37 s**. Generated fences now use 63 random bits,
with zero still rejected. No fixture-only workaround or validation relaxation was
used. The initial OS-random failures were **0.36 s** and **0.46 s**.

Focused local evidence on the current working tree:

- Real production dispatcher with consensus: expired unadmitted attempt becomes
  incomplete; a distinct next occurrence is successfully claimed: **1 test,
  0.42 s**, build **9.33 s**.
- Dispatcher lifecycle, competing worker, recorded takeover and bounds:
  **3 tests, 0.00 s**.
- Canonical command, exact claim/expiry rejection, reopen/replay, next occurrence
  and rollback at all four transaction fault points: **7 tests, 3.90 s**, build
  **10.32 s**.
- Metadata/daemon all-target/all-feature Clippy: **24.96 s**.

Task 9 **5 → 4 points**, Stage 10 **101 → 100**. Physical orphan retirement,
lost admission evidence and real process-loss takeover remain open. This is not
stage closure or full-workspace acceptance. Signed commits/pushes remain blocked
by the previously reported signing authentication; no retry or publication ran.

## Snapshot workflow prerequisite audit and backup-recovery caller correction

Inspection of the snapshot workflow found a missing access boundary, not merely
missing HTTP routes. COW-007 and `copy-on-write.md` require a current explicit
snapshot-level grant in addition to active authentication and captured historical
permissions. The implemented `PermissionScope` has only global, volume and object
variants; the persisted `permission_grants` scope constraint likewise accepts
only those three. The daemon/OpenAPI inventory has no user snapshot routes.
Existing snapshot commands, root retention and restore-history transfer therefore
do not prove a complete user-facing snapshot workflow. Ordinary file permissions
or system-manager status must not silently substitute for explicit snapshot access.

The owner has been asked asynchronously whether to proceed with the broader
snapshot-scoped permission/schema change before exposing historical files. No
snapshot route or weaker permission fallback was added while that decision is
pending. This is an existing requirement gap; the overall goal remains open.

While that decision is pending, the real backup-source-loss workflow exposed one
missed request fixture from the typed destination API change: its second-copy
configuration still sent flat `target_id`/`target_generation` fields. The process
test failed with HTTP 400 in **8.18 s**; private failure state is retained at
`/var/folders/xk/vb061tws5wv3z_00cskjqtwr0000gn/T/.tmpodvWK7`.
The fixture now sends the same discriminated provider and exact generation as
the public contract. Inspection of the remaining real-process destination callers
found no further old request shape. The unchanged recovery assertions then passed:
exact admitted ciphertext is recovered, the same backup generation completes,
and encrypted export remains identical after daemon restart: **1 test, 13.68 s**,
build **3.54 s**. The affected headless-process Clippy target passes in **2.77 s**;
formatting and diff checks pass. No validation, assertion or timeout was relaxed.

No task points are removed for correcting this missed test caller. Stage 10
remains **101 points**; snapshot integration needs its scope/estimate reconciled
when the permission-model decision is settled. No signing retry, commit, push,
release, image publication or GitHub Actions run was performed.

## Task 22 — strong-publication completion after background convergence

Strong publication previously required both a successful foreground head CAS and
a current head carrying that foreground metadata operation. A background
coordinator could commit the exact same publication first, leaving a legitimate
foreground request stuck at `StrongBarrierPending`. A later committed head could
also make confirmation of an earlier publication fail.

The metadata reader now confirms an exact retained publication transition using
the existing unique namespace-commit index, after validating the retained history.
The predicate binds volume, predecessor, namespace commit, root revision and
original publication operation/request/result digests. It neither accepts a mere
matching location nor treats a current head with different evidence as equivalent.

The native strong-completion boundary checks that evidence before proposing a
new transition, after an uncertain/rejected proposal and after a successful
receipt. Existing content-policy verification still happens before this boundary.
Confirmation does not write another transition, rewind a newer head or demand a
fresh metadata operation for an already committed publication. Actual successful
command receipts remain checked for operation, request digest, entity, revision
and nonzero result digest. The authority-completion responsibility is separated
from content publication/IO so the same production operation can be exercised
directly against real consensus; no test-only timing hook or new dependency was
introduced. Schema and wire formats are unchanged.

Focused local evidence on the working tree:

- The controlled background-first test failed before the fix with
  `StrongBarrierPending`: **0.36 s**, build **23.57 s**.
- Exact history confirmation, different publisher, later head, reopen,
  substituted identity/predecessor/root/digests, corrupt history and existing
  transaction rollback tests: **6 tests, 3.48 s**, build **4.26 s**.
- Production completion against real consensus: background-first, foreground
  publication of the next head, retry of the earlier publication without a new
  revision and exact rejection of a substituted root: **1 test, 0.36 s**, build
  **12.20 s**. This controls publisher ordering; it is not every race schedule.
- Real HTTPS strong upload, exact acknowledgement fields, file readback and
  daemon restart: **1 test, 8.12 s**, build **19.46 s**.
- Metadata/daemon all-target/all-feature Clippy: **9.18 s** on the final tree;
  the preceding implementation pass took **26.08 s**. Formatting/diff checks pass.

Task 22 **8 → 7 points**, Stage 10 **102 → 101**. Retired-history recovery,
transitive source loss, user-facing snapshot/restore completion and all-scope
rolling availability remain; uninterrupted update is still disabled. No full
workspace gate, signing retry, commit, push or publication was performed.

## Task 7 — typed destination configuration and retained-provider pause

The native backup-destination API now accepts the existing discriminated provider
binding (registered target, federated swarm or installed component) plus its exact
generation. The daemon converts each variant into the existing replicated command;
current metadata checks still reject absent providers/relationships. Configuration
is not a transfer authorisation or evidence of independent protection.

The generated OpenAPI, TypeScript, Fetch and Zod contracts agree on that closed
request shape. The existing folder selector still selects registered folders;
pause/resume controls now preserve all three retained provider variants instead
of converting or hiding non-folder destinations. An existing unchanged destination
can be paused after provider replacement or relationship revocation; creation and
resumption still require current binding eligibility. Rebinding and retired
destination edits remain rejected. This is a pre-alpha request-shape change,
not a persistence migration or a compatibility alias.

Focused local evidence on the working tree:

- Rust boundary variants, malformed requests and response checks: **3 tests, 0.02 s**.
- Real consensus-backed configuration/paging/replay, unknown provider rejection,
  HTTP rejection and shared-capacity selection: **5 tests, 0.44 s** (build **19.60 s**).
- Replaced-provider pause regression failed with `InvalidCommand` before the fix
  (**0.30 s**); the focused metadata selection then passed **6 tests, 2.39 s**.
- Generated client/schema and existing panel workflows: **15 tests, 1.75 s**.
  TypeScript checking and strict ESLint pass. The enlarged test group was split
  by request-schema versus client-transport responsibility; no lint was weakened.
- API/metadata/daemon all-target/all-feature Clippy: **32.21 s**.
- Real clean-machine CLI/HTTPS setup, backup controls and node-enrolment workflow:
  **1 test, 20.75 s** (build **28.52 s**).

Task 7 remains **13 points**, Stage 10 **102**: the runtime resolver still only
delivers to registered targets in this swarm. Other-swarm transport, installed
external provider activation and current remote failure evidence remain required.
No claim of working federated backup delivery is made. No full workspace gate,
signing retry, commit, push, release or publication was performed for this slice.

## Task 22 — snapshot-restore history transfer

Canonical namespace-history format **5** now carries whole-volume restore
evidence without pretending it is an ordinary mutation or a federation grant.
The receipt binds the snapshot, its exact source commit/root, the replaced head,
the new commit, actor/time and original request/result digests. Local mutation
format 1, federated format 3 and merge format 4 are unchanged.

The restored snapshot commit is an immutable dependency, not an extra causal
parent. Both bounded export paths include it even when it belongs to a different
branch; transactional import waits for it, validates the source root and retains
the original unactivated receipt. Missing dependencies roll back the whole import.
Source and destination can reopen between every page. Exact retries and subsequent
file operations keep the restored history usable.

Native gateway adoption now checks received lineage against its locally applied,
replicated converged head. A prepared restore, or a later mutation built on one,
cannot become an authorised restore just because another gateway sent it.
Immutable delivery retention remains distinct from head adoption. Exact already-
committed heads are checked directly; other candidates use the existing causal
planner, which rejects pending uncommitted restores. No new consensus algorithm,
dependency or schema migration was introduced.

Focused local evidence on the working tree:

- The new round-trip regression failed with `InvalidInput` before format support
  (**0.08 s**, build **18.89 s**), confirming the explicit unsupported path.
- Flat/reopened import, exact receipt/re-export, corrupt canonical rejection,
  two-record paged transfer with a non-ancestor snapshot, continued directory work
  and missing-dependency atomic rollback: **3 tests, 2.37 s** (build **3.97 s**).
- Existing snapshot prepare/activate/substitution/transaction-fault cases:
  **2 tests, 0.28 s**.
- Existing canonical/bounded/paged/import history selection: **15 tests, 8.37 s**.
- Real two-daemon pre-enrolment delivery and disconnected writes/reconnect/restart:
  **2 tests, 31.44 s** (build **42.76 s**).
- Filesystem/cluster/daemon all-target/all-feature Clippy: **40.99 s**.

The paged fixture initially passed the same ID as both converged and eligible
frontier heads; the planner correctly rejected that duplicate. The fixture now
checks continued work against the committed restore. Gateway adoption similarly
handles exact equality directly rather than constructing an invalid frontier.
No planner validation or timeout was weakened.

Task 22 **9 → 8 points**, Stage 10 **103 → 102**. This closes transfer capability,
not a real user-facing snapshot/restore workflow, retirement/compaction recovery,
transitive source loss, the controlled strong-publication race or all-scope
rolling availability proof. Uninterrupted update remains disabled. Stage-wide
hardening and full integration gates still follow remaining functional work.
No signing retry, commit, push, release or publication was performed.

## Task 19 — certificate and retained inventory measurements

The existing storage worker now samples selected public-certificate validity and
exact-generation gateway installation acknowledgements, retained backup run
states, retained update states and selected rollout checkpoint counts. Inventories
advance in indexed 16-row pages without keeping transactions open between ticks.
Independent pass ages and failure counters preserve last-complete evidence;
unknown categories are omitted rather than reported healthy or empty. Scanning
does not make inventory counts an atomic cross-page snapshot or current protection
proof. Certificate validity uses the host clock, explicitly not quorum-agreed time.
The [catalogue](metrics.md#certificate-backup-and-update-inventory) documents all
28 additional fixed families and their interpretation.

Focused local evidence on the working tree:

- Certificate validity boundaries, invalid delivery counts and failed-pass sample
  preservation, alongside existing filtered inventory tests: **14 tests, 0.42 s**.
- Complete 242-family runtime/exporter/history response: **1 test, 0.02 s**.
- Real daemon, public certificate/backup APIs and authenticated exporter across
  process restart: **1 test, 20.58 s** (incremental build **3.61 s**).
- Contracts/API/metadata/daemon all-target/all-feature Clippy: **21.60 s**.
- Rust-generated API and Zod updated together; focused web metric-boundary tests:
  **4 tests, 0.43 s**; TypeScript and strict ESLint passed under NVM.

The first process fixture failed in **19.81 s** because it demanded a selected
public certificate without provisioning one. Read-only retained-state inspection
confirmed zero issuances. It now provisions through the existing real API and
uses the returned trust anchor; no production behaviour or timeout was relaxed.
The failed fixture remains at `.tmpQd7Tis` in the system temporary directory.
Lint corrections make the small observation value explicitly Copy and retain one
exhaustive declarative name/help table with a narrowly documented length exception.
No arbitrary logic was extracted or lint ceiling changed.

Task 19 **5 → 3 points**, Stage 10 **105 → 103**. Runtime resources, clock
uncertainty and assembled-stage acceptance remain. No full gate, signing retry,
commit, push or publication is claimed; the existing signing blocker remains.

## Task 19 — SMB authentication rejection measurements

The production SMB authentication-error classifier now records rejected
credential proofs before returning the unchanged protocol failure. It does not
count unavailable authority, internal verification failures, malformed handshake
packets or successful logins as rejected credentials. The non-waiting counter
does not change dispatch counts and carries no user/credential labels. The
existing exporter and bounded local history expose
`meshspan_v1_smb_authentication_rejections_total`.

The catalogue/history bound is now **214** families. Rust generated OpenAPI and
Zod were regenerated together. The complete-inventory regression caught a stale
startup count that omitted the two existing HTTPS rejection families, then
caught the old history limit; the explicit inventory and API bound now include
all named families. Generated validation accepts 214 and rejects 215, rather
than weakening the bound. The real SMB fixture initially used `ls` on an empty
share, which reports `NT_STATUS_NO_SUCH_FILE`; its successful-login control now
uses `pwd`, keeping this proof specific to authentication.

Focused evidence:

- Classification preserves all three protocol outcomes, counts two explicit
  credential rejections, leaves dispatch counts unchanged and exports exact
  counter text: **1 test, <0.01 s**.
- Full runtime catalogue, history and response validation: **1 test, 0.04 s**.
- Real embedded daemon plus external SMB 3.1.1 client: bad credential counted
  exactly once, successful authentication unchanged, retained exporter after
  process restart with counter reset: **1 test, 7.51 s** (build **3.60 s**).
- Metrics/notification clients, panels and contract parity: **37 tests, 1.02 s**;
  web TypeScript and strict ESLint passed under NVM.

This closes **6 → 5 points** for task 19, Stage 10 **106 → 105**. Certificate
coverage, retained backup/update inventory, resources, clock uncertainty and
assembled-stage acceptance remain. No dependency or licence changed. The
initial affected Rust lint identified the composed entry future crossing its
stack-size tripwire; the process-lifetime appliance future is now boxed at the
executable boundary, without extracting lifecycle logic or relaxing the lint.
Final contracts/API/daemon all-target/all-feature Clippy passed in **3.77 s**.
The combined four-case real-daemon notification suite passed with four test
workers in **47.99 s** (build **4.60 s**) after the executable-boundary change.
Rust formatting, strict web lint, TypeScript and document/diff checks passed.
No full workspace or publication claim is made.

## Tasks 2/21 — complete notification transport and gateway integration

The existing public notification configuration now has real-daemon SMTP proof
for both implicit TLS and STARTTLS. Two isolated tests run in parallel, submit
the shared encrypted settings through HTTPS, authenticate to the local relay,
check the exact redacted event and Message-ID, and require a durable accepted
outcome: **2 tests, 5.14 s** (build **20.68 s**).

A three-daemon proof configures credentials before either additional gateway
joins, waits for all three voters, kills the configuring node and delivers from
the surviving mesh. The authenticated receiver rejects the first attempt;
the retry retains identical event/delivery identity and commits accepted attempt
two. This passed in **47.02 s** (build **4.61 s**), demonstrating actual use of
redistributed settings rather than merely inspecting recipient envelopes.

The existing isolated manual-DNS process lifecycle now configures a notification
channel restricted to manual-DNS events. It checks all four committed phases,
one deliberate transient rejection, exact duplicate payload, four distinct
delivery identities and durable acceptance after restart. It passed in
**14.41 s**; the existing Cloudflare and webhook process cases also passed in
**18.50/18.42 s**, concurrently in separate offline Linux networks. The offline
Linux build took **47.92 s**. Docker tag lookup failed before execution; the
runner then used the inspected local immutable image ID. No image was pulled
or published, and no public CA/DNS service was contacted.

Affected all-target/all-feature daemon Clippy passed in **3.03 s**. No production
dependency, API or licence changed. Task 21 decreases **3 → 1 points**, Stage 10
**108 → 106**: its remaining point is the assembled-stage verification, not a
missing delivery transport. Task 2's notification integration dependency is now
implemented; its final assembled renewal acceptance remains explicit. Live-CA
proof stays separately open as task 5. No full workspace gate or release is
claimed, and the previously reported signing blocker remains.

## Task 22 — automatic disconnected-write convergence

The daemon now owns a durable convergence frontier and restart-stable attempts
(branch schema **44**). Complete received history is retained for onward
delivery even when its head diverges from the local connector branch. One
bounded volume step prepares immutable reconciliation, then proposes the exact
root through the existing authoritative metadata compare-and-swap. Lost replies
resume the saved attempt; a superseded base retains pending branch work. No
local merge alone claims global convergence or permits an uninterrupted update.

The real two-daemon test acknowledges a common file, kills the peer while the
source writes `home.txt`, then kills the source while the peer writes
`office.txt`. Reconnecting and subsequently restarting both daemons returns all
three exact file contents from both HTTPS gateways without manual intervention.
It passed in **31.35 s**. This is process-outage/divergent-branch evidence, not a
physical network partition or a one-hour isolation proof.

Earlier failed runs exposed three concrete integration defects: relaying an
already verified content layout attempted a different source-bound import;
relayed authoritative heads duplicated the reconciliation frontier; and two
reconcilers assigned different actor/time bytes to the same plan-derived object
IDs. Layout acceptance now revalidates the existing exact volume/publication,
included ancestry is pruned before planning, and generated immutable objects
derive attribution from the original mutation. The outer merge receipt still
records its coordinator and attempt time. This changes pre-alpha merge creation;
existing stored objects are not rewritten.

Focused local evidence on the current working tree:

- Independent reconcilers with different actors/times produce identical
  immutable records and cross-import their merges: **1 test, 0.24 s**.
- Frozen convergence attempts, relayed-current-head regression and restart
  replay: **1 test, 0.19 s**.
- Existing real strong-publication/create/restart workflow: **1 test, 7.95 s**.
- Filesystem, metadata, cluster and daemon all-target/all-feature Clippy with
  warnings denied: **19.06 s** after correcting three needless value parameters.

Task 22 decreases **11 → 9 points**, Stage 10 **110 → 108**. Snapshot-restore
history, retired-history catch-up/compaction, transitive source-loss recovery
and all-scope update readiness remain. The existing strong test passes, but
coordinator-versus-foreground strong publication races still need controlled
stage-integration coverage; that test alone does not prove every interleaving.
No full workspace gate, Stage 11 completion, commit/push or publication is
claimed. Signing remains blocked by the previously reported authentication.

## Task 22 — merge-history transfer and continued file work

The existing transfer codec accepted only single-parent mutation commits, so a
locally computed merge could not be sent to another gateway. Canonical format
**4** now carries multi-parent merge evidence through the same bounded pages and
immutable-object transfers. Local/federated mutation formats remain **1/3**.
Import verifies the commit/result identities and ordered parents, persists the
merge and its receipt atomically, supports exact replay, and does not advance
any branch or authoritative metadata head. A merge is not a new signed
federation mutation and cannot supply that mutation's authority/digest.

The filesystem root-selection boundary now handles both mutation and merge
roots. Single-parent mutation receipts retain their existing verification;
head reads, branch adoption/forking and subsequent namespace mutations use the
verified root independently of parent count. This avoids representing a merge
as a fictitious ordinary mutation or recursively traversing mutation intents
just to read its root.

Focused local evidence:

- The existing two-store convergence test now transfers the merge through
  paged export/import rather than independently applying it on the receiver.
  It reopens stores between pages, rejects an altered merge record, checks
  exact receive replay and re-export/import, verifies unchanged live heads,
  and resolves the same receipt/root after restart. It then adopts the merge,
  creates another directory, restarts again and verifies the new entry/head
  and complete exportable history. Final run: **1 test, 2.37 s**.
- Existing history/codec/receive regressions: **16 tests, 8.42 s**.
- Existing federation mutation/admission regressions: **5 tests, 0.97 s**.
- Cluster convergence consumer: **1 test, 0.27 s** (build **36.50 s**).
- Existing real two-daemon pre-enrolment replay/key/read regression passed in
  **12.12 s** (build **43.33 s**) after the shared filesystem changes. This checks
  exact gateway bytes across restarts, not automatic divergent daemon merging.
- Filesystem/cluster/daemon all-target, all-feature Clippy passed with warnings
  denied in **35.39 s**. The initial lint run identified enum-size and identity
  naming findings; optional federation acknowledgements now allocate only when
  present, while the root identities retain the repository's descriptive field
  names under a narrowly explained naming exception.
- Rust formatting, edited-document Prettier under NVM and `git diff --check`
  passed. No generated public API or schema migration changed in this slice.

The first history regression exposed an unintended error-category change for
corrupt commit digests; import again reports `Corrupt`, and the unchanged test
passes. An intermediate new test did not compile because it treated an exact
directory-entry result as an option; it now checks the exact revision identity.

Stage 10 remains **110 points**, task 22 **11**: this closes merge transport and
continued namespace work, not automatic authoritative convergence in the
daemon. That coordinator, snapshot-restore history transfer, retired-history
catch-up/compaction, transitive source-loss recovery and complete update workload
readiness remain required. Uninterrupted restart remains disabled. No full
workspace gate or Stage 11 completion is claimed. Signing remains blocked by
the previously reported 1Password authentication failure; no commit/push or
publication was attempted.

## Task 22 — durable publication replay and historical gateway keys

Source-branch publication no longer depends on an unowned task with a finite
retry count. Branch schema **43** journals published head references in the
head's own transaction, backfills reachable pre-existing history, and stores
independent peer delivery cursors. The cycle-owned sender performs bounded
requests, drains its workers on shutdown and retains failed work for retry.
Only the exact operation and durable result digest advance a cursor. Delivery
order is not consensus order; receiver ancestry checks still prevent rewinding.

The real two-daemon proof initially failed in **26.87 seconds**: namespace
listing/stat worked, but content reads returned HTTP 500. Retained metadata
confirmed that activation redistributed cluster secrets but omitted existing
volume keys. The corrected activation path adds envelopes to every retained
volume-key generation for current gateway/recovery recipients. It preserves
the original ciphertext, key generation and existing envelopes. The new
audited `ExtendVolumeKeyRecipients` command has distinct canonical identity,
checks current recipients and rejects ciphertext/envelope substitution.
Storage-only nodes receive no volume-key envelope. Metadata command version is
now **6**; no new partition schema or dependency was needed.

The unchanged process proof then passed in **13.88 seconds** and, after the
sender's bounded failure backoff and codec ownership adjustment, **12.61
seconds** (final build **24.55 s**). It uploads before any peer exists, kills and
restarts the source, enrols a new peer, verifies listing/stat and exact range/full
bytes through that peer, then kills/restarts both daemons and reads again.
No manual namespace import or key installation is used.

Focused local evidence on this working tree:

- Recipient rewrapping: **1 test, 0.01 s**, including wrong owner, substituted
  ciphertext and generation rejection.
- Metadata secret/codec lane: **9 tests, 5.38 s**; includes additive recipients,
  unchanged historical ciphertext, exact replay and unregistered-key refusal.
  The first new fixture used the same Raft position for an operation retry and
  failed `InvalidLogPosition`; it now uses the next committed position, as the
  existing state-machine contract requires.
- Durable delivery/reopen/index selection: **1 test, 0.09 s**.
- Publication fault rollback, including the delivery journal: **1 test, 0.38 s**.
- Existing-schema migration and delivery backfill: **1 test, 0.07 s**.
- Affected daemon/filesystem/metadata/secret-envelope all-target, all-feature
  Clippy passed with warnings denied in **26.03 s**. Initial lint findings were
  corrected by placing secret-command encoding in its owning codec module and
  namespace-worker composition beside filesystem construction, not raising limits.
  Final affected Clippy passed again in **20.12 s**; Rust formatting, edited
  document formatting and `git diff --check` passed. No full workspace gate ran.

Task 22 **12 → 11 points**, Stage 10 **111 → 110**. This closes source-owned
durable replay and late-gateway historical-key delivery, not all workload
coverage. Divergent-head reconciliation, retired-history catch-up/compaction,
transitive replay after original-source loss, all-scope readiness and the final
handoff fence remain required. Uninterrupted restart is still disabled. This is
focused feature evidence, not a full stage/workspace gate. Signing remains
blocked by the previously reported 1Password authentication failure; no new
commit/push, release, tag, image/package publication or GitHub Actions run is
claimed.

## Task 22 — authenticated local-content observations

The private readiness response now carries the update worker's optional local
scan observation separately from the executable report. The shared projection
holds no database or provider locks, and serving a peer request never starts a
scan. It omits observations that no longer match the active rollout, candidate
node/incarnation, preparation sequence/barrier and source metadata revision.
Completed scans retain their original observation time rather than acquiring a
fresh timestamp merely because another peer asks. Unknown states and invalid
identity, position or time bindings are rejected by the wire boundary.

The protocol lane passed **3 tests in under 0.01 seconds** (build **32.89 s**).
The exact-preparation/shared-state unit passed in **under 0.01 seconds** (build
**13.90 s**); an earlier incorrectly named filter selected zero tests and was
corrected, not counted as evidence. The real two-daemon test passed in **34.04
seconds** (build **92 s**): an enrolled peer obtained the correct empty-catalogue
scan and candidate binding over mTLS/QUIC, while restart count stayed zero.
The previous real single-copy test covers actual stored-content refusal; the
empty-catalogue peer test does not substitute for that provider behaviour.
Final affected protocol/daemon all-target/all-feature Clippy passed with warnings
denied in **28.56 seconds**, after placing the status owner's test module after
its implementation. Rust formatting and diff checks passed. The full integration
gate has not been rerun for this intermediate composition.

The additive private response field is documented in [protocol.md](protocol.md#update-readiness-observations).
It is historical local progress, not mesh-wide scope completeness, a publication
fence or a restart grant. Task 22 remains **12 points**, Stage 10 **111**; the
all-scope coordinator and final handoff are still required. No dependency,
database-schema, public API, release or publication change was made.

## Task 22 — daemon-owned uninterrupted preparation

The existing update distribution worker now owns local-content preparation for
uninterrupted rollouts. The coordinator admits `Preparing` separately from
`Restarting`. It pages topology to exclude every storage target belonging to the
selected node, walks logical volumes, and reconstructs ciphertext using global
survivors and each required complete-local cell. Eventual cells do not become
required cells. The same catalogue connection retains its original change fence
across volume transitions; concurrent catalogue or metadata changes invalidate
the pass. Provider handles are refreshed between worker ticks.

Work stays on the existing owned blocking worker, with bounded topology pages
and stripe quanta rather than an async-executor scan. A single replaced,
owner-only `update-workload.json` records its exact rollout, node/incarnation,
preparation sequence/barrier, source revision and local progress. It explicitly
states `restart_authorised: false`; startup never restores it as fresh evidence.
It is a local diagnostic observation, not the mesh-wide restart receipt or a new
public API. There are no dependency, database-schema or private-wire changes.

Five filesystem availability regressions pass in **4.69 seconds**, after a
**4.41-second incremental build**. They cover exact survivor/cell selection,
provider loss/return, retained publications with optional debt, refusal to skip
unfinished volumes, and a later volume retaining the fence over earlier ones.
The new real-daemon single-copy test also passed: it creates a volume, uploads
bytes through HTTPS, selects a signed local candidate without interruption
consent, observes preparation fail for the exact volume with its sole target
excluded, and reads the unchanged bytes from the still-running daemon.

The accompanying existing two-node automatic replacement test failed in the
first combined run (**44.38 seconds**): one node had a durable installation
selection and remained `Restarting` without a verified receipt before the
fixture deadline. State was retained at `.tmpgeI9D2` and `.tmpi84gaG`; both
repositories reached log position 41/term 3. Executable-identity and authenticated
readiness diagnostics established that the selected image ran, both daemons had
bound listeners and caught-up metadata, and no installation error was returned.
The final diagnostic fixture retained an actual verified receipt **15.24 seconds
after restart admission**, just outside the test's 15-second no-progress window.
It had published its durable installation selection during that interval, but
the test did not count this intermediate progress. The test now recognises each
node/rollout-bound selection once, retaining the same 15-second no-progress
deadline and a finite maximum of four milestones per node. It still requires
both verified receipts, exact process images and cold-launch recovery. Temporary
production failure instrumentation was removed; failure-only identity/readiness
diagnostics remain in the test.

Both process scenarios then passed together in **82.95 seconds**, after a
**24.89-second build**. These are real process/cold-launch acceptance timings,
not the fast storage-test lane or a throughput benchmark. Clippy subsequently
requested an equivalent `is_none_or` expression in the new test assertion; that
test-only simplification does not change the deadline or admission behaviour.
Final affected all-target/all-feature Clippy passed with warnings denied in
**5.20 seconds**; Rust formatting and `git diff --check` also passed. The full
integration gate has not been rerun for this intermediate feature composition.

Uninterrupted `Restarting` remains disabled. Complete remote/federated/delegated
scope discovery, namespace/policy/key/gateway coverage, freshness at final
handoff and the integrated rolling-availability proof are still required.
The global metadata revision is deliberately conservative at this intermediate
boundary; it is not a scalable scope-specific publication fence. This daemon
composition closes one estimated point: task 22 **13 → 12**, Stage 10 **112 → 111**.
The task and stage remain open for the integration listed above.
No release, tag, publication, GitHub Actions or signing retry was performed.

## Task 22 — incremental whole-volume survivor verification

The filesystem now provides an owned `VolumeReadAvailabilityProbe` for the update
worker's data-verification phase. It walks the volume's committed-publication
index rather than assuming that a joined stripe query proves every publication
was present. Each step checks at most one stripe, reconstructing verified
ciphertext in the selected global survivors and independently in every required
cell. Empty publications consume a step; unsupported unprotected formats and
inconsistent stored chunk counts refuse verification. Optional replication debt
does not hide an acknowledged publication from the scan.

The probe owns its catalogue connection and fixed target sets so a worker can
retain it between ticks without borrowing itself. It holds no SQL transaction
over provider IO. SQLite data-version checks before/after verification and when
reading progress invalidate the whole scan after another connection commits,
including after a previously completed scan. Provider failure does not advance
the stripe cursor. Reopening begins from zero; no persisted completion is treated
as current evidence. This is a local catalogue observation, not restart authority,
decryption-key availability or proof of complete mesh-wide scope discovery.

Three real-provider availability tests passed in **2.31 seconds** after an
**11.60-second incremental build**. The new scenario verifies two publications,
loses a required-cell survivor while the global survivors remain sufficient,
checks that progress stays unchanged, resumes after return, then adds a third
publication through another connection. Both completed-progress access and the
next step refuse the stale scan; a reopened probe checks all three publications.
Existing selected-survivor and optional-replica-debt tests also passed.

An initial focused run passed in **1.83 seconds**, followed by a Clippy rejection
of explicitly dropping the borrowed probe. The final ownership model removes
that lifetime-only wrapper and supports retention by the eventual worker without
an allowance. Affected all-target/all-feature Clippy then passed in **23.10
seconds**. No migration, dependency or wire format changed.

Task 22 remains **13 points**, Stage 10 **112**. The next integration must bind
these local observations to authoritative workload/locality and delegated-group
inventories, then fence changes at the actual daemon handoff. The current
coordinator still deliberately does not restart uninterrupted rollouts. Removing
that guard before the scope and handoff fences exist would not implement the
accepted availability guarantee. No daemon-update acceptance, complete local
gate, signing retry or publication was performed for this component.

## Task 19 — HTTPS access rejection measurements

The existing dispatch observer now distinguishes returned 401 and 403 responses
from ordinary responses, server failures and cancellation. Two fixed counters
reach the authenticated exporter and its existing local history. They contain
no user, credential, endpoint or path labels. Their meaning is deliberately
response-based: missing credentials and disabled-exporter refusal count; TLS
admission and concealed-resource 404 responses do not. This is not an audit log
or a count of unique sign-in attempts. No dependency or persistence change was
needed; generated history validation now accommodates the 213-family catalogue.

Three focused dispatch tests passed in **0.02 seconds**, including unchanged
response bytes/status and cancellation. The existing real two-gateway exporter
workflow passed in **21.37 seconds**, now asserting exact increases of one 401
and one 403 through its public HTTPS controls, alongside restart, joining a
gateway and service after original-gateway loss. Four generated-client tests
passed (**1.27-second runner, 59-millisecond test bodies**) and affected ESLint
passed. Rust test builds took **1 minute 52 seconds** and **1 minute 5 seconds**;
these are compilation costs, not test execution times. Affected all-target/
all-feature Clippy passed in **1 minute 15 seconds**; rustfmt, Prettier and diff
checks passed. No complete integration gate or publication ran.

Task 19 remains **6 points**, Stage 10 **112**: SMB authentication outcomes,
certificate/backup/update inventories, process resources and clock uncertainty
still need their complete owning-component instrumentation and stage acceptance.
This focused addition does not close those categories or the stage.

## Task 27 — gateway history and backup recipient workflows

The private control runtime now owns a lazily opened namespace-history store.
Its source and receiver operations run on blocking workers, sharing a guarded
connection instead of reopening, migrating and integrity-checking the complete
SQLite database for every immutable record. Existing scope, digest and expiry
checks remain; no transaction or lock spans network IO. This addresses the
per-record cost observed in the reproducer below, without changing its deadline,
retry count or assertions. It does not implement durable announcement retry or
divergent-head reconciliation.

The unchanged real encrypted SMB 3.1.1 three-gateway test passed twice, in
**35.02** and **32.61 seconds**. It covers cross-gateway uploads, downloads,
rename and deletion, then exact reads of a file written on the surviving gateway
after killing the other two processes. This is not physical power-loss proof or
proof that a remote-only file survives the loss of its writer. Two focused shared
history tests passed in **0.14 seconds**, covering externally committed rows,
scope rejection, reopening and refusal of corrupt database bytes.

The operator workflow's backup `409` was reproduced separately in **21.63
seconds**. Its verified immutable container was captured **6.607 milliseconds
before** the joined gateway registered its wrapping key. It contained envelopes
for the original gateway and offline recovery key, not the joined gateway. A
`gateway_key` restore check cannot decrypt that pre-enrolment backup. The API now
reports that specific limitation instead of an undifferentiated verification
failure; it does not weaken cryptographic validation or copy private node keys.

The workflow now deliberately verifies the pre-enrolment backup on its original
gateway, verifies export but missing-recipient rejection on the new gateway,
requests a post-enrolment capture through the public backup-policy API, and
requires both gateways to restore the same new generation. The complete public
HTTPS operator workflow passed in **45.82 seconds**, including users, groups,
volume/grants, file bytes, diagnostics and continued access after stopping the
original gateway. Five restore-readiness and two export-route unit tests each
completed their groups in **0.28 seconds**; affected all-target/all-feature Clippy
passed. No full gate, new package, signing retry or publication was performed.

Task 27 falls **8 → 6 points**, Stage 10 **114 → 112**. Packaged Linux/macOS/mixed
acceptance remains open. These results resolve the current-tree workflow failures
below, not every historical failure or the complete stage.

## Task 27 — current-tree SMB propagation reproducer

The real three-gateway `smbclient` test was rerun on the current working tree:
`cargo test -p meshspan-daemon --test headless_process real_smb311_clients_round_trip_one_volume_through_three_gateways -- --ignored --exact --test-threads=4`.
It failed in **59.15 seconds** after a **0.41-second build**. This run's second
gateway retained the 47-byte upload, but the third gateway still returned
`not_found`. It does not resolve the earlier zero-length failure or establish
SMB acceptance. All three private test databases were retained locally.

Read-only inspection found five namespace commits on the writer and three on
each other gateway. The third gateway's import of the empty-file creation had
received its terminal history page, but still lacked **111 of 275 immutable
records** when the test stopped. **62** of those missing digests already had bytes
in completed earlier imports. The subsequent written-file head had not yet begun
import there. This establishes incomplete propagation and repeated transfer work,
not the root cause of every failure. No timeout, retry count, assertion or
implementation was changed during this diagnosis. The next investigation must
distinguish transfer cost, queued head delivery and final adoption; it must not
declare a fix solely from a passing retry.

## Tasks 24/25 — package SBOM and upstream notices

The existing local packaging command now collects the selected Cargo normal/build
closure and production web package notices, preserving source text and recording
its hash without exporting local filesystem paths. It handles nested licence
directories, checks JavaScript source identities and refuses missing texts or
notice symlinks escaping a package. It generates a CycloneDX 1.6 source-package
SBOM with the exact executable hash, Cargo dependency edges and notice hashes.
Composition remains explicitly incomplete: this is not linked-symbol evidence or
an independent audit of every vendored source. The package and container recipe
include both files; unpacked checksums cover them. No dependency was added.

The real scan found missing archive notices for `asn1-rs-impl@0.2.0`,
`solid-js@2.0.0-rc.3` and `@solidjs/web@2.0.0-rc.3`. Their notices were recovered
from the exact package source commits, bound to name/version/declaration/repository,
and compared byte-for-byte with the upstream files. The Cargo package records
commit `a20e5f7319c896737ad0f2557037817b91ad854f`; both npm manifests identify
`af6fee86e6dcfbf41869da2c607c82b1fd0939ce`. These are source-document copies, not
new runtime dependencies or alternate licence claims for MeshSpan.

The scan still refuses `unicode-casefold@0.2.0`: its crate declares alternative
licences but supplies no notice text, and its [archived upstream repository](https://github.com/lambda-fairy/unicode-casefold)
also has no licence file at inspected head
`07d0b6a32c090a6e569d3a2ac9be10af9f9790f6`. No generic copyright statement was
substituted. This is an unresolved dependency/notice issue, not a claim that the
crate's declared licence is incompatible. The newly stricter local package command
will refuse assembly until this is resolved; no complete new package is claimed.

Seven focused collection/SBOM/assembly tests passed in **0.14 seconds**, and
affected ESLint passed. A generated fixture also passed the upstream
[CycloneDX 1.6 JSON schema](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json)
using the existing Ajv dependency; that validator ignores unsupported IRI/email
formats, which this fixture does not emit. No schema or validator dependency was
vendored. The local test suite requires no network.

The final combined packaging/update-tooling run passed **all 11 tests in 0.13
seconds**, including the real Rust executable's verification of Node-signed
candidate fixtures; nothing was installed or published. The local command's
actual preflight passed Rust and JavaScript licence admission, then refused the
missing `unicode-casefold` notice **before building either panels or Rust**.

The packaging estimates remain unchanged until the real dependency issue and
candidate acceptance are resolved. No Linux package build, product container
build, full integration gate, signing retry or publication ran. The existing
local Rust container was inspected and has no musl toolchain installed.

## Task 23 — supported-schema backup restoration

Restoration now accepts a captured older schema when the existing supported
migration chain can advance the new private copy. It still verifies the source's
exact schema, bytes, identity, membership and committed position before copying.
The post-migration comparison checks the retained log position and revision, not
an equality between the old capture version and the upgraded version. Source
bytes remain unchanged. The offline report exposes both `schema_version` and
`restored_schema_version`; it does not start services or grant recovery authority.

Three real SQLite regressions cover schema 92 → 93, the encrypted-backup path and
rejection of changed migration history. The migration regression failed with
`BackupMismatch` before the fix. The final focused run passed in **4.91 seconds**;
existing restore checks passed (three selected tests in **2.02 seconds**, one
encrypted-backup test in **3.23 seconds**). The real daemon export/offline-verify/
changed-byte rejection test passed in **11.94 seconds**. Affected all-target/
all-feature Clippy and workspace rustfmt passed. No new migration, dependency or
private-wire change was introduced. These fixtures prove database restoration,
not replacement-node admission or an operational disaster-recovered swarm.

Task 23 falls **8 → 7 points**, Stage 10 **115 → 114**. Task 10 remains eight
points: recovery authority, required secret references and service admission
are still open. No full integration gate, signing retry or publication ran.

## Task 18 — replica catch-up measurements

The existing consensus observation worker now exposes remote-member count, local
apply gap and leader-local replication coverage: unknown peers, peers behind the
committed head and the largest known committed-entry gap. The core supplies its
existing current-plan match positions; collection makes no peer request, log
append or admission decision. Both stable and joint membership include learners.
Followers/candidates omit leader-only gauges; observing a step-down removes those
gauges rather than retaining a stale leader's apparent success. Unknown replicas
are not folded into a zero-gap claim. These are recorded match positions, not
fresh quorum, peer liveness or physical durability evidence.

The fixed exporter and local-history catalogue now contains 211 families, with
the Rust-authored bound propagated through generated OpenAPI, Fetch and Zod.
Twenty-four observation tests passed in **0.06 seconds** after a **2m19s build**;
twelve consensus tests passed in **17.33 seconds** after a **1m08s build**. The
three-repository test isolates one replica, commits through the remaining quorum,
observes its exact committed-entry lag, reconnects it and waits for catch-up.
This is real persistence with injected message loss, not physical network loss.
The same selected suite also passed its existing real-QUIC leader-loss proof.
Four generated-client tests, strict TypeScript and ESLint passed. Clippy found
duplicate numeric match arms; merging those equivalent patterns resolved it.
Affected all-target/all-feature Clippy then passed in **32.51 seconds**.
The real two-gateway HTTPS exporter/restart proof passed in **19.62 seconds**
after a **1m08s build**, including leader-only gauge presence, follower omission
and exact local committed-minus-applied gap.

No dependency, schema migration or private-wire change was added. Task 18 falls
**3 → 2 points**, Stage 10 **116 → 115**. It remains open for federation progress
and fresh authority evidence; the implementation
does not manufacture either from local role or recorded replica positions.
Signing remains blocked by the previously reported 1Password authentication
failure. Publication remains prohibited.

## Task 9 — recorded-generation source recovery

The normal backup worker now recovers an admitted generation when its local
staging file is missing or corrupt. It first checks remaining local bytes against
the authoritative container evidence, then considers recorded copies in bounded
pages through the existing replaceable provider interface. Paused destinations
remain readable. Unavailable or invalid copies leave a normal `Recovering`
outcome; they do not trigger a new snapshot under the old backup identity.

Recovery independently verifies the complete encrypted stream and its receipt,
uses private temporary files, rechecks backup/copy/destination authority, then
synchronises and installs the exact source before committing its local journal.
After an interrupted installation, the next pass can recover journal evidence
from the already installed exact bytes without contacting a provider. Changed
journal evidence and retired authority fail closed. Recovery needs no decryption
key, creates no replicated admission and deletes no provider object.

The coordinator retains a separate bounded source-page cursor, resumes normal
destination publication only after recovery, and reports pending recovery through
the existing worker metrics. Restore-readiness and recovery share one mapping from
the authoritative catalogue to exact encrypted/source evidence. No dependency,
database migration or new wire/public-API message was added.

Fourteen focused backup tests passed in **0.52 seconds**, including actual
encrypted providers, corruption followed by a valid next page, local-database
reopen, exact decrypted source bytes, lost journal evidence with no reachable
provider, retired records and coordinator sequencing. Three restore-readiness
regressions passed in **0.01 seconds**. Test-only type/access mistakes and lint
findings were corrected; provider provisioning is separated from encrypted-source
fixture creation by responsibility, not an arbitrary line-count extraction.
Daemon all-target/all-feature Clippy passed in **40.03 seconds**.

The real-daemon proof first passed in **20.71 seconds**, after a **64-second build**;
the final rerun passed in **15.90 seconds**, after a **7.03-second incremental
build**, with final affected Clippy passing in **5.84 seconds**.
Through real HTTPS it requires two verified copies, waits for the recorded run,
removes only that fixture's exact local staged source and observes automatic
byte-identical recovery. Adding the second destination then completes the same
backup ID; exports before and after daemon restart match the original encrypted
container exactly. Both destinations are on one host: this proves copy-count
completion and source recovery, not independent-machine protection or remote
worker takeover. No production lease was shortened to make this test fast.

Task 9 **7 → 5 points**, Stage 10 **118 → 116**. Still required: recovery and
authoritative retirement of generations which never reached replicated admission,
including lost admission evidence, plus remote-worker takeover and assembled-stage
acceptance. Signing remains blocked by the known 1Password authentication failure;
these results describe the local working tree, not a commit/push or full-stage gate.
Publication remains prohibited; no release, tag, image/package publication or
GitHub Actions run occurred.

## Task 19 — operational worker observations

The existing certificate automation, certificate installation, metadata backup and
update-preparation workers now record finite outcomes, duration and last-pass age.
The exporter and local history consume the same fixed catalogue; scrapes start no
worker, provider access or external request. Missing observations remain absent,
stopped workers become stale, and retries can count again. No identity, path,
credential or raw error is accepted by the observation interface. These are worker
passes, not unique jobs, current inventory or whole-rollout completion.

One contract test and six lifecycle-filtered daemon tests passed; all 23 runtime
observation tests subsequently passed in **0.05 seconds**. The complete-catalogue
test first caught `ResourceExhausted`: the 206-family catalogue exceeded the
exporter's old 64-KiB allowance. The Rust-authored exporter bound is now 128 KiB,
without raising ordinary JSON response limits; generated drift verification passes.
Web metric-client tests, typecheck and strict ESLint passed.

The real headless restart/folder-loss/reconnection/exact-readback proof passed in
**20.28 seconds**, after a **61-second build**. Its first run checked the update
worker before its first two-second pass; the test now waits for the actual bounded
observation condition instead of assuming another worker's readiness implies it.
No production timing or outcome was changed to satisfy that assertion. Combined
daemon/backup all-target, all-feature Clippy passed in **50.92 seconds**.

Task 19 **8 → 6 points**. Authentication rejection, expiry/delivery coverage,
retained backup/update inventory, runtime resources and clock uncertainty remain,
as does the assembled-stage acceptance pass. These are local working-tree results,
not a full-stage gate or publication.

## Task 9 — reservation-backed provider recovery

Directory backup providers now use the existing durable target reservation to
recover a published object's missing provider index. Under exclusive destination
ownership, recovery checks a regular file's exact length and complete digest,
synchronises the bytes/directory, records local inventory transactionally, then
commits the existing capacity charge. It invents neither an original operation
receipt nor replicated admission. Existing catalogue evidence is not discarded;
absence is still required before cancelling an unpublished reservation.

The real-folder regression first failed with `NotFound` in **0.10 seconds**.
It now reads exact bytes after reopening **before any upload retry**, then accepts
an exact retry without requiring the source bytes, reopens again and verifies
unchanged accounting. All eight shared-capacity cases passed in **0.54 seconds**,
including same-length corruption retaining both bytes and capacity without
admitting an index entry; all 16 backup-library tests passed in **2.17 seconds**.
The final four web metric-client tests and typecheck also passed. No dependency, database
migration, private RPC or deletion authority was added.

Task 9 **8 → 7 points**. Recovery/retirement of unadmitted generations and lost
replicated admission evidence remains required. Together with task 19, Stage 10
falls **121 → 118 points**. Signing remains blocked by the previously reported
1Password authentication failure: none of this local work is claimed committed or
pushed. No release, tag, package/image publication or GitHub Actions run occurred.

## Task 17 — independent upload reuse

The [same-volume reuse slice](stage-5-evidence.md#independent-same-volume-uploads-now-reuse-compatible-layouts)
now connects indexed plaintext discovery, current encryption/protection and live
byte verification, namespace retention reservations, durable upload-to-layout
bindings and ordinary file reads. Two independent real-folder uploads share
physical payload but retain separate file/version/creator identities and logical
byte accounting after restart. Incompatible or unavailable candidates take the
normal fresh-publication path. The first integrated proof caught and fixed a
read-routing identity mismatch; it now passes in **1.38 seconds**.

All seven protected-content tests pass in **6.11 seconds**; all 207 filesystem
library tests pass in **58.88 seconds**; affected filesystem Clippy passes in
**32.67 seconds**. These are local working-tree results, not a full-stage gate.
Branch schema 42 and content schema 12 receive explicit updater compatibility
fields. Both updater-report tests pass in **0.16 seconds**, after a **92-second
build**; daemon all-target, all-feature Clippy passes with warnings denied in
**61 seconds**. Rust formatting, the three edited evidence/task documents'
formatting and `git diff --check` also pass. No additional dependency, release,
tag or publication was made. Signing
remains blocked by the previously reported 1Password authentication failure;
this progress is local and is not claimed committed or pushed.

Task 17 **21 → 16 points**, Stage 10 **126 → 121**. Still required: remote-only
layout discovery/import, automatic terminal reservation cancellation, assembled
rights/quota/cleanup and federation acceptance, and actual savings metrics. The
pack-lifecycle acceptance gaps remain separate. Following the owner's direction,
continue remaining functional work before the assembled-stage fixing/refactoring
pass; do not repeatedly run the full repository gate for each helper.

## Task 20 — bounded local metric history

The [local history API and panel](metrics.md#local-panel-history) now retain at
most 360 minute buckets and 168 hour buckets in memory. The local observation
worker samples outside the request path; no history request starts collection,
provider IO or peer traffic. Last-observation downsampling preserves cumulative
counts, durations and histogram buckets, not invented per-bucket averages. Missing
families, failed samples, time gaps and retention expiry remain distinguishable.

The manager-only endpoint rechecks access after collection, has owned bounded
admission and serves at most 30 newest-first buckets with an optional next URL.
Continuations bind a fresh random 128-bit history identity, not the durable node
incarnation. The first real restart test exposed that mistaken distinction; its
failed equality assertion is resolved by the separate history-store identity.
Entropy failure makes optional history unavailable, not appliance startup fatal.

The generated Rust/OpenAPI/TypeScript/Zod surface shares the existing typed metric
catalogue. The client rejects substituted continuation hosts/routes/query fields
before credentials are attached and derives its one-MiB response allowance from
Rust. A full-page regression exceeds the generic 64-KiB JSON allowance and proves
that this endpoint works without raising unrelated API limits. The panel's
on-demand controls, one-page ownership, unknown states and no-late-results
behaviour follow the existing interface; no browser session was opened.

Focused verification:

- Six local-history and HTTP tests passed in **0.09 seconds**, after the final
  core correction's **20.83-second build**. They cover deterministic 14-day
  retention/downsampling without sleeps, page boundaries, restart identity,
  backward wall time, gaps, exact `u64` counters, malformed output and authentication
  before query work and after collection.
- Fifteen affected web tests passed in **1.79 seconds**; web typecheck and affected
  ESLint passed. The embedded panel build completed in **393 milliseconds**.
  The final generated-client rerun passed all fifteen in **2.13 seconds**;
  generated artefact drift verification also passed.
- Affected API/daemon all-target/all-feature Clippy passed in **17.41 seconds**.
- Real HTTPS exporter/history enablement, restart, stale-cursor refusal, peer
  join and gateway-loss proof passed in **10.93 seconds**, after a **39.64-second
  build**. History works before opting in to external metrics.

Earlier local checks caught fixture type imports, missing field documentation and
lint issues; these were corrected without exceptions. One Rust check was wrongly
run alongside a web bundle replacement and lost an embedded asset input. Running
generation, bundle build and Rust checks in dependency order resolves that
execution error; those steps must not overlap. It was not a daemon runtime fault.

Task 20 falls **5 → 1 points**, Stage 10 **132 → 128 points**. No full-stage gate
or publication is claimed. The backup-restore and SMB integration findings remain
open for the assembled-stage fixing pass.

## Task 4 — external publisher gateway lifecycle

The implemented external-publisher API now has a real two-daemon HTTPS proof.
An authenticated API-key caller publishes a finite externally issued certificate;
a gateway joining afterwards receives its encrypted delivery. A second generation
is published and the peer is forcibly restarted before waiting for installation.
Both gateways must then acknowledge the current publication and select the exact
expected leaf on a fresh TLS handshake. Exact retries through either gateway
return their original receipt; replaying the old publication cannot roll back
the live selection. Wrong names, mismatched keys, invalid chains, expired leaves,
non-increasing generations and changed operation retries are rejected.

The first test build exposed two fixture API mismatches, corrected locally. Its
first execution incorrectly inspected a resumable TLS client's retained peer
certificate when checking the new leaf. The proof now explicitly disables session
resumption for leaf inspection: existing sessions may retain their original
identity, while a full new handshake must select the current certificate. It
compares complete leaf bytes, not merely acceptance by the same issuer. Mismatch
returns through the fixture cleanup/retention path rather than panicking.

Final affected daemon Clippy passed in **2.78 seconds**. The process test passed
in **19.55 seconds**, after a **3.11-second build** (the preceding corrected run
also passed in **19.59 seconds**). No external CA, browser or publication service
was contacted. No dependency or production certificate interface changed.

This closes the missing lifecycle proof, not the full assembled-stage gate:
task 4 **5 → 1 points**, Stage 10 **136 → 132 points**. Existing packaged backup
restore and SMB findings remain open.

## Task 18 — local consensus measurements

The daemon now samples its existing local consensus reactor independently of
scrapes. Ten fixed, identity-free metric families expose role, term, committed
and applied positions, pending/queued operations, persistence blocking, known
leader presence, sample age and failed observations. A failed source preserves
the last good sample and its increasing age. No synthetic quorum-health claim is
made. Collection uses neither peer probes nor consensus writes, and its owned
worker stops with the appliance. See the [catalogue](metrics.md#local-consensus-observations).

Six contract tests and eleven daemon metric tests passed in **0.00** and **0.11
seconds**, after a **39.32-second build**. The actual HTTPS exporter enable/disable,
join, gateway-loss and restart proof passed in **10.00 seconds**, after a
**31.26-second build**. Affected all-target/all-feature Clippy passed in the same
successful command chain. Earlier Clippy failures led to a responsibility-based
consensus metric family and separate SMB connection composition; no blanket lint
exception or weakened assertion was added.

Task 18 falls **5 → 3 points**, Stage 10 **138 → 136 points**. Remote catch-up,
current quorum evidence and federation progress still need instrumentation.
This is focused implementation evidence, not a full-stage gate or a resolution
of the recorded backup-restore/SMB integration failures.

## Task 13 — complete diagnostic projection implementation

The existing diagnostic download now includes explicitly allow-listed operational
configuration and a bounded unfinished-work window. Configuration exposes only
compiled OS/architecture, exporter enabled state, backup interval/retention/copy
policy, public certificate source category and observed private generation.
Destination paths, host/domain names, recipient identities, raw component payloads
and all key material are omitted by construction.

Pending work includes only opaque work identity, closed kind/state, attempt count,
revision and retry instant. It never serialises subjects, file/shard identities,
claims, fences or result payloads. Selection uses the existing maintenance-ready
index with a limit-plus-one truncation probe. It does not claim work, retry it,
perform provider IO or scan the complete queue. Concurrent completion remains
explicitly representable; metadata revision-before/after still exposes collection
across concurrent changes. Existing bounded events, target probes, topology,
reactor observations and command outcomes remain part of the bundle.

Focused implementation verification:

- Five Rust response/diagnostic tests passed in **0.04 seconds**, including nested
  secret-field rejection and contradictory configuration/counter rejection.
- Four HTTP diagnostic tests passed in **0.11 seconds**, covering pre-collection
  authentication, revocation, cancelled-job ownership and invalid output.
- The SQLite bounded-window/read-only/index-plan test passed in **0.28 seconds**.
  It verifies truncation and unchanged revision/unclaimed jobs, plus indexed
  ordering without a temporary sort. A `usize` SQL-binding compile mistake was
  corrected before these tests. Combined affected-crate build: **33.25 seconds**.
- Rust-generated OpenAPI/TypeScript/Zod artefacts were regenerated. Eleven web
  diagnostic/client/download tests passed in **1.48 seconds**; web typecheck and
  affected ESLint passed.
- The real two-daemon setup/join/renewal/restart test now verifies the complete
  diagnostic download through both gateways. It passed in **15.46 seconds**, after
  a **35.14-second build**, with rebuilt embedded web assets.
- Affected API/metadata/daemon all-target/all-feature Clippy passed in **31.40 seconds**.

Task 13 implementation is ready for the assembled-stage verification pass;
remaining estimate **3 → 1 points**, Stage 10 **140 → 138 points**. This is not
stage completion. The packaged backup-restore and cross-gateway SMB failures below
remain open and are not erased by this independent successful diagnostic proof.

## Tasks 24/27 — local native package and packaged-process execution

`pnpm package:local` now builds the embedded web bundle and daemon, runs both
licence gates, checks architecture and linkage, and assembles a fresh local
directory/archive with `GPL-2.0-only` text, operating instructions, conservative
Rust/web dependency inventory, source/toolchain observations and SHA-256 checksums.
It has no publish, release, tag or push command. `--plan` only reports build steps;
`--profile dev` provides an explicitly labelled fast development artefact. Default
release-profile builds are local builds, not signed releases or acceptance proof.

macOS rejects non-system library dependencies. Linux packaging requires a static
musl executable. The prepared `scratch` container recipe runs as an unprivileged
user with explicit persistent state/storage mounts and an operator-supplied public
CA bundle; it installs no packages or external services. Linux/container execution
is not yet proved: the inspected local Linux builder has only
`aarch64-unknown-linux-gnu` installed, not the required musl target.

Three focused packaging tests passed in **73.34 milliseconds**, covering exact
bytes/checksums, immutable output directories, inventory scope/path exclusion and
rejected options. Tooling ESLint passed. The actual macOS ARM64 dev package passed
both licence gates, rebuilt the embedded web bundle in **350 milliseconds** and
the daemon in **7.21 seconds**. Linkage inspection found only Apple system libraries.
This is a conservative package inventory, not yet the complete third-party
notices, signed provenance or link-level SBOM required by task 25.

The existing headless harness now accepts an absolute, existing
`MESHSPAN_DAEMON_PROOF_BINARY`, allowing the same real tests to execute the packaged
binary rather than silently testing the Cargo output. The package used here has
binary SHA-256 `52e58e31fafeb429aa357753861fd36a5fb5a13d2e948373b11a41b33623ea5c`;
its provenance records source `a47dce1`, a dirty working tree and `dev` profile.
The packaged setup/panel/join/private-renewal/forced-restart proof passed in
**12.70 seconds**, after a **3.81-second harness build**.

Two broader packaged-process failures are open for the assembled-stage fixing pass:

- The operator workflow failed in **10.60 seconds** with HTTP `409 state_conflict`
  while verifying an isolated restore of an actual automatic backup. Both daemons
  were still running. Private fixtures were retained locally; they must not be
  uploaded as evidence. No cause or fix has been established.
- The real three-gateway SMB test failed in **36.30 seconds**: the remote gateway
  still listed `remote-only.bin` as length **0**, while the expected written length
  was **47**. This is not an SMB interoperability pass. That run's fixture was not
  retained by the older harness; failure retention is now added before further
  investigation. No timeout was increased or assertion weakened.

The SMB harness also accepts an explicit immutable `MESHSPAN_SMB_PROOF_IMAGE` and
always uses `--pull=never`. This run used the existing local client image
`sha256:9daac97f82472b031c7bc56e5cdd2446ab01ceafd6dc2a4705cdd20a8ae90d6d`, avoiding
the broken tag lookup without downloading an image. Native/container acceptance,
backup/recovery, signed update tooling and the above defects remain open. Tasks
24 and 27 are partial; no stage completion or release is claimed.

## Task 3 — live internal TLS credential selection

### Automatic daemon renewal implementation

The daemon now owns a private-certificate worker independently of public ACME.
It scans bounded topology pages, stages due same-key renewals through the
authoritative command path, installs its own staged credentials without rebinding,
signs installation acknowledgements and retires completed overlaps. Unknown
commit outcomes retain the exact operation for retry. Private keys stay local.

The real two-process test
`private_node_renewal_runs_automatically_and_survives_restart_and_join` passed in
**14.91 seconds**, after a **5.72-second build**. It shortens only the initial
single-node fixture's scheduling deadline, then exercises the normal worker:
generation 2 activation, unchanged node key, continued public HTTPS, joining a
second daemon, exact renewed private TLS fingerprint, forced process loss and
fresh-handshake selection after restart. It does not simulate a month passing or
prove expired-credential recovery. The fixture reuses the workspace's existing
SQLite dependency; no dependency version or external package was added.

Affected daemon/cluster/metadata all-target/all-feature Clippy passed in
**12.94 seconds**. A private-database test access mistake and collapsible conditions
were corrected before this evidence. Offline/expired-credential readmission,
issuer/federation rollover and the assembled-stage integration pass remain open.
Task 3 is still partial; this checkpoint does not claim those missing behaviours.

### Stage-first renewal implementation checkpoint

Explicit same-key renewal now binds its exact generation, DNS name and at-most
30-day validity into a replay-stable signed certificate. Metadata reuses the
existing MeshSpan certificate crate to validate the signature, admitted key,
issuer and exact interval rather than introducing an external library.

Migration 88 and private command kinds 77–79 implement durable staging, signed
node installation acknowledgement, atomic activation and prior-leaf retirement
after one hour of overlap. Transport bindings permit the exact current plus one
overlapping leaf for the same incarnation. Updating another node does not erase
that overlap; explicit retirement rejects subsequent old-connection requests.

Focused evidence during implementation:

- All 18 certificate tests passed in **0.15 seconds**; the later renewal-validator
  tests passed in **0.06 seconds** after a **2.26-second build**.
- Two peer-registry tests passed in **0.00 seconds** after **6.90 seconds** of build.
- Eleven actual QUIC network tests passed in **0.48 seconds** after **24.60 seconds**
  of build, including staged fresh-handshake admission and old-connection retirement.
- Three SQLite renewal tests passed in **1.53 seconds** after **7.13 seconds** of
  build: exact replay/reopen, signed activation, deadline-gated retirement and
  rejected stale/substituted input without a mutation.
- Affected certificate/transport/metadata/cluster all-target/all-feature Clippy
  passed in **8.85 seconds**. Earlier compile/type mistakes and overlong tests
  were corrected; the latter were separated by staging versus installation scope.

The subsequent daemon topology integration reads staged/installed overlap from
replicated rotation records. An exact unchanged route/overlap refresh is a no-op,
preserving queues and connections. An expired uninstalled candidate can be
abandoned without retiring the active leaf; a fresh candidate uses the next
unused generation and can later activate and retire its actual predecessor.
The four focused SQLite tests passed in **2.41 seconds** after a **4.43-second
build**, including generation 2 abandonment followed by generation 3 activation
and retirement of generation 1. Final affected all-target/all-feature Clippy,
including the daemon, passed in **20.83 seconds**. No full integration rerun was
used for this implementation checkpoint.
Rust and JavaScript licence gates passed; the lockfile adds only the internal
metadata-to-certificate crate edge, with no new external package or version.

This is an implementation checkpoint, not Task 3 completion. Daemon
scheduling, acknowledgements, catch-up and federation rollover remain to be
integrated on the same stage-completion branch. No full workspace or unrelated
slow-suite run was added between these changes; stage-wide acceptance follows
the assembled implementation. Stage 10 remains 140 points, Stage 11 126.

The private transport can now replace its client and server TLS configurations
without restarting or rebinding either socket. Preparation validates the complete
chain against the configured mesh roots, exact local DNS name, current TLS time,
both client/server uses and matching private key. Credentials are bounded to eight
non-empty certificates of at most 64 KiB each before duplication. Installation
retains the original node identity key, accepts exact replay and rejects stale or
conflicting generations without changing either direction.

Every accepted replacement creates fresh TLS configurations and resumption caches.
New outbound setup snapshots the selected configuration under the selection lock;
there is no lock across network IO. Existing handshakes/connections may complete
with their original identity until authority retires it separately. The returned
generation, leaf fingerprint and length-bound chain digest are public installation
evidence, not a metadata acknowledgement or permission to change trust.

`ConsensusNetwork` now uses this transport and exposes local selection/installation
to its daemon owner. Startup restores the exact selected certificate generation
from the existing metadata row; initial join still explicitly begins at generation

one. No migration, wire format, dependency or trust-root change is introduced. The
test-facing certificate crate re-exports the existing node-key types so fixtures
use the same implementation as production, not another signing library.

The real-QUIC proof selects a new leaf for the **same node-owned key**, signed by
a root-authorised online intermediate. It checks fresh handshakes in both
directions, repeat connections, exact bytes over old connections, unchanged
socket addresses and idempotent installation. Negative cases check generation
rollback/conflict, identity-key substitution, mismatched key material, wrong
names, untrusted issuers and credential-size bounds. This is not evidence of
automatic intermediate-CA rotation or a complete daemon renewal state machine.

Local evidence before full integration:

- **12 transport tests passed in 0.66 seconds**, after a **2.78-second build**.
- **10 network tests passed in 0.51 seconds**, after an **8.10-second build**,
  including an exact control round trip under the new local certificate.
- The metadata generation-selection/reopen test passed in **0.31 seconds**,
  after a **15.04-second build**, retaining generation 2 while ignoring a higher
  retired row. This tests the projection, not authorisation of an issuance.
- **10 enabled headless tests passed in 39.13 seconds**, after a **48.54-second
  build**. Seven cases were ignored by that command: three isolated DNS-provider
  proofs, two real-time ACME recovery proofs and two external SMB-client proofs.
- Affected all-target/all-feature Clippy passed in **24.37 seconds**.

The first focused compile found test-helper visibility and error-conversion
mistakes; both were corrected before these runs. Task 3 remains **5 points**, Stage 10
**140**, Stage 11 **126**. Remaining automatic lifecycle work includes finite
node-certificate issuance, staged peer trust and durable installation receipts,
renewal scheduling, offline catch-up and federation rollover. Releases and all
other publication remain prohibited.

### Live private TLS integration

Signed, pushed and GitHub-verified source
`c6a5d40c5ccb1cdd12b4a58efaf61091ade8a2f7`
(tree `0afd9f16d65ced5264f7ebb545d05b63f7b55278`) passed the complete local
gate in **691.46 seconds**: Rust workspace tests **623.96 seconds**, web tests
**8.03 seconds**, and all static, generated-contract, licence and tooling lanes.
The run used NVM Node **26.8.1**, pnpm **11.19.0**, Rust **1.98.0** and four
build/check workers. Both opt-in real-time ACME recovery tests passed together in
**339.39 seconds** on the final rebuilt binary.

The isolated Linux provider suite passed on the same source after a **56.49-second
build**: manual DNS **16.06 seconds**, webhook **20.91 seconds** and Cloudflare
**21.14 seconds**, concurrently. Source remained unchanged during these runs.
This verifies live credential selection, not the remaining automatic lifecycle.

### Stage completion cadence — owner direction, 2026-09-07

Implement the remaining Stage 10 behaviour before a stage-wide adversarial and
refactoring pass. During implementation, use focused local tests and affected
lint/contract checks; commit and integrate coherent progress without repeating
the entire workspace suite or unrelated slow acceptance cases for every slice.
Run the complete integration and required failure suites against the assembled
stage, and fix known defects when found. Do not pre-optimise, speculate about
unimplemented edge cases, weaken safety requirements or label partial tasks
complete. Report task numbers and observable delivered behaviour, not branch
names or "nearly done". The publication hold remains unchanged.

## Task 3 — retire private peer admission on reused connections

The internal rotation review found that replacing a committed peer route updated
new-connection checks but left existing QUIC connections carrying their original
admission indefinitely. Two real-QUIC regressions reproduced subsequent control
requests reaching authority after certificate or incarnation replacement. The
three-case red run finished in **0.17 seconds** after a **16.20-second build**:
both retirement cases failed, while unchanged-binding reuse passed.

The current peer registry now revalidates previously authenticated bindings.
Consensus, control, snapshot and data ingress recheck admission; decoded control
headers and each snapshot frame retain the connection's exact identity rather
than substituting the latest incarnation. Queue admission reserves capacity
without a lock, then verifies and enqueues under the peer-registry read lock,
linearising it against route replacement. Work already admitted is not claimed
rolled back, and operation-specific authority remains required downstream. There
is no automatic retry of an unknown mutation or new dependency/schema/wire format.

The final focused network run passed **9 tests in 0.43 seconds** after an
**8.84-second build**, including exact Pong responses, unchanged connection reuse,
retirement rejection and a deterministically blocked queue. All **9 transport
tests passed in 0.38 seconds** after a **6.52-second build**, including exact-binding
replacement/removal, real mTLS and control/data isolation. Affected all-target,
all-feature Clippy passed in **43.11 seconds**. Full integration is pending.

Task 3 remains **5 points**: this is the retirement-admission correction, not
automatic internal renewal. Remaining scope includes explicit node-certificate
lifetimes, staged trust/installation generations, live local QUIC replacement,
offline catch-up and federation identity rollover independent of public ACME.
The existing HTTPS live resolver and public per-recipient envelope acknowledgements
are not evidence that those internal lifecycle steps exist. Stage 10 remains
**140 points**, Stage 11 **126**; publication stays prohibited.

### Private-peer retirement integration

Signed, pushed and GitHub-verified source
`209f373369159cc5d661e453d6e5b7f3193cb784`
(tree `c55c52a8c1e02354090ac1a463ed97f9a97c931a`) passed the complete local
gate in **710.14 seconds**: Rust workspace tests **628.33 seconds**, web tests
**7.53 seconds**, and every static, generated-contract, licence and tooling lane.
The command used NVM Node **26.8.1**, pnpm **11.19.0**, Rust **1.98.0**,
`CARGO_BUILD_JOBS=4`, `MESHSPAN_CHECK_WORKERS=4` and `pnpm check`.

The isolated Linux provider suite passed on the same source after a **50.18-second
build**: manual DNS **15.50 seconds**, Cloudflare **21.30 seconds** and webhook
**21.32 seconds**, running concurrently. Both opt-in real-time ACME recovery cases
passed together in **337.29 seconds** on the final rebuilt macOS headless binary.
The exact lease-loss and rejected-order filters excluded the Linux-only provider
cases. The tested source remained unchanged throughout these runs.

This closes the reproduced stale-connection admission defect. Automatic internal
certificate rotation remains open, and the older independent cluster-startup
timeout is not claimed resolved. No release, tag, publication or GitHub Actions
run occurred.

## Task 2 — isolated DNS-provider process lifecycles

The candidate adds real-daemon Cloudflare, authenticated webhook and manual-DNS
lifecycle tests. Production transports are unchanged: Cloudflare still uses its
fixed HTTPS origin; authoritative probes still use the system resolver and direct
DNS sockets. Each case runs in its own offline Linux container with loopback-only
DNS and provider origins, test-owned TLS trust, no host port publication and no
external CA/provider traffic. The CA independently derives the expected TXT from
the authenticated signing account. The fixtures enforce exact record ownership
and keep unrelated TXT data present through publication and cleanup.

Cloudflare and webhook cases verify issuance, exact cleanup, daemon restart and
new-gateway installation without a second order. The manual case follows the
manager-only HTTPS task inventory, denies anonymous access, verifies that no CA
challenge is notified before publication, checks the exact matching removal task
and proves completed tasks stay absent after restart. These are local protocol
and daemon integration proofs, **not live Cloudflare or public-CA evidence**.

Run through NVM with `pnpm check:dns-providers`. The runner requires a locally
available Rust image matching `rust-toolchain.toml`; `MESHSPAN_DNS_PROOF_IMAGE`
can select an exact local image ID. It never pulls or publishes an image. Cargo
builds offline with the existing registry cache and a dedicated Linux target
volume; cases run in parallel without sharing their DNS/HTTPS listeners. Failed
containers retain private fixture state for diagnosis, while successful containers
are removed. Do not upload retained databases or credentials as public artefacts.

The initial three-case run passed after a **77.58-second Linux build**. On the
final harness (including failure-state retention), its incremental build passed
in **9.43 seconds**, with manual DNS **13.35 seconds**, Cloudflare **18.46 seconds**
and webhook **18.48 seconds**, all running concurrently. The image was
`sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7`
(Linux ARM64, Rust **1.98.0**), under NVM Node **26.8.1**, pnpm **11.19.0** and
four workers. Affected all-target/all-feature Clippy passed in **2.23 seconds**;
the new runner's ESLint and formatting checks passed. Existing normal HTTP-01,
RFC 2136 and two-gateway ACME tests passed in **21.22 seconds** after a
**5.91-second build**, before the container-only retention adjustment.

The initial provider candidate changed no production behaviour, dependency,
schema or protocol. Task 2 remains partial: advance renewal delivery
depends explicitly on the existing **task 21 durable-notification implementation**,
not a second notification system. Live CA verification remains task 5.

### Provider integration finding — remote backup export

Signed and GitHub-verified provider source
`2ceb677b64c0dfff9d0d3fc191049d512e992a88`
(tree `3653cfa448d910491f00182ae1c850bfe4275b92`) failed the full gate in
**279.78 seconds**: Rust **215.62 seconds**, web passed in **6.26 seconds**, and
all static/generated/licence/tooling lanes passed. The clean-machine operator
flow exposed an existing remote-backup export panic: the HTTP body writer called
`Handle::block_on` while a remote provider was already inside its async QUIC
fetch. The resulting response declared **2,626,456 bytes** but sent **zero body
bytes**. Private state remains in `.tmpjhYkr0` and `.tmpCgsLDc` under the local
test temporary directory; it is not a public artefact.

A direct regression reproduced the exact nested-runtime panic in **0.01 seconds**,
using more bytes than the two-frame channel can buffer. The writer now polls only
the existing channel-send future with a thread-unparking waker on the owned
blocking-provider thread. It retains the same bounded channel, 64-KiB frames,
drop cancellation and absolute monotonic deadline without starting another
executor or adding a dependency. Four focused body tests passed in **0.03 seconds**
after a **15.59-second build**, including stalled-reader timeout and cancellation.

The operator proof now exports and verifies the **same backup through both
gateways**, rather than exercising whichever local/remote source the root happened
to choose. It passed in **16.88 seconds** after a **21.67-second build**; affected
all-target/all-feature Clippy passed in **7.01 seconds**. The provider-source
opt-in ACME recovery pair separately passed in **339.64 seconds**; that binary
preceded this backup correction. Final corrected-source integration is pending,
and PR #252 remains unmerged.

### Final provider integration

Signed, pushed and GitHub-verified source
`4449f5dc4c7e1e49f643935dbfce25e151a915d2`
(tree `c29984249e51df053b0ece4ac8776ca5d5105b87`) passed the full local gate in
**601.03 seconds**: Rust workspace tests **564.43 seconds**, web tests **4.82
seconds**, and every generated, formatting, lint, licence, TypeScript and tooling
lane passed. This used NVM Node **26.8.1**, pnpm **11.19.0**, Rust **1.98.0**,
`CARGO_BUILD_JOBS=4` and `MESHSPAN_CHECK_WORKERS=4` with `pnpm check`.

On that corrected source, `pnpm check:dns-providers` passed after a **27.71-second
Linux build**: manual DNS **13.30 seconds**, Cloudflare **18.16 seconds** and
webhook **18.27 seconds**, running concurrently in the isolated networks described
above. Both opt-in real-time ACME cases passed together in **340.25 seconds** on
the final rebuilt all-feature headless binary, selecting the exact lease-loss and
rejected-order recovery tests with `--ignored --test-threads=4`. The newer Linux-only
provider cases were not selected by this macOS command.

The remote-backup defect now has a failing-before/passing-after regression and
passing full integration; the clean-machine workflow verifies the same exported
backup through both gateways. The older independent cluster-startup timeout is
not claimed resolved. Task 2 drops **2 → 1 points**, Stage 10 **141 → 140**;
advance renewal notification delivery remains required through task 21. Stage 11
remains **126 points**. No publication or GitHub Actions occurred.

A separate diagnostic ran all **406 metadata library tests** successfully in the
same offline Linux image in **150.38 seconds**, after a **22.88-second build**, with
four test workers. It ran alongside the macOS gate using a separate Cargo target.
This is an additional platform result, not a controlled speed comparison or a
replacement for the macOS gate.

## Task 2 — shared HTTP-01 gateway challenges

### Final recovery integration

Signed, pushed and GitHub-verified source
`115a6c5f3332729f37c196d5c3ab489af78f74aa`
(tree `73b8f3ed1b5dbf9e9b3fa718c3940ffd88660971`) passed the full local
integration gate in **780.44 seconds**: Rust workspace tests **732.27 seconds**,
web tests **5.58 seconds**, and every generated, formatting, lint, licence,
TypeScript and tooling lane passed. The command used the NVM-selected Node
**26.8.1**, pnpm **11.19.0**, Rust **1.98.0**, `CARGO_BUILD_JOBS=4` and
`MESHSPAN_CHECK_WORKERS=4` with `pnpm check`.

Both opt-in real-time ACME recovery cases then passed together in **337.90
seconds**, using the final gate's rebuilt all-feature binary
`headless_process-955f61bbc0f09fcd acme_lifecycle:: --ignored --test-threads=4`.
They cover process loss with the unchanged five-minute claim lease and rejected
order cleanup/restart with the unchanged retry backoff. This is final-source
evidence, unlike the earlier diagnostic run below.

The reproduced port, cancelled-connection, election-deadline and backup-provider
findings below now have owning-boundary corrections and passing integration.
The additional wrong-plan timer regressions passed in **0.79 seconds**, and
affected all-target/all-feature Clippy passed in **21.94 seconds** before the
full gate. The independent, older cluster-startup timeout is **not** claimed
fixed by these results. DNS-provider process lifecycles remain outstanding;
task 2 stays **2 points**, Stage 10 **141**, Stage 11 **126**. No release, tag,
package/image publication or GitHub Actions run occurred.

### Integration findings — not closed

The full local gate on signed source `3f920adf87b69e0d337a57c4de77b8457a594583`
(tree `f1530c9c10c2bed14ee69b3cdc58af5cc4af130a`) **failed in 353.00 seconds**.
Rust tests failed in **285.89 seconds** at the two-gateway restart proof;
web tests passed in **5.57 seconds**, and all static/generated/licence lanes
passed. PR #251 remains unmerged. The affected Clippy preceding this gate passed
in **21.81 seconds**; that does not supersede the process failure.

The concurrent opt-in recovery run completed in **337.42 seconds** with rejected
order recovery passing but lease-loss recovery failing at a child's HTTPS bind:
`Address already in use`. The harness allocated from the same counter in each
test process and released its probe socket before child startup. A new actual
child-process regression reproduced reuse of port 16384. OS file-lock reservations
now retain each allocated TCP/UDP address through daemon restarts until the owning
test process exits. Locks cover individual ports, not the suite. The regression
and range parser passed in **0.01 seconds**, after a **3.24-second build**.
Both opt-in recovery cases subsequently passed together in **337.14 seconds**
with reservations and temporary gateway diagnostics. Production lease/backoff
durations were not shortened. Final-source integration is still required.

Port isolation did **not** fix the gateway restart defect. A diagnostic parallel
headless run failed in **42.38 seconds**, and a later run failed in **38.64
seconds**. The peer's requests reach the surviving node, but reverse-direction
requests do not reach the restarted peer's HTTP-proof handler. Both nodes can
remain without a known leader. Waiting for both gateways within the unchanged
deadline exposed persistent unavailability, rather than merely a readiness race;
the three-case focused run failed in **40.48 seconds**. Investigation continues
at the private connection boundary; isolated passing retries do not close it.

The 42.38-second run also exposed an independent automatic-backup failure. Its
retained authoritative state has a recorded run requiring two verified copies,
two active destinations, but only one verified copy. Evidence is retained in
the private temporary directories `.tmp3IEjub` and `.tmp6zqGWd`. A later passing
operator flow does not establish the cause or close this finding. Neither this
failure nor the earlier independent cluster timeout is waived for integration.

### Recovery corrections awaiting final integration

The port fix is signed, pushed and GitHub-verified as
`09119037c1a589664c5d7e3b96f6827dcc83fc3b`. Further diagnosis identified three
separate ownership defects; none is addressed by extending test deadlines:

- An outer request deadline cancelled `request_control` before its ordinary error
  path could evict the cached connection. Repeated lookups reused that uncertain
  connection. A real-QUIC regression failed in **0.12 seconds**. Cancellation now
  evicts only the exact connection used by that request, without closing other
  streams, automatically retrying a mutation or implying remote rollback. A
  second regression protects a newer replacement from an older cancelled call.
  All five focused network tests passed in **0.23 seconds**.
- A higher-term but log-stale candidate reset the receiver's election deadline
  even when refused a vote. With fixed election slots, the quicker outdated node
  could repeatedly postpone a viable candidate. The direct reactor regression
  failed in **0.30 seconds**. Higher terms remain durably persisted, but timer
  resets require a granted vote or validated current-leader contact. The latter
  binds both membership epoch and plan digest: a previously recognised leader
  sending the wrong plan must not reset the timer either. That additional
  regression failed in **0.28 seconds** before its binding correction.
- The retained backup claim belonged to the peer while only the root destination
  had a verified copy. A worker refreshed its local backup providers only when
  it personally committed the defaults transition. A peer claiming work after
  another node's transition could therefore lack its own destination indefinitely.
  Provider refresh now follows the replicated projection on every backup pass,
  regardless of which node committed the defaults.

The gateway proof now waits for two stable voters before killing the peer, checks
bounded recovery of both public challenge listeners, and requires a new committed
administration write afterwards. The exact operation ID/body are retained while
retrying temporary `503` responses; any other failure still fails immediately.
This distinguishes public-proof availability from restored consensus. The
parallel headless run passed **10 enabled tests in 36.64 seconds**, after an
**18.06-second build**, including two-copy backup completion. Four opt-in tests
were not run by that command. This preceded the final wrong-plan timer check;
final-source integration and opt-in recovery must still pass before PR #251 merges.
The earlier unrelated cluster-start timeout is not claimed fixed.

### Candidate behaviour and focused evidence

The current candidate makes public HTTP-01 material available independently of
which gateway claimed the order. The local publisher remains the challenge
component; other gateways read an indexed, revalidated projection of the
replicated checkpoint. A miss can query an authenticated voter without issuing
an ACME request or appending consensus work. The response contains only the
exact token's public key authorisation and original expiry. Preparation,
cleanup and retirement are not projected as serving states. Reads use one
database snapshot; negative lookups use the token index instead of scanning
order history. Remote reads reuse a dedicated reader and bypass the mutation
queue. Anonymous lookup admission and total duration are bounded.

The new two-daemon CA proof initially failed in **22.38 seconds**: one gateway
returned `404` during actual CA validation. After delivery was implemented, the
proof exposed a separate persistent restart defect. A joined node retained the
founding node's certificate but **no private endpoint**, so its route registry
could never recover that peer. Diagnostics confirmed the missing endpoint in
the persisted topology; waiting for readiness did not fix it. New appliance
bootstrap now commits its advertised private endpoint atomically. The topology
reader exposes it without inventing an enrolment activation for the founding
node. Endpoint validation and cross-table duplicate protection apply.

Migration **86** adds the derived challenge-token index and backfills existing
checkpoints transactionally, preserving their bytes/digests. Corrupt migration
evidence rolls back both the index and migration history. Migration **87** adds
the optional founding endpoint. Existing bootstrap records retain their exact
wire bytes and request digests; new records use a bounded tagged endpoint
extension. Missing legacy addresses remain missing rather than being invented.
There is no dependency or public HTTPS schema change.

The final focused parallel process run passed **all three normal ACME cases in
23.30 seconds**, after a **17.02-second build**: ordinary HTTP-01, RFC 2136
DNS-01, and two active HTTP gateways followed by gateway restart. The CA checks
both actual HTTP listeners against its independently derived account proof,
requires exact removal and observes exactly one order/issuance. Startup may
temporarily return `503` while restoring peer routes, but the removed token may
never reappear and lookup readiness has a bounded deadline. An earlier parallel
run exposed the fixture's two-second client deadline matching the server's new
two-second work deadline; the client now leaves one second for the response,
without increasing the server budget or serialising tests.

Focused metadata coverage passed **5 tests in 3.12 seconds**; founding-endpoint
and legacy-codec coverage passed **3 tests in 2.93 seconds**. Both new private
wire tests passed, including malformed tokens, substituted bodies, missing or
invalid expiry and round trips of found/absent responses. The broader ACME
repository run passed **32 tests in 24.12 seconds**. Affected Clippy passed
before the final allocation-free token-validation cleanup; final integration
and the two opt-in real-time recovery cases remain pending for this candidate.

This closes neither the remaining DNS-provider process lifecycles nor Stage 10.
Task 2 remains **2 points**, Stage 10 **141**, and Stage 11 **126** pending their
recorded acceptance. Releases, tags, package/image publication and GitHub
Actions remain prohibited. The previously recorded independent cluster timeout
is not claimed fixed by these passing ACME tests.

## Task 2 — interrupted challenge recovery

### Retry guidance survives parsing and terminal certificate refusal

Signed, pushed, GitHub-verified commit
`9ff95fe08f21d086f3894842d1b17acefb3f32e4`, tree
`8e44e2c8aee7a1ca31cd8f6541d984bef6d78adc`, corrects the response-parsing gap
identified in PR #249. [PR #250](https://github.com/KarlLivesey/MeshSpan/pull/250)
contains this candidate. The full NVM-default gate passed on that source in
**619.72 seconds**: Rust workspace tests **568.60 seconds**, web tests **8.40
seconds**, Rust lint **20.61 seconds**, and web lint **24.61 seconds**. Generated
drift, embedded bundle, formatting, both licence checks, TypeScript and tooling
tests also passed. The command was
`CARGO_BUILD_JOBS=4 MESHSPAN_CHECK_WORKERS=4 rustup run 1.98.0 pnpm check` after
initialising NVM. Closing edits are evidence only; the tested implementation
did not change after the final gate.
Both opt-in real-time process-recovery cases passed in parallel in **337.22
seconds**, selected through the rebuilt executable with
`acme_lifecycle:: --ignored --test-threads=4`. Actual lease-expiry takeover and
rejected-order cleanup/reissuance after restart both pass without shortening
the production lease or backoff.

Every remote ACME step now validates retry guidance before parsing its response
fields. Valid guidance survives a malformed body or missing required response
field; absent or malformed/duplicate guidance does not invent a deadline or
trigger an inline retry. The shared parser still returns typed events only for
valid responses. Terminal certificate downloads carry receipt-time guidance
through certificate parsing, name/key/lifetime checks and trust verification.
If those checks reject the certificate, the ordinary authoritative retry keeps
the later CA deadline. The accepted download checkpoint remains intact and no
unvalidated certificate is committed.

The trust result also separates `UntrustedCertificate` from `InvalidTrust`.
Remote trust refusal now queues certificate retry; an unusable local trust-anchor
configuration still fails construction. This fixes the previously escaping
`Result(InvalidTrust)` without masking local configuration failure.

The initial executor regression failed because malformed success returned
`Protocol` without its valid delay. All three initial driver regressions failed:
malformed bodies and malformed certificates used only local backoff instead of
the CA's two-hour deadline, and an otherwise valid untrusted chain escaped as
`Result(InvalidTrust)`. After correction, **62 ACME tests passed in 0.16 seconds**
(**3.63-second build**) and **52 focused daemon tests passed in 0.58 seconds**
(**17.06-second build**). Vectors cover all ten current remote action forms,
relative/absolute hints, absent/invalid/duplicate hints, malformed certificates,
untrusted chains, unchanged checkpoint bytes and exact retry receipts. A real
TLS success with an invalid body advances the controlled clock from request time
to response time and verifies the resulting exact queued deadline with only one
network request. Existing bad-nonce and successful-polling regressions pass.
Affected all-target/all-feature Clippy passed in **9.05 seconds**. Rebuilt normal
HTTP-01 and RFC 2136 DNS-01 daemon lifecycles passed in **20.42 seconds**.

No dependency, database, checkpoint encoding or wire-format change was needed.
The Rust terminal-step result adds an optional receipt-time retry deadline and
the Rust result error distinguishes remote trust refusal. Task 2 remains **2
points**, Stage 10 **141**, Stage 11 **126**: DNS-provider process lifecycles and
active-gateway challenge distribution still remain, with live-CA acceptance a
separate task. The earlier unexplained cluster timeout remains open. No release,
tag, package/image publication or GitHub Actions were run.

### Rejected CA responses retain accepted state

Signed, pushed, GitHub-verified commit
`17e633d89398f3ec68acee46908741b29d2c4208`, tree
`13b669e124626d78b352e4c13d7a1a3d121a8ded`, separates semantic CA refusal from
local execution failure. [PR #249](https://github.com/KarlLivesey/MeshSpan/pull/249)
contains this candidate. The full NVM-default local gate passed on that source
in **489.14 seconds**: Rust workspace tests **453.02 seconds**, web tests **4.84
seconds**, Rust lint **10.13 seconds**, and web lint **20.88 seconds**. Generated
drift, embedded bundle, formatting, both licence checks, TypeScript and tooling
tests also passed. The command was
`CARGO_BUILD_JOBS=4 MESHSPAN_CHECK_WORKERS=4 rustup run 1.98.0 pnpm check` after
initialising NVM. Closing edits are evidence only; no implementation changed
after the final gate.
Both opt-in real-process recovery tests passed together in **336.74 seconds**
on the rebuilt candidate executable: actual lease-expiry takeover and rejected
order cleanup/reissuance after queued-daemon restart. The command selected
`acme_lifecycle:: --ignored --test-threads=4`; both ran in parallel and neither
production lease nor retry delay was shortened.

Before the correction, the new driver regressions failed with
`Execution(Machine(NameMismatch))` and
`Execution(Machine(InvalidRemoteState))`. These errors escaped the automatic
certificate worker instead of queuing a retry. The execution boundary now
validates an external event against a cloned candidate and reports a distinct,
redacted `RejectedResponse` for remote semantic refusal. The driver queues the
existing protocol retry without checkpointing the rejected candidate, clearing
the old checkpoint or pretending the order succeeded. Valid retry guidance is
resolved at response receipt time and retained in the authoritative retry.
Local publication/cleanup events, invalid transitions, corrupt state and invalid
local inputs are not reclassified as remote retries.

The **47 focused certificate-order tests passed in 0.37 seconds** after an
**11.22-second build**. New vectors cover foreign names, unexpected wildcards,
unsupported challenge families, substituted order/finalisation URLs and changes
to an already-published challenge's token, URL or family. They assert unchanged
checkpoint bytes, exact queued retry time, no new checkpoint, ordinary Retry
rather than Restart, and continued service of the original token without
publishing the substituted token. The explicit error-classification table covers
local versus remote origin for every current machine-error variant. Affected
all-target/all-feature Clippy passed in **6.86 seconds**. Rebuilt normal HTTP-01
and RFC 2136 DNS-01 daemon lifecycles passed together in **20.30 seconds**.

There is no dependency, database or wire-format change; the Rust execution error
adds the rejected-response variant. This focused correction is not a complete
hostile-CA process campaign, a claim about every malformed response's retry
handling, DNS-provider lifecycle completion or active-gateway challenge delivery.
In particular, inspection of `executor/remote_steps.rs` found that successful
response-body parsing precedes `progress_with_retry`: a valid retry header can
therefore be lost when body parsing returns a protocol error. That separate
wire-response path still needs a failing regression and correction; this
candidate handles already-parsed responses refused by the state machine.
Task 2 remains **2 points**, Stage 10 **141**, Stage 11 **126** while those gaps
remain. The earlier unexplained cluster timeout remains open. No release, tag,
package/image publication or GitHub Actions were run.

### Rejected-order process restart and replacement issuance

Signed, pushed, GitHub-verified commit
`789ce79ced06b665429442eeaef12678c4b32027`, tree
`0d967701fbfe2413e0c5e16c51556a84c03bfd1f`, adds the real-process retirement
acceptance test. [PR #248](https://github.com/KarlLivesey/MeshSpan/pull/248)
contains this test-only candidate. The full NVM-default local gate passed on
that source in **494.96 seconds**, with Rust workspace tests in **453.22 seconds**
and web tests in **5.09 seconds**. The command was
`CARGO_BUILD_JOBS=4 MESHSPAN_CHECK_WORKERS=4 rustup run 1.98.0 pnpm check` after
initialising NVM. Rust lint (**18.11 seconds**), web lint (**18.53 seconds**),
generated drift, embedded bundle, formatting, both licence checks, TypeScript
and tooling tests passed. No implementation edits followed the gate.

The existing opt-in
`acme_lifecycle::http01_authorization_recovers_after_process_loss_and_real_lease_expiry`
regression also passed on this candidate in **319.68 seconds**, using the same
rebuilt executable, exact filter and four-worker harness. Both affected slow
process cases therefore ran explicitly; neither is inferred from the default
suite's ignored entries. Together with the full gate, this closes the
rejected-order/reissuance acceptance slice: task 2 **3 → 2 points**, Stage 10
**142 → 141**, Stage 11 unchanged at **126**. The closing changes are evidence
only; the tested implementation tree is unchanged.

The opt-in
`acme_lifecycle::rejected_http01_order_is_cleaned_and_reissued_after_queued_daemon_restart`
test passed in **336.68 seconds**. A local TLS CA independently reads the actual
HTTP challenge, then rejects the first authorisation. The test requires the
exact old token to return 404 and the authoritative order to be queued without
its retired checkpoint or live claim. It kills the daemon, restarts from the
same SQLite state, and checks the entire queued record—including its original
retry instant—and encrypted leaf-key digest are unchanged. The CA refuses a
replacement before five real monotonic minutes and assigns distinct order,
authorisation, challenge, finalisation and certificate URLs plus a new token.
Exactly two CA orders produce one validated certificate; another daemon restart
and gateway join install that certificate without another order. The configured
account key and protected leaf key remain unchanged.

Normal HTTP-01 and RFC 2136 DNS-01 process lifecycles passed together in **20.15
seconds**; affected Clippy passed. The long rejection test uses the rebuilt
Rust 1.98.0 executable with `--exact --ignored --test-threads=4`, independently
of the full NVM-default gate. It remains opt-in so the real five-to-six-minute
production backoff does not slow every-edit checks. No production clock, lease,
backoff, runtime code, dependency, schema or protocol was changed. An initial
test compile failure used an unavailable direct SQLite-driver import; the test
now inspects state through the existing typed metadata repository, without a
new dependency.

Remaining acceptance includes other CA error responses, Cloudflare/webhook/manual
DNS process lifecycles, active-gateway challenge delivery and the separate live-CA
gate. This result does not close the previously recorded unexplained cluster
timeout. Publication remains prohibited; no releases, tags, packages/images or
GitHub Actions were published or run.

### Exact retirement and atomic fresh-order retry

The final full NVM-default local gate passed on signed, pushed, GitHub-verified
commit `6dc6dbeb6a2e72a8d99beb7a95fd411624e9f0de`, tree
`6a8770f56b492a64b3065a1ddd9b4dec8483ac1e`, in **590.19 seconds**. The command was
`CARGO_BUILD_JOBS=4 MESHSPAN_CHECK_WORKERS=4 rustup run 1.98.0 pnpm check` after
initialising NVM. Rust workspace tests took **536.36 seconds**, web tests **6.19
seconds**, Rust lint **25.60 seconds**, and web lint **21.36 seconds**. Generated
drift, embedded web build, both licence checks, formatting, TypeScript and tooling
tests also passed. No implementation changes followed this gate. The closing
commit updates evidence only. [PR #247](https://github.com/KarlLivesey/MeshSpan/pull/247)
contains this slice; the open validation statement below records its pre-gate
state, not a remaining integration-check failure.

The `codex/stage10-task2-order-retirement` candidate distinguishes ordinary
transport retry from abandoning an unusable protocol attempt. Terminal
authorisation rejection and an invalid CA order now produce a retirement state,
not the previous fatal machine error. Reaching the retained publication deadline
also starts retirement; that deadline is a local budget, not evidence that the CA
declared its order invalid. Published or prepared material retains its original
payload, receipt identity, configuration, epoch and expiry until exact cleanup
completes. Valid authorisations already in cleanup still proceed normally.

The worker checkpoints retirement intent before provider cleanup and preserves
CA retry guidance without delaying cleanup itself. Failed checkpoint commits
cannot change executable state or remove the challenge. A replacement worker
binds completed retirement to its current claim before the new authoritative
`Restart` completion consumes it. Checkpoint deletion, claim completion and the
future queue deadline commit atomically. Ordinary `Retry` keeps the existing
checkpoint; it cannot accidentally become a fresh CA order. The encrypted
leaf-key generation is not deleted or replaced by restart.

The checkpoint format is **4**. Original phases remain readable in formats
**1–3**, but those versions reject the new retirement variants rather than
silently adopting newer semantics. The private completion codec adds outcome
**3** with failure digest, retry instant and exact retired-checkpoint digest;
existing Retry/Issued outcomes **1/2** are unchanged. There is no SQL schema,
public HTTP API or dependency change. Restart requires the exact current claim
and completed checkpoint; outstanding manual-DNS cleanup tasks also prevent it.
Manual DNS may proceed from never-observed publication to removal/completion
only with matching durable retirement material, including recovery before the
operator task was first created.

Local focused checks under Rust 1.98.0 with four test workers passed: **60 ACME
tests in 0.07 seconds** (2.89-second build), **30 metadata ACME tests in 19.34
seconds** (8.80-second build), and **43 daemon certificate-order tests in 0.31
seconds** (29.80-second build). Coverage includes all four rejected authorisation
statuses, no false validated-name advancement, version substitution, exact
receipt rejection, expiry without CA IO, checkpoint refusal, CA-guided restart,
wrong retirement digest, early claim refusal, operation replay at a new log
position, and real SQLite reopen after all four apply fault points. The
repository fixture's sentinel secret bytes are checked for exact preservation;
that is not a new cryptographic key-recovery proof.
Affected ACME, metadata and daemon Clippy, all targets/features with warnings
denied, passed in **24.11 seconds**; Rust formatting and `git diff --check` passed.

Development failures were local: two new-test compile mistakes (a missing new
enum match and an owned rather than borrowed test authority), an extra expected
checkpoint commit where exact same-time replay returned the existing receipt,
and two repository fixture assumptions. The latter attempted reuse of a consumed
Raft log position and cryptographic decoding of the fixture's deliberately
synthetic secret row. The corrected tests use a fresh log position and assert
the sentinel bytes directly. Initial lint findings concerned duplicate match
arms, documentation, a boolean expression and the expanded transition function;
normal and retired cleanup now share their publication lifecycle owner. None of
these results closes the earlier unexplained cluster timeout.

At the initial progress commit, full integration validation and merge were pending.
This is not a new whole-process CA rejection/reissuance proof, live public-CA
acceptance, support for every CA error response, or completion of the remaining
DNS-provider lifecycle and active-gateway challenge distribution work. No
release, tag, package/image publication or GitHub Actions were run. Estimates
remain task 2 **3**, Stage 10 **142**, Stage 11 **126**: the production retirement
path and its focused persistence proof are integrated, but the whole-process
rejected-order/reissuance acceptance still needs to close alongside the other
remaining task-2 work. No unit-test result is being presented as that proof.

### Integrated independent-lifetime and takeover proof

The final opt-in HTTP-01 process-loss test passed in **325.02 seconds** on signed,
pushed, GitHub-verified commit `86be66f3876ed874944fe243e5352464982378ed`, tree
`0e5623d2d4be484c3be579c77d92fe9fcb47bc0e`. It ran the rebuilt test executable's
exact `acme_lifecycle::http01_authorization_recovers_after_process_loss_and_real_lease_expiry`
case with `--ignored --test-threads 4`. This replaces the earlier fixture replay
gap below. No production lease, clock or timeout was shortened: `SIGKILL`, real
disk state and the five-minute claim-expiry path were exercised before the
replacement restored the exact challenge and finished the same order.

The full NVM-default local command
`CARGO_BUILD_JOBS=4 MESHSPAN_CHECK_WORKERS=4 rustup run 1.98.0 pnpm check` passed
on that same source in **792.30 seconds**. Rust workspace tests took **717.65
seconds**, web tests **9.94 seconds**, Rust lint **45.33 seconds**, and web lint
**23.47 seconds**. Generated drift, embedded bundle, both licence gates,
formatting, TypeScript and tooling tests also passed. The isolated long-running
test used its already-built executable alongside the gate, avoiding a second
Cargo build competing for the build lock. No implementation edits followed the
gate; the closing changes are prose only.

[PR #246](https://github.com/KarlLivesey/MeshSpan/pull/246) integrates this slice.
The basic interrupted HTTP-01 process/lease takeover and independent publication
lifetime are now demonstrated: task 2 decreases **4 → 3 points**, Stage 10
**143 → 142**; Stage 11 remains **126**. This is not live-CA acceptance, a
multi-gateway challenge-distribution proof, an interrupted manual-DNS/Cloudflare/
webhook lifecycle or proof of publication-deadline exhaustion. The historical
unexplained cluster timeout is still an open Stage 11 finding; a passing gate
does not erase it. SMB-image, hardware and soak gates remain separate.

The next recovery boundary is explicit cleanup/retirement and authoritative
retry of unusable CA orders. Currently terminal machine errors can propagate
out of automation, and an expired retained publication cannot simply acquire a
new lifetime. That follow-up must keep ordinary transport retries distinct from
fresh-order retries, retain exact cleanup evidence and never treat a timeout as
proof that an order is invalid. No release, tag, package/image publication or
GitHub Actions were run; the publication hold remains in force.

### Independent publication lifetime and real expired-lease takeover

The `codex/stage10-task2-challenge-lifetime` candidate separates a publication's
retained lifetime from the current worker lease. The runtime proposes **24 hours**
for new challenge material. The internal drive policy accepts an explicit bounded
lifetime, longer than its request timeout and no longer than **seven days**. This
is a local publication budget, not a statement that the CA considers an order or
authorisation valid for that duration. The first authoritative checkpoint fixes
the exact expiry; later worker scheduling or replacement cannot extend it.

Requests remain bounded by the current claim. While a retained publication is
still live, the driver also caps the request deadline before that publication's
expiry. Claim expiration still discards the old execution and uses ordinary
fenced admission; no lease duration was increased and no automatic deadline
extension was substituted for takeover. The policy constructor gains a lifetime
argument; no SQL, HTTP or private wire format, dependency or persisted checkpoint
shape changes in this increment.

The new regression failed with `InvalidInput` in **0.02 seconds** after a
30.12-second build because publication could not outlive a claim. With the fix,
the final **39 certificate-order tests passed in 0.27 seconds** (10.41-second
build). The replacement restores the same original receipt, opaque epoch, exact
HTTP body and expiry after the old claim has expired. **Four metadata handoff
tests passed in 3.02 seconds** (16.04-second build), including an on-disk close /
reopen followed by natural lease expiry, one unchanged manual-DNS task, exact
TXT material/creation time/expiry, no-op replay and rejection of expired workers.
Affected all-target/all-feature Clippy passed in **2.02 seconds** after replacing
a seconds multiplication with `Duration::from_mins`; no suppression was added.

A new opt-in real-process test pauses the local TLS CA before processing an
authorisation poll or consuming its nonce, kills the daemon, restarts it, and
waits for the **actual five-minute lease** to expire. The CA independently probes
the restarted HTTP listener before accepting its next poll. It requires the exact
account-derived proof, one challenge notification, one order, one finalisation,
cleanup, another post-issuance restart and a second gateway receiving the same
certificate. The first execution passed in **322.28 seconds**, after a 17.23-second
build. Issuance orchestration was then separated from gateway-join orchestration
in the fixture; the final fixture replay and complete integration gate are still
pending. This test is deliberately outside the fast default suite and must be
invoked explicitly with `--ignored`; its ignored status is not itself evidence.

Remaining: publication-deadline exhaustion and invalid/expired CA order recovery,
manual-DNS and other provider full-process lifecycles, active HTTP challenge
distribution to other gateways and the separately tracked live-CA proof. No task
is closed by this candidate yet: task 2 remains **4 points**, Stage 10 **143** and
Stage 11 **126**. No release, tag, package/image publication or GitHub Actions were
run.

### Integrated publication recovery candidate

The complete local integration gate passed on signed, pushed and GitHub-verified
commit `aa4f5e8bdeaed2685d744e4f33c32777285f8305`, tree
`d012ed17b32415f8133c170da19797d4281f541e`, in **748.09 seconds**. Command:
NVM-default `CARGO_BUILD_JOBS=4 MESHSPAN_CHECK_WORKERS=4 rustup run 1.98.0 pnpm check`.
Rust workspace tests passed in **687.72 seconds**, web tests in **5.46 seconds**,
workspace Clippy in **34.53 seconds** and web lint in **20.27 seconds**. Generated
drift, embedded bundle, both licence gates, formatting, TypeScript and tooling
tests also passed. No source changes followed this gate; the integration evidence
and task-list updates are prose only.

[PR #245](https://github.com/KarlLivesey/MeshSpan/pull/245) integrates the three
recovery increments below: publication material retained before IO, exact
manual-task continuation across claims, and receipt-verified ordinary legacy
lifetime recovery. This supersedes their earlier unintegrated status; it does not
claim universal interrupted-order recovery. The historical unexplained cluster
timeout remains an open Stage 11 finding despite this passing run. Ignored SMB
image cases, live CA, hardware and soak proofs are not provided by this gate.

Task 2 remains **4 points**, Stage 10 **143**, Stage 11 **126**. The next lifecycle
work separates challenge lifetime from the five-minute worker lease and tests
expired/taken-over work without renewing old publication identity by assumption.
Actual interrupted-process issuance, remaining DNS-provider lifecycles and
active-gateway challenge distribution are still outstanding. Publication remains
on hold; no release, tag, package/image publication or GitHub Actions were run.

### Verified legacy publication lifetime

The checkpoint reader now exposes the original publication claim's retained
lease end as a read-only recovery candidate. It looks up the original opaque
publication fence, not the current worker's fence. The checkpoint bytes and
digest remain unchanged by this read. The executor verifies that candidate
against the original publisher receipt before checkpointing recovered material
or performing publisher IO. Missing or mismatched receipt evidence cannot be
silently replaced with the new worker's lifetime. This is not universal legacy
recovery: renewed original leases or different original publication lifetimes
still require exact evidence, and expired pending challenges remain separate work.

Format-3 `unprepared` state now remains unprepared when a worker changes: provider
IO was never permitted for that state. Its first publication uses the new worker
identity. Formats 1 and 2 retain their explicitly decoded legacy epoch. After a
recovered challenge finishes, its old lifetime candidate must not affect a new
unprepared challenge in the same execution. No SQL schema, wire command, HTTP
contract or dependency changed; the candidate is a Rust read-model addition.

The metadata regression first failed with `None` instead of the original
100-microsecond lease end in **0.24 seconds** (5.47-second build). The daemon
recovery regression failed with `InvalidInput` in **0.04 seconds** (21.75-second
build). A further regression caught the previous lifetime leaking into a fresh
challenge: **100 instead of 180**, in **0.05 seconds** (9.61-second build). After
the fixes, **12 execution tests passed in 0.10 seconds**, **22 ACME metadata tests
in 14.22 seconds**, and **58 ACME tests in 0.07 seconds**. The tests check the
unchanged protocol action/receipt, original publication epoch and expiry, current
worker fence, checkpoint-before-IO ordering and rejection without side effects.
They use checkpoint reconstruction/recording authority, not a daemon crash proof.

Affected all-target/all-feature Clippy passed in **10.83 seconds** after removing
an unnecessary reference in the historical fixture. The exact new SQL query was
extracted from source and explained against all current partition migrations
using NVM Node's in-memory SQLite: it uses the unique `(order_id, fence)` index,
without scanning claim history. That is query-shape evidence, not a benchmark of
the bundled Rust database. Both real-daemon HTTP-01/DNS-01 lifecycle cases passed
in **20.12 seconds** after a 23.55-second build, including post-issuance restart,
cleanup and second-gateway installation without another CA order. They still do
not interrupt unfinished authorisation. The final integration gate is outstanding.

This resolves the ordinary legacy-candidate integration gap recorded below,
alongside the retained manual-task ownership work. It does not close all of task
2: long-running publication/claim handling, interrupted real-process issuance,
remaining provider lifecycle proofs and active-gateway challenge distribution
remain. Task 2 stays **4 points**, Stage 10 **143**, Stage 11 **126**. Publication
remains prohibited.

### Manual-DNS task continuation across worker claims

The next increment on `codex/stage10-task2-publication-handoff` separates current
worker authority from the task's original creator. Both the observation/no-op
path and mutation path validate the live claim and exact checkpointed publication
inside their SQLite transaction. The original task must also match a retained
creator claim. A replacement worker can advance that same task without changing
its digest, creator fence, original creation time or expiry. The stale worker
remains rejected, and a satisfied phase still creates no revision or operation.

The metadata reader now receives the original publication epoch separately from
the current claim fence. It verifies that epoch against retained publication
material, including the actual immutable configuration revision and canonical
DNS owner name. The epoch is checked dynamically for each task: an order can
finish a handed-off challenge and subsequently publish another authorisation
under its current worker. No adapter-wide original-epoch cache is introduced.
Missing or substituted evidence cannot authorise cross-claim task continuation.
Legacy same-claim transitions remain supported; complete legacy lifetime
recovery and long-running publication handling are still unfinished.

Operation and audit identity domain **2** includes the order and complete current
claim identity as well as the task, phase and occurrence time. Two workers at the
same clock instant must not share an operation identity merely because they now
share the original publication. Previously committed phases are still resolved
by the authoritative no-op observation. Task digests, authoritative command
encoding and SQL tables are unchanged; no migration or dependency was added.

The handoff regression failed at the exact replacement-task observation in
**0.24 seconds**, after a 12.11-second build; a diagnostic-only rerun confirmed
that the fixture itself had succeeded. After the fix, all **21 ACME metadata
tests passed in 13.10 seconds** (3.41-second build). The handoff case was then
extended to close and reopen an on-disk SQLite database; both handoff acceptance
cases passed in **0.95 seconds** (3.47-second build). They assert one unchanged
task identity, original creator/expiry, exact phase/revision, no-op replay, stale
worker rejection, wrong publication-epoch rejection, and refusal of missing or
substituted checkpoints. A rejection fixture initially skipped a log index and
therefore returned `InvalidLogPosition`; its input sequence was corrected before
asserting the intended `InvalidCommand`, without changing production behaviour.

The daemon's **9 manual-DNS cases passed in 0.09 seconds** after a 35.52-second
build. All **58 ACME cases passed in 0.07 seconds** after a 7.55-second build.
Affected all-target/all-feature Clippy passed in **30.22 seconds**; formatting and
diff checks passed. The exact revised task query was extracted from source and
explained against the current migrations in in-memory system SQLite: it uses
the task-digest primary-key index and the historical claim's order/fence index,
without scanning task history. This is query-shape evidence, not a throughput
benchmark or a real multi-daemon manual-DNS interruption proof.

This remains an in-progress branch without a final full integration gate. Task 2
stays **4 points**, Stage 10 **143**, Stage 11 **126**. No release, tag, package,
image publication or GitHub Actions were run.

### Publication identity handoff — in-progress branch

The current `codex/stage10-task2-publication-handoff` candidate checkpoints exact
HTTP/DNS publication material before publisher IO. It retains the original
identifier, payload/version, provider revision, opaque publication epoch and
expiry independently of the current worker claim. Later scheduling inputs do
not extend that expiry. Signer-derived material must still match the retained
record before publication or cleanup. Providers expose a pure expected-receipt
calculation; calculating it is not evidence that anything was published, became
visible or was removed.

A replacement worker keeps the original CA phase. Restoration of a lost HTTP
catalogue republishes and verifies the exact retained material without notifying
the CA again, changing its polling schedule or checkpointing fictitious progress.
A valid authorisation instead stays in cleanup, using its original receipt even
after expiry. Candidate machine changes become locally executable only after
their checkpoint succeeds; failed prepublication commits remain unpublished on
retry. These changes are not yet a complete manual-DNS handoff implementation.

Checkpoint format **3** adds an explicit publication-state field. Formats 1 and 2
remain readable in every original phase; absent old publication material is
represented as legacy evidence, not silently replaced by the new worker's
identity. New binaries write format 3 on their next authoritative checkpoint;
old binaries cannot read it. No SQL migration, dependency or HTTP API changed.
Recovery of legacy lifetimes across claim changes is still incomplete: a
candidate lifetime cannot be bound to a published legacy record unless its exact
expected receipt matches. This branch must not be merged as completed handoff
work before that integration and manual-task ownership are addressed.

The daemon prepublication regression first failed in **0.02 seconds** after a
37.78-second build: the HTTP response was already visible before its material
had been checkpointed. After the change, **34 certificate-order daemon tests
passed in 0.23 seconds** (34.00-second build), and **57 ACME tests passed in 0.08
seconds** (5.73-second build). Tests cover checkpoint failure and retry, exact
expiry despite changed scheduling inputs, a lower-valued replacement fence,
catalogue reconstruction without another CA request, and expired cleanup with
both populated and empty catalogues. These handoff cases use recording authority
and checkpoint encode/decode, not real consensus/process-crash proof.

Both real-daemon HTTP-01/DNS-01 issuance, post-issuance restart and gateway-join
tests also passed in **20.07 seconds**, after a 38.36-second build. They preserve
the existing one-order/one-finalisation and successful-response polling checks.
They do not yet interrupt the daemon during an unfinished authorisation.

Affected all-target/all-feature Clippy passed in **17.00 seconds** after fixing
collapsible conditionals, duplicate match arms and a runtime wildcard import;
no suppression was added. Formatting passed. The current branch has not passed
the full integration gate. Task 2 remains **4 points**, Stage 10 **143**, Stage 11
**126**: legacy lifetime recovery, long-running publication/claim handling,
manual-task ownership transfer, remaining provider process proofs and active
gateway challenge distribution remain open. No release, tag, package/image
publication or GitHub Actions were run.

### Integrated cleanup and manual-DNS polling candidate

The complete local gate passed on signed commit
`cf277358f2a0a5ddf7cf888aafb55da84731c957`, tree
`dfca2f599625d426f447a7d03cbe57608cd9eef0`, in **1,011.68 seconds**.
Rust workspace tests passed in **886.89 seconds** and web tests in **9.57 seconds**.
Generated drift (2.75 seconds), embedded bundle (1.45), Rust format (3.62), Rust
lint (82.42), Rust licences (0.68), JavaScript licences (1.27), workspace format
(5.03), web lint (33.86), web typecheck (11.69) and tooling tests (1.61) passed.
The candidate remained unchanged throughout this run. Ignored or external tests
are not covered by this result; publication remains prohibited.

The exact invocation, from a non-login Bash shell after sourcing NVM and selecting
the repository default (Node 26.8.1, pnpm 11.19.0), was:

```sh
CARGO_BUILD_JOBS=4 MESHSPAN_CHECK_WORKERS=4 \
  /Users/karllivesey/.cargo/bin/rustup run 1.98.0 pnpm check
```

Read-only investigation found that login shells selected Homebrew Rust while
non-login shells selected rustup. Although both reported Rust 1.98.0 and the same
upstream commit, their Cargo compiler fingerprints differed. Alternating them
invalidated compiler caches and made prior timing comparisons inconsistent. This
gate explicitly used rustup for the harness and its children; no global shell or
tool installation was changed. This finding does **not** explain or close the
earlier cluster-admission timeout. Its diagnostic state retention stays in place;
no timeout or concurrency assertion was relaxed to obtain this pass.

The two exact manual-DNS runtime queries were also extracted and explained against
all current partition migration SQL in an in-memory system SQLite database.
Claim validation used indexed order/fence, order identity and configuration
identity lookups; task observation used the existing order/fence/task-digest
index. There was no task-history scan. This checks query shape on system SQLite,
not bundled-engine performance or a real daemon restart.

This closes validation of the current cleanup and no-op polling slice, not all
interrupted-order recovery. Task 2 remains **5 points**, Stage 10 **144**, and
Stage 11 **126**. Original publication identity/lifetime across worker handoff,
long-running manual tasks, successful-response polling guidance, remaining DNS
provider process proofs and active-gateway challenge distribution remain open.

PR #243 subsequently merged into `main` at
`026e9e8e66e11117a9d503c123d21488487fdab0`; GitHub verified the signed evidence
commit and merge. Both local and remote completed branches were removed.

### Successful-response polling guidance

The next candidate carries validated `Retry-After` from successful order,
challenge-notification, authorisation and finalisation responses into the order
machine. When polling remains necessary, the checkpoint retains an absolute
not-before instant derived from response receipt time, not request start. The
daemon returns pending without CA IO or another checkpoint until that instant;
it does not sleep inside the worker or spend its step budget polling the CA.
Completion of validation/issuance clears the delay so cleanup/download can
proceed immediately. This follows the processing/polling guidance in
[RFC 8555 §§7.4 and 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).

Checkpoint format **2** adds the explicitly nullable `poll_not_before` field.
The decoder still reads every original format-1 phase without that field and
rejects missing format-2 fields, version substitution, malformed timestamps and
deadlines attached to impossible phases. Reading format 1 does not rewrite its
stored bytes or digest; the next normal authoritative checkpoint writes format 2.
Old binaries cannot read the new format: this is an explicit pre-alpha forward
format change, not a claim of mixed-version downgrade compatibility. SQL schema,
HTTP API shapes and dependencies are unchanged. The in-process executor gains
an explicit progress-with-retry outcome.

The immediate-poll regression first failed with `Worker(Transport)` in **0.03
seconds**, after a 24.31-second build: a single successful response requested a
120-second wait, but the worker immediately requested another response. It passed
after correction in **0.02 seconds** (21.28-second build). Broader evidence:

- Five execution cases passed in **0.05 seconds**. A response received at second
  21 with a 120-second hint retains second 141 through checkpoint decoding and
  a replacement fence. Calls before that exact instant produce no extra requests
  or commits; the request at second 141 proceeds. Malformed guidance leaves the
  machine and authority unchanged. This uses a recording authority/transport,
  not a physical crash or on-disk recovery proof.
- All **30 certificate-order daemon tests passed in 0.20 seconds**. Final ACME
  coverage passed **55 tests in 0.07 seconds**, after a 3.89-second build. It
  includes all successful polling transitions, both time forms, duplicate hints,
  old checkpoint compatibility and immediate cleanup/download after success.
- Both existing real-process HTTP-01/DNS-01 lifecycles passed in **19.94 seconds**
  after a 37.38-second build. Their TLS CA now announces two-second delays after
  notification and finalisation and permanently records any early request as a
  failed proof. Both deadlines must be observed alongside exact one-order/
  one-finalisation issuance, cleanup, restart and gateway delivery. These are
  local CA proofs; the process restart is after issuance, not during a delayed poll.
- Final affected all-target/all-feature Clippy passed in **22.22 seconds**;
  formatting and diff checks passed. Earlier lint failures rejected a test-fixture
  `expect` and nested options at the versioned decoder boundary. Errors now
  propagate, and a named absent/present field enum expresses the three states;
  no lint suppression was added.

The final full local gate passed on signed commit
`c48a0781dfb7282022a5be7a67e2c46a500aafb4`, tree
`87fff0bbe5e5b9fcd7b7d823d9f5b9ddafb61276`, in **751.75 seconds**. Rust workspace
tests passed in **688.03 seconds** and web tests in **5.69 seconds**; every
generated/static/licence lane passed. The exact invocation was the non-login
Bash/NVM/rustup command recorded above, with four compiler jobs and four harness
workers. The source candidate stayed frozen. This is not a controlled performance
comparison with earlier runs or an explanation of their admission failure.

This closes successful-response polling guidance: Task 2 **5 → 4 points**, Stage
10 **144 → 143**, Stage 11 unchanged at **126**. PR #244 contains this candidate.
Original publication identity/expiry across handoff, long-running claims/manual
tasks, remaining provider process lifecycles and active-gateway challenge sharing
remain required; no external CA, physical failure or publication gate is closed.

Manual-DNS polling now checks the exact retained task and live claim before
proposing another transition. The claim and task are read in one SQLite read
transaction; a satisfied phase creates no operation, audit entry or revision.
An absent task or genuinely later phase still goes through the normal
authoritative command and its receipt checks. Identity mismatch, expired or
replaced claims, superseded tasks and unavailable observations cannot take the
no-op path. This is not an in-memory success cache, lease renewal or a new grant
of authority; subsequent writes retain their normal authoritative checks.

The old timestamp-derived operation identity caused two commits when the same
request was polled at times 10 and 11. The regression failed in **0.01 seconds**
after a 2-minute-25-second build. It now passes with one commit across advancing
clocks and adapter reconstruction. A separate SQL regression proved that manual
task writes were incorrectly accepted exactly at claim expiry (**0.63 seconds**,
38.65-second build); both observation and mutation now use exclusive lease
expiry. Cleanup still permits the original publication expiry to be in the past.

Verification for this slice:

- Seven focused metadata cases passed in **5.03 seconds** after a 13.94-second
  build. They cover every claim/publication field, missing tasks, unchanged
  revisions, later/earlier phases, expiry and hostile superseded state.
- Eight daemon manual-DNS, projection and API cases passed in **0.19 seconds**
  after a 24.63-second build. Lost commit replies recover from confirmed task
  state without another write; unavailable/stale reads do not fall back to writes.
- All 19 ACME metadata cases passed in **17.41 seconds**. Affected all-target/
  all-feature Clippy passed first in 1 minute 15 seconds, then in **13.42 seconds**
  after the additional tests. Formatting and diff checks passed.

The database cases use the existing SQLite fixtures, and adapter reconstruction
uses a recording authority; these are not a full daemon restart or manual-DNS
wire-lifecycle proof. No schema, persisted record format, wire message or dependency
changed. Task 2 remains **5 points**, Stage 10 **144**. The failed full gate recorded
below remains unresolved, and this slice has not been merged.

After the preceding candidate reached `main`, two new HTTP-01 cleanup regressions
failed with `NotFound` in **0.00 seconds** (18.69-second build): replay after a
successful removal, and receipt validation against an empty restarted catalogue.
Cleanup now verifies the complete request-derived receipt before inventory lookup,
then accepts exact absence. An existing replacement publication still returns
`Stale` and its exact response bytes remain unchanged. This does not accept an
unknown or mismatched receipt merely because its token is absent.

All **47 ACME tests passed in 0.06 seconds** after the correction (3.56-second
build); all-target/all-feature ACME Clippy passed in **18.35 seconds**. Formatting
and diff checks passed. No dependency, schema or wire shape changed. This is a
focused provider correction, not complete interrupted-order recovery or a fresh
full integration gate. Task 2 remains **5 points**, Stage 10 **144**.

The next recovery boundary must separate a live worker claim from the original
publication identity, receipt and expiry retained for cleanup. A new claim must
not reconstruct an old publication with new expiry/fence values, nor send a
completed authorisation back through notification merely to obtain a new receipt.
Coverage must include already-valid authorisation cleanup, same-worker restart,
replacement-worker restart, stale cleanup against a replacement, and checkpoint
round-trips. Persisted-state handling must be explicit before changing the
checkpoint shape; this is not permission to discard a checkpoint or weaken its
authority binding.

Cleanup now has separate expiry validation from publication/visibility. Its
current operation deadline may outlive the original publication expiry, while
the original expiry remains part of the exact receipt identity. HTTP-01,
automatic DNS-01 and manual DNS-01 share this rule; they continue rejecting
invalid identity/configuration, non-positive time fields and mismatched receipts.
Publication and visibility still require expiry beyond the request deadline.

Four provider regressions failed with `InvalidInput` before that change
(**0.07 seconds**, 2.37-second build), including real signed RFC 2136 removal
after provider reconstruction at a later supplied clock time. An initial test
compile failure shadowed the settings helper; the fixture binding was renamed
before collecting those regression results. All 48 cases then passed in
0.06 seconds. A separate executor regression reproduced its duplicate expiry
guard (**0.00 seconds**, 2.38-second build). That guard now applies to publication,
not cleanup; the executor test verifies retained-receipt cleanup without any CA
request or republication. The final **49 ACME tests passed in 0.11 seconds**
(4.48-second build), and affected Clippy passed in **3.22 seconds**. Formatting
and diff checks passed. The checkpoint still needs to supply the original
publication fields during worker replacement; this does not close that remaining
integration requirement. No persisted shape or dependency changed.

Manual DNS cleanup now distinguishes a durable removal request from confirmed
removal. The challenge-provider contract returns an explicit `Pending` or
`Complete`; the executor emits `ChallengeCleaned` only for the latter. The daemon
forwards that result through every built-in provider choice. HTTP and automatic
DNS retain their synchronous removal behaviour, while manual DNS waits for an
authoritative observation that the exact TXT value is absent.

The executor regression first failed with `Advanced(ChallengeCleaned)` where
`Pending` was required (**0.01 seconds**, 2-minute-14-second build). It now checks
pending removal, reconstruction of the manual provider with the same task,
continued pending status, observed absence, and exact completed-cleanup replay.
Unexpected CA transport calls fail the test. Existing manual-provider coverage
also asserts the explicit pending/completed results. All **50 ACME tests passed
in 0.06 seconds**. The first affected lint run rejected an unnecessarily async
test transport; it now returns a ready future without a lint suppression. The
post-correction ACME run again passed all 50 tests in **0.06 seconds**.

This changes the in-process Rust provider interface, not SQL, persisted
checkpoints, network messages or dependencies. Provider reconstruction in this
focused test is not a daemon crash or durable metadata proof. Long-running claims,
original-publication checkpoint recovery and manual-DNS process acceptance remain
open; task and stage estimates are unchanged. Broader validation and integration
will be recorded below when they actually finish.

Affected all-target/all-feature Clippy passed in **15.53 seconds** after that
test-transport correction. The 27 daemon certificate-order regressions passed
in **0.19 seconds**, following a 1-minute-8-second build. Commit `8136ac8` was
signed, pushed and verified by GitHub; PR #243 is open, not merged.

The full local gate on `8136ac8cd372c820391df8d4852c9c96df5b36c0`, tree
`1df930f4dbe64a8ac9ad82ec96019e3d63053e2c`, **failed in 610.81 seconds**. All
static/licence lanes and web tests (10.87 seconds) passed. Rust workspace tests
failed after **442.13 seconds** in the three-process cluster suite: six cases
passed, but `three_process_cluster_survives_lost_reply_and_leader_restart` timed
out waiting for node 2's `FOLLOWER_WITH_LEADER` response. Its control connection
was refused, its log was empty and all three children were still alive.

That proof node binds its control listener only after learner snapshot admission
and repository restoration. The available evidence therefore does not distinguish
process startup, snapshot delivery and installation. The targeted recovery proof
now retains its owned temporary state on admission/failover failure and reports
whether the node database exists. No timeout, concurrency, protocol or acceptance
assertion was weakened. A passing diagnostic rerun alone cannot close this failure;
the candidate remains unmerged and the goal remains active.

The diagnostic three-process suite passed all **seven cases in 24.39 seconds**
with four test threads and the unchanged 15-second per-operation wait, after a
2-minute-56-second build. No failed workspace was retained because no case failed.
The initial diagnostic command stopped at Rust formatting; formatting was applied
before the actual test run. This successful rerun does not identify or fix the
full-gate failure.

A read-only host observation during that diagnostic build reported 12 logical
CPUs and load averages **252.95 / 210.47 / 128.38**, with 3,109,958 compressed-memory
pages at 16,384 bytes per page. Those observations make timing/performance
comparisons unreliable; they are context, not proof that host load caused the
earlier failed admission. No unrelated process, host setting, wait limit or test
concurrency was changed. The proof executable's CPU-sized Tokio worker pools are
an investigation lead, not an implemented correction or established root cause.
The diagnostic harness passed affected all-feature Clippy in **39.03 seconds**,
with this owned compiler invocation bounded by `CARGO_BUILD_JOBS=4`. Rust
formatting and `git diff --check` passed. No second full-gate retry was run and no
merge is claimed.

## Task 2 — real DNS-01 issuance, restart and gateway delivery

The existing real-process lifecycle now also runs RFC 2136 DNS-01 through the
public certificate-provisioning API. Two daemon processes use a local TLS CA and
an independent signed-DNS transcript verifier. The verifier checks the exact
zone, TXT operation, TTL, TSIG identity/signature and exact-value deletion. Two
separate authoritative queries prove daemon propagation and CA validation; the
CA derives the expected TXT value from its independently authenticated JWK.
An additional query proves the completed record is absent.

The shared lifecycle checks certificate-backed HTTPS, restart, second-gateway
installation and exactly one CA order/finalisation. It does not export the
daemon's private key, change OS DNS/trust, use the browser or contact a public CA.
The existing RFC 2136 fixture is reused directly by the integration test, not
exported from a production library. The fixture's fixed-clock unit mode remains;
real processes use current-time TSIG responses. Its completion is bounded and a
dropped fixture cancels its owned task.

Focused verification:

- `cargo test -p meshspan-acme rfc2136_provider_tests -- --nocapture`: all three
  passed in **0.00 seconds**, after a 10.11-second build.
- `cargo test -p meshspan-daemon --test headless_process acme_lifecycle -- --nocapture`:
  HTTP-01 and DNS-01 passed together in **16.17 seconds**, after a 4.38-second build.
  An initial compile error used the wrong test query constructor; it was corrected
  to the existing fallible `DnsQuery::txt`. No process test failed.
- Affected all-target/all-feature Clippy with warnings denied passed in
  **21.28 seconds**. Rust formatting and `git diff --check` passed.

The first full `pnpm check` on `ded7810`, tree
`60118e27812acf25a8923aee89e57726b40eca2c`, failed in **270.51 seconds**. Static
lanes and web tests passed; the Rust lane failed in the DNS process proof because
the daemon's SMB bind returned `AddrInUse`, before any CA request. The competing
owner was not captured. Diagnostic-only parallel reruns passed in **41.26** and
**28.02 seconds**; these did not establish a cause or close the failure.

Certificate lifecycle tests never connect to SMB, so they now request an
OS-selected SMB port (`:0`), atomically allocated by the real daemon's bind. The
service still starts normally, but this test no longer has an unnecessary
probe-to-child-start race for an unused fixed SMB address. The error path also
records every allocated root/peer listener address. This removes that collision
opportunity for these two proofs; it does not claim all fixed-address process
fixtures are now race-free. The full focused headless suite then passed in
**32.46 seconds** (eight passed, two container-dependent tests explicitly ignored),
after a 2.81-second build. No timeout increase or serialisation was introduced.

The corrected candidate `bf98d56`, tree
`4d887e01333bbf64a39b1e1b82303a7ecdd5831c`, failed its full `pnpm check` in
**440.23 seconds**. Static lanes and web tests (9.58 seconds) passed; Rust workspace
tests failed after 404.24 seconds. Both certificate process workflows passed.
The operator workflow received a TLS EOF with both children still alive, and
the metrics workflow timed out waiting for a configured HTTPS listener. The
operator fixture's retained operation history places its failure before file
uploads; encrypted backup export is being investigated. The metrics failure did
not retain enough context to distinguish root restart from peer join. Neither
failure is explained or closed by the earlier passing focused runs. Request
framing and metrics-phase/child-state diagnostics have been added without
weakening assertions, increasing timeouts or serialising tests.

The next diagnostic-focused parallel headless run passed those two workflows and
both certificate lifecycles, but failed the three-node join proof (**38.05 seconds**,
seven passed, one failed, two ignored). The child reported only `HeadlessNodeJoin`.
The daemon now preserves the join phase and closed, redacted error category, and
the three-node fixture retains failure state. This changes diagnostic detail only;
it does not retry, accept an invalid response or alter join behaviour.

Further diagnostic runs failed in **59.46**, **43.55** and **45.54 seconds**;
the last two explicitly selected NVM Node 26.8.1. The failures now identify live
peers missing HTTPS readiness after join. A retained peer's local setup record is
already complete, so these observations are not evidence of failed admission.
The single three-node workflow passed in **26.14 seconds**; that does not close
the parallel failure. Native stack sampling during a further **44.02-second**
failing parallel run places repeated repository opening, schema parsing and
integrity checks inside service composition before public listeners are bound.
Sampling adds overhead and is diagnostic evidence, not a performance result.
Inspection also found unconditional schema-marker updates on current database
reopens; a held-writer regression is being added before changing that boundary.

An intermediate system-process listing was incorrectly attributed to a Node
child of this suite. Inspection confirms its panel checks use Rust over HTTPS;
no such Node child is launched. Node version is not an established failure cause.

The focused database regressions both reproduced `DatabaseBusy` on a current
database reopen while another connection held a writer transaction (**5.49 seconds**,
43.67-second build). Binding now reads the existing identity/schema first and
does not rewrite an already-current marker. Creation, migration, mismatched
identity rejection and full existing integrity checks remain intact. All **49
database tests passed in 13.28 seconds** after correction (5.75-second build).
The parallel process effect and full integration still require verification;
this evidence does not yet close the startup or backup-transfer failures.

The first unprofiled parallel run after that correction passed all startup,
join and certificate workflows in **31.57 seconds**; seven cases passed, while
the operator workflow now failed at restore-readiness with HTTP 503 after its
encrypted export passed. Both child processes remained alive. Affected metadata
and daemon all-target/all-feature Clippy passed with warnings denied in **33.58
seconds**. The no-op writer-lock defect is reproduced and corrected, but this
single run is not a claim of exhaustive startup proof. Inspection of the backup
path found that provider snapshots use `try_lock` on the entire storage runtime,
so ordinary maintenance contention can become an export/restore failure. That
boundary is the next focused investigation, not an accepted 503 workaround.

The real-runtime lock regression reproduced `Unavailable` in **0.56 seconds**
(31.39-second build) while holding only the maintenance mutex. Backup provider
inventory now has its own shared catalogue, used by export, restore, background
backup and the data router. Its guards cover handle lookup and replacement, not
provider open/close/transfer IO or the surrounding maintenance cycle. No duplicate
provider cache or second source of authority was introduced. Existing destination,
generation, current permission, receipt and ciphertext checks are unchanged.
The focused backup suite passed **49 tests in 5.45 seconds**, after a 22.36-second
build. A final guard-scope review also moves retired provider destruction outside
the catalogue mutex. The next parallel process run still failed joined-node
readiness (including the three-node, operator and DNS workflows); its final
summary was not retained, so no aggregate count or duration is claimed. These
failures do not close the startup investigation. The final focused backup run
passed **49 tests in 8.82 seconds** after an 11.66-second build. Clippy then found
an unnecessary owned route-composition argument; after using references instead,
all-target/all-feature daemon Clippy passed in **20.05 seconds**, with formatting
and diff checks also passing.
The real CLI/public-HTTPS operator workflow then passed in **13.75 seconds**
(16.80-second build), including encrypted export and isolated restore checking.
This verifies the backup integration in that workflow, not parallel startup.

No dependency, schema or protocol changed. Full local
integration remains incomplete for the corrected slice; task 2 stays at **6 points** and Stage
10 at **145** until that gate passes. Cloudflare/webhook/manual lifecycle,
interrupted and long-running orders, successful polling hints and active gateway
challenge distribution remain open. No publication or Actions ran.

## Task 2 — response-time deadlines and normal claim expiry

The certificate driver now owns cancellation of each external action rather than
relying on a replaceable transport to honour its deadline. It rereads the supplied
clock after IO, rejects late responses before advancing the machine and timestamps
successful checkpoints at receipt time. Expired claims yield a normal outcome
that clears the active execution for fenced admission on the next worker pass;
they do not submit checkpoint, completion or retry commands under expired authority.
Corrupt state and ambiguous authoritative commits still fail closed.

Five original regressions all failed before implementation in **0.13 seconds**
(88-second build): stale checkpoint time, accepted late response, mutation after
claim expiry, fatal pre-expired claim and an unbounded transport future. The
corrected certificate-order suite first passed 25 tests in **0.20 seconds**.
Two additional exact-boundary regressions then reproduced fatal `InvalidInput`
when the lease elapsed between admission and execution (**0.04 seconds**) and
when only its last microsecond remained (**0.08 seconds**, six other cases passed).
Expired execution deadlines are now distinct from invalid structure; the last
microsecond waits without starting an impossible challenge-request interval.

`cargo test -p meshspan-daemon --lib certificate_order_ -- --nocapture` passed
all **27 tests in 0.39 seconds**, after a 37.94-second build. Tests use per-test
clocks, exact mutation counts and observed future cancellation, not global time
changes or provider sleeps. The stalled transport's worker deadline remains
10 milliseconds; its separate two-second deadlock watchdog is not a performance
claim. Affected all-target/all-feature Clippy with warnings denied passed in
**134 seconds**. Rust formatting and `git diff --check` passed. No dependency,
schema or wire format changed. Full local integration remains required before
merge. Lease renewal, interrupted challenge
recovery and successful CA polling hints remain separate open task-2 scope.

### Combined candidate and bounded Rust test scheduling

Signed merge `9942e63` combines DNS lifecycle and certificate deadlines on the
candidate branch, not on `main`. The combined tree passed all **27 certificate-order
tests in 0.40 seconds** after a 19.24-second build. Both source histories remain
intact; neither PR is claimed merged into `main` yet.

Inspection found that `MESHSPAN_CHECK_WORKERS` bounded outer lanes but was not
passed to Cargo's Rust test harness. In this suite, each harness case additionally
launches multiple real daemon processes. An unchanged combined-candidate run with
four concurrent test cases passed **all eight active process tests in 34.62 seconds**
(13.69-second build); the two existing container-image-dependent cases remained
explicitly ignored. No readiness deadline, assertion or case topology changed.

The canonical runner now passes its existing selected worker count to the Rust
harness, retaining workspace/all-target/all-feature coverage. Five scheduler
tests passed in **0.05 seconds**, including exact command arguments and rejected
invalid budgets. The new test first failed because this scheduling boundary did
not exist. Targeted ESLint, formatting and diff checks passed. This is bounded
test scheduling, not a daemon startup optimisation: the earlier higher-concurrency
timeouts remain observed evidence for startup-cost and scale measurements. It
does not establish a maximum supported mesh size. The combined candidate still
needs the complete local integration gate before `main` integration.

The complete local `MESHSPAN_CHECK_WORKERS=4 pnpm check` then passed on signed
commit `510748ff7ece1404ec7fee47b402f34cea7b8476`, tree
`1dc4a5c18fdebe9e9c51a164eb8b7be1d165258c`, in **892.62 seconds** under NVM
Node 26.8.1 and pnpm 11.19.0. Rust workspace/all-target/all-feature tests passed
in **803.13 seconds**; web tests passed in **6.69 seconds**. Generated drift,
embedded bundle, Rust/web formatting, Clippy, ESLint, TypeScript, both licence
checks and tooling tests passed. The tested source remained unchanged throughout,
and no competing Cargo build ran. This is successful bounded integration, not a
claimed test-speed improvement or closure of higher-concurrency startup costs.

This closes the basic DNS-01 issuance/restart/gateway-delivery slice alongside
the tested response-deadline and backup/database corrections. Task 2 decreases
**6 → 5 points** and Stage 10 **145 → 144**; the remaining certificate lifecycle
and delivery tasks remain open. The two container-dependent SMB cases were not
part of this proof: a read-only Docker inspection confirmed the named local
`meshspan-smbclient-test:bookworm` image is absent. No live-CA, physical-hardware,
soak or publication proof is claimed. No releases, tags, images or Actions were
published or run.

PR **#241** merged into `main` at `eae170a2774a028aee22cfc5da95c1946b01ad6f`;
GitHub reports that merge signature verified. PR **#242** also reports merged
through the contained signed merge `9942e63`. Both feature heads are ancestors
of `main`. Their local and remote branches were removed, along with the clean
temporary deadline worktree; committed source and evidence remain in `main`.

## Task 2 — real HTTP-01 issuance, restart and gateway delivery

The new `headless_process::acme_lifecycle` proof runs real child daemons and a
local TLS test CA. The CA checks ES256 signatures, account binding, single-use
nonces, exact order names, the actual HTTP-01 response and the public CSR's
signature/name/key binding. It never reads the daemon's private key. The workflow
checks certificate-backed TLS, challenge cleanup, restart, a second gateway's
installation and **exactly one CA order/finalisation** throughout.

The first successful process run passed in **16.82 seconds**, following a
23.77-second incremental build. Earlier failures identified and reproduced:

- Nested runtime entry: the certificate worker's asynchronous pass called the
  synchronous consensus adapter's `block_on` while already inside `block_on`.
  The daemon panicked before contacting the CA (19.60-second red process run).
  The synchronous adapter now explicitly enters a blocking section before its
  async commit/forwarding path. It retains the existing owned blocking worker.
- Unpersistable claim fences: deterministic entropy seed 128 generated
  `11574711341044573863`, outside SQLite's signed integer range. The regression
  failed before correction; fences now use 63 unpredictable bits and retain the
  non-zero check. Four dispatcher regressions pass.
- Successful challenge status: an authorisation poll changed its challenge from
  `pending` to `valid`, but the selected challenge retained the old status and
  failed checkpoint validation. Existing fixtures incorrectly left it pending.
  Correcting the fixture reproduced `CorruptState`; the machine now tracks status
  changes while rejecting token/URL substitution. All 45 ACME tests passed in
  **0.08 seconds**. The process then reached certificate download.
- Terminal hand-off: downloaded chains were sent to the incomplete-checkpoint
  service, which explicitly rejects terminal state. The focused regression
  failed with `Checkpoint(InvalidInput)` in **0.03 seconds**. Chains now pass to
  the existing trust validation and atomic completion transaction. Until that
  commits, recovery retains the prior download checkpoint, not an unvalidated
  terminal certificate. Both execution tests pass in **0.03 seconds**.

The other red process runs took 19.91, 19.83 and 20.23 seconds as those distinct
boundaries were reached; no timeout was increased. A later 9.76-second failure
was a fixture error: the generic node-certificate constructor expires in year
4096, outside the public API's safe timestamp range. The certificate library now
offers explicit, bounded, server-only public-identity signing, used by the test
CA for a 90-day leaf. Exact names/key/validity/usage and invalid bounds are tested.
The API timestamp limits were not relaxed.

The certificate library's 16 tests passed in **0.14 seconds**, and the 20
certificate-order tests passed in **0.17 seconds**. The dedicated real-consensus
worker-context regression initially compared `Applied` and `Replayed` dispositions
as equal; that fixture assertion is corrected while checking every receipt field.
All ten real-consensus boundary tests then passed in **7.44 seconds**. The final
process proof rerun passed in **17.52 seconds** after an 11.42-second build.
Affected all-target/all-feature Clippy passed with warnings denied in **7.71
seconds**, following corrections to fixture field ordering and an unnecessary
owned argument. `cargo deny check licenses` and `git diff --check` passed.
The final `pnpm check:dependency-update` passed on signed commit `7fb130c`, tree
`d1a83a0088db57d25b3883dacb104a0c68cf301f`. Its integration gate took **909.68
seconds** with four workers; Rust workspace tests took **776.10 seconds** and web
tests **10.38 seconds**. All static/generated, advisory and licence lanes passed.
This includes the new default process proof, not ignored or external-service tests.

Only development dependency edges to already-resolved `base64` and `x509-parser`
were added; their MIT options remain subject to the existing allow-only gate.
No persistence or public API schema changed. The public-identity signing method
is an additive Rust library interface with a concrete test-CA consumer.

Integration closes the basic HTTP-01 lifecycle slice: task 2 falls **7 → 6 points**,
and Stage 10 **146 → 145 points**. This
proof does not yet cover worker interruption during issuance, long-lived/manual
challenges, successful-response polling hints or publishing an active challenge
on every gateway. DNS lifecycle and live-CA acceptance remain open. No releases,
tags, publication or Actions ran.

## Task 2 — CA-directed error retry deadlines

The ACME executor previously collapsed error responses into a generic protocol
failure and the daemon driver always supplied `None` to the retry scheduler.
The new regression observed **361,896,937 µs** instead of the CA-directed
**3,620,000,000 µs** deadline and failed in **0.04 seconds** before correction.
A second regression proved that the existing seven-day cap shortened an eight-day
CA deadline; it failed in under **0.01 seconds**.

Typed retry guidance now crosses unsigned GET/HEAD and signed POST execution,
including an error after the sole bad-nonce retry. Seconds and all three HTTP-date
formats are parsed without consulting host time. Duplicate, malformed, signed,
fractional and overflowing fields fail protocol validation; they never trigger
an inline retry. Relative delays use authority-aligned response receipt time,
not request start. Local exponential backoff remains bounded, but no longer
shortens a valid later CA deadline. Existing order administration exposes the
queued deadline. There is no schema migration or public API change.

Two real localhost TLS proofs pass through the Rustls ACME client, executor,
driver and retry service. They assert one remote request, the exact retry command
and receipt, no checkpoint advancement, an absolute HTTP date, and a relative
delay after five seconds of controlled response latency. The authority here is
a recording fixture: this proves wire-to-command composition, not new SQLite,
multi-process restart or public-CA acceptance.

The complete ACME crate's **44 tests passed in 0.07 seconds**; the final focused
daemon run's **18 certificate-order tests passed in 0.13 seconds** after a
17.37-second incremental build. Affected all-target/all-feature Clippy passed
with warnings denied in **6.52 seconds**. An earlier Clippy conversion-style
failure was corrected without an exception. Rust/JavaScript advisory scans and
the Rust licence check passed. The final `pnpm check:dependency-update` on signed
commit `d83002b`, tree `c2c7dab8fbb6cb5c0fecb0936ddff4c725f0c7d0`, passed.
Its integration gate took **1,059.56 seconds** with four workers, including Rust
workspace tests in **936.18 seconds** and web tests in **10.63 seconds**. This
is slower than task 1's prior gate; no test-speed improvement is claimed.
All static, generation, advisory and licence lanes passed. Ignored/environmental
tests are not covered by that result.

`httpdate` 1.0.3 was already in the resolved graph. Its direct ACME reference
adds no package/version or runtime dependency; its MIT option remains permitted
by the existing licence gate. The standard library has no HTTP-date parser, so
this reuses the existing purpose-built implementation. Upstream is not archived;
no unsupported older release line was selected as a compatibility workaround.
Sources: [HTTP retry syntax](https://www.rfc-editor.org/rfc/rfc9110.html#name-retry-after),
[ACME rate limits](https://www.rfc-editor.org/rfc/rfc8555.html#section-6.6), and
[httpdate upstream](https://github.com/pyfisch/httpdate).

Integration closes this error-response retry slice: task 2 falls **8 → 7 points**,
and Stage 10 **147 → 146 points**. Successful-resource polling hints, worker
replacement, full challenge lifecycle and multi-gateway order sharing remain
separate outstanding acceptance within task 2. Live CA proof remains task 5.
No release, tag, package/image publication or Actions run occurred.

## Task 1 — mesh-local HTTPS lifecycle and trust-download integration

The new independent `headless_process::local_certificates` proof uses real child
daemons and TLS clients, not a fake certificate authority service. It creates a
mesh, provisions the local CA through the authenticated public API, trusts only
the returned public anchor, rejects bootstrap-only trust on a fresh handshake,
restarts the root, joins a gateway, rotates the leaf and restarts that gateway.
Both stable node identity fingerprints remain unchanged. It checks exact issuance
replay and active installation counts on both gateways.

The proof exposed three concrete integration defects:

- Installation operation IDs survive restart, but retry hashing used the new
  wall-clock time instead of the original durable operation time. Resolution now
  returns the validated receipt and original timestamp together; a changed stored
  timestamp still fails digest validation. The focused regression failed with
  `Conflict` in 0.05 seconds before the fix.
- Join-grant issuance captured the bootstrap TLS pin permanently. It now reads
  the live resolver's leaf pin when issuing an invitation. TLS pin verification
  remains exact. Invitations remain bound to that leaf: a subsequent leaf change
  requires a fresh invitation, not bypassing TLS checks. Preserving invitation
  usability/exact replay across later leaf changes is not established by this proof.
- Recipient redistribution advances the encrypted delivery generation without
  changing the immutable certificate's source revision. Rotation now accepts a
  strictly newer delivery of the same secret identity and bundle digest at that
  revision, but rejects rollback or changed content. The focused regression
  failed with `ConflictingRevision` in 0.13 seconds before the fix.

Eight focused public-certificate tests passed in **0.25 seconds**, including the
real TLS listener and rewrapping regression. The real two-daemon lifecycle passed
in **52.89 seconds**, following a **23.05-second** incremental process-test build.
Affected-crate Clippy across all targets/features with warnings denied passed in
**41.30 seconds**. These are focused results, not the final integration gate.

Earlier red process runs are retained: 26.18 seconds (restart acknowledgement),
35.25 seconds (join admission), and 39.06 seconds (installation after enrolment).
An additional run timed out at initial `claim_required` readiness in **18.82
seconds**, before exercising certificate changes; its cause remains unresolved.
No deadline was increased and a later green run does not close that startup
failure. Test failures now include child exit observations; certificate-worker
failures preserve secret-free selection/loading/conflict/acknowledgement categories.

The certificate panel now offers mesh-local issuance, explains device trust and
domain/DNS requirements, and keeps a downloadable public PEM anchor while TLS
changes. It does not claim gateway installation from issuance alone, return a
private key, install OS trust, or invoke the user's browser. The generated native
Fetch method uses Rust-generated request/response Zod schemas and CSRF headers;
the form additionally binds the response to its operation and names. Uncertain
retries retain the operation identity, and disposed views do not offer downloads.
The rendering and request/retry lifecycle have separate responsibilities in the
same feature module. No dependency, SQL schema or wire-schema change was needed.

Ten focused web tests passed in **1.28 seconds** across the local trust flow,
existing ACME panel and generated certificate client. Targeted ESLint passed
without exceptions; web TypeScript checking passed. An initial fixture incorrectly
expected `X-CSRF-Token`; it was corrected to the existing `MeshSpan-CSRF-Token`
contract, with assertions moved outside the UI's error-catching callback.

Task 1 remains open for integration verification and resolution of the startup
timeout. Its estimate fell from 5 to 3 points; Stage 10 from 152 to 150. Nothing
has been released, tagged or published.

### Parallel startup investigation and correction

The first full local gate on `653b463` failed in **423.08 seconds**: all static,
licence, generation and web-test lanes passed, but all five active headless tests
timed out before initial HTTPS readiness. Observed children were alive. The 311
daemon unit tests had passed in 59.39 seconds. This result supersedes any claim
that the earlier isolated lifecycle pass alone closed startup reliability.

A focused parallel rerun passed three workflows but timed out two joined-node
workflows in **53.55 seconds**. Automatic native sampling then captured initial
startup. In the third sampling window, 85 main-thread samples were in appliance
composition and 79 in authentication-route composition; individual routes were
repeatedly constructing/serialising the complete Rust-authored OpenAPI document.
The retained first-failure database had all 85 migrations applied. Database-open
work was visible too, but no database or durability policy was changed based on
that suspicion.

`generate_openapi` now shares an immutable `Arc<Value>` after successful initial
generation. The document and header digest remain deterministic; external
request/response validation is unchanged. A regression checks shared schema
identity, identical digest and byte-for-byte output. The 45 API-contract tests
passed in **0.22 seconds**. The `OpenApiDocument::value` accessor is no longer a
const function; ordinary call signatures and wire output are unchanged.

With this correction, all five active headless workflows passed together in
**31.26 seconds**. A profiling run had separately exposed `AddrInUse` for HTTPS
and SMB: the old bind-to-zero probe released listener ports back into the OS
outbound pool before child binding. The harness now reads the OS ephemeral range,
excludes it, checks candidate availability and assigns distinct candidates within
the test process. It does not claim to reserve ports against unrelated processes.
Linux/macOS range parsing fails closed; there is no guessed fallback range.

All five workflows plus the range-parser test passed in **26.68 seconds**, with
the two existing container-dependent tests still explicitly ignored. Affected
API-contract/daemon Clippy across all targets/features passed in **20.70 seconds**.
No deadlines were raised and no test was serialised. These focused results
address the profiled startup defect; the full candidate must still pass the
integration gate. Task 1 now has 1 point remaining; Stage 10 has 148.

### Task 1 integration closure

The final `pnpm check` on signed commit `b9ff3de`, tree
`222a013b04a9b822e8700fc9d7be6bc6f11d6066`, passed in **852.44 seconds** with
four scheduler workers under NVM Node 26.8.1 and Rust 1.98.0. All generation,
embedded-bundle, formatting, lint, licence and typecheck lanes passed. Rust
workspace tests passed in **796.77 seconds** and web tests in **9.35 seconds**.
There were no implementation edits during this run. The earlier failures are
resolved by the profiled schema-generation correction, listener allocation fix,
focused parallel proof and this final integration pass, not by a blind retry.
The two existing container-dependent headless cases remain ignored; this is not
container, hardware or public-CA evidence. The full feedback cycle remains long;
no test-speed improvement beyond the measured startup correction is claimed.

Task 1 is recorded complete: **0 points remaining**, Stage 10 **147 points**.
Task 2 is current with **8 points remaining**. Initial tracing found that the
retry service accepts CA retry deadlines, but the ACME executor reduces remote
failures to a generic protocol error and the driver supplies no retry guidance.
That boundary needs a regression and correction before claiming rate-limit
acceptance. No release, tag, package/image publication or Actions run occurred.

## Target accounting and selected maintenance measurements

The [metrics catalogue](metrics.md) now includes seven target-accounting gauges
and fifteen selected-maintenance families across repair, target drain, rebalance,
return reconciliation and scrub. Observations do not authorise work, reserve
capacity or certify job completion. The replaceable usage source reads existing
target accounting, including backup holds, and skips busy provider locks. No
provider IO happens on scrape. Partial or overflowed sampling omits byte totals;
the exporter reports coverage and age instead of inventing complete capacity.

Five contract tests passed in under **0.01 seconds**. Four shared-provider tests
passed in **0.12 seconds**, exercising real shard reservation/publication,
backup hold/commit/release accounting, policy ceilings and contention. Ten
runtime observation tests passed in **0.01 seconds**, including distinct work-kind
counts, successful/failed/early-return attempts, exact aggregate accounting,
partial passes, overflow, recovery after missing evidence and non-waiting
observation loss. Affected all-target/all-feature Clippy passed in **10.61 seconds**.
Its repair-function size warning was resolved by separating selection/observation
from execution of an already-selected repair; no responsibility rule was relaxed.

The real-process exporter proof first failed because startup sampled the empty
open-target set before reopening persisted folders. A diagnostic reproduction
failed in **26.07 seconds**, reporting zero sampled targets but four reconciliation
attempts. New/opened target membership now marks accounting dirty and the existing
worker refreshes it; administration does not scan providers, and the health-probe
interval remains unchanged. The same process case then passed in **16.50 seconds**
(14.45-second build), requiring fresh non-zero target coverage, byte units,
accounting gauges and real reconciliation-attempt observations after restart.
Existing HTTPS, SMB dispatch, policy replication and node-loss assertions remain.

The complete NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` passed in
**515.56 seconds** against staged tree
`ff08c4ecbaa838dc6324334186c9e81933c7b13e`. Rust workspace tests took 463.01
seconds and web tests took 4.53 seconds. Both licence gates, workspace Clippy,
formatting, web/tooling lint, TypeScript, scheduler tests, generated-contract
drift and the embedded web build passed. The tree identifies the tested source
because 1Password signing failed before a commit could be created. This evidence
addition changes no implementation code.

This is partial OPS-019 coverage, not whole-stage completion. Scope-drain job
progress, queue/debt state, complete physical-space attribution and the other
operational measurement categories remain outstanding. No dependency, schema,
private protocol, release, tag, image or publication workflow was introduced.

## HTTPS and SMB dispatch measurements

The daemon now records aggregate dispatch counts, handler failures, cancellations
and fixed-bucket latency for its composed HTTPS router and embedded SMB handler.
The replaceable observation sink performs no IO or waiting, takes no request
strings, and cannot change the returned response. It records dropped observations
separately. The [catalogue](metrics.md) defines the eight new families and their
limits: dispatch completion is not transfer completion or file durability; SMB
handler errors are not ordinary SMB error-status responses.

Four metrics contract tests, six observation tests, three gateway adapter tests
and two encoder tests passed; each focused test harness completed in **0.01
seconds or less**, excluding compilation. They cover response/payload preservation,
5xx versus client rejection, exact cancellation counts, unpolled futures, lock
contention, atomic overflow, histogram validation and bounded encoding. The
catalogue expansion initially failed an old family-count assertion; it now
requires all 23 families and still omits the five unobserved last-cycle gauges.
Affected all-target/all-feature Clippy passed in **9.71 seconds**.

The real-process exporter case passed in **17.15 seconds** after a **24.70-second**
integration build. It exercises both the creating gateway and an enrolled peer,
asserting positive HTTPS dispatch counts and SMB handler-error counts after a
real TCP malformed-payload probe. Its existing policy, restart, peer catch-up and
original-node-loss assertions remain intact. This negative SMB listener probe is
not a claim of external SMB client file-transfer interoperability.

The complete local NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` passed on
the implementation in `360be29` in **680.01 seconds**. Rust workspace tests took
617.99 seconds and web tests took 5.57 seconds. Generated-contract drift,
embedded web build, Rust format/Clippy, web/tooling formatting and lint,
TypeScript, scheduler tests and both licence gates passed. This was one local
gate run, not a GitHub Actions run; this evidence addition changes no code.

No dependency, SQL migration, public API schema or private protocol changed.
This closes dispatch instrumentation only, not the broader OPS-019 catalogue or
Stage 10. No release, tag, image or publication workflow was run.

## Metrics collection and encoding — in progress

The [metrics contract and catalogue](metrics.md) now have a typed replaceable
source, bounded aggregate runtime measurements and an OpenMetrics text encoder.
The storage runtime records process-lifetime probe/cycle latency histograms;
diagnostic-window eviction does not reset them. Output contains no dynamic
identity/path labels. Unavailable sources and unobserved gauges remain distinct
from zero-valued measurements.

Three contract tests, four observation/source tests and two encoder tests all
passed, each focused harness completing in under **0.01 seconds**. They check
exact inclusive buckets and nanosecond sums, no partial overflow update,
duplicate-family rejection, bounded churn, lock contention, missing gauges,
deterministic family order and exact OpenMetrics bytes including counters above
JavaScript's safe-integer range. Affected all-target/all-feature Clippy passed
in **8.38 seconds** after correcting documentation, borrowing and test-import
lint findings. No rule was suppressed or loosened.

That initial commit covered collection/encoding only. The following integration
adds configuration and routing; the wider metric catalogue remains outstanding.
No release or publication ran.

### Replicated opt-in and authenticated exporter integration

The native configuration API and scrape route are now composed into the daemon.
The [metrics contract](metrics.md) records access, cancellation, exact-retry,
configuration bytes and private command impacts. Default-off, consumer grants,
current authentication and the response bound are enforced independently of any
web client. No dependency or SQL migration was added.

Focused local Rust verification:

- Four metadata tests passed in **5.38 seconds**: exact receipts and CAS,
  immutable history, all four apply-fault rollback points, reopen persistence,
  canonical wire rejection, unknown consumers and corrupt stored evidence.
- Two Rust API boundary tests passed in **0.09 seconds**.
- Four daemon HTTP tests passed in **0.43 seconds**: early rejection, no implicit
  manager scrape grant, revocation before response, invalid outgoing policy,
  malformed/oversized mutations and owned work after client cancellation.
- Affected all-target/all-feature Clippy passed in **34.17 seconds**.
- The independent real-process HTTPS test
  `metrics::exporter_policy_survives_restart_and_reaches_another_gateway`
  passed in **16.92 seconds**. It asserts default-off, enable/disable, exact
  original receipt replay without re-enabling, mixed-cookie rejection, actual
  runtime counters, restart persistence, policy catch-up by another gateway and
  scraping after the original process stops. It does not prove non-admin
  credential enrolment, a real Prometheus ingestor, hardware failure or soak.

The broad operator flow also ran and failed in **27.50 seconds** at the existing
automatic-backup restore-readiness request with HTTP 503, before reaching metrics.
Its root cause is not established. The metrics process case is independent so it
can run in parallel; the original operator assertions remain intact. This failure
is not waived or described as fixed by a later passing run.

The Operations panel now exposes the exporter policy through the generated
client. Eleven focused client/panel tests passed in **4.48 seconds**, including
default-off, on-demand bounded user pages, selections across pages, enable and
disable, CSRF transport, Rust-derived Zod rejection, exact retry after connection
loss, mismatched receipts, stale-policy conflict recovery, refreshed form values
and late response suppression after unmount. TypeScript and focused ESLint
passed with no relaxed rules. The frontend-design skill guided the existing
restrained layout, labelled controls, optional detail and honest pending states;
these are headless DOM checks, not browser visual or device evidence.

The complete NVM-default `pnpm check` subsequently passed in **1,149.60 seconds**
with four workers. Rust workspace/all-target/all-feature tests took **1,026.21
seconds**; web tests took **25.75 seconds**. Generated-contract drift, embedded
web build, Rust format, workspace Clippy, Rust and JavaScript licence checks,
workspace format, full ESLint, TypeScript and tooling tests all passed. The
operator flow's earlier HTTP 503 did not recur in this gate. This is full local
integration evidence, not a root-cause resolution of that intermittent result.

A fresh final debug-bundle build succeeded, but its subsequent parallel
`headless_process` run failed in **44.83 seconds**: two cases timed out waiting
for joining daemons' HTTPS listeners (`Connection refused`), while the metrics
case and standalone restart case passed. Two external SMB-container cases were
explicitly ignored. The branch remains unmerged pending diagnosis; the earlier
full passing gate does not override these later failures.

### Snapshot capture race isolated

Inspection of a retained failed join found committed node activation on the
existing node but no installed authority database on its peer. Snapshot creation
sampled the live consensus position before making an online database copy, then
compared that old position against the newer copy. A concurrent commit could
therefore reject a valid copy with `SnapshotMismatch`.

A deterministic regression places a separate-connection commit exactly between
those operations. It failed with `SnapshotMismatch` before the correction and
passed in **0.38 seconds** afterwards. Capture now holds one SQLite read view
across consensus inspection and copying; the test proves that the other connection
still commits and that the captured older position restores correctly. The existing
receiver-vote preservation case passed in **0.36 seconds**. Affected all-target,
all-feature Clippy passed in **14.03 seconds**. No timeout was increased, no tests
were serialised, and no schema or protocol was changed.

After rebuilding the daemon, parallel process verification completed in **28.90
seconds**: standalone restart, metrics gateway catch-up and three-node original-node
loss passed. The operator case joined successfully but reproduced the separate
backup failure: its run remained `Recorded` with only one verified destination.
Both children were still running before cleanup. The fixture now retains private
test state on failure and reports child exit observations; successful fixtures are
still removed. Inspection found the local encrypted copy but no remote provider
object. That remaining failure is not explained or waived by the snapshot fix.

### Bootstrap-node remote backup identity

The retained backup run was claimed by the original bootstrap node. Its local
copy was verified, while the second node's provider remained empty. Remote backup
authorisation incorrectly required a `node_activations` join receipt, which the
original node never has: bootstrap commits it directly as an active node.

The identity check now reads the current incarnation together with the active
certificate and active-node predicate in one indexed query. Bootstrap and joined
nodes therefore use the same current identity boundary; neither gets an exemption
from certificate, incarnation, expiry, destination or backup-claim checks.

A regression using the real bootstrap metadata/consensus fixture failed with
`Unauthorized` before the correction and passed in **0.31 seconds** afterwards.
It rejects a changed incarnation, fingerprint, unknown node and expired
certificate. A separate persistence test passed in **0.27 seconds**, checking
inactive node states, current-incarnation changes and certificate revocation.
Affected all-target/all-feature Clippy passed in **5.87 seconds**. This adds one
field to the internal Rust certificate projection, not a SQL migration, public
API or wire change. After rebuilding, all **four** ordinary process tests passed
in parallel in **22.63 seconds**, including automatic multi-node backup placement,
encrypted download and restore-readiness, node joining, restart and original-node
loss. The two opt-in SMB-container cases were ignored, not executed.

The final complete NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` passed on
`65ea7ef` in **553.90 seconds**. Rust workspace/all-target/all-feature tests took
**515.59 seconds** and web tests took **4.63 seconds**. Generated-contract drift,
embedded web build, Rust format, workspace Clippy, both dependency licence gates,
workspace format, full web lint, TypeScript and tooling tests all passed. This is
local integration evidence, not hardware, soak or ignored SMB-container evidence.
No release, tag, image or publication workflow was run.

## Runtime diagnostic bundle and download control

`GET /api/latest/admin/diagnostics/bundle` combines the existing metadata
section with bounded process-local storage observations. The Operations panel
provides an explicit download action with collection, cancellation and error
states. The generated native client is also available to non-panel clients.
No collection starts merely because the panel is opened. Responses are validated
again before a browser download; cancellation, unmount or a changed client
discards late results. A download request is not reported as a successfully saved
file, and the panel explains that diagnostics are not a backup or protection proof.

The bundle shares metadata collection's authentication, reauthorisation, worker
admission and cooperative deadline. It has an independent Rust-authored 512 KiB
response limit; the metadata-only endpoint remains 256 KiB. Runtime collection
reads a separate in-memory store and never acquires the storage IO lock, probes
a provider, contacts a peer or starts repair. An unavailable observation store
is explicit `runtime: null`.

Existing provider health checks and storage reconciliation cycles now record
completion times, monotonic ages/durations, closed outcomes and process-lifetime
counters. Target generations remain bound to their samples. At most 100 target
samples and 100 newest-first transition events are retained. Eviction and dropped
update counters expose missing evidence; repeated failures do not flood the
transition history. Clock corrections cannot reorder events, and unavailable or
invalid local timestamps drop an observation without blocking domain work.
These transient events have no arbitrary message/payload field and are not
durable audit or notification-delivery authority. A passing provider check is
not a complete shard scrub or a current availability guarantee.

Focused Rust contract cases passed (**4 cases, 0.04 seconds**), observation
transition/window/contention/clock cases passed (**3 cases, under 0.01 seconds**),
and HTTP authentication, reauthorisation, invalid-output and shared cancelled-job
admission cases passed (**4 cases, 0.43 seconds**). All-target/all-feature
affected-crate Clippy passed in **21.91 seconds**; the final process-test change
passed Clippy in **1.60 seconds**. The real two-daemon HTTPS operator cycle
passed in **16.61 seconds**, collecting bundles from both gateways and again
after one daemon was killed.

The first operator-cycle run failed in **27.54 seconds** because an automatic
backup remained `Claimed` beyond its existing wait deadline, before the new
diagnostic checks ran. No timeout was increased and no cause/fix is claimed.
Its failure path now attempts a bounded, validated runtime summary instead of
discarding all diagnostic evidence; the focused repeat above passed. This
unexplained timing failure remains relevant to the Stage 11 reliability audit.

The generated OpenAPI document grew to **1,059,843 bytes**, exceeding the build
tool's original 1 MiB source limit. The code-generation file reader now allows
2 MiB, bounds actual reads as well as the initial file stat, and rejects invalid
UTF-8. Its exact-limit/oversize/non-file/encoding test passed (**0.055 seconds**
including the Node harness) and is included in the canonical local gate. This
does not raise public request or ordinary response budgets. No dependency was
added. Twelve focused native-client and headless DOM cases passed in
**0.648 seconds**, covering exact downloaded JSON values, explicit admission,
cancellation, unmount, invalid output, route/budget generation and existing
operation pagination. Full web/tooling ESLint, strict TypeScript and generated
drift checks passed. An initial DOM assertion compared JSON property order,
which Zod normalises; it now checks the exact parsed values without asserting
an ordering the download contract does not promise.

The complete NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` passed on
`258b0f0` in **649.67 seconds**. Rust workspace tests took **593.34 seconds**
and web tests took **9.22 seconds**. Generated-contract drift, embedded web
build, Rust formatting and workspace Clippy, both licence gates, workspace
formatting, strict TypeScript, ESLint and tooling tests all passed. The earlier
backup timing failure remains recorded above; a passing full gate does not
establish its cause or claim that it was fixed.

This advances OPS-007/011/017/019 without claiming the remaining full metric
catalogue, persistent metric history, exporters, durable notifications or
operational dashboard are finished. No release, image, browser interaction or
publication workflow was run.

## Native metadata diagnostics

`GET /api/latest/admin/diagnostics/metadata` collects a bounded, redacted local
metadata snapshot through the ordinary system-manager API-key/session boundary.
It returns an attachment containing daemon/mesh/node/partition identity, a local
collection timestamp, before/after metadata revisions, configured nodes/targets
and recent durable operation outcomes. Each inventory is limited to 100 records
with explicit truncation. User-supplied names, paths, endpoints, actor identities,
command inputs, result entities, credentials and file content are not projected.

One fixed-size query to the existing metadata reactor adds its observed role,
known leader, term, committed/applied positions, membership-plan identity and
queued/pending work. It neither appends nor contacts peers. A full ingress queue,
stopped owner or one-second timeout produces unavailable evidence, represented by
`consensus: null`; no cached healthy result is substituted. Configured lifecycle
is not reported as live reachability or target IO health, and a locally observed
leader does not prove a live quorum. The sections are not one atomic swarm-wide
read; revision bounds expose concurrent local application.

Authentication precedes collection/input interpretation and is repeated with
current time before output. Query/body input is rejected. The endpoint owns one
diagnostic worker, a five-second response deadline and cooperative cancellation;
the permit remains held until interrupted blocking work actually exits. It does
not cap normal connections or affect foreground IO admission. Output is validated,
bounded to 256 KiB and marked no-store. Rust OpenAPI generates the native Fetch
method, Zod response schema and its independent response budget; ordinary JSON
and error response budgets remain unchanged. No telemetry is sent elsewhere.

Focused evidence so far: three reactor cases passed in **1.00 seconds**, three
HTTP boundary/cancellation cases in **0.62 seconds**, two Rust contract cases in
**0.03 seconds**, and four generated-client cases in **0.914 seconds** including
the Vitest harness. Affected-crate all-target/all-feature Clippy passed in
**10.47 seconds**, with the final changed-target pass in **12.45 seconds**.
Web/tooling lint, TypeScript checking and generated-contract drift passed.
The real two-daemon HTTPS operator cycle passed in **24.65
seconds**, collecting and validating redacted snapshots from both gateways after
create/join, storage registration, backup, users/groups, volume and file work.
The final cycle, including diagnostics and file reads from the surviving gateway
after killing the other daemon, passed in **25.32 seconds**. The complete local
gate now passes. Its first run failed the Rust workspace lane and the web
source guard. The web guard incorrectly treated the English phrase "if any" in
a generated comment as an unsafe type; it now walks TypeScript syntax and has
positive/negative fixtures for real type nodes versus comments, strings and
property names. Existing TypeScript is reused; no dependency or rule is removed.
The earlier Rust failure detail was lost in truncated output. The affected
daemon suite subsequently passed **289 unit tests in 33.49 seconds** and all
**three enabled process tests in 42.95 seconds** (two existing ignored tests
remain ignored). No cause or fix for that first Rust failure is claimed. The
canonical Cargo invocation now uses concise output without changing features,
targets or test parallelism, so the repeated full gate retains useful failure
details. These are real HTTPS/process tests, not browser, hardware
or release artefact evidence.

The second complete gate failed in **107.78 seconds**. Every static lane and
the web suite passed; the Rust lane identified
`membership_catches_up_when_every_old_phase_commit_notification_is_lost`, whose
learner control endpoint remained connection-refused. Enhanced timeout evidence
now includes the learner's bounded log and child exit status. The six-case
process suite subsequently passed, as did three concurrent complete copies and
20 focused repetitions; repetition alone did not establish a cause.

A deterministic transport fault then established two real defects in the
dedicated Stage 3 proof runtime (not the appliance metadata reactor):

- Rejecting the first authenticated snapshot before installation stalled the
  living learner indefinitely (**16.19-second failing proof**). Dispatch had
  treated enqueue as delivery and discarded failed attempts.
- Dropping the installation reply receiver before restore made the learner
  exit after durable installation (**16.10-second failing proof**). A lost
  response had incorrectly become a fatal configuration error.

Snapshot delivery now retains one immutable image, observes actual transfer
completion, retries failed/unqueued attempts with 200 ms backoff, and cancels
obsolete IO after verified catch-up or membership retirement. Existing
15-second operation deadlines and parallel test execution are unchanged. Lost
installation replies do not undo durable state or terminate the learner.
The added process case requires actual rejection/reply-loss markers on both
learners, stable three-voter promotion, subsequent committed work on all nodes,
and exact persisted membership after shutdown. Its first combined suite run
also exposed a fixture ordering mistake: it stopped nodes while promotion was
still at revision 4. The test now explicitly waits for stable epoch 5 before
the final write/shutdown, keeping the exact revision-5 assertion.

These faults reproduce the stalled-join symptom, but the original gate had no
transfer-failure evidence; its precise initiating cause remains unconfirmed.
The final seven-case real-process suite passed in **8.69 seconds** and
all-target/all-feature cluster Clippy passed in **8.98 seconds**. The complete
NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` passed on signed `cd670ec` in
**631.42 seconds**: Rust workspace tests **594.06 seconds**, web tests
**3.78 seconds**, plus generated drift, embedded web build, formatting, strict
Rust/web lint, type checking, tooling tests and both licence gates. No release,
tag, image or publication workflow was run.

This is the metadata section of OPS-011, not completion of the full diagnostic
bundle, local metric history/exporters, notification delivery or the operational
dashboard. Live target health, runtime logs and the other operational sections
still require implementation. No SQL schema, private wire message, dependency,
release, tag, image or publication workflow is changed.

## Dependency-update admission

`pnpm check:dependency-update` now runs Rust/JavaScript advisory checks before the
complete canonical local gate, including all configured parallel Rust/web tests,
generated API drift, licence policies and lint. It has no release or publication
step. Audit-service failure stops admission instead of being treated as clean.

An actual audit found the code generator pinned to vulnerable `js-yaml@5.2.0`.
An exact transitive-edge override selects maintained MIT-licensed `5.2.2`, fixing
the two upstream advisories recorded in [the dependency inventory](dependencies.md).
Rust and JavaScript advisory scans then passed; generated contracts did not drift
and both licence gates passed. No runtime library was added.

The install also exposed ESLint 9's declared end-of-life. The lint toolchain now
uses MIT-licensed ESLint 10.10.0 and `@eslint/js` 10.0.1. Existing plugin peer ranges
accept this line except the current accessibility plugin. Its one exact peer
exception is documented and supported by source/API inspection plus two strict
valid/invalid JSX cases (**0.565 seconds** including the Node harness). Full
web/tooling lint passed without changing or reducing rules. The complete NVM-default
`MESHSPAN_CHECK_WORKERS=4 pnpm check:dependency-update` passed on `d836156` in
**669.64 seconds**. Rust workspace tests took **622.50 seconds**, and web tests
took **5.86 seconds**; advisory scans, generated drift, embedded web build, both
licence gates, formatting, Clippy, TypeScript/ESLint and tooling tests all passed.
This is not independent security-review evidence.

## Embedded appliance panels

The actual Vite-built web application is now embedded into the daemon binary and
served by the same HTTPS listener before claim and after configuration/join. The
runtime does not read a web directory, run Node.js, launch another service or
expose provider folders. This closes the previous integration gap between the
implemented panels and the native appliance listener (SYS-007, D-016, D-020).

`pnpm build:daemon` builds the panel then the development daemon. The canonical
local check rebuilds the panel before Rust compilation. Cargo embeds the last
explicitly built bundle; a missing bundle fails with build guidance. Generated
assets remain ignored, and no release/publication command is added or run.

The public asset boundary serves only embedded HTML, JavaScript and CSS, with
explicit media types, no-sniff/frame/CSP headers, non-cached-index revalidation
and immutable hashed-asset caching. HEAD reports the same length without a body.
HTML navigation supports deep links, but API paths, missing assets, source maps,
Vite metadata, source files and encoded/traversal paths never fall back to HTML.
The build bounds file count and size and rejects unsupported served asset kinds.
Static application code is public; every native API keeps its existing independent
authentication and authorisation boundary.

Four asset/router cases passed in **0.01 seconds**. Daemon all-target/all-feature
Clippy passed in **15.65 seconds**, and the final changed-target pass took **4.67
seconds** after renaming the now-used temporary-fixture owner out of its
underscore-prefixed name. Script lint plus workspace formatting passed.
`pnpm build:daemon` built Vite in **0.264 seconds** and the development
daemon in **24.63 seconds**. The real TLS operator proof compares the exact HTML
and every built JS/CSS asset before claim and on a joined node, tests deep links
and non-public-resource rejection, then continues through users, groups, storage,
volumes, automatic backup/export/restore and file/node-loss behaviour. The first
run failed with an unexpected TLS close without request context; no cause or fix
is claimed. Added request diagnostics leave errors fatal. A repeat passed in
**17.61 seconds**, and three independent concurrent runs passed in **24.34,
24.19 and 24.28 seconds**. The intermittent close remains a reliability observation
for the wider Stage 11 churn proof, not erased evidence.

These are headless HTTP/DOM proofs, not a live-browser or released-artifact claim.
The complete NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` passed on `4a03236`
in **684.38 seconds**: Rust workspace tests took 620.00 seconds and web tests took
7.34 seconds. The new bundle build, generated drift, both licence checks,
workspace Clippy, formatting, TypeScript/ESLint and scheduler checks all passed.
No dependency, SQL schema, private protocol, release, tag, image or publication
workflow changed.

## Automatic metadata-backup policy API

`GET /api/latest/admin/backups/schedule` reads the current authoritative
partition's schedule. `schedule: null` means it has not been configured; a
configured policy with `enabled: false` is distinct.

`PUT /api/latest/admin/backups/schedule` configures frequency, retained
generations, verified-copy thresholds and whether attempts are enabled. The
request includes an operation ID and the observed policy sequence. Sequence zero
creates the first policy. An enabled replacement becomes immediately eligible
for an attempt, subject to the existing unfinished-run guard.

The endpoint uses the existing replicated `ConfigureMetadataBackupSchedule`
command, immutable policy history and audit/receipt transaction. It does not add
a second configuration store. The original receipt is returned for an exact
retry, including after a later policy supersedes it. Changed input under the
same operation ID or a stale sequence is rejected.

Authentication uses the common swarm API keys or browser sessions. Mutations
check authority before reading the body and again after receipt of the body;
browser mutations retain CSRF protection. Requests and responses are validated
in Rust. OpenAPI, TypeScript, Zod and native-Fetch helpers are generated from the
Rust contract. Configuration acceptance does not claim successful backup or
retention execution.

Focused evidence:

- `meshspan-api-contract` backup policy tests cover valid input, bounds,
  unknown/missing/null/coerced fields, inconsistent copy thresholds and invalid
  responses.
- `meshspan-daemon` backup schedule service test uses the real SQLite-backed
  consensus authority: configure, replace, resolve an earlier receipt, reject
  changed retries, reject stale sequences, and read the unchanged current policy.
- HTTP tests prove an unauthenticated request body is not polled, validate
  malformed/oversized input and reject an invalid outgoing receipt.
- `web/tests/backup-schedule-client.test.ts` exercises the generated request
  method, URL, body, response validation and Zod rejection rules.

Local verification on 5 September 2026:

- `pnpm check`, using NVM's default Node 26.8.1: passed in **426.50 seconds**
  with four workers, including generated-contract drift, Rust format/lint/tests,
  dependency licence gates, web format/lint/typechecking/tests and scheduler
  tests. The Rust workspace test lane took 392.89 seconds.
- The real CLI/HTTPS clean-machine operator test passed separately in 12.09
  seconds. Its storage-folder assertions now compare canonical paths, matching
  the daemon's inventory on macOS where `/var` resolves through `/private/var`.
- The two opt-in SMB process tests requiring the pinned local client image were
  not run by this gate. Hardware, power-loss, soak and release acceptance are not
  implied by this result. No release or image was published.

## Shared local and remote destination ownership

The local backup worker and incoming QUIC service now share one opened provider
and catalogue per destination. The local resolver no longer opens a second
exclusive file lock. Resolution binds destination, target and generation; the
runtime stops retaining a route when its local target disappears, and does not
reuse it after a target/path rebind. This is an in-process ownership change, not
a persistence migration or an expansion of backup authority.

The real mTLS/QUIC lifecycle test writes remotely, retries and reads through a
local provider handle, deletes remotely and observes the deletion locally. The
directory test reproduces the rejected second open, races exact retries through
two shared handles, checks capacity and reopens after the final owner drops.
The resolver test rejects substituted destinations, targets and generations.

Local validation on 5 September 2026:

- All 272 library tests in `meshspan-backup`, `meshspan-data-plane` and
  `meshspan-daemon` passed. The daemon tests took 15.36 seconds and backup tests
  0.76 seconds; these cases use the parallel Rust harness.
- Warning-denied Clippy passed for those crates, all targets and all features.
- The real mTLS/QUIC lifecycle passed locally. This proof is not a claim that
  destination administration, retention or end-to-end disaster recovery is done.

## Common shard and backup capacity accounting

Registered-target backup providers now charge the existing target journal rather
than receiving an independent copy of the folder allowance. Every destination
on that target shares the shard reservation and committed-usage counters.

The durable order is reserve before provider IO, commit usage after durable
catalogue publication, and release after exact physical retirement. Exact object
identity—not a fresh request ID—keys the charge. Unknown/failed writes keep their
hold through reservation expiry and restart; exact retry resolves it. Existing
catalogued backup objects are charged during provider opening, including when
their usage exceeds a reduced ceiling. Admission then refuses additional space.
This accounting does not claim that an uncertain write produced a usable backup.

Target-journal migration 2 adds the charge records without replacing shard
reservations or inventory. Provider capacity is mutable policy rather than part
of destination identity. Runtime routes share the live target policy owner and
are rebuilt when that owner changes.

Focused local tests prove common admission across two real backup destinations
and a shard provider, rejection before consuming an over-limit stream, release
exactly once, failed-stream retry after provider restart, startup charging,
target-journal restart and migration from schema 1. `pnpm check` passed locally
on 5 September 2026 in **457.36 seconds** with four workers under NVM default
Node 26.8.1. The Rust workspace test lane took 416.18 seconds and web tests took
4.07 seconds. This includes format, warning-denied lint, typechecking, contract
drift and dependency licence gates. Opt-in SMB image tests, hardware and soak
acceptance remain separate; nothing was released or published.

A follow-up recovery check found that a failed write could leave a temporary
file under an older operation ID. The exclusively owned provider now removes
strictly named unpublished staging files on opening and before another write,
so repeated attempts cannot accumulate uncharged temporary copies. Published
objects and non-matching names are not selected. After this follow-up, all 11
backup tests passed in 0.74 seconds, the three real-folder capacity tests in
0.20 seconds and the real mTLS/QUIC lifecycle in 0.34 seconds. Affected
all-target/all-feature warning-denied Clippy passed in 12.85 seconds; the full
workspace result above precedes this focused follow-up.

## Backup destination controls

`GET /api/latest/admin/backups/destinations` lists a bounded current inventory,
including paused destinations. Keyset continuations retain the partition, caller
and page size, and fence a minimum observed metadata revision; every request
checks current system-manager authority. Responses
provide relative next-page URLs. This is a live inventory, not a historical
snapshot of configuration.

`PUT` on the same route selects an exact registered target/generation, sets its
display name and enables or pauses new copies. Target generations use the same
lossless decimal-string representation as storage-folder inventory. Settings
are committed and audited through consensus. The destination's own revision
guards replacement without conflicting with unrelated partition activity.
Exact retries return their original receipt even after a later settings edit.
Existing destination bindings cannot be changed: another provider or target
generation requires another destination identity, preserving lookup for older
copies. Pausing never deletes a backup, and the runtime retains provider routes
for reading and guarded retirement while new-copy authority rejects paused
destinations.

Folder selection records failure independence as **unknown**; it is not proof
of a separate device, power supply or building. Configuring through this endpoint
also resets any previous declared assessment to unknown. Automated assessment
and its product presentation remain to be integrated. The listing can describe
all existing binding kinds, but this configuration endpoint does not pretend
that unimplemented external-provider/federation setup is operational.

Requests and outgoing responses are independently validated in Rust. OpenAPI,
strict TypeScript, Zod and native-Fetch controls are generated. The Fetch
generator's static import registry now has its own module; generated behaviour
is unchanged apart from the new destination operations.

Focused evidence on 5 September 2026:

- Seven metadata catalogue tests passed in 2.82 seconds, including independent
  revision checks, rejected rebinding, pause/resume, exact replay and bounded
  administration pages. Metadata Clippy passed with warnings denied.
- The real SQLite/consensus-backed destination service test creates destinations,
  pauses one, resolves the original creation receipt after replacement, rejects
  changed/stale retries and follows a bounded inventory continuation.
- HTTP tests exercise authentication before body consumption/query parsing,
  current authentication after body transfer and outgoing-receipt rejection.
- The real CLI/HTTPS clean-machine test now selects its actual registered folder,
  creates and pauses a destination, retries the earlier create and observes the
  unchanged paused revision through the real listener. It passed in 12.30 seconds.
- Generated-client fixtures check request intent, CSRF headers, pagination,
  unknown/missing/null/coerced values and rejection of invalid server responses.

Persisted catalogue rows are unchanged. The pre-alpha blind-upsert command kind
63 is replaced by revision-checked kind 72, and the canonical digest includes
the expected destination revision. Old command bytes are not reinterpreted;
mixed-build compatibility and replay of old kind-63 log entries are not provided.
This is not an automated rolling-upgrade compatibility claim.

The complete NVM-driven `pnpm check` passed in **512.81 seconds** with four
workers (Rust workspace tests 470.02 seconds; web tests 4.17 seconds). After the
final continuation-revision fence and its rejection fixture, all **643 library
tests** across the API-contract, daemon and metadata crates passed, followed by
all-target/all-feature warning-denied Clippy in 9.54 seconds. Generated-contract
drift and Rust formatting were checked again. No release, tag or image was
published; the opt-in SMB-image and hardware/soak gates remain separate.

## Automatic retention and physical reclamation

The daemon now retires excess generations and reclaims exact provider objects
through the normal local/QUIC backup resolver. One pass proposes at most one
retirement and processes one bounded cleanup page. An unavailable destination
does not block later pages; unfinished copies remain durable debt across restart.

Retirement is a replicated transaction, not a timer-side deletion. It rechecks
the schedule sequence, victim revision, terminal run and a unique bounded set of
newer protected generations. Ordering uses committed source revisions, not wall
time. Retained generations must still satisfy both the current and captured
verified/independent-copy thresholds. Pausing the schedule stops new retirement,
but does not abandon already authorised cleanup.

That transaction retires the generation and every copy together. Only an exact
provider deletion receipt clears physical-cleanup debt. Provider deletion uses a
stable object/retirement operation identity with a renewable per-attempt deadline,
so loss after deletion or before capacity release can be recovered without a
second charge or a guessed success. Generation creation and retention are
attempted independently within the backup maintenance pass.

Partition migration 84 adds reclamation receipts and ordered retention/debt
indexes. It also preserves older failed, unverified generations as recorded
rather than incorrectly treating their unfinished copies as retired. New failed
runs use the same lifecycle and become eligible once enough newer protected
generations exist. Closed private command kinds 73/74 carry retirement witnesses
and reclamation receipts; no public API schema changes or dependencies are added.

Focused local evidence covers:

- exact excess-generation selection, current-policy revalidation, stale and
  duplicate witnesses, and incomplete-generation retirement;
- four transactional fault boundaries, exact replay, database reopen and debt
  pagination;
- inspected ordered index plans without temporary history sorting;
- schema-83 upgrade, integrity check and the migration's fixed digest;
- bounded wire round trips, every truncated prefix and oversized witness counts;
- real directory deletion replay after restart with a renewed deadline;
- worker recovery after deletion-before-receipt failure and fairness under an
  unavailable destination;
- real shared-folder capacity recovery after provider deletion commits but the
  target capacity release fails, including a retry that cannot release twice.

## Automatic configuration defaults

The daemon now reconciles backup defaults after initial storage registration and
authoritative topology/configuration changes. A fresh appliance selects up to
three destinations and enables a daily schedule retaining three generations.
It prefers separate hosts/shared-failure groups and then separate known devices
within a host. Existing choices remain stable when those preferences are equal.
This is a small automatic destination set, not a limit on explicitly configured
destinations or mesh size.

Configuration ownership is explicit in schema 85. Existing records and direct
administrator edits belong to the administrator; defaults never overwrite a
custom schedule or recreate a paused destination for the same target generation.
No longer selected automatic destinations are paused, preserving historical
bindings and copies for restore and guarded retention. Normal file writes and
temporary connectivity losses do not reduce the configured copy threshold.

Defaults, destinations and schedule commit in one authoritative transaction with
topology/default-state revision fences. They do not depend on cross-file
atomicity. The private command codec adds kind 75; no public HTTPS contract or
dependency changed. Automatic failure relationships remain `unknown`: selecting
apparently separate locations is not proof of independence from metadata voters.

Local evidence for this slice:

- Seven repository tests passed in 4.86 seconds, covering single-target setup,
  growth, known-device diversity, shared-power-group changes, explicit ownership,
  stale topology, wire bounds, transactional interruption, replay and reopening.
- Schema 84-to-85 migration passed in 0.26 seconds, including the committed SQL
  fingerprint, preservation of an existing paused destination as explicit,
  integrity and foreign-key checks.
- The real two-daemon clean-machine HTTPS cycle passed in 12.96 seconds. Before
  any destination API mutation, it checks that the enabled daily policy and
  active automatic destinations appear through the public API.
- The production selection query-plan check passed in 0.26 seconds. Correlated
  identity/overlap lookups use indexes; ranking requires a top-one ordering step
  over eligible inventory, at most three times per configuration reconciliation.
- The complete NVM-default `pnpm check` passed on the final implementation in
  **551.45 seconds** with four workers. Rust workspace tests took 510.99 seconds,
  web tests 4.78 seconds and workspace Clippy 22.79 seconds. Both licence gates,
  formatting, TypeScript/ESLint and generated-contract drift also passed. This
  run was slower than the preceding retention gate; no test-speed improvement is
  claimed. Hardware/soak and opt-in SMB-image proofs remain separate.

## Backup administration panel

`/admin/backups` now exposes the existing Rust-generated backup APIs through the
manager-gated web panel. It shows the current schedule and paged destinations,
supports explicit frequency/retention/copy thresholds, pauses or resumes a
registered destination, and selects existing active storage anywhere in the mesh
for a new destination. It never asks for provider filesystem paths or duplicate
credentials. Advanced settings are collapsed; the ordinary view distinguishes
configuration from proof of a completed backup and labels unknown failure
independence honestly.

Inventory loading and save/retry handling have separate responsibilities. Reads
are coalesced while in flight; pages are requested only on demand. Paging does
not reset partially completed forms, while successful destination creation does.
Failed reads clear stale private inventory instead of displaying an empty mesh
as if the query succeeded. Mutations carry CSRF and observed revisions, wait for
matching receipts and retain the exact operation/request for in-panel retry after
an unknown result. No optimistic saved or protected state is invented.

The native-Fetch generator now includes `listNextBackupDestinations`, validating
the continuation origin, exact endpoint, duplicate/unknown query fields and
numeric limits before sending credentials. Generated files were regenerated,
not hand-edited. No public API schema, Rust persistence or dependencies changed.

Sixteen focused component/client tests passed in 1.53 seconds. They cover actual
DOM form submissions, pause/resume revisions, CSRF, invalid policy, unknown
outcomes, duplicate-click admission, invalid receipts, pagination, preservation
of form input, large generation identifiers and failed-read clearing. These are
headless DOM tests and generated-client transport fixtures, not a live-browser
or real-device visual acceptance claim. TypeScript and strict ESLint passed; the
final production web build also passed in 0.307 seconds.

The complete local gate failed in the three-process consensus suite after
166.39 seconds: `STATUS 5` did not become `COMMITTED` within 15 seconds. Operation
5 is initial node enrolment, not the later leader-restart phase. All five process
cases subsequently passed together, including ten consecutive runs of the exact
workspace-feature build (7.33–7.61 seconds each). That does not establish the
original failure's cause or prove it fixed. Test timeout diagnostics now retain
the last response, node role and bounded process log, with a deadline on each
control request.

Inspection found a separately deterministic membership liveness counterexample,
captured in `core::tests::membership_loss::follower_recovers_after_losing_membership_commit_notification`.
An incumbent follower durably holds a transition but loses its old-plan commit
notification. The leader activates the joint plan. All three subsequent reliable
heartbeats are rejected as `StaleMember`, leaving the follower at commit index 0
instead of 1. Reintroducing the deliberately lost notification advances that same
follower, confirming the fixture itself is viable. The regression was committed
red in `c8e4c82` and was not ignored or weakened. The production authority and proof runtime both
send an old-plan heartbeat once before activation; neither supplies replay after
that notification is lost.

No claim is made that this counterexample proves the cause of the original
process timeout. The panel remains unmerged until the repaired tree passes the
complete local gate.

Focused Clippy across all targets/features of `meshspan-consensus` and
`meshspan-cluster` passed in 24.82 seconds after the diagnostic additions. The
deterministic counterexample compiled and failed in under 0.01 seconds exactly
at the expected commit-index assertion, including the passing lost-packet
control. Formatting and diff-whitespace checks passed.

### Membership catch-up repair

The core now returns bounded phase hints instead of silently discarding every
message whose membership phase differs. Applied canonical membership records
reconstruct historical phase boundaries from the durable log on restart. A
known historical voter may serve `CommittedPrefix` through the normal Quinn
consensus stream even before a replacement election completes. This distinct
message cannot elect its supplier, reset a newer vote, acknowledge a read
barrier or contribute to the current write quorum. It contains only a bounded
committed prefix up to the exact historical transition, with independently
validated indices and digests. New bytes are persisted before commit/apply
effects, and committed content cannot be overwritten.

The deterministic regression now routes replies as well as requests, allowing
the receiver to request its missing phase; it never needs the deliberately lost
notification to return. Twenty-nine core tests passed in 4.63 seconds, covering
the original loss, a newer follower election term, source restart without an
elected leader, commit-limit overreach, immutable committed content and exclusion
from current quorum/read evidence. Seven wire-related tests passed in 0.01
seconds, including the new message's Protobuf round trip, corrupt entry bytes and
commit-range overreach.

A real three-process Quinn/mTLS proof deliberately drops every old-phase
membership commit notification, records that multiple drops occurred, then
completes promotion, writes, leader loss and restart. All six process cases
passed concurrently in 8.14 seconds. Setup/promotion and failover are distinct
test responsibilities; no timeouts or lint limits were raised and no tests were
serialised. These proofs do not replace Stage 11's wider churn and hardware
campaigns.

The private protocol adds `CommittedPrefix` (envelope field 28); peers need this
implementation for the new recovery exchange. There is no SQL migration, public
API schema change or new dependency.

The complete NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` passed on the
repaired tree in **655.03 seconds**. Rust workspace tests took 586.47 seconds;
web tests took 5.06 seconds; workspace Clippy took 49.82 seconds. Generated drift,
both licence policies, formatting, TypeScript/ESLint and scheduler tests also
passed. This run was slower than the earlier 551.45-second backup-defaults gate;
no test-speed improvement is claimed. No release, tag, image or publication
workflow has been run.

### Current local backup failure assessments

Registered-folder destinations now derive their failure relationship from the
current authoritative topology whenever they are read. The same projection feeds
the administration inventory and protection/retention evidence; an old configured
`independent` label cannot override a shared source host or fault group.

Source boundaries include every partition replica member, including learners and
retiring members. A destination on any source host or sharing any declared group
is overlapping, even when its folder is on a different drive. Different hosts
alone leave the relationship unknown. Declared independence requires disjoint
groups and assignments for every administrator-defined class on both the
destination and all source hosts. Missing assignments, missing/current-generation
mismatches and unsupported parent-group evidence remain unknown. Built-in machine
and device classes are not manual group-assignment requirements. This is evidence
under administrator-declared topology, not discovery of undeclared shared power,
network storage or buildings.

The evidence digest binds the source partition, topology and membership revisions,
target identity/generation and evaluated facts. A group change is reflected on
the next authoritative read without waiting for a defaults job. A copy may remain
byte-verified while ceasing to count towards an independent-copy requirement.
There is no database migration, new dependency or public/private wire change.
Remote swarm/provider declarations retain their separate evidence contract;
implementing those destinations remains outstanding.

The 45 focused metadata backup tests passed in 24.26 seconds, including six new
topology/protection cases and the indexed-query-plan check. Affected all-target,
all-feature Clippy passed in 11.00 seconds. The first full gate stopped at an
outdated real-process assertion requiring every destination to remain unknown
(239.17 seconds total). Both nodes in that fixture hold metadata replicas, so
their backup folders must report overlapping. The updated real CLI/HTTPS flow
passed in 15.69 seconds. A final focused rerun passed all 45 metadata cases in
27.25 seconds; metadata/daemon all-target, all-feature Clippy passed in 20.66
seconds. The complete NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` then
passed on `ad592f2` in **585.84 seconds**, including Rust workspace tests
(554.71 seconds), web tests (3.41 seconds), workspace Clippy, both licence gates,
formatting and generated-contract drift. Existing opt-in SMB container and
hardware/soak proofs remain separate; no release or image was produced.

### Recovery of empty unpublished backup reservations

A real-folder regression reproduced a short upload whose temporary bytes were
removed but whose shared target reservation survived provider restart. A new
shard reservation still failed with `ResourceExhausted` (0.07 seconds).

The directory provider now reconciles pending capacity on attachment and before
another store. It holds exclusive destination ownership, removes only recognised
unpublished staging, checks the exact catalogue identity and confirms absence of
the published pathname before cancelling a hold. Directory synchronisation
precedes cancellation. Existing files, dangling symlinks, other entries and
catalogue evidence keep their charge. No lease timeout grants permission to free
space or delete published bytes.

The internal accounting contract exposes bounded, destination/generation-bound
pages and exact unpublished cancellation. The target journal atomically removes
only held reservations and their reserved-byte charge; stored and retired rows
cannot be cancelled. Cancellation does not create a retirement tombstone: an
exact retry must obtain fresh admission, while genuinely retired objects remain
fenced. This is an in-process capability, not a new public or private RPC. No
dependency or database migration was added.

Seven real-folder capacity cases passed in 0.40 seconds, including restart,
recovery before another upload, retained publication-without-catalogue bytes and
exact retry. Six journal cases passed in 0.06 seconds, including 64-item paging,
changed identity, stored/retired rejection and transactional fault rollback.
The full backup/storage library suites passed (12 tests in 0.77 seconds and 30
tests in 1.08 seconds). Affected all-target/all-feature Clippy passed in 20.53
seconds, then 4.57 seconds after the final integration cases. The complete
NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` passed on `953b47d` in
**619.68 seconds**: Rust workspace tests took 575.63 seconds and web tests took
5.33 seconds. Workspace Clippy, both licence gates, formatting, type checking and
generated-contract drift passed. Existing opt-in SMB container and hardware/soak
proofs remain separate; no release or image was produced.

An unindexed published object deliberately keeps its charge and is recoverable
by exact retry; this is not a claim that an abandoned published generation may be
removed without authoritative retirement. That remaining interruption-recovery
path is tracked below.

## Native backup history and panel

`GET /api/latest/admin/backups/runs` now exposes a bounded newest-first page of
automatic backup attempts, with caller/partition/limit/revision-bound relative
continuations. Every page checks current system-manager authority. Run sequence
strings retain exact values beyond JavaScript's safe integer range; recorded
outcomes explicitly describe historical execution, never present restore safety.
The repository uses the existing partition/run-sequence index; there is no
migration, provider scan or new dependency.

The backup panel reads this native API through generated Fetch/Zod contracts.
It keeps one page, follows older history on demand, refreshes the newest attempts,
and clears private rows when reads fail. Its labels distinguish queued, claimed,
recorded, completed-at-required-protection and incomplete attempts. Existing
panel styles are reused; no browser interaction or real-device visual proof was
performed.

Focused local evidence: two repository history cases passed in 0.77 seconds,
including concurrent new-run paging, terminal-page behaviour, index plans and
corrupt-record rejection. Two Rust contract cases passed in 0.02 seconds; two
daemon HTTP/consensus cases passed in 0.47 seconds, including early rejection,
invalid outgoing data, substituted cursors and committed credential revocation.
The real CLI/HTTPS operator flow observed an automatic run in 13.95 seconds.
Fifteen focused panel/generated-client tests passed in 2.77 seconds. TypeScript,
ESLint and affected all-target/all-feature Clippy passed (final Clippy 4.39
seconds). The complete NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` passed
on `c0eab43` in **866.95 seconds**, including Rust workspace tests (807.76
seconds), web tests (8.58 seconds), both licence gates, workspace Clippy,
formatting, TypeScript/ESLint and generated-contract drift. No release, tag,
image or publication workflow was run.

This is historical inventory, not restore-readiness or recovery proof. Native
encrypted export is described below.

## Native encrypted backup export

`GET /api/latest/admin/backups/{backup_id}/export` streams an exact encrypted
container through the existing local-folder or private QUIC/mTLS backup provider.
It accepts current system-manager credentials, not provider paths or a recovery
private key. Rust-authored OpenAPI defines the canonical generation identifier,
lossless `Content-Length`, and `MeshSpan-Backup-Digest` headers. There are no query
parameters or range/resume semantics in this operation.

The daemon hashes and counts bytes independently of the provider receipt and
withholds its final 64 KiB frame until the receipt, current authority and exact
catalogue evidence pass verification. Corruption, truncation, changed copies,
revocation or deadline expiry cannot produce the declared complete download.
Another provider is tried only before any prefix has escaped. The HTTP bridge
uses two 64 KiB queue slots, closes its sink on client cancellation, and times
out backpressure. Export admission covers preparation and provider work; its
default worker capacity follows available CPU parallelism, and its constructor
accepts explicit capacity and transfer-time limits. The daemon currently supplies
a one-hour transfer deadline. This does not cap ordinary HTTP connections.

The generated Fetch client validates the path and response headers and exposes a
cancellable byte stream. The stream checks exact length and SHA-256 through EOF
using the existing hashing dependency. A caller must finish consuming that stream
before committing its downloaded file. Opening a transfer, receiving headers or
downloading encrypted bytes does not prove decryption or restoration. The panel
download action is described below; product-facing recovery remains separate work.

The real-process proof exposed an existing admission race: encrypted bytes could
be stored, but any intervening metadata commit made the captured revision differ
from the live head, preventing admission forever on retry. Admission now verifies
an older captured position against retained committed log-term and indexed
operation-revision evidence, while rejecting unknown/future or contradictory
positions. If that historical evidence is no longer retained, admission still
fails closed; recovery of such unpublished generations remains outstanding.
Snapshot construction derives its manifest from the finished SQLite copy, not a
separate pre-copy read of the changing live head. Capture time is also preserved
independently of later publication or retry time.

This adds `source_created_at` to the pre-`1.0` private `RecordMetadataBackup`
command encoding and canonical request digest. Nodes need matching builds;
old encoded instances of that command are not compatible. No SQL migration,
dependency, release, tag, image or publication workflow was introduced.

Focused local evidence: four streaming-core cases passed in 0.01 seconds; five
HTTP/body cases passed in 0.36 seconds; two Rust boundary cases passed in 0.02
seconds. Indexed copy paging/corrupt-row rejection passed in 0.29 seconds and the
capture/admission regression passed in 0.36 seconds. The metadata backup suite
passed 48 cases in 37.23 seconds before the added capture regression. All 165 web
tests passed in 4.16 seconds, and TypeScript/ESLint passed. After correcting the
admission race, the actual CLI/HTTPS operator flow completed an automatic backup,
downloaded it, checked its container magic, exact length and digest, and completed
the existing node-loss/file round trip in 18.89 seconds. Three concurrent reruns
passed in 25.99, 25.94 and 25.92 seconds; the earlier claimed-run timeouts were not
accepted as success.

The complete NVM-default `MESHSPAN_CHECK_WORKERS=4 pnpm check` passed on
`071620e` in **1121.29 seconds**. Rust workspace tests took 1016.67 seconds and
web tests took 15.51 seconds. Generated-contract drift, Rust/workspace formatting,
all-target/all-feature Clippy, TypeScript/ESLint and both dependency licence gates
also passed. No release, tag, image or publication workflow was run.

### Panel encrypted download

Protected history entries now offer an encrypted-backup download. The generated
SDK derives its URL from the Rust operation and validates the generation ID;
rendering a link never starts provider work. It includes no credential or recovery
secret. API-key clients continue using the authenticated streaming SDK operation,
because an ordinary browser link cannot carry their authorisation header.

The browser handles byte storage and transfer completion, without a whole-backup
JavaScript buffer. The link opens a separate context with no opener or referrer,
leaving the panel available if the server rejects the request. Only the server's
successful response supplies attachment headers; there is no HTML `download`
attribute forcing an error response to be saved as a backup. Current authority and
copy checks still happen on the server for every download. Invalid link evidence
shows a retry message, and rejected history refreshes remove old download links.

The panel does not claim completion, decryption or restore-readiness. It reminds
the operator to keep the offline recovery bundle separately. Existing typography,
focus treatment and wrapping layout are retained.

Local evidence: the three affected files passed **25 tests in 2.98 seconds**.
After the final generated-helper type correction, all **171 web tests across 36
files passed in 5.25 seconds**, alongside full web/tooling ESLint, TypeScript,
workspace formatting and generated-contract drift checks under NVM default.
The component cases are headless DOM tests, not a claim that a real browser's
download manager saved a file. The underlying real HTTPS export cycle and full
Rust gate are recorded above; no Rust code, dependency, SQL or wire format changed
in this panel slice. No release, tag, image or publication workflow was run.

## Gateway restore-check API and panel

`GET /api/latest/admin/backups/{backup_id}/restore-readiness` now performs a
non-destructive restore, rather than reporting a saved readiness flag. Current
system-manager authority is checked before identifier parsing or provider IO.
No body, query, provider path or recovery secret is accepted. The response names
the exact backup, gateway, recovered partition, committed log position, revision
and check time. Its only verification scope is `gateway_key`.

The service composes the same verified export/provider boundary used by downloads.
It reads an exact encrypted copy, decrypts using the gateway's existing protected
recipient key, then exercises the SQLite restore, integrity and recovery-state
validation in a private disposable workspace. It rechecks current catalogue and
caller authority before returning, and normal completion requires successful
workspace cleanup. Live metadata is never replaced or admitted as a new authority.

One restore worker per gateway bounds disk demand independently of ordinary
traffic and encrypted exports. Cancelled requests remain owned by the route's
task set until their jobs finish; provider writes check cancellation and a
monotonic deadline. Decryption and SQLite operations check the budget between
phases, not by forcibly interrupting running kernel IO. A cancelled/expired check
cannot return success. Recognised abandoned workspaces, including interrupted
owner-marker publication, are cleaned before the service starts. Cleanup does not
follow a substituted root or recursively remove arbitrary sibling content.

The panel adds an explicit **Check restore** action to protected attempts. It
does not trigger provider work on page load, has cancellable pending state, and
clears previous proof on a failed recheck. Rust-generated Fetch and Zod validate
the request and returned exact-generation evidence; counters remain lossless
decimal strings and the panel uses Temporal for the displayed instant. Wording
distinguishes a disposable gateway restore from testing offline recovery custody.

Focused local evidence: five daemon rejection/cancellation/workspace cases passed
in **0.22 seconds**; the Rust boundary case passed in **0.02 seconds**. Four affected
web files passed 35 cases in 2.47 seconds, and the complete web suite passed **181
cases across 37 files in 5.00 seconds**, with TypeScript and full web/tooling ESLint.
The real CLI/HTTPS operator flow created an automatic encrypted backup, downloaded
it and successfully exercised this isolated-restore endpoint before completing
the existing file/node-loss cycle in **21.77 seconds**. Workspace Clippy passed
after correcting two unnecessary owned arguments. The complete NVM-default
`MESHSPAN_CHECK_WORKERS=4 pnpm check` passed on `4ee4388` in **818.77 seconds**:
Rust workspace tests took 779.34 seconds and web tests took 12.19 seconds. Generated
contract drift, both licence gates, Rust and web lint, formatting, TypeScript and
scheduler checks all passed. The gate ran locally; no GitHub Actions were used.

This is not an offline-bundle verification, catastrophe-recovery authority
transition, restore-as-live activation or a guarantee that a historical copy will
remain available. Those recovery workflows remain outstanding. No dependency,
SQL migration, private wire change, release, tag, image or publication workflow
was introduced. Panel checks use headless DOM tests, not live-browser evidence.

## Task 21 — durable notification outbox

The first notification slice implements replicated channel configuration and
delivery transitions, not an operational notification sender yet. Migration 89
adds immutable channel configurations referencing envelope-encrypted kind-10
settings. Settings must use the same complete gateway/recovery recipient check
as other mesh-wide service credentials. Channels are explicitly enabled and
select a closed event allow-list. No endpoint, credential or source audit payload
is copied into an outbox event.

Committed certificate-order, manual-DNS-task and backup-run events can produce
one deterministic delivery per channel/event pair. New channels do not replay
events predating channel creation. Claims bind the attempt, active node and
incarnation for 60 seconds; an expired attempt cannot acknowledge delivery.
Temporary failures retain the delivery identity and schedule bounded exponential
backoff with deterministic identity jitter. Configuration replacement cancels
queued/claimed work instead of silently sending it to a different destination.
Already-started remote IO cannot be undone; stable external idempotency is still
needed for ambiguous replies. Permanent rejection and cancellation retain their
deduplication records.

Four focused metadata tests passed in **2.44 seconds** after a **13.05-second
build**: actual committed ACME source events, duplicate enqueue, retry timing,
stale attempt rejection, file-backed reopen, configuration cancellation and
transaction rollback, plus command codec truncation/unknown-variant checks.
Affected metadata all-target/all-feature Clippy passed in **25.60 seconds**.
The downstream daemon and its Rust dependencies compiled in **27.62 seconds**.
Secret-reference fixtures do not prove SMTP/HTTPS transport or decryption.
The first compile exposed conversion and migration-array-size mistakes; these
were corrected before the passing runs. No whole-workspace gate was run.

Still required: authenticated configuration/status API,
email and webhook transports, owned daemon delivery worker, operational panel,
manual-DNS/renewal delivery acceptance and the assembled-stage check. Task 21
remains partial with its existing estimate until the complete delivery path runs.
No dependencies, release, tag, publication or GitHub Actions were introduced.

### Notification transport slice

The in-process sender now supports authenticated HTTPS webhooks and authenticated
SMTP submission with implicit TLS or required STARTTLS. Destination settings are
typed Rust schema inputs, bounded to 16 KiB, and revalidated after decryption or
direct construction. Unknown/duplicate fields, plaintext webhook URLs, header
injection and duplicate recipients are rejected. The configured endpoint/relay
and recipient list form the explicit destination allow-list; event content never
selects a destination. Settings deliberately have no `Debug` implementation.

Each attempt has a 35-second deadline. HTTPS follows no redirects and sends a
stable canonical UUID `Idempotency-Key`; SMTP sends the same stable `Message-ID`
on retry. Only the closed event code, source ID, delivery ID, schema version and
source timestamp leave the appliance. Endpoint acceptance is not proof of inbox
arrival or exactly-once remote side effects. HTTP temporary failures request an
outbox retry; SMTP never falls back to plaintext and requires fresh EHLO/AUTH
inside TLS ([STARTTLS specification](https://www.rfc-editor.org/rfc/rfc3207),
[SMTP authentication](https://www.rfc-editor.org/rfc/rfc4954)). The initial SMTP
adapter supports SASL PLAIN over verified TLS and explicit ASCII mailboxes, not
automatic MX discovery or an arbitrary MIME/message editor. The current provider
and wire proof use TLS 1.3.

One settings-boundary test passed in **0.01 seconds** and three real local wire
tests passed in **0.25 seconds** after a **13.76-second build**. The wire tests
assert exact webhook JSON/authentication/idempotency values, success/redirect/
temporary-failure classifications, complete implicit-TLS and STARTTLS SMTP
conversations, and connection closure without credentials when STARTTLS is absent.
The first run exposed internal unhyphenated IDs leaking into the wire format;
the sender now uses the established canonical UUID formatter. A subsequent
webhook failure exposed `Connection: close` completing the connection driver in
the same poll that made the response available. The driver now consumes the
request's final result; the original expected success assertion remains unchanged.

Affected API/daemon all-target/all-feature Clippy passed in **10.37 seconds**;
`cargo deny check licenses` passed. No whole-workspace gate was run.

The sender reuses the existing locked Base64 and HTTP-date libraries; no versions
were added or upgraded. This remains transport-level evidence, not an operational
outbox-to-receiver workflow. Scheduling, administrative endpoints, panel controls,
gateway enrolment redistribution and the owned runtime worker still need wiring.

### Notification scheduling reads

The repository now exposes the bounded channel inventory, pending committed
source events and queued/expired-claim delivery pages. Projection does not move
a separate cursor: an event remains discoverable until its outbox row commits.
The delivery uniqueness constraint suppresses already queued or terminal events;
channel filters and the creation boundary are reapplied to each source page.
The worker must still claim the exact observed attempt before doing IO.

The four focused metadata cases, extended with source discovery and due-work
assertions, passed in **2.41 seconds** after a **6.75-second build**. Affected
metadata all-target/all-feature Clippy passed in **9.03 seconds**. These are
scheduling projections, not an executing background worker. The complete
outbox-to-transport integration and its restart proof remain required.

### Notification administration and owned daemon delivery

The native manager-only `GET/PUT /api/latest/admin/notifications` surface now
configures channels and reports redacted configuration/local worker health.
Authentication precedes body parsing and is rechecked for output; bounded owned
blocking jobs keep SQL off executor threads. Rust validates requests and
responses; OpenAPI generates Fetch, TypeScript and Zod boundaries used by the
operations panel. The panel offers webhook/email configuration, event selection,
explicit credential retention/replacement, disable and in-memory exact retries.
No credentials are returned in status or persisted in browser storage.

Migration 90 adds a settings commitment; migration 89's digest is unchanged.
Kind-80 configuration commands now carry the commitment and optional encrypted
secret generation, committed in the same transaction. This is an intentional
pre-alpha private-wire change. Old unbound configurations cannot deliver until
explicitly replaced. Settings plaintext is version byte 1, a private random
32-byte nonce, and strict destination JSON. SHA-256 binds that complete envelope;
rewrapping for new gateway recipients preserves the plaintext. Existing enrolment
secret redistribution now includes configured notification secrets.

The independently owned worker projects committed facts, claims due work,
decrypts settings, uses the existing in-process transports and records a fenced
outcome. Receiver/authority failure never stops file service or healing. A
cancelled/ambiguous send keeps its durable attempt for expiry/retry. Shutdown
observes its blocking worker; each network attempt remains bounded to 35 seconds.

Focused metadata/API tests: **5 metadata cases in 2.76 seconds; 2 API cases in
0.02 seconds**, after a 40.73-second dependency build. The new atomic-configuration
case injects failures after command, after audit and before commit, checking that
neither channel nor ciphertext survives the rolled-back transaction. Historical
configuration remains readable after a newer disabled revision.

Real local daemon proof:
`cargo test -p meshspan-daemon --test headless_process notification_channel_delivers -- --test-threads=4`
passed in **10.46 seconds**, after a **13.85-second build**. A real authenticated
HTTPS receiver returns 503, the daemon records retry, is killed/restarted, and
then sends the identical event/ID to a 204 response. The proof checks the durable
accepted attempt, explicit disable without resubmitting credentials, exact retry
after a newer configuration, redacted status and rejection of changed secret
input under an old operation ID. It authenticates before rejecting malformed JSON.

The first run failed after 19.51 seconds: retained metadata showed certificate
provisioning audit kind 122 but no outbox entry. Initial provisioning queues the
order atomically; the earlier projection included only standalone queue kind 115.
Both now map to the same queued fact. The original expected delivery assertions
are unchanged. The private failed fixture remains at
`/var/folders/xk/vb061tws5wv3z_00cskjqtwr0000gn/T/.tmpvufyRN`; it is not published.
Affected all-target/all-feature Rust Clippy passed in **24.20 seconds**.

Web TypeScript and strict ESLint passed. Eight focused web cases passed across
four files in **1.18 seconds**, including webhook creation, credential-free
disable, email form input, exact ambiguous retry, generated request/response
validation, and the affected operations/metrics clients. Initial fixture failures
were corrected: fake HTTP responses must carry contract headers, JSON object key
order is not a wire semantic, and a nested input is disabled by its ancestor
fieldset even when its own `disabled` property is false. The assertions still
require every field and the same exact retry payload. The panel work follows
the frontend-design guidance through labelled controls, contextual method fields,
explicit feedback and reuse of the existing layout; no visual redesign or live
browser operation was performed.

Full API regeneration and `pnpm check:generated` passed; the production web bundle
built in **340 ms**. An earlier check caught an index-only drift after running
just the Fetch sub-generator; rerunning the complete generator restored its
deterministic index. No generated file was edited by hand.
After embedding that rebuilt panel, the real daemon case passed again in
**10.68 seconds** after a **10.07-second build**. Final TypeScript, strict ESLint,
Rust formatting and affected document/web formatting passed; the eight focused
web cases passed again in **945 ms**.

Remaining task-21 proof and functionality: new-gateway delivery after recipient
redistribution, daemon-level SMTP, manual-DNS task notifications, retained
delivery/rejection visibility, and the assembled-stage checks. The existing wire
tests prove SMTP transport only. No full-workspace acceptance, release, tag,
image publication or GitHub Actions run is claimed by this slice.

### Retained notification outcome visibility

Each redacted channel status now includes exact decimal-string totals for pending,
receiver-accepted, permanently rejected and cancelled deliveries. Retries count
once, not once per attempt. The panel distinguishes a running worker from retained
rejections and explains that changed settings affect future events, not already
rejected events. No credential or remote error body is exposed. Counts refresh
on explicit status reads; no new polling loop or network request per delivery.

The repository query groups at most five persisted states. A real `EXPLAIN QUERY
PLAN` inspection selects the existing covering
`notification_deliveries_channel_state` index by channel identity. The five
focused metadata cases, extended with pending/accepted/rejected/cancelled totals,
passed in **2.78 seconds** after a **13.25-second build**. The panel fixture also
uses a counter above JavaScript's safe integer limit to require exact display.
Task 21 now has its intended initial feature path implemented; joined-gateway,
SMTP/manual-DNS and assembled-stage acceptance remain, so the estimate stays at
three points. This is not a declaration that Stage 10 is complete.

Affected all-target/all-feature Clippy passed in **26.46 seconds**. Complete API
regeneration/drift, web type checks and strict ESLint passed; six focused
web/client/component cases passed in **961 ms**, and the embedded web bundle
built in **282 ms**. Verification remains scoped to this behaviour, not the
whole-workspace gate.

The real daemon restart/delivery case also passed with the exact persisted
outcome totals in **10.76 seconds** (incremental build **0.14 seconds**). Rust
formatting passed. No publication or GitHub Actions were run.

## Tasks 22/25 — signed local candidate admission

The existing local package provenance now binds its generated API digest. The
local candidate preparer accepts one to four clean-source native packages,
requires matching source/version/API identity, copies exact executable bytes
into a fresh owned directory and signs their bounded canonical manifest with a
dedicated P-256 key. It never creates a tag, release or publication. The manifest
binds `GPL-2.0-only`, source commit, API digest, target, exact decimal byte length,
SHA-256 and explicit partition-schema/private-protocol compatibility claims.
Pre-1.0 rollback remains unsupported.

`meshspan-daemon verify-update` uses the existing in-process Rust cryptography to
verify a separately pinned public key and domain-separated signature, then
streams the selected executable through SHA-256. It opens no mesh database or
listener and does not execute the candidate. The report explicitly distinguishes
authenticity from compatibility, installation authority and acceptance. No new
dependency or system cryptographic service was introduced.

Focused static checks caught a tooling complexity violation and three Rust lint
issues before integration. Manifest identity, compatibility and artifact-set
validation now have separate responsibilities; the verifier borrows its command
arguments, uses a bounded heap IO buffer and formats hex without per-byte string
allocations. Affected all-target/all-feature Clippy passed in **13.87 seconds**;
the actual daemon executable built in **36.27 seconds**. Strict tooling ESLint
passed. The first tooling run passed six cases in **76.79 ms**, with the explicit
Node-to-daemon process case skipped until the updated binary had built.

With that binary explicitly selected, all **seven** packaging/candidate cases
passed in **2.50 seconds**, with **no skips**. The real daemon accepted the
Node-signed fixture with the independently pinned key and exact expected digest;
it rejected a same-length altered executable and an unrelated trusted key.
This closes task 25's initial signing/verification path (**5 → 3 points**), not
task 22's still-required rolling runtime. Stage 10 remains **121 points**.

This implements local authenticity tooling, not the mesh-wide update feature.
Remaining: trusted-signer configuration/admission, all database-family and
mixed-version compatibility, replicated rollout state, node staging/replacement,
quorum/gateway-aware order, failed-probe interruption/recovery, manager API/panel,
complete notices/SBOM and the assembled-stage proof. No user signing key, real
release or publication command has been used; tests sign disposable fixtures.

## Task 22 — replicated rollout journal and restart admission

Partition schema **91** adds independently configured immutable update signer
keys, one running-or-paused candidate and indexed per-node progress. Selecting
a candidate authenticates the exact manifest against the separately configured
enabled key and snapshots active members with `INSERT ... SELECT`; it does not
allocate a whole mesh-sized command. Reads page by node identity. Existing
schema-90 migration bytes remain unchanged. This is additive schema preparation,
not evidence of a real binary upgrade or downgrade support.

Typed canonical command kinds **84–87** configure a signer, start a rollout,
advance one node, and pause/resume/cancel. They use the existing manager
authorisation, transaction, audit, digest and exact-retry receipt path. Restart
admission requires every selected node staged and reserves one exclusive restart.
A failed or ambiguous restart pauses the rollout **without freeing that slot**;
resume continues probing it, and cancellation cannot pretend it is resolved.
Only verified node outcomes produce aggregate completion. Disabling a signer
pauses its running work; enabling it does not silently resume installation.

The restart witness binds the current compiled root stable/joint plan and fresh
ordered node-incarnation/catch-up observations. It must leave an eligible leader,
satisfy the actual election/write/read predicates and retain an available gateway,
unless the original selection explicitly accepted service interruption. Its
19-entry limit is a sufficient quorum/gateway witness, not a mesh-size or
connection limit. The runtime must still acquire these observations through
authenticated peers and check affected workload/placement and every delegated
group before authorising process replacement. **No automatic installer or public
advance-node endpoint is connected by this slice.**

Signed-manifest parsing moved from the CLI into the metadata owner so admission
and inspection use one Rust implementation. Metadata now directly uses the
already-present workspace `serde_json`; no package/version was added or upgraded.
The CLI retains only bounded file IO and exact executable hashing.

Four focused file-backed metadata cases passed in **2.80 seconds** after a
**6.01-second build**: ordered staging/completion, reopen with an active restart,
ambiguous failure/resume/cancellation, signer revocation, exact operation replay,
and two-versus-three-voter admission. Every command also round-trips the canonical
wire codec. These are persistence/protocol fixtures, not actual multi-node
installation or service-availability proof. Initial compilation exposed explicit
SQL integer conversion requirements; affected lint caught missing error docs and
an enlarged infrastructure dispatcher. The update command dispatcher now lives
with the update state transitions rather than extending unrelated dispatch code.
Affected all-target/all-feature Clippy passed in **26.63 seconds**, and
`cargo deny check licenses` passed.

After requiring a remaining eligible leader as well as the quorum predicates,
the four cases passed again in **2.81 seconds** (build **4.40 seconds**) and
affected metadata Clippy passed in **16.97 seconds**. The rebuilt real daemon
also passed all four local candidate/Node-to-Rust verification cases in
**2.54 seconds**, with no skips; the shared-parser move preserved executable
verification and wrong-key/altered-byte rejection. No full-workspace gate was
repeated for this slice.

Remaining task-22 construction: manager endpoints and panel, signed candidate
staging/distribution, owned node replacement/restart, authenticated probes,
workload/delegated-group readiness and real interrupted rolling-update proof.
The estimate remains **13 points**; Stage 10 remains **121 points**. No release,
tag, publication, GitHub Actions or user-browser operation occurred.

## Task 22 — native update administration

The native `GET/PUT /api/latest/admin/updates` route now exposes publisher trust,
signed candidate selection and pause/resume/cancel through the replicated journal.
These are public specialised API operations, not panel-only handlers. Managers
authenticate before the bounded body is read and again before output. Requests
and responses are validated in Rust; the same source generates OpenAPI, TypeScript,
Fetch and Zod. Unknown/duplicate fields, coercion and client installation claims
are rejected. The route uses its own owned blocking-job admission and deadline.

Signer keys are explicitly pinned public SEC1 material, immutable per identity;
no private signing key is accepted. Selection verifies the exact signed canonical
manifest through the metadata owner. An exact retry reconstructs its original
actor/time-bound command and returns its original receipt even after subsequent
controls or process restart. An unavailable/ambiguous commit stays unresolved,
not a false definitive rejection. The response means the manager command was
committed, **not that software was installed**.

Status returns bounded signer configuration and indexed phase counts without
materialising every member. Counts are exact decimal strings. `rollout_id` selects
retained work after completion/cancellation; omission selects active work. The
Operations panel offers trust, signed-file selection, progress and controls,
retains an unchanged in-memory request for ambiguous retry, and disables
cancellation while restart ownership is unresolved. It uses the existing panel
layout with separate publisher-trust, candidate-input and rollout-control
responsibilities. **Installation is explicitly unavailable in this build**;
there is no public advance-node/probe-success endpoint.

Local verification for this slice:

- Rust boundary regression: **1 passed, 0.02 seconds**, build **8.94 seconds**.
- Four file-backed rollout cases, including exact pending/staged/restarting/
  verified counts across reopen: **4 passed, 2.79 seconds**, build **12.56 seconds**.
- Native Fetch/Zod and headless DOM panel checks: **7 passed, 1.29 seconds**,
  including bounded file selection, default interruption consent off, exact retry,
  publisher disablement and unresolved-restart controls. DOM tests are not a real
  browser or installation proof.
- Real HTTPS child-daemon lifecycle: **1 passed, 6.81 seconds**, build **45.57 seconds**.
  Creates the mesh and recovery bundle, pins a disposable publisher, admits its
  signed manifest, checks exact pending counts, pauses, kills/restarts the daemon,
  replays original trust/selection receipts, resumes, cancels, reads retained work
  and rejects a changed retry. Anonymous malformed input returns 401 before decoding.
- Affected all-target/all-feature Rust Clippy passed in **19.66 seconds**;
  generated drift and web type-checking passed. The embedded web build took
  **0.331 seconds**. Initial checks caught a composition-size limit and a Fetch
  query-helper argument mismatch; neither limit nor generated validation was weakened.

No dependency/version or persisted schema/wire version changed. No full-workspace
gate was repeated per the current feature-first cadence. Remaining task-22 work:
candidate-byte staging/distribution, owned replacement/restart, authenticated
readiness collection and real rolling availability. Its **13-point** estimate and
Stage 10's **121-point** total remain unchanged until there is an operating updater.
No release, tag, publication, GitHub Actions or user-browser operation occurred.

Final affected TypeScript/ESLint checks passed, including the generators and
handwritten tests; seven web cases passed again in **1.39 seconds** after fixture
lint corrections. Final affected Rust Clippy and formatting passed in
**10.89 seconds** after the route's HTTP bound was aligned with the 24 KiB contract.

## Task 22 — verified executable upload

The native `PUT /api/latest/admin/updates/{rollout_id}/artifacts/{target}` now
streams raw executable bytes for a selected, trusted candidate. Managers are
authenticated before reading bytes and again before publishing the source.
The signed manifest supplies the only accepted platform, byte length and SHA-256.
Two owned transfer workers, bounded frames and a 30-minute deadline separate
bulk IO from short control jobs, so revocation/pause can run during an upload.

The daemon writes a private temporary file, verifies the entire stream, fsyncs it
and atomically publishes its immutable hash-named cache entry. Interrupted,
truncated, oversized or changed bytes do not become a published executable.
Existing cached bytes are reverified, including after restart. Only then does
typed metadata command 88 advertise this gateway's exact node/incarnation as a
source. Migration 092 stores these bounded, indexed retrieval hints. Source rows
are not node-staging, installation or continued byte-availability claims.

Rust generates the API contract, Fetch upload and Zod validation. The panel uses
the existing update layout and distinguishes upload receipt from installation.
Its upload model retains the exact file and operation for ambiguous retries;
the view displays the candidate's signed platform/size choices. Fetch sends a
Blob directly, leaving Content-Length to the browser rather than buffering JSON.

Focused local evidence:

- Five file-backed metadata cases passed in **3.26 seconds** (build **12.29**),
  including codec round-trip, wrong digest/incarnation rejection, reopen and
  keyset source lookup without marking the node staged.
- Two real file-store cases passed in **0.06 seconds** (build **9.82**): exact
  bytes, truncation, excess, changed hash, interrupted read, reopen and corruption.
- Real HTTPS daemon lifecycle passed in **6.97 seconds** (build **29.32**):
  signed upload, exact on-disk bytes, kill/restart, original receipt retry and
  changed-body rejection. This uses disposable local signing material only.
- Nine focused SDK/Zod/headless DOM cases passed in **1.51 seconds**. They cover
  raw transport, invalid inputs rejected before fetch, response validation and
  identical retry after a lost reply without claiming installation.
- Affected all-target/all-feature Clippy passed in **15.14 seconds**; Rust
  formatting, generated drift, web type-checking and affected strict ESLint passed.
  The final web bundle built in **0.301 seconds**.

Task 22 remains partial: peer distribution, owned executable replacement,
authenticated readiness and rolling availability are still to be connected.
The assembled-stage pass must also cover cache reclamation and receipt recovery
after candidate cancellation/revocation (upload currently requires a live trusted
candidate, including on retry). There is no install or public advance-node API.
The full-workspace gate was not repeated during feature construction. No new
dependency, release, tag, package/image publication, GitHub Actions or browser
operation occurred. Stage 10 remains **121 points**, including task 22's **13**,
until these pieces form an operating updater.

## Task 22 — automatic private executable distribution

Every daemon now runs one owned candidate-distribution worker. Once a manager
selects a trusted signed candidate and uploads an executable to one node, other
nodes select their own platform entry, page currently active source identities
and fetch the bytes over the existing Quinn/mTLS data channel. Control/consensus
traffic never carries executable bodies. A failed or absent source advances the
bounded source cursor; a later pass tries the other advertised nodes.

The source binds the request to current same-swarm node/incarnation/certificate,
root partition, deadline and the exact currently trusted signed candidate. It
returns a freshly verified file, not an arbitrary path from the request. Both
ends count and hash the stream. Headers and terminal results repeat the exact
candidate/platform/length/digest; frames must be contiguous and the receiver
requires terminal EOF. Only then may the shared cache verifier publish/fsync
the file. Peer transfer and HTTPS now share one bounded reader with explicit
finish versus disconnected-input semantics.

The receiving node publishes its own source advertisement through the existing
typed authoritative command, with a deterministic operation ID and original
receipt retry. It does not mark its update checkpoint staged or installed.
Cached bytes are reverified after process restart; an in-process successful
source publication avoids repeatedly hashing the same candidate on every tick.
Actual source reads still reverify the file, and later restart admission must
independently verify executable/compatibility/readiness evidence.

The daemon now owns data-stream tasks within its service cycle. Executable
sources have two transfer slots; each node has one outbound fetch job. Shutdown
interrupts transport and observes owned cache work. The assembly separates
operational composition from service supervision/result collection, rather than
extracting arbitrary lines to satisfy size limits. A failed updater does not
terminate otherwise healthy file services.

Focused local evidence on the current macOS host:

- Two real HTTPS/child-daemon cases passed in **21.37 seconds**, build **4.13**.
  The new case joins three real voters, admits a disposable signed candidate,
  uploads **196,725 bytes** once, waits for exact bytes and three committed source
  records on every node, kills/restarts a peer and confirms retained bytes/state.
  This spans multiple transfer frames; its fixed SHA-256 was calculated
  independently using Node crypto. All three checkpoints remain pending and
  `installation_available` remains false. The original upload/control restart
  and changed-body rejection case also passes.
- The private wire identity/malformed-shape case passed in **0.00 seconds**,
  build **5.91**; the shared real-file cache cases passed in **0.05 seconds**,
  build **27.23**.
- Existing real mTLS shard and backup lifecycle tests each passed in
  **0.32 seconds**, shared build **19.74**. These exercise the dispatcher retained
  beneath the appliance's new executable route.
- Affected all-target/all-feature Clippy passed in **15.20 seconds**. Rust
  formatting and diff checks passed. Initial local checks caught type/fixture
  mistakes and composition-size violations; no lint was disabled or weakened.

Private data envelope tags **80–82** are documented in the protocol catalogue.
No dependency, persisted schema, public API or released version changed in this
slice. No full-workspace test gate was repeated during feature construction.
Task 22 still needs owned executable replacement, authenticated current readiness
and the rolling availability proof; its **13 points** and Stage 10's **121 points**
remain. The assembled-stage pass also retains cancellation/revocation, corrupt
cache reclamation, mid-transfer loss and lifecycle stress coverage. This is real
peer-delivery evidence, not installation, hardware failure or release evidence.
No release, tag, image/package publication, GitHub Actions or user-browser
operation occurred.

## Task 22 — executable compatibility and durable staging

After verified distribution, the owning daemon now probes the signed executable
and commits a real node checkpoint. The candidate's `update-runtime-info` mode
opens no daemon state or listeners and emits one canonical bounded report:
format, exact `GPL-2.0-only` identifier, package version, compiled Cargo target,
generated API digest, private protocol major, metadata-command version and
partition/local schema targets. The compiled target prevents a GNU development
binary being misrepresented as a static-musl distribution artefact.

The updater freshly verifies the executable, enables owner-only execution and
runs this command in its owned blocking worker with an empty environment,
discarded stderr and an 8 KiB report bound. A single ten-second monotonic deadline
covers the report and child exit. Invalid/noncanonical reports, unsuccessful
exit or a failed probe do not produce a staged checkpoint. This is execution of
administrator-trusted signed code, not an OS sandbox for untrusted programs.

The report must match the signed version/API and selected platform. Command and
persistence formats must remain unchanged; schema-changing candidates currently
fail admission until a tested migration path exists. A signed compatibility
range alone is not evidence of a safe migration. These checks are executable
capability admission, not service readiness or completed installation.

Probe evidence binds the manifest digest, rollout, node/incarnation and expected
checkpoint sequence. It is fsynced in owner-only `update-evidence` before the
typed authoritative transition. Successful probes commit staged; failed probes
commit failed and pause the rollout. Exact operation/receipt retry is shared with
the existing update service. Pausing prevents new probes while still allowing
verified byte distribution; resumed failed nodes are eligible for a new probe.
The worker uses a keyed node lookup, not a whole-mesh membership scan.

Final focused local run under the active NVM toolchain and Rust 1.98.0:

- Three real daemon/HTTPS update cases passed in **34.72 seconds**, build
  **15.72**: exact administration/upload retry after restart, three-node signed
  multi-frame distribution plus failed executable admission, and actual signed
  daemon staging/evidence retained across restart. The last uploads the real
  approximately 152 MiB debug executable, not a reporting stub.
- Two runtime-report contract/IO cases passed in **0.10 seconds**, build **9.41**.
  They cover the exact accepted report, altered identity/API/platform/format,
  persistence/command mismatch, unknown fields, excessive output and expiry.
- Affected all-target/all-feature Clippy passed in **13.78 seconds**. Formatting
  and diff checks passed; no lint was disabled. No whole-workspace gate was
  repeated during feature construction.

No dependency, persisted schema or public API changed. No releases, tags,
package/image publication, GitHub Actions or user-browser operations were
performed. The current host proves macOS ARM64 staging, not Linux/macOS mixed
rolling installation or hardware availability.

The first real-binary upload stalled with exactly **27,684 bytes** absent from
the server's temporary file. Process samples showed the cache waiting for input,
not hashing. The shared test client had not flushed its final TLS records before
waiting for a response. Adding the required flush made the complete real-binary
path pass; the update upload test also now has a sixty-second deadline. The
interrupted failing fixture remains at `/var/folders/xk/vb061tws5wv3z_00cskjqtwr0000gn/T/.tmpo8fIef`.
A new socket-bound unit fixture initially filled its socket before starting the
reader; its writer and reader now run together in an owned scoped thread.
Neither interrupted run is passing evidence.

Task 22 remains incomplete: peer/service/catch-up observations, all-scope
availability admission, durable executable handoff, new-process verification
and the rolling availability proof are still required. The **13-point** task
estimate and **121-point** Stage 10 estimate remain unchanged. Migration
admission/refusal acceptance also remains in task 23. `installation_available`
remains false; staged is not installed.

## Task 22 — authenticated process readiness observations

The daemon now serves `ProbeUpdateReadiness`/`UpdateReadinessResult` on its
existing same-swarm Quinn/mTLS control channel. An indexed authority read checks
the current requester incarnation/certificate and retained candidate/publisher
trust. Only then does the endpoint request a fresh observation from the live
consensus reactor. The reply binds the rollout, identity, exact quorum plan,
applied/committed indices and public executable report. A changed plan or an
unmet applied-index barrier is refused, not reported ready.

The service-cycle owner sets listener-bound state only after HTTPS, HTTP-01 and
SMB have bound. It withdraws the state before sending normal shutdown to any
service; a guard also withdraws on cancellation/unwind. Persistence-blocked and
listener-bound fields remain separate. No inference of complete data availability
or a valid write quorum is made from them. No update phase is advanced by a probe.

The endpoint has two admitted probes, a maximum five-second request lifetime,
an 8 KiB report bound and a lazily reused repository reader. Blocking IO keeps
its permit and has an observed completion; it is not performed on the async
executor. Private read probes do not queue behind the private mutation lane.
Messages and their limits are recorded in the existing protocol catalogue.

Final focused local evidence under NVM and Rust 1.98.0:

- The real-process test passed in **12.41 seconds**, build **27.09**.
- The wire round-trip/bounds test passed in **0.00 seconds**, build **6.83**.
- Affected all-target/all-feature Clippy passed in **17.87 seconds**; formatting
  and diff checks passed. No lint was weakened and no full-workspace gate was
  repeated during feature construction.

The real-process test uses a second enrolled node's actual private certificate and Quinn negotiation
to query a live daemon, assert node/operation/plan/position/format bindings,
reject mismatched plans and impossible catch-up barriers, kill/restart the
responder, and obtain fresh observations without advancing any restart phase.
Its TLS identity stays inside the disposable fixture; no credentials are logged.

This closes the private responder, not the whole updater. The coordinator still
needs to collect/use these observations, prove all-scope workload availability,
admit and perform the durable executable handoff and verify the new process.
The existing applied-index admission also needs its final barrier/handoff
integration under concurrent writes; a moving local log head must not become
an endless retry loop. Task 22 remains **13 points**, Stage 10 **121**.
No dependency, persisted schema or public API changed. No release, tag,
publication, GitHub Actions or user-browser operation occurred.

## Task 22 — durable executable handoff

The updater now consumes the local node's **committed** `Restarting` reservation.
It rechecks candidate trust, verifies and probes the executable, retains an
owner-only fsynced installation selector, and asks the existing service-cycle
owner to stop its services. Only after that cycle ends does it self-exec the
signed cache executable. There is no external supervisor, shell or per-node
manual replacement command. The selector contains public authentication material,
not signing or node private keys.

The original launch command follows this selector before opening or migrating
databases. It checks the existing node identity and authenticated executable while
holding the daemon-state lock; the lock closes across exec. Reconstructed arguments
preserve native storage paths and listener settings but omit a consumed join code.
The new process checks its actual executable path, signed runtime contract,
retained minimum metadata revision and live applied/committed/listener state before
committing `Verified`. An unresolved reservation is not cleared by mere process
existence. A previously admitted running installation can finish verification
after publisher revocation; revocation still blocks a not-yet-started replacement.

The first focused two-daemon test passed in **42.14 seconds**, after a **4.97-second
build**. It uses the actual daemon executable, a disposable signing key, real
private caches, automatic daemon verification/staging, and typed private commands
to admit two explicitly interruption-allowed restarts. It observes each process's
real executable, checks retained evidence and committed progress, kills the first
node, launches the original command and verifies it follows the retained selection.
The test client reconnects after replacement and honours a changed leader. It does
not write authoritative SQLite tables or claim the rolling coordinator is finished.
This fixture runs on macOS/static-musl targets; GNU development binaries are not
silently treated as supported distribution artefacts.

Three focused startup-configuration tests passed in **0.00 seconds** after a
**34.13-second build**, including explicit join-secret omission. The final five
real-process update regressions passed together with four test workers in
**39.12 seconds**, build **33.18**. This includes upload/retry, three-node
distribution, executable staging, private readiness and the two-process handoff.
Affected all-target/all-feature Clippy passed with warnings denied in **3.97
seconds**; no lint was weakened. The operations-composition method now belongs
to its existing private authority owner, keeping update readiness and command
authority paired without enlarging the top-level service constructor. No full
workspace gate has been repeated during this feature-construction checkpoint.

During construction, the original combined-transfer fixture timed out while
downloading debug symbols: only 38 MB of a 159 MB executable had reached the peer
at its 15-second status deadline. Concurrent HTTPS upload and background download
also left the downloader busy after the cache was populated. The final actuator
fixture therefore prepares real cache bytes before candidate selection; existing
upload/distribution tests retain those independent responsibilities. Earlier
fixture errors included a noncanonical HTTP operation UUID, retry before receipt
catch-up, a stale control connection and treating a leader redirect as rejection.
These were corrected in the test, not by weakening runtime admission or increasing
its limits. The assembled updater must still exercise transfer/replacement together
and recover promptly from interrupted connections.

Remaining: automatic probe collection/order, all-scope data/locality/delegated-group
availability gates, fresh catch-up barrier integration under concurrent writes,
failed/ambiguous restart coordination and assembled rolling-availability proof.
`installation_available` remains false. No schema, public API or dependency changed.
Task 22 remains **13 points**, Stage 10 **121**, Stage 11 **126**. No release, tag,
package/image publication, GitHub Actions or user-browser operation occurred.

## Task 22 — automatic interruption-allowed installation

The owned updater now drives interruption-allowed installation without a test
client or administrator admitting each node. After every selected node has staged
the authenticated executable, an indexed query selects one candidate. That node
commits `Preparing`, continues serving, then commits `Restarting` and consumes the
existing durable handoff. No next node advances until the replacement commits
`Verified`. Explicit interruption consent is retained in the selected rollout;
the empty survivor witness does not claim availability. Without that consent,
automatic preparation/restart remains disabled pending all-scope readiness gates.

Partition migration **93** retains the actual preparation command's committed log
index. `Preparing` uses the existing staged storage encoding plus that non-null
barrier; it is distinct in the typed model and private command format **5** (phase
discriminator **6**). A unique index reserves preparation/restart together. Restart
admission compares fresh peers with that fixed index and the current quorum plan,
not the ever-moving applied head. Failed preparation can resume staging without
claiming a process restart; already admitted ambiguous restarts remain reserved.
No dependency or public API schema changed.

The two-node real executable test now selects once and observes both automatic
replacements, committed completion and original-launcher recovery. It no longer
submits private admission commands. As before, this fixture preloads real cache
bytes; upload/distribution remain independently exercised, not a combined
full-size transfer-and-install proof. The initial automatic run failed because
its old 15-second timer began before staging instead of after manual admission.
Retained state showed committed restart and a saved installation selector. The
fixture now keeps the same 15-second per-step bound and permits only three forward
milestones per selected node to reset it; no production timeout changed.

The next five-test run passed automatic replacement but exposed a different real
bug: the status response combined the old rollout sequence with freshly committed
staging counts. Update administration now reads publisher trust, selected work and
counts in one short SQLite read transaction, without a writer lock or network IO.
A deterministic regression commits staging through another connection at the
former read boundary and proves the response is wholly before the commit, while
the next response is wholly after it. The existing failed process assertion is
unchanged.

Focused evidence so far on this working tree:

- Eight metadata update tests passed in **4.70 seconds**, build **9.63**; this
  includes preparation/reopen, a changed log head, stale witnesses, scheduling
  selection, ambiguous restart ownership and the concurrent-read regression.
- The automatic two-process test passed in the **47.77-second** five-test run;
  that run was **not green** because of the status race above. The earlier run
  was **4 passed, 1 failed in 34.52 seconds** at the aggregate fixture deadline.
- Nine focused web tests passed in **2.09 seconds**. TypeScript and targeted
  warning-denied ESLint passed. The initial root `pnpm exec eslint` invocation
  could not find ESLint; the check used the existing tooling package binary.
- After the read fix and embedded panel rebuild, all five real-process update
  tests passed in **47.31 seconds**, build **31.88**. Affected all-target/all-feature
  Clippy passed in **25.86 seconds**. No full-workspace gate was repeated here.

The coordinator then gained actual surviving-voter probe collection through the
existing Quinn/mTLS endpoint. At most eighteen stable/joint voters share one
two-second monotonic deadline; observations bind operation, mesh, partition, peer,
incarnation, selected rollout, current plan, applied barrier and serving state.
Invalid or unavailable peers are absent from the sorted witness. Evidence retains
the actual returned participants; interruption consent never manufactures one.

The stronger automatic test requires the joined node's retained admission to
contain the live root's witness. Its first run completed both installations but
failed that check in **45.66 seconds**: the root's first admission retained its
peer, while the peer's later probe used an old connection after root self-exec,
spent its deadline and retained an empty list. The existing network drops that
specific cached connection on request cancellation/failure. Readiness now reserves
half its unchanged deadline for one fresh retry of the same read-only request.
No mutation retry or generic networking policy changed. That run retained valid
witnesses for both replacements, but the new assertion compared compact `NodeId`
display text with hyphenated UUID evidence and failed in **44.01 seconds**. The
assertion now compares the same identity representation. Final witness/replacement/
cold-launch verification passed in **47.13 seconds**, build **2.99**; affected
all-target/all-feature Clippy passed in **10.29 seconds** before that test-only
representation correction. The prior missing-witness run's retained state is not
claimed as a pass.
Final affected Clippy after the corrected assertion passed in **4.94 seconds**;
Rust/document formatting and diff checks also passed.

The panel now states that interruption consent is required by this build's
operating installer; it no longer falsely promises that no running software can
be replaced. The clarify skill informed that wording only, not authority policy.
Remaining: full multi-voter failure acceptance, workload/locality/delegated-group
availability, placement/publication fencing, failure coordination and assembled
transfer/rolling-availability acceptance. Task 22 remains **13 points**, Stage 10
**121**, Stage 11 **126**. Signing is still blocked by the previously reported
1Password authentication failure; no unsigned commit or repeated prompt was used.
No release, tag, package/image publication, Actions or user-browser operation ran.

## Task 22 — surviving encrypted-content checks

The filesystem repair owner now also checks current read availability without
writing shards, reserving storage or obtaining volume decryption keys. Its caller
selects permitted surviving targets; it reads distinct authenticated shards,
reconstructs the ciphertext and independently verifies the recorded length and
BLAKE3 digest. The result contains only the exact contributing provider receipts.
Unavailable or corrupt slices do not count, and excluded targets are never read.
The existing repair operation reuses this reconstruction path.

The catalogue has a separate bounded committed-volume inventory which includes
acknowledged stripes with unfinished eventual placements. The existing rebalance
inventory continues selecting only fully populated layouts. Availability scans
must use the former: ignoring files merely because an optional replica has not
arrived would incorrectly make them disappear from update admission.

Focused real-folder evidence on this working tree:

- Four protected-content tests passed in **2.37 seconds**, build **19.56**.
  The new verifier checks exact surviving receipts, rejects duplicate selectors,
  fails when a selected survivor is lost despite healthy excluded targets, and
  leaves the original plaintext readable. Its routing guard rejects all writes
  and reads outside the selected set.
- With the inventory added, five protected-content tests passed in **2.94
  seconds**, build **5.84**. Two real publications prove pagination includes an
  acknowledged three-of-four layout followed by a complete layout, while the
  existing rebalance query still selects only the latter.
- Affected filesystem/daemon all-target/all-feature Clippy passed in **45.12
  seconds** before the final completeness recheck was retained for the existing
  rebalance query. Final affected Clippy passed in **22.43 seconds**.
- The final filesystem crate suite passed: **202 unit tests in 25.01 seconds**
  and **10 integration tests** across the five existing harnesses, with the five
  protected-content cases taking **2.91 seconds**; build **13.38 seconds**.
  Rust formatting, NVM-run document formatting and diff checks passed. The full
  workspace gate was not repeated for this slice.

These are usable filesystem operations, not completed automatic update admission.
The daemon still needs all-scope catalogue catch-up, publication fencing, locality
and delegated-group checks before enabling uninterrupted installation. A local
scan is explicitly not a promise about subsequent writes. No new dependency,
SQL migration, API schema or protocol message was introduced by this slice.
Task 22 and Stage 10 remain in progress; the publication hold is unchanged.

## Task 10 — headless offline backup verification

`meshspan-daemon verify-backup BACKUP SHA256 RECOVERY_BUNDLE RECOVERY_CODE_FILE
NEW_WORK_DIRECTORY` now runs before normal daemon configuration or state opening.
It needs no running mesh, gateway key, listener or external service. The expected
digest comes from the original authenticated export receipt; recalculating it
from an untrusted replacement is not equivalent. The code is read from an
owner-only bounded file, never passed as a secret command argument. Bundle decoding
accepts the binary format and the existing prefixed hexadecimal setup/panel
download through its encoding owner's decoder.

The command authenticates the recovery bundle, verifies the pinned full-container
digest, decrypts/authenticates every encrypted chunk and uses the existing staged
SQLite restore verifier. Source mesh/partition, schema, membership, integrity and
exact applied position/revision are checked. The restored recovery public key,
root certificate and bundle digest must match the independently supplied authority.
The new private workspace is not a live database destination; an existing path is
never overwritten. Temporary plaintext is removed before success is reported.
Cleanup failure is an error. Power loss can leave private temporary plaintext;
normal unlinking is not a secure-erasure guarantee.

The JSON report identifies that exact verified metadata generation and explicitly
does not claim latest-state, file-shard or live-service recovery. Neither arbitrary
cluster admission nor complete recovery of every data-encryption key is implemented
by this command. The [operator flow](flows.md#offline-backup-verification) records
the command, digest provenance, workspace requirements and these scope boundaries.

Real-process proof creates a mesh through HTTPS, saves/verifies the setup bundle,
waits for an automatic protected backup and downloads its real encrypted export.
After stopping the daemon it runs the actual executable's offline command and
compares its exact log index, term, revision and schema with the retained backup
catalogue. It then proves wrong-code rejection, rejection of modified ciphertext
with both the original and recalculated outer digest, cleanup after failed
decryption, refusal to overwrite an existing workspace and unchanged live database
and exported bytes.

The initial compile used unavailable identifier/process conveniences; it was
corrected to the workspace's UUID construction and an explicitly owned standard
library child, without adding dependencies or Tokio features. The first runtime
proof failed in **7.12 seconds** because the command assumed base64 rather than
the existing prefixed hexadecimal bundle download. Adding decoding to the actual
download owner fixed it: the full workflow passed in **8.29 seconds**, build
**14.47**. Strengthening the position comparison first failed in **6.07 seconds**
because the test passed a hyphenated API identifier into the compact domain parser;
that failed fixture was retained. Normalising the test identity yielded the final
pass in **8.13 seconds**, build **3.58**. Failed checks are not counted as passes.
The saved-bundle round-trip/reopen unit test passed in **0.08 seconds**, build
**28.13**. Warning-denied all-target/all-feature Clippy initially rejected two
late test imports and an unnecessarily owned assertion argument; after those
test-only corrections it passed in **4.05 seconds**. Rust formatting, NVM-run
document formatting and diff checks passed. No full-workspace gate was repeated.

Task 10 is now **8 points remaining**, down from 13; Stage 10 is **116**, Stage 11
**126**. The outstanding work is replacement-cluster recovery authority, secret
coverage, membership/service admission and assembled-stage acceptance. No schema,
wire or public HTTP API changed; no new dependency was added. Signing is still
blocked by the existing 1Password authentication failure. No release, tag, image,
package, Actions or user-browser operation occurred.

## Task 10 — retained recovery-secret verification

The offline verifier now uses an indexed, bounded metadata identity inventory to
check every retained secret generation, including historical keys. It loads one
encrypted record at a time, requires the exact recovery recipient/context,
authenticates its envelope and decrypts the secret; the plaintext is immediately
zeroised. The result reports `retained_secret_generations_verified` as a string
count without exposing identities or material. This adds no network service,
schema migration, public HTTP change or dependency.

The repository regression verifies exact historical ordering, full final-page
termination, an empty continuation and use of the existing covering index:
**1 passed in 0.30 seconds**, build **8.67**. The first compile exposed use of an
unavailable statement-cache feature and an unsupported `usize` SQL parameter;
the implementation now uses the existing ordinary preparation and checked integer
conversion, without changing features. Exact-recipient and substituted-ciphertext
rejection passed in **0.01 seconds**, build **25.61**. The actual encrypted export,
daemon shutdown and offline verification workflow passed in **7.29 seconds**,
build **33.94**, including the new non-zero verified-secret count and existing
wrong-code/corruption/unchanged-live-state checks.

All-target/all-feature metadata and daemon Clippy initially rejected a nested
conditional. Expressing recipient selection as a guard preserves behaviour;
the warning-denied rerun passed in **15.64 seconds**. After that correction, the
secret regression passed again in **0.01 seconds** (build **7.73**) and the real
process workflow passed in **7.28 seconds** (build **13.44**). No full-workspace
integration gate, signing retry or publication was performed.

This proves recoverability of retained secret rows, not the presence of every
referenced content key or replacement-cluster service admission. Recovery epoch,
old-node/capability fencing and replacement membership remain unfinished. Task 10
remains **8 points** and Stage 10 **116**; no stage-completion claim is made.

## Task 15 — protection and locality observations

The complete collection path now joins a read-only placement assessment,
incremental local-catalogue collection, the non-waiting observation store,
authenticated exporter and existing panel history. Nine fixed families report
pass age/duration/failure, assessed and unassessable stripes, missing receipts,
insufficient decode receipts, failure-policy debt and locality debt. The closed
catalogue grows from 55 to 64 families, within the existing history schema bound;
no public HTTP schema, private message or persistence migration changes.

The placement assessment reuses existing fault-scenario and cell predicates,
including eventual locality and excluded cells, without planning mutations.
Current-generation recorded slices are assessed; planned-but-unreceipted slices
are never substituted. Unknown policy/topology evidence remains unknown. The
existing storage IO worker collects at most 16 stripes per tick and waits 60
seconds between completed/failed passes. A new indexed volume-identity page avoids
rename-sensitive UI cursors. A failed pass keeps the older completed observation
with increasing age, not partial totals. These are local catalogue observations,
not mesh-wide coverage, a cross-page snapshot, physical byte probes or authority.
The [metric catalogue](metrics.md#protection-and-locality-observations) records
their exact scope and units.

Focused evidence on this uncommitted candidate:

| Check                              | Result         |     Execution |   Build |
| ---------------------------------- | -------------- | ------------: | ------: |
| Contract and placement unit suites | 23 + 15 passed | 0.00 + 0.43 s |  3.56 s |
| Runtime observation tests          | 12 passed      |        0.01 s | 58.20 s |
| Rename-stable volume pagination    | 1 passed       |        0.29 s |  3.94 s |
| Daemon local-state tests           | 6 passed       |        0.44 s | 13.89 s |
| Real protection-metrics lifecycle  | 1 passed       |       10.24 s | 22.41 s |

Test preparation initially exposed two module-path errors, a short-lived closure
input, a standard/Tokio deadline mismatch and a fixture's versioned-ID convention.
These were corrected without loosening bounds or changing expected outcomes.
The first executed lifecycle then failed in **21.71 seconds**: disconnecting the
folder caused `UpdateInstallation` before HTTPS could start. Its fixture remains
retained at `/var/folders/xk/vb061tws5wv3z_00cskjqtwr0000gn/T/.tmpE4L15N`.

The cause was shared state-directory admission canonicalising every storage path
as though data mounts must be present. Admission now resolves the existing prefix
of an absent storage path without creating it; overlapping state and unresolved
parent traversal are still rejected. The reconciler checks the actual canonical
location again before writing a registration marker, including a returning path
whose symlink destination changed. The real test verifies exact debt/unknown
counts after restart, folder loss and return, then checks original file bytes.
The local-state regression also removes several path ancestors, checks identity
continuity, absent storage remaining absent and rejection of nested state overlap.

Warning-denied all-target/all-feature Clippy for contracts, placement, filesystem,
metadata and daemon passed in **44.36 seconds**. Its first pass requested an
explicit copyable view for the borrowed placement request; adding the same
`Clone, Copy, Debug` representation as the neighbouring placement request types
resolved it without suppressing lint or changing runtime behaviour. No full
workspace integration gate was repeated.

No new dependency, release, tag, publication workflow, image/package push or
signing retry was used. Task 15 is implemented with assembled-stage verification
remaining: **3 → 1 points**. Stage 10 is **114 points**, Stage 11 **126**. This is
not stage completion or a substitute for the outstanding live/hardware proofs.

## Task 16 — filesystem space and durable maintenance jobs

Two additional collection paths are implemented end to end on the existing
storage IO worker, with no provider IO or consensus mutations on metric scrapes:

- Folder-backed filesystem observations use the open directory capability for
  capacity, available bytes and host-local device identity. Shared-filesystem
  folders count once per pass, with conservative repeated observations and
  explicit missing evidence. Payload accounting remains separate. Distinct
  filesystems sharing APFS/ZFS/thin pools are not asserted to be independent
  physical capacity; the exporter help and metric contract state this limit.
- A stable primary-key cursor pages 16 retained maintenance jobs per tick through
  the same validated record decoder as execution. All five maintenance kinds
  expose queued, claimed and authoritatively completed counts, recorded debt,
  execution-demand budgets and sample age. Failed passes preserve the previous
  sample and count a dropped observation. No count is inferred from attempts;
  budgets are not progress percentages or bytes remaining to transfer.

The closed catalogue grows from 64 to 103 families. The Rust history bound is
updated and OpenAPI/Zod artefacts regenerated through NVM; no new dependency,
database migration, private protocol message or publication workflow is added.

Focused evidence on the uncommitted working tree:

| Check                                                                              | Result    | Execution |   Build |
| ---------------------------------------------------------------------------------- | --------- | --------: | ------: |
| Real folder shared-provider capacity/read/write regression                         | 1 passed  |    0.08 s |  5.39 s |
| Runtime observations, including full-catalogue history encoding                    | 14 passed |    0.03 s | 16.06 s |
| Durable maintenance lifecycle, stable pagination and completed-effect observations | 8 passed  |    3.79 s |  6.23 s |
| Worker aggregation excludes completed jobs from pending debt/demand                | 1 passed  |    0.00 s | 11.21 s |
| Real two-daemon exporter, history, restart and peer service after root loss        | 1 passed  |   10.93 s | 27.58 s |
| Web generated metrics/history and update administration                            | 14 passed |    1.41 s |       — |

Warning-denied all-target/all-feature Clippy for contracts, storage, metadata and
daemon initially passed in **37.73 seconds**. Final schema-bound tests verify all
103 families encode in Rust and the generated Zod boundary accepts 103 and
rejects 104. Generated drift, web ESLint and TypeScript checks passed. Web lint
first caught an oversized test grouping and an unnecessary fallback in the
update-client renderer: history/exporter tests now have separate responsibility
groups, and the renderer uses its validated non-optional query directly. Generated
files were regenerated, not hand-edited. The additional Rust history assertion
also needed its import moved to module scope; no lint rule was weakened.
The final affected Clippy pass succeeded in **4.92 seconds**, followed by
Rust formatting and diff-whitespace checks.
No full workspace gate was repeated. Signing remains
unavailable pending owner reauthentication; no bypass or retry was attempted.
No release, tag, package/image publication or GitHub Actions run occurred.

Task 16 remains partial for target IO/integrity, actual transfer progress and
assembled-stage acceptance: **5 → 3 points**. Stage 10 now has **112 points**;
Stage 11 remains **126**. This is not completion of Stage 10.

## Task 16 — target IO and integrity observations

The shared provider now reports exact reads, installations and scrub calls to
the daemon's process-lifetime observation store through a replaceable contract.
An owned call observation records duration including target-lock residence,
failure/unwind, returned/acknowledged/scrub-observed payload bytes and corruption
reports. The provider lock is released before invoking the non-waiting observer.
Checked counters/histograms and dropped-observation reporting do not change
domain outcomes. Provider reopening keeps the same process counters; a process
restart resets them.

Successful scrub calls can contain corrupt records, so scrub corruption is not
conflated with call failure. Corrupt reads return their original failure and
report corruption independently. Payload replay is counted again: these counters
are not unique stored bytes, disk traffic, pack amplification, network delivery
or filesystem publication acknowledgements. No paths or identities become labels.
No new dependency, persistence migration or private wire message is introduced.

Fifteen fixed families extend the catalogue and Rust-authored history bound from
103 to 118. OpenAPI/Fetch/Zod artefacts were regenerated under the active NVM
toolchain. Generated drift, strict web ESLint and TypeScript checks passed;
the generated metrics/history tests passed **8 tests in 0.795 seconds**, including
the 118/119 collection boundary.

Focused local evidence:

| Check                                                                                                            | Result    | Execution |   Build |
| ---------------------------------------------------------------------------------------------------------------- | --------- | --------: | ------: |
| Shared provider: real read/write, healthy scrub, altered stored payload, rejected corrupt read and corrupt scrub | 4 passed  |    0.15 s |  5.20 s |
| Contracts including IO-family identity and histogram validation                                                  | 24 passed |    0.00 s |  5.17 s |
| Runtime observations including IO, contention, overflow and complete history encoding                            | 16 passed |    0.03 s | 57.62 s |
| Real upload/restart/folder loss/reconnection/readback with observed write/read counters                          | 1 passed  |   10.56 s | 39.31 s |

The local corruption test independently expects 13-byte write, read and scrub
measurements, zero returned bytes on the corrupt read, and separate corruption
reports from the read failure and completed scrub. It changes only an owned
temporary pack database. No test timeout or safety contract was weakened.
Warning-denied all-target/all-feature Clippy for contracts, storage and daemon
passed in **50.44 seconds**. Rust formatting and diff-whitespace checks passed.
The broad workspace integration gate was not repeated for this feature slice.

Task 16 remains partial for actual transfer progress and assembled acceptance:
**3 → 2 points**. Stage 10 now has **111 points**; Stage 11 remains **126**.
There is no full-stage, physical-power-loss or real-hardware completion claim.
No signing retry, release, tag, package/image publication or GitHub Actions run
occurred. The release hold remains in force.

## Task 16 — durable maintenance progress

The retained-job observation worker now reads existing durable work progress
rather than inferring it from attempts or execution budgets. Repair totals use
committed replacement-shard receipts, including effects whose completion response
was lost. Scrub and reconciliation prefer complete authoritative effects and
otherwise use generation-bound local checkpoints through a new read-only loader.
Rebalance contributes committed scanned stripes/admitted repairs. Drain progress
uses authoritative safe-to-detach state; relocation bytes stay under repair jobs,
not a duplicate drain transfer total. No second accounting journal was introduced.

Missing global/local verification progress after a job has started is explicitly
unknown, since its worker may be remote. Unknown progress omits aggregate progress
gauges for that pass while keeping coverage and ordinary queue counts. An invalid
or contradictory read abandons the pass and retains the preceding aged sample.
These are durable recorded steps, not bytes in flight, an ETA, a percentage or
new authority. Local checkpoints and their later global effects are never summed.

Nine fixed families extend the Rust-authored catalogue/history bound to 127.
OpenAPI/Zod generation and drift checks passed through NVM. Web metrics/history
tests passed **8 tests in 1.37 seconds**, with ESLint and TypeScript checks passing.
No dependency, database migration, private message or new background task was added.

Focused evidence:

| Check                                                                              | Result    | Execution |   Build |
| ---------------------------------------------------------------------------------- | --------- | --------: | ------: |
| Durable maintenance lifecycle, including exact scrub/reconciliation progress views | 8 passed  |    3.86 s | 21.55 s |
| Local verification checkpoint read, identity fencing, replay and reopen            | 1 passed  |    0.02 s |  0.11 s |
| Runtime observations, progress aggregation/unknowns and complete history encoding  | 17 passed |    0.03 s | 49.95 s |
| Real upload/restart/folder loss/reconnection/readback and progress coverage        | 1 passed  |   10.81 s | 34.71 s |

The metadata fixtures independently assert **6 observations / 12,288 verified
bytes** for scrub and **2 / 4,096** for reconciliation. The checkpoint fixture
reads an absent record without creating it, verifies intermediate progress and
checks final exact state after reopening the database. Aggregation tests assert
exact repaired-byte totals, distinguish scan counts from repair admission, and
omit partial totals rather than presenting unknown progress as zero. The process
proof checks coverage and omission semantics, not a complete multi-worker progress
or repair-throughput acceptance matrix.
The final warning-denied all-target/all-feature Clippy pass for contracts,
metadata and daemon passed in **14.78 seconds**, after correcting one missing
statement semicolon without changing behaviour or lint policy. Rust formatting
and diff-whitespace checks passed.

Task 16's core collection is implemented, with underlying shared-pool attribution
and assembled-stage verification remaining:
**2 → 1 points**. Stage 10 has **110 points** and Stage 11 **126**. Physical IO
attribution, client transfer outcomes and byte-in-flight observations remain part
of task 17's separate data-path work. No full integration gate, signing retry,
release, tag, package/image publication or GitHub Actions run occurred.

## Task 17 — transport and coding measurements

Implemented on the current uncommitted `codex/stage10-update-handoff` tree:

- HTTPS observes actual HTTP-byte reads/writes after TLS admission; SMB observes
  actual Direct TCP socket bytes. The shared wrapper preserves partial writes,
  vectored IO, pending polls, EOF and error results without extra buffering.
- Eight fixed transfer families separate received/sent bytes from failed IO
  polls. They do not claim logical payload totals, peer delivery or saved files.
- The production filesystem and repairer compose the existing Reed–Solomon
  engine with twelve fixed coding families: calls, failures, supplied/returned
  bytes, missing-systematic-slice requests and duration for encode/reconstruct.
  No engine, lifecycle, placement, publication or acknowledgement result changes.
- OpenMetrics and local history share the same typed 147-family catalogue.
  Collection does no provider/network IO; telemetry contention or arithmetic
  exhaustion cannot fail domain work. Counts reset on process restart.

Focused local verification:

| Check                                                                 | Result    | Execution |   Build |
| --------------------------------------------------------------------- | --------- | --------: | ------: |
| Partial/pending/vectored IO, EOF and explicit IO failures             | 2 passed  |   <0.01 s | 44.81 s |
| Real listener tests, including exact TLS/SMB transfer counts          | 4 passed  |    0.15 s |  0.17 s |
| Real coding healthy/degraded/insufficient-slice vectors               | 1 passed  |    0.23 s |   121 s |
| Observation store and complete catalogue/history encoding             | 17 passed |    0.06 s |  0.36 s |
| Daemon upload, restart, folder loss, return, readback and new metrics | 1 passed  |   20.24 s |    81 s |

The coding vector independently expects 16 logical bytes → three 8-byte slices,
then two exact 16-byte reconstruction results and one explicit insufficient-data
failure. Totals are 48 reconstruction input bytes, 32 output bytes, three calls,
one failure and two calls with missing systematic data. The real TLS test excludes
the rejected plaintext connection and TLS framing; the SMB test counts the four
bytes read from the rejected frame as well as the valid request/response.

The initial transfer Clippy pass found a composition-length violation and test
imports after statements. Composition now shares one observation owner between
dispatch and transfer interfaces; imports are module-scoped. No lint suppression
or arbitrary helper extraction was added. The transfer-only warning-denied pass
then succeeded in 38.08 s. Combined coding/transfer lint also identified the
central catalogue's growing responsibility and a copy-only observation value.
Gateway family metadata now lives together in the gateway catalogue, preserving
every existing name/help string; coding observations are explicitly `Copy`.
The final warning-denied daemon/contracts all-target/all-feature Clippy pass
succeeded in **32.52 s**. Rust formatting, generated API drift, strict ESLint,
TypeScript, Markdown formatting and whitespace checks passed. The regenerated
147-family Zod boundary and web history tests passed: **8 tests, 1.52 s**.
After the catalogue regrouping, the combined focused Rust rerun passed:
**24 tests in 0.26 s**, following a **49.68 s** incremental build. This covers
both listeners, transfer IO, coding and runtime observation/history projection.

Task 17 remains partial: **5 → 3 points**; Stage 10 **110 → 108**. File-level
outcomes, pack/deduplication measurements and assembled-stage acceptance remain.
Missing-data reconstruction is not a full degraded-file-read or mesh-availability
assessment. No full integration gate, signing retry, release, tag, publication
or GitHub Actions run occurred. Signing remains blocked by the previously
reported 1Password authentication failure; no unsigned workaround was used.

## Task 17 — shared filesystem outcomes

The shared production adapter now observes open, read, staged write, flush,
close and upload completion for both connectors. Calls, returned errors and
duration are separate from verified read bytes and accepted staging bytes.
Returned errors do not imply rollback; exact retries count again. Observation
contention cannot prevent the operation or change its result.

Successful publication-barrier results additionally record their exact
node-local, cell-replicated or globally converged scope. These counts occur after
the existing verification and any required converged-head commit. They do not
claim unique versions or client delivery, and a later outer error does not undo
an already verified publication. No authority or persistence rules changed.
The typed exporter/history catalogue now has **170** families.

Focused evidence on the current uncommitted branch:

- **19 observation tests passed in 0.05 s**, after a **196 s** build. New vectors
  distinguish four verified read bytes, six replay-inclusive staged bytes,
  pre-coding read failure and ambiguous upload failure from publication counts.
  A held telemetry lock does not prevent the operation from returning unchanged.
- The real daemon upload/restart/folder-loss/return/readback flow passed in
  **20.41 s**, after a **75 s** build. Before restart it independently expects
  one successful staging call, **31** staged bytes, one upload completion and
  exactly one node-local publication (zero cell/global publications). After
  restart it expects two successful reads totalling **43** bytes, two closes,
  a third open returning the missing-file error before coding, and zero new
  publications. Existing integrity/readback and protection/progress assertions
  remain in the same flow.

Task 17 remains partial: **3 → 2 points**; Stage 10 **108 → 107**. Remaining
scope is pack amplification/compaction, deduplication savings and assembled
failure/durability acceptance. The first Clippy pass found identical counter
match arms and a missing statement semicolon; these were corrected without a
behaviour change or suppression. Final daemon/contracts all-target/all-feature
Clippy passed in **31.64 s**. Generated API drift, strict ESLint, TypeScript,
Rust/Markdown formatting and whitespace checks passed. Generated 170-family
validation and web history tests passed: **8 tests in 2.32 s**.
No full integration gate or publication was run. Signing remains blocked by the
previously reported authentication failure; no unsigned commit was attempted.

## Task 17 — pack space and reopened storage prerequisites

The provider now reads coherent pack page metadata through its existing owned
SQLite connection; the existing periodic IO worker records four fixed pack-space
families. Database extent and internally reusable free-list bytes are separate
from logical quota and filesystem free space. Missing or invalid evidence omits
the aggregate bytes and reports unknown coverage without invalidating independent
quota evidence. This adds no schema migration, allocation scan, compaction or
scrape-time IO. The catalogue now has **174** families.

Focused local results on the uncommitted branch:

- **6 storage tests passed in 0.18 s**, following a **13.13 s** build. Exact
  page conversion expects 10 × 4,096 = 40,960 extent bytes and 3 × 4,096 =
  12,288 reusable bytes; invalid/overflowing page metadata fails explicitly.
  Real pack/reopen checks retain valid extent evidence. The existing guarded
  tombstone/restart/unlink proof now uses a 128 KiB shard and verifies at least
  120 KiB becomes internally reusable while database extent remains present.
- **20 runtime observation tests passed in 0.05 s**, following a **119 s**
  build. Two samples independently total 81,920 database bytes and 16,384
  reusable bytes while logical committed quota remains 34 bytes. Missing,
  contradictory and overflowing pack evidence omits pack totals but preserves
  independent quota observations.
- The real daemon upload/restart/folder-loss/return/readback and metrics flow
  passed in **20.94 s**, following an **80 s** build. It sees one measured
  pack target, zero unknown pack targets and coherent extent/reusable values.

This work also contradicted two prerequisite assumptions behind the former
2-point task estimate:

1. `FolderShardStore` opens one `PackStore` at `ACTIVE_PACK_SEQUENCE = 1`.
   Guarded BLOB unlink/free-list reuse exists; explicit bounded pack rollover,
   multi-pack routing and CoW compaction cutover do not. These are DAT-021
   requirements, not optional metric enhancements.
2. `ProtectedContentPublisher::resolve` resolves the same publication operation;
   `finish` invokes `prepare_layout`, which generates a new content key and
   encrypted layout. The catalogue reseals that operation, and the pack only
   coalesces the exact shard identity. This does not implement D-058 §5 compatible
   encrypted-layout reuse for independently uploaded identical content.

Stage 4 and Stage 5 completion labels are reopened for these exact omissions;
their existing core/provider/federation evidence remains valid. Task 17 now
tracks **13 points for each prerequisite including its measurements and proof**,
counted once: **2 → 26 points**, Stage 10 **107 → 131**. This is correction of
an unsupported estimate, not newly invented product scope. No savings counter
has been fabricated, and no cleanup or authority rule was weakened.

Affected storage/daemon/contracts Clippy, API regeneration and generated drift,
the two focused web test files, web ESLint and TypeScript checks completed
successfully in the retained local command session. No full integration gate,
release, tag, package/image publication, GitHub Actions or signing retry was run.

## Task 17 — indexed packs and automatic copy-on-write reclamation

The [provider implementation and exact fixtures](stage-4-evidence.md#journal-owned-pack-rollover)
now cover journal-owned payload/record rollover, indexed older-pack access and
automatically retried copy-on-write reclamation. The storage-journal schema is
now **3**; the updater's strict executable report includes that schema. No
public API, private wire, dependency or pack schema was changed by this slice.

Local validation on the uncommitted working tree:

- Storage library: **36 tests, 1.71 s**, incremental build **7.36 s**.
- Final affected storage/daemon Clippy: **36.04 s**, warnings denied.
- Updater compatibility/reader checks: **2 tests, 0.23 s**, build **139 s**.
  These ran before subsequent compaction edits; final daemon Clippy and the
  process test below include those edits.
- Real three-process shard round trip: **2 harness tests, 0.93 s**.
- Real mTLS backup lifecycle: **1 test, 0.68 s**.
- Real mTLS shard lifecycle: **1 test, 0.49 s**.
  These three consumer targets compiled together in **63 s**.
- Real daemon upload/restart/folder-loss/return/readback and metrics:
  **1 test, 30.98 s**, build **140 s**. This checks the integrated maintenance
  composition, not a claim that the process fixture generated compaction debt.

The initial rollover regression failed against the single-pack provider with
`Journal(OperationConflict)` in **0.06 s**, then passed after route integration.
The full storage run exposed a legacy-schema fixture that had not removed the
new additive tables and a live-free-space equality assertion invalid under
parallel IO. Both fixtures were corrected at their owning assumptions; tests
remain parallel. Compaction's first compile caught unsupported `u64` SQL decoding;
it now reuses the existing checked signed-page conversion. Clippy's documentation
warning was fixed without an allowance.

This closes five estimated points of implemented provider behaviour:
task 17 **26 → 21**, Stage 10 **131 → 126**. Its remaining pack lifecycle/
measurement acceptance is eight points and compatible-content reuse is thirteen.
The [current task list](stage-tasks.md) records exact gaps, including bounded
operation-log growth and large-target observations. No full integration gate,
signing retry, release, tag, package/image publication or GitHub Actions ran.
Signing remains blocked by the previously reported 1Password authentication
failure; this progress is preserved locally rather than committed unsigned.

## Remaining backup integration

For this retention slice, the complete NVM-default `pnpm check` passed in
**444.29 seconds** with four workers. Rust workspace tests took 398.64 seconds;
web tests took 4.35 seconds. The gate also passed workspace Clippy, both licence
checks, formatting, TypeScript/ESLint and generated-contract drift. No release
or image was produced; hardware/soak and opt-in SMB-image proofs remain separate.

The schedule API does not close these separate outstanding requirements:

- remote/provider failure-assessment integration;
- authoritative recovery/retirement of abandoned published-but-unindexed backup objects;
- offline-recovery verification and product-facing disaster-recovery workflows;
- provider/federation destination implementations and their acceptance evidence.

The remaining certificate, operational panel, metrics, update, packaging and
Stage 11 gates continue to be tracked by [the roadmap](roadmap.md). This file
records evidence for completed slices, not completion of the whole stage.

## ACC-01 — browser first-key enrollment and session confirmation

Managers can select an existing user or the newly created identity, confirm a
recent additional factor, issue a ten-minute invitation and revoke that exact
invitation. The anonymous `/enroll` page, linked from sign-in, accepts the token
and returns an ordinary HTTPS/native-API key for independent sign-in. Tokens and
keys remain in component memory; they are not placed in URLs or browser storage.
Requests retain their operation, recipient route, revision, expiry and payload
across unknown outcomes. Pending edits and recipient changes are locked. Only a
matching committed receipt reveals a secret or reports revocation; unsuccessful
sign-in does not erase the already-created key or imply enrollment failed.

Session-owned step-up adopts the rotated CSRF proof while preserving the chosen
storage lifetime. Exact retries retain the original factor and operation. The
integrated review reproduced two races before fixing them: a delayed refresh
restored the administrator's displayed identity after Bob signed in, and a
competing sign-in was dispatched while step-up could still replace the cookie.
Refresh results now belong to a session generation; stale successes and failures
cannot replace newer state. A shared in-flight guard prevents overlapping
cookie-changing actions within the session provider. Late step-up receipts are
also rejected after an observed external session replacement.

Validation on `27de83ab` plus this browser/session slice, using NVM Node 26.8.2:

- Missing invitation entry: new regression failed before implementation; the
  four existing identity panel tests passed. Both session race regressions also
  failed before their respective fixes.
- `pnpm --filter @meshspan/web test` with the enrollment, enrollment-client,
  identity panel/client, session provider/step-up and mutation-outcome files,
  `--maxWorkers=2`: **39 tests across seven files passed**, Vitest **4.30 s**,
  command wall time **5.57 s**.
- `pnpm web:lint`: passed with warnings denied, **40.79 s**. Earlier fixture-only
  void-type and nested-conditional lint findings were corrected.
- `pnpm web:typecheck`: passed, **10.05 s**. Scoped Prettier and diff checks passed.

The native HTTPS two-user enrollment/restart scenario is prepared separately
and has not been run as evidence for this slice. First-passkey enrollment and
real two-user file-sharing/SMB acceptance remain required follow-ups. This does
not close ACC-01 or Stage 10, and no full integration gate, Cargo lane,
dependency change, release or publication was performed by this browser slice.
