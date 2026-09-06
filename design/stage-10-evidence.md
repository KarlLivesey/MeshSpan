# Stage 10 implementation evidence

Status: **in progress**. Stage 11 has not started. Publication remains on hold
pending the owner's dependency review.

Current task status and outstanding acceptance live in the single numbered
[Stage 10 task list](stage-tasks.md#stage-10--certificates-packaging-and-operations).
This file is a historical evidence log: earlier statements such as “unmerged”
or “remaining” describe their recorded point in time, not necessarily current
status. Later evidence must resolve them explicitly; a passing retry alone does
not close an unexplained failure.

## Task 2 — interrupted challenge recovery

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
