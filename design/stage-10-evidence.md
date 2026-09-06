# Stage 10 implementation evidence

Status: **in progress**. Stage 11 has not started. Publication remains on hold
pending the owner's dependency review.

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
