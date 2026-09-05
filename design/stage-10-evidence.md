# Stage 10 implementation evidence

Status: **in progress**. Stage 11 has not started. Publication remains on hold
pending the owner's dependency review.

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

## Remaining backup integration

### Native backup history and panel

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
seconds). The complete local gate will be recorded after it finishes.

This is historical inventory, not the still-outstanding restore-readiness,
encrypted export or recovery workflow.

For this retention slice, the complete NVM-default `pnpm check` passed in
**444.29 seconds** with four workers. Rust workspace tests took 398.64 seconds;
web tests took 4.35 seconds. The gate also passed workspace Clippy, both licence
checks, formatting, TypeScript/ESLint and generated-contract drift. No release
or image was produced; hardware/soak and opt-in SMB-image proofs remain separate.

The schedule API does not close these separate outstanding requirements:

- remote/provider failure-assessment integration;
- authoritative recovery/retirement of abandoned published-but-unindexed backup objects;
- product-facing restore-readiness, encrypted export and recovery workflows;
- provider/federation destination implementations and their acceptance evidence.

The remaining certificate, operational panel, metrics, update, packaging and
Stage 11 gates continue to be tracked by [the roadmap](roadmap.md). This file
records evidence for completed slices, not completion of the whole stage.
