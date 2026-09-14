# Operational metrics

Status: **implementation in progress**, under OPS-012/017/018/019/020. Metrics
are observations, never authority, health certification or durability evidence.

## Collection and encoding now implemented

The replaceable `RuntimeMetricSource` contract returns a bounded typed snapshot.
It accepts no dynamic metric names, labels, identities, paths or arbitrary text.
The current source reads the existing process-local observation store without
provider IO, network requests or waiting for the storage worker. Contention
returns unavailable evidence, not a synthetic empty/healthy snapshot.

The current catalogue has 250 distinct families. Names carry `meshspan_v1_`;
counter samples additionally carry `_total`.

The federation session owner reports the eight standard lifecycle families under
`federation_sessions_*`: idle, pending, progress, completed, retried and failed
passes, pass duration and observation age. Current refresh and handshake passes
record completed/failed outcomes; neither is a data grant, backup receipt or
proof that a remote swarm is available. These process-local counters reset on
restart and contain no peer, relationship or credential labels.

| Family suffix                             | Type      | Meaning                                                    |
| ----------------------------------------- | --------- | ---------------------------------------------------------- |
| `uptime_seconds`                          | Gauge     | Monotonic process lifetime                                 |
| `observation_drops`                       | Counter   | Updates not recorded                                       |
| `target_check_evictions`                  | Counter   | Target samples evicted from the diagnostic window          |
| `event_evictions`                         | Counter   | Transitions evicted from the diagnostic window             |
| `storage_reconciliation_cycles`           | Counter   | Observed completed cycles                                  |
| `storage_reconciliation_failures`         | Counter   | Observed cycles containing failed steps                    |
| `target_probe_passes`                     | Counter   | Observed passing provider checks, not full scrubs          |
| `target_probe_failures`                   | Counter   | Observed failed provider checks                            |
| `storage_reconciliation_duration_seconds` | Histogram | Observed cycle durations                                   |
| `target_probe_duration_seconds`           | Histogram | Observed provider-check durations, across all targets      |
| `storage_reconciliation_age_seconds`      | Gauge     | Age of the cycle supplying the following gauges            |
| `storage_configured_folders`              | Gauge     | Last-cycle configured folders, not measured capacity       |
| `storage_open_targets`                    | Gauge     | Last-cycle open handles, not guaranteed read availability  |
| `storage_pending_return_scans`            | Gauge     | Last-cycle return-scan admission backlog                   |
| `storage_reconciliation_failed_steps`     | Gauge     | Last-cycle failed steps                                    |
| `https_dispatches`                        | Counter   | Ended HTTPS handler dispatches, including cancellations    |
| `https_server_error_responses`            | Counter   | Dispatches returning a 5xx response                        |
| `https_cancelled_dispatches`              | Counter   | Dispatch futures dropped before returning a response       |
| `https_dispatch_duration_seconds`         | Histogram | HTTPS handler lifetime, not response-body streaming        |
| `smb_dispatches`                          | Counter   | Ended complete-payload dispatches, including cancellations |
| `smb_dispatch_errors`                     | Counter   | Handler errors, not ordinary SMB error-status responses    |
| `smb_cancelled_dispatches`                | Counter   | Dispatch futures dropped before returning                  |
| `smb_dispatch_duration_seconds`           | Histogram | SMB payload handler lifetime, not socket writes            |
| `storage_usage_age_seconds`               | Gauge     | Age since the most recent target-usage sampling pass began |
| `storage_usage_sampled_targets`           | Gauge     | Open targets included in that pass                         |
| `storage_usage_unavailable_targets`       | Gauge     | Open targets whose usage could not be included             |
| `storage_accounted_committed_bytes`       | Gauge     | Accounted committed shard and backup payload bytes         |
| `storage_accounted_reserved_bytes`        | Gauge     | Active shard and backup holds                              |
| `storage_configured_limit_bytes`          | Gauge     | Summed configured ceilings, not physically available space |
| `storage_repair_reserve_bytes`            | Gauge     | Configured repair headroom, not occupied bytes             |

The five fixed maintenance kinds are `repair`, `drain`, `rebalance`, `reconcile`
and `scrub`. Each has three families: `maintenance_<kind>_attempts` (counter),
`maintenance_<kind>_failures` (counter) and `maintenance_<kind>_duration_seconds`
(histogram). These are literal catalogue names, not dynamic labels. Attempts
begin only after work selection (and, for drains, after establishing pending
attestation or completion recovery). Failed/interrupted attempts are included;
an empty scheduler tick is not an attempt. A successful page or step can still
leave a job unfinished. These measurements never replace durable job outcomes,
and their timing excludes queue residence and selection.

## Local consensus observations

Ten fixed families describe the local reactor: `consensus_observation_age_seconds`,
`consensus_observation_failures` (counter), `consensus_role`, `consensus_term`,
`consensus_committed_index`, `consensus_applied_index`,
`consensus_pending_operations`, `consensus_queued_operations`,
`consensus_persistence_blocked` and `consensus_leader_known`. Except for failures,
these are gauges absent until the first coherent observation. Role values are
follower **1**, candidate **2** and leader **3**; boolean gauges use **0**/**1**.

An owned worker reads the existing local reactor once per second, with a
500-millisecond observation deadline and skipped missed ticks. It performs no
peer probes or consensus writes. Scrapes only read the cached observation. A
failed sample increments the failure counter and retains the older sample with
its increasing monotonic age; contradictory applied/committed indices are
rejected. Shutdown interrupts both scheduling and an outstanding observation.

Five additional gauges report catch-up. `consensus_remote_members` counts remote
voters and learners in the active stable or joint plan. `consensus_apply_gap` is
the locally committed index minus the applied index. Leaders also report
`consensus_replication_unknown_members`, `consensus_replication_lagging_members`
and `consensus_replication_maximum_committed_gap`. These use the consensus core's
existing match positions: unknown peers are excluded from the maximum rather than
treated as caught up. The latter three gauges are absent on followers/candidates
and are removed on an observed step-down. A single-node leader reports zero remote
members and zero gaps. Sampling does not request replication or change admission.

Role is not current quorum or write authority. Knowing a leader identity is not
evidence that it is reachable. A previously acknowledged match position is not a
fresh heartbeat or proof that a replica still holds the data. Observation age
describes when the local core was sampled, not when each peer last replied.
Node identities, plan digests and partition labels are never exported. Federation
progress and fresh authority evidence remain open.

## Protection and locality observations

Nine fixed `protection_catalogue_` families describe a completed pass over the
local committed-content catalogue: `age_seconds`, `pass_duration_seconds`,
`observation_failures` (counter), `assessed_stripes`, `unassessable_stripes`,
`missing_shard_receipts`, `insufficient_receipts_stripes`,
`protection_debt_stripes` and `locality_debt_stripes`.

The existing storage IO worker visits stable volume identities and at most 16
stripes per tick. It waits 60 seconds between completed or abandoned passes.
Volume renames do not change the identity cursor. Collection uses retained
receipts and each page's current policy/topology, with no provider probes,
network requests, repair admission or consensus writes. Scrapes and panel history
read only the cached completed observation; neither triggers a scan.

The placement component applies the same fault-scenario and cell predicates as
placement planning, without searching for moves. Missing receipts are omitted,
not replaced by planned destinations. Sufficient recorded slices, failure-policy
survival and locality satisfaction are separate results. Required and eventual
locality predicates both contribute debt; excluded-cell violations also do.
Unknown or stale target generations and unavailable policy count as unassessable,
not protected. Assessed debt counts exclude those unknown stripes, whose count
must always be considered alongside them.

Before the first completed pass its gauges are absent. A failed collection
increments the failure counter and retains the older pass with increasing age;
partial totals do not replace it. Age starts at pass **start**, so it includes
collection duration. Values describe local retained committed catalogue entries,
including optional-replica debt, not every file in the mesh or one atomic
cross-page snapshot. Concurrent writes can appear in the next pass. Receipts do
not prove present bytes: loss of a folder can leave all receipts intact while
making its policy assessment unknown. These observations never authorise a
write, a drain, an update or a claimed live read.

The exporter and existing local history use the same typed families. Cardinality
is bounded by the Rust-authored 206-entry history schema and no identities, paths,
principal labels or secret bytes enter a sample.

## Target accounting scope

`StorageUsageSource` reads the existing target journal and configured policy on
the storage IO worker. Shared providers skip contended locks. The exporter only
reads cached observations; it does not perform provider IO. The worker samples
with its ordinary health-probe pass and refreshes after targets are opened or
registered. Registration itself only marks observations dirty, rather than
scanning other providers on the administration request path.

Accounted bytes include the target's shared shard/backup holds and committed
payload accounting. They exclude filesystem metadata, pack overhead and dead
pack space, and are not filesystem allocation measurements. Pending holds can
include interrupted work with an unknown publication outcome. Repair headroom
is a policy budget, not occupied space. Several targets can share a physical
filesystem: summed target ceilings must never be labelled free or usable space.

Each pass covers the open target set at its sampling time, not every configured
target or the whole mesh. Targets are read sequentially, not in one cross-target
transaction. Age and sample coverage accompany totals. If any target is busy,
unavailable or makes aggregation overflow, all four byte gauges are absent;
partial totals are never represented as complete. A later successful pass
restores them. Before the first pass all usage gauges are absent. A pass
over no open targets reports zero with zero coverage, not a healthy mesh.

Four additional families separate mounted-filesystem measurements from payload
accounting: `storage_sampled_filesystems`,
`storage_unavailable_filesystem_targets`, `storage_filesystem_total_bytes` and
`storage_filesystem_available_bytes`. Capacity and device identity come from the
already-open folder capability, not a new lookup of the configured path. Within
one pass, multiple folders with the same host-local device identity count once;
the smaller repeated capacity/free-space observations are retained. Missing or
invalid evidence and arithmetic overflow omit both filesystem-byte totals.

These are mounted-filesystem statistics, **not independent physical pool
capacity**: separate APFS volumes, ZFS datasets or thin-provisioned filesystems
may share an underlying pool. Available bytes include competing applications,
not just MeshSpan's quota; measurements are neither reservations nor admission
authority. Raw device identities remain private to the bounded sampling pass.

## Durable maintenance observations

Each fixed maintenance kind (`repair`, `drain`, `rebalance`, `reconcile`, `scrub`)
has seven additional `maintenance_<kind>_` families: `job_observation_age_seconds`,
`queued_jobs`, `claimed_jobs`, `completed_jobs`, `protection_debt_jobs`,
`locality_debt_jobs` and `pending_demand_bytes`. Counts are gauges of retained
durable jobs, not process-lifetime counters. A completed job has a validated
authoritative terminal effect; it is not inferred from a successful attempt.
Claimed jobs may have expired leases. Debt counts unfinished jobs with recorded
debt signals, not missing shards. Pending demand sums execution budgets, **not
bytes remaining to transfer or an estimated completion percentage**.

The existing storage worker pages at most 16 retained jobs per tick using the
primary-key index, including completed records, without claiming work or writing
consensus metadata. Each record uses the execution path's validated decoder.
A completed pass replaces the cached gauges; failed/partial passes retain the
older sample and its increasing age and count a dropped observation. There is
a 60-second interval between passes. This is local retained metadata, not a
cross-page transaction or a live mesh-wide queue. Jobs added behind the cursor
are observed in a later pass. Exporter and panel history use the same catalogue.

## Durable maintenance progress

Nine `maintenance_progress_` gauges share the completed retained-job pass and
its age with the job counts: `unavailable_jobs`, `repaired_bytes`,
`scrub_observations`, `scrub_verified_bytes`, `reconciliation_observations`,
`reconciliation_verified_bytes`, `rebalance_scanned_stripes`,
`rebalance_queued_repairs` and `safe_drains`.

Repair bytes come from committed replacement receipts, including an effect
committed before its job's completion response was recorded. Scrub/reconciliation
prefer complete authoritative effects; otherwise they read generation-bound local
checkpoints without creating or advancing them. A checkpoint and its later
authoritative effect are never added together. Never-started verification jobs
have zero recorded progress; an attempted job with neither global evidence nor
a local checkpoint is unknown, since its worker may be elsewhere. Missing or
contradictory completed effects fail the observation pass, not domain work.

Rebalance progress is committed scanned stripes and admitted repair jobs, not
an estimate of transferred bytes. Drain completion is authoritative safe-to-detach
state. Drain relocation bytes remain under the ordinary repair jobs performing
the transfer and are not counted a second time. These gauges can decrease when
retained jobs/checkpoints change; they are not lifetime counters or percentages.
They report durable recorded steps, not bytes in flight, total remaining work,
an ETA or a fresh integrity attestation.

Unknown progress increments `unavailable_jobs` and omits the eight aggregate
progress gauges for that pass rather than displaying a partial value as a
complete total. Other queue and attempt measurements remain available. This is
local metadata/checkpoint coverage, not an on-demand query to every remote worker.

## Target IO and integrity observations

The shared folder-provider boundary records five process-lifetime families for
each of `read`, `write` and `scrub`: `storage_io_<kind>_calls`, `failures`,
`payload_bytes`, `corruption_reports` and `duration_seconds`. The first four are
counters; duration is a histogram. These measurements cover exact shard reads,
exact installations, exact scrubs and bounded scrub pages used by local file
services and the shard service. Counts survive provider reopening but reset on
daemon restart.

An owned observation covers target-lock residence and the provider call; the
lock is released before the observer is invoked. The process-wide observer uses
a non-waiting lock with checked arithmetic. Overflow or contention drops the
observation and increments the existing dropped-observation counter, without
changing the operation result. No target, path, user or shard identity is a label.

Payload bytes mean bytes returned by reads, acknowledged by installations, or
actually observed in scrub evidence. Replay can count the same payload again;
these are not physical disk traffic, unique bytes stored, pack amplification,
client-delivery proof or filesystem publication acknowledgements. Failed calls
contribute no payload bytes. A corrupt read result counts a failed call and one
corruption report. A completed scrub page can succeed while reporting corrupt
records: corruption reports are counted independently of call failures. Reports
are observations, not the number of unique damaged shards.

## Gateway transfer and coding observations

HTTPS also exposes `https_authentication_required_responses` (401) and
`https_forbidden_responses` (403) counters. These are returned response counts,
not unique users, failed passwords or authoritative audit events. Missing or
ambiguous credentials count as 401; an administrator refused by a disabled
exporter counts as 403. Concealed-resource 404 responses and TLS admission
failures are deliberately excluded. They remain separate from 5xx server errors,
retain no request-derived labels, use the same bounded local history and reset
on restart.

SMB exposes `smb_authentication_rejections`: parsed credential proofs refused
by the shared authentication authority. The protocol classifier records it
before returning the existing logon-failure response. Successful authentication,
malformed negotiation/transcript errors, unavailable metadata and internal
verification failures do not increment it. It does not change dispatch counts
or latency distributions, retains no user or credential labels, and resets on
process restart. Collection uses a non-waiting checked counter; observation loss
does not change the authentication result.

HTTPS and SMB each expose `received_bytes`, `sent_bytes`, `read_errors` and
`write_errors` counters under their protocol prefix. Reads count bytes actually
returned by the stream; writes count the accepted byte count, not the submitted
buffer length. Pending IO and clean EOF add no bytes. Errors count failed IO
polls (including flush/shutdown), not timeouts or cancelled futures. Partial
transfers remain counted even when a later operation fails.

HTTPS counts decoded HTTP protocol bytes after TLS admission, including headers
and framing. SMB counts socket bytes including Direct TCP framing and encrypted
payloads. Neither is a logical file-byte counter, TLS ciphertext measurement,
delivery confirmation or durable-publication acknowledgement. Counter deltas
over monotonic sampling intervals provide observed throughput; observation loss
remains visible through the existing drop counter.

The composed coding engine also emits six families for each of `encode` and
`reconstruct`: `coding_<operation>_calls`, `failures`, `input_bytes`,
`output_bytes`, `missing_data_calls` and `duration_seconds`. Duration is a
histogram; the other families are counters. Input includes failed calls; output
only includes successful results. Encoding output includes parity and padding.
Replay and repair work are counted again; these are not deduplication savings.

`missing_data_calls` counts reconstruction requests lacking one or more
systematic slices, including unsuccessful requests. Encode always reports zero.
It does not label an entire file read or swarm degraded, detect corruption in
present slices, or count reads that fail before reaching the coding engine.
Coding time excludes storage/network IO. The wrapper delegates the existing
engine and lifecycle unchanged, and both filesystem and repair composition use
the same process observation store. All counters reset on daemon restart.

## Shared filesystem outcomes

Both access protocols use the observed production filesystem adapter. Each of
`open`, `read`, `stage_write`, `flush`, `close` and `upload_commit` has fixed
`filesystem_<operation>_calls`, `returned_errors` and `duration_seconds`
families. Calls/errors are counters; duration is a histogram covering the adapter
and its lock/publication work, not subsequent client delivery. Handle and upload
range writes share `stage_write`; neither is a completed file publication.

These are calls which returned, including exact retries. An error may follow
durable side effects and is not proof of rejection or rollback. Panics do not
produce a returned-call observation. Dropping a client connection does not cancel
or undo an already running blocking filesystem operation. Authentication failures
before reaching the adapter belong to separate security measurements.

`filesystem_read_bytes` counts verified bytes returned to the connector;
`filesystem_staged_write_bytes` counts accepted staging bytes including replay.
Neither is a network transfer count or a count of unique stored bytes. Failed
calls contribute no successful-byte total, even if earlier partial effects exist.

`file_publications_node_local`, `file_publications_cell_replicated` and
`file_publications_globally_converged` count successful verified publication
barrier acknowledgements at their recorded scope. They include replay and are
not unique versions. The observation happens only after the existing barrier's
verification and any required converged-head commit. A later outer operation
may still return an error; the earlier acknowledged publication remains real.
Metrics do not weaken, strengthen or replace any durability check.

## Pack database space

The existing target IO worker samples `storage_sampled_pack_targets`,
`storage_unavailable_pack_targets`, `storage_pack_database_bytes` and
`storage_pack_reusable_bytes`. All are gauges; the shared usage age applies.
The folder provider reads page size, page count and free-list count inside one
read transaction, with no table scan, vacuum, checkpoint or metadata mutation.

Database bytes are the logical page extent including schema, indexes and retained
operation metadata. Reusable bytes are free-list pages available inside that
database after guarded unlink. Neither is physical device allocation, WAL size,
filesystem free space, CoW compaction completion or deduplication savings.
Allocated extent need not shrink when shard payloads are removed.

Missing, invalid or overflowed pack evidence increments unavailable coverage and
omits aggregate pack byte gauges; it does not discard independently valid quota
or filesystem observations. Scraping reads only the cached worker sample.
The multi-pack provider samples at most 32 packs per target per pass. A larger
target currently reports missing pack coverage rather than a misleading partial
sum; completing this collector is outstanding in task 17, not a storage limit.

DAT-021 pack bounds/CoW compaction and D-058 §5 mesh-wide compatible-content reuse
were reopened during this work. Exact-shard replay and free-list reuse must not
be substituted for those capabilities or labelled as their savings. Their
implementation and actual amplification/savings accounting are tracked in
[Stage 10 task 17](stage-tasks.md).

## Operational worker outcomes

Existing worker owners report finite pass results. Scrapes and history reads do
not select jobs, contact peers, probe providers or query the CA. Each of these
closed prefixes has the eight suffixes below:

| Prefix                     | Observed unit                                         |
| -------------------------- | ----------------------------------------------------- |
| `certificate_automation`   | ACME admission/renewal/order-execution pass           |
| `certificate_installation` | Selected public-certificate installation pass         |
| `backup`                   | Metadata backup capture/copy/protection pass          |
| `update_preparation`       | Local candidate preparation or installation-wait pass |

| Suffix                    | Kind      | Meaning                                     |
| ------------------------- | --------- | ------------------------------------------- |
| `idle_passes_total`       | Counter   | No new work, or installed selection current |
| `pending_passes_total`    | Counter   | Waiting for external/authoritative evidence |
| `progress_passes_total`   | Counter   | Non-terminal progress recorded              |
| `completed_passes_total`  | Counter   | The named worker unit completed             |
| `retried_passes_total`    | Counter   | Explicit retry or expired claim             |
| `failed_passes_total`     | Counter   | Pass returned an error                      |
| `pass_duration_seconds`   | Histogram | Monotonic pass duration, including failures |
| `observation_age_seconds` | Gauge     | Monotonic age of the latest observed pass   |

These are observed passes, not unique jobs or durable inventory totals. A retry
can count again and process restart resets the counters. Update preparation
completion means this process verified/advertised its candidate and returned
from staging coordination; it is not whole-rollout completion or proof of a
successful restart. Backup completion reflects the worker's committed protection
outcome, not the number of still-retained backups. An ACME retry remains distinct
from a returned internal error.

All eight families for a worker remain absent until its first observation.
Observation age increases if it stops reporting; absent/stale evidence is not
replaced with zero job counts. Contention or counter exhaustion drops telemetry
without waiting or changing the worker's result. Subjects, actors, certificate
names, paths, versions, keys and raw errors are not accepted by the measurement
contract. Certificate expiry/delivery coverage, retained backup/update inventory,
authentication rejection, process resources and clock uncertainty remain separate
outstanding measurements.

## Histogram and encoding rules

The histograms aggregate the process lifetime, independently of eviction from
the diagnostic windows. Inclusive finite buckets are 0.001, 0.005, 0.025, 0.1,
0.5, 1, 5 and 30 seconds, followed by `+Inf`. Counters and duration sums use
checked integer accumulation; overflow rejects the whole observation without
partially advancing its histogram. Durations retain nanosecond precision.
Unobserved last-cycle gauges are absent. Counters restart with the process;
dropped observations mean distributions are incomplete.

Gateway observations cover the composed HTTPS router and embedded SMB payload
handler. HTTPS timing excludes TLS admission and subsequent response-body
streaming; SMB counts one complete Direct TCP payload, not each command in a
compound request, and excludes socket reads/writes. HTTP-01 challenge traffic
uses its separate listener and is not included. These counters do not certify
file-operation success, delivery or durability. A cancelled dispatch future may
leave an already-started owned blocking job running; the cancellation counter is
not proof that the operation was cancelled. Unpolled futures are not dispatches.

The fixed-size observation sink uses a non-waiting lock attempt and performs no
IO or request-derived labelling. Contention or overflow drops the observation
and increments the drop counter, without changing the gateway's response.

The encoder implements the fixed text subset of
[OpenMetrics 1.0](https://prometheus.io/docs/specs/om/open_metrics_spec/): typed
families, seconds units, cumulative buckets, count/sum and an EOF terminator.
It validates snapshots again, orders families deterministically and bounds
output to 128 KiB. The only labels are the fixed histogram boundaries. There
are no user labels, timestamps or exemplars. Integer output is exact; external
ingestors may store numbers as floating point.

## Configuration and HTTPS

The exporter is off until explicitly enabled. System managers read or replace
its policy through `GET`/`PUT /api/latest/admin/metrics/exporter`. The replacement
binds an operation ID, the exact current sequence (zero before configuration),
an enabled flag and at most 64 distinct existing user identities. This is a
configuration bound, not a limit on ordinary connections. Enabling requires at
least one consumer. Browser mutations require the current session's CSRF proof.

`GET /api/latest/metrics` accepts a current HTTPS-capable API key belonging to an
explicitly allowed user. Administration grants no implicit scrape access. Cookie
credentials, query parameters and request bodies are rejected. The endpoint
returns only OpenMetrics 1.0 with `no-store` and `nosniff`; it does not negotiate
other exposition formats. It neither contacts a monitoring server nor probes
storage. Authentication and policy are checked before collection and again
before output, against the gateway's current replicated authority. This is not
a claim of instantaneous revocation across disconnected gateways.

Each gateway admits one owned configuration/collection job with a five-second
cooperative deadline. Cancellation does not release admission while blocking
work continues. Configuration commits cannot be undone by cancelling HTTP;
retrying the exact operation returns its original receipt even if another policy
has since superseded it. A scrape's unavailable source is not an empty success.

The Operations panel provides the same policy API, optional paged user selection,
enable/disable and exact retry. No user pages are loaded until requested. It never
uses an exporter scrape to infer protection or health. Broader metric coverage
and whole-stage acceptance remain outstanding.

## Local panel history

`GET /api/latest/admin/metrics/history` serves one newest-first page of at most
30 local observation buckets. It requires current system-manager access, checked
before query handling and again before output. This local view does not require
enabling the external exporter. Requests do not trigger collection, provider IO
or network probes, and share the exporter's owned bounded admission/deadline.

The background observation worker samples once per minute. The minute window
retains 360 buckets (six hours); the hourly window retains the last minute sample
in each of 168 hour buckets (seven days). At most 528 buckets are held in memory.
This is last-observation downsampling, not averaging or integration. Values retain
the existing fixed catalogue's exact counters, byte counts, nanosecond durations
and cumulative histogram buckets. They are not per-bucket rates. Missing families
remain absent, a failed sample has `metrics: null`, and unsampled time is not
filled with zeros. All history clears when this daemon restarts.

`resolution=minute` is the default; `resolution=hour` selects the longer window.
The response includes an optional `next_page_url`; its `history_id` and exclusive
`before` bucket must be preserved together. A fresh random 128-bit history ID is
created for each observation store, independently of node identity/incarnation.
It is not a credential. A previous process's continuation returns `409`; entropy
failure makes history unavailable without preventing appliance service. Ordering
uses monotonic uptime; host wall timestamps are display hints and may move
backwards. Retention expiry is explicitly reported.

The Operations panel loads history only on request and retains one page, with
an optional older-page action and measurement selector. Failed reads clear the
previous page. Unmounting discards late results. The generated client validates
same-gateway continuation routes before attaching credentials and uses the
Rust-authored one-MiB history response limit rather than raising every API limit.
No telemetry leaves the appliance automatically and no time-series database or
new dependency is required.

## Persisted and private-wire contract

The typed `ConfigureMetricsExporter` command uses private command kind **76**
inside the existing version-4 envelope, and durable operation kind **140**.
Older implementations reject this unknown command; mixed-version compatibility
is not claimed. There is no SQL migration or new dependency.

One mesh-derived component instance uses kind 10 (observability), implementation
`meshspan-openmetrics`, contract 1.0 and configuration schema 1. The existing
component tables atomically advance immutable configuration heads together with
the operation receipt and audit event. They are included in ordinary metadata
replication and backups; metrics samples themselves are not replicated.

Canonical configuration bytes are `MSM` followed by byte `01`, enabled byte
`00`/`01`, a big-endian 16-bit consumer count, then that many 16-byte principal
identities in strictly increasing byte order. The maximum is 1,031 bytes.
Decoders reject unknown versions/tags, duplicates, trailing data, inconsistent
counts, corrupt digests and invalid active heads rather than treating them as an
unconfigured exporter. Disabling remains possible when a selected user has since
been suspended; that user's current credentials still cannot authorise scraping.

## Certificate, backup and update inventory

The existing storage worker collects three independent inventories, with a
15-second interval after each completed or failed pass. Backup/update scans
advance at most 16 rows per worker cycle using indexed cursors. Scrapes perform
no database, provider or remote IO. These are observations accumulated during a
scan, not an atomic cross-inventory snapshot; a concurrent state change may
appear in the next pass. Active update progress is read together at the end of
its pass. No transaction spans worker ticks.

The 28 additional fixed families are:

- Certificate: `certificate_selected`, `certificate_remaining_validity_seconds`,
  `certificate_not_yet_valid`, `certificate_expired`,
  `certificate_required_gateways`, `certificate_installed_gateways`,
  `certificate_observation_age_seconds`, `certificate_observation_failures`.
- Backups: `backup_queued_occurrences`, `backup_claimed_occurrences`,
  `backup_recorded_occurrences`, `backup_protected_occurrences`,
  `backup_incomplete_occurrences`, `backup_inventory_age_seconds`,
  `backup_inventory_failures`.
- Updates: `update_running_rollouts`, `update_paused_rollouts`,
  `update_completed_rollouts`, `update_cancelled_rollouts`, `update_selected`,
  `update_pending_nodes`, `update_staged_nodes`, `update_restarting_nodes`,
  `update_verified_nodes`, `update_failed_nodes`, `update_unresolved_restarts`,
  `update_inventory_age_seconds`, `update_inventory_failures`.

Failure families are process counters; the others are gauges. The three failure
counters exist from startup. Unobserved categories omit their gauges; failed
passes preserve their last complete sample with increasing monotonic age. Ages
start at the beginning of a scan, so they also expose slow inventory collection.
No selected certificate omits expiry/coverage values instead of inventing zeros.
No selected update explicitly reports no active rollout and zero active-node
counts. `staged` includes nodes preparing a restart.

Certificate validity is evaluated against the **host wall clock at sample time**,
not a claim of quorum-agreed time. Installed gateways count exact-generation
durable acknowledgements, not current reachability. Protected backup occurrences
record historical threshold completion, not current backup-copy survivability.
Metrics cannot authorise an update, declare a backup recoverable or establish
that a certificate is currently served by a reachable gateway.

## Remaining Stage 10 measurements

This catalogue is not completion of OPS-019. Underlying shared-pool attribution,
physical IO attribution and byte-in-flight transfer measurements,
assembled file-operation failure/durability acceptance,
current quorum evidence, packs/deduplication,
federation backlog, authentication rejection, certificates, backups, updates,
runtime resources and clock uncertainty still need their corresponding
instrumentation. The local history above retains these observations only;
durable deduplicated notification delivery remains separate and outstanding.
