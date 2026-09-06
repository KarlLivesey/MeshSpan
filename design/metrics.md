# Operational metrics

Status: **implementation in progress**, under OPS-012/017/018/019/020. Metrics
are observations, never authority, health certification or durability evidence.

## Collection and encoding now implemented

The replaceable `RuntimeMetricSource` contract returns a bounded typed snapshot.
It accepts no dynamic metric names, labels, identities, paths or arbitrary text.
The current source reads the existing process-local observation store without
provider IO, network requests or waiting for the storage worker. Contention
returns unavailable evidence, not a synthetic empty/healthy snapshot.

The current catalogue has 45 distinct families. Names carry `meshspan_v1_`;
counter samples additionally carry `_total`.

| Family suffix                             | Type      | Meaning                                                   |
| ----------------------------------------- | --------- | --------------------------------------------------------- |
| `uptime_seconds`                          | Gauge     | Monotonic process lifetime                                |
| `observation_drops`                       | Counter   | Updates not recorded                                      |
| `target_check_evictions`                  | Counter   | Target samples evicted from the diagnostic window         |
| `event_evictions`                         | Counter   | Transitions evicted from the diagnostic window            |
| `storage_reconciliation_cycles`           | Counter   | Observed completed cycles                                 |
| `storage_reconciliation_failures`         | Counter   | Observed cycles containing failed steps                   |
| `target_probe_passes`                     | Counter   | Observed passing provider checks, not full scrubs         |
| `target_probe_failures`                   | Counter   | Observed failed provider checks                           |
| `storage_reconciliation_duration_seconds` | Histogram | Observed cycle durations                                  |
| `target_probe_duration_seconds`           | Histogram | Observed provider-check durations, across all targets     |
| `storage_reconciliation_age_seconds`      | Gauge     | Age of the cycle supplying the following gauges           |
| `storage_configured_folders`              | Gauge     | Last-cycle configured folders, not measured capacity      |
| `storage_open_targets`                    | Gauge     | Last-cycle open handles, not guaranteed read availability |
| `storage_pending_return_scans`            | Gauge     | Last-cycle return-scan admission backlog                  |
| `storage_reconciliation_failed_steps`     | Gauge     | Last-cycle failed steps                                   |
| `https_dispatches`                        | Counter   | Ended HTTPS handler dispatches, including cancellations    |
| `https_server_error_responses`            | Counter   | Dispatches returning a 5xx response                        |
| `https_cancelled_dispatches`              | Counter   | Dispatch futures dropped before returning a response      |
| `https_dispatch_duration_seconds`         | Histogram | HTTPS handler lifetime, not response-body streaming        |
| `smb_dispatches`                          | Counter   | Ended complete-payload dispatches, including cancellations |
| `smb_dispatch_errors`                     | Counter   | Handler errors, not ordinary SMB error-status responses    |
| `smb_cancelled_dispatches`                | Counter   | Dispatch futures dropped before returning                 |
| `smb_dispatch_duration_seconds`           | Histogram | SMB payload handler lifetime, not socket writes            |
| `storage_usage_age_seconds`               | Gauge     | Age since the most recent target-usage sampling pass began |
| `storage_usage_sampled_targets`           | Gauge     | Open targets included in that pass                        |
| `storage_usage_unavailable_targets`       | Gauge     | Open targets whose usage could not be included             |
| `storage_accounted_committed_bytes`       | Gauge     | Accounted committed shard and backup payload bytes         |
| `storage_accounted_reserved_bytes`        | Gauge     | Active shard and backup holds                             |
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
restores them. Before the first pass all seven usage gauges are absent. A pass
over no open targets reports zero with zero coverage, not a healthy mesh.

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
output to 64 KiB. The only labels are the fixed histogram boundaries. There
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
uses an exporter scrape to infer protection or health. Broader metric coverage,
local history and whole-stage acceptance remain outstanding.

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

## Remaining Stage 10 measurements

This catalogue is not completion of OPS-019. Protection/locality debt,
physical-space attribution, queue/debt/completion state beyond selected maintenance
attempts, target IO/integrity beyond health probes,
HTTPS/SMB transfer throughput and operation outcomes beyond dispatch,
consensus/catch-up, coding/degraded reads, packs/deduplication,
federation backlog, authentication rejection, certificates, backups, updates,
runtime resources and clock uncertainty still need their corresponding
instrumentation. Bounded downsampled panel history and durable deduplicated
notification delivery are separate from these process-lifetime counters.
