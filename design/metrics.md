# Operational metrics

Status: **implementation in progress**, under OPS-012/017/018/019/020. Metrics
are observations, never authority, health certification or durability evidence.

## Collection and encoding now implemented

The replaceable `RuntimeMetricSource` contract returns a bounded typed snapshot.
It accepts no dynamic metric names, labels, identities, paths or arbitrary text.
The current source reads the existing process-local observation store without
provider IO, network requests or waiting for the storage worker. Contention
returns unavailable evidence, not a synthetic empty/healthy snapshot.

The current catalogue has fifteen distinct families. Names carry `meshspan_v1_`;
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

The histograms aggregate the process lifetime, independently of eviction from
the diagnostic windows. Inclusive finite buckets are 0.001, 0.005, 0.025, 0.1,
0.5, 1, 5 and 30 seconds, followed by `+Inf`. Counters and duration sums use
checked integer accumulation; overflow rejects the whole observation without
partially advancing its histogram. Durations retain nanosecond precision.
Unobserved last-cycle gauges are absent. Counters restart with the process;
dropped observations mean distributions are incomplete.

The encoder implements the fixed text subset of
[OpenMetrics 1.0](https://prometheus.io/docs/specs/om/open_metrics_spec/): typed
families, seconds units, cumulative buckets, count/sum and an EOF terminator.
It validates snapshots again, orders families deterministically and bounds
output to 64 KiB. The only labels are the fixed histogram boundaries. There
are no user labels, timestamps or exemplars. Integer output is exact; external
ingestors may store numbers as floating point.

## Remaining integration in this branch

- Persist explicit exporter opt-in and authorised-consumer restrictions through
  the authoritative metadata/configuration boundary. No configuration means off.
- Wire an authenticated HTTPS scrape endpoint to the replaceable source, with
  early rejection, current policy revalidation and bounded owned work.
- Expose configuration through the native API and administration panel.
- Prove enable, scrape, revoke, disable and restart over real HTTPS.

No scrape route or exporter configuration is enabled by this initial collection
and encoder commit. No background telemetry leaves the appliance.

## Remaining Stage 10 measurements

This initial catalogue is not completion of OPS-019. Protection/locality debt,
capacity/reservations, repair/scrub/drain/rebalance work, target IO/integrity,
HTTPS/SMB, consensus/catch-up, coding/degraded reads, packs/deduplication,
federation backlog, authentication rejection, certificates, backups, updates,
runtime resources and clock uncertainty still need their corresponding
instrumentation. Bounded downsampled panel history and durable deduplicated
notification delivery are separate from these process-lifetime counters.
