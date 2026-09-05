// SPDX-License-Identifier: GPL-2.0-only

//! Version-one public metric names and meanings. No field is derived from an identity or path.

use meshspan_contracts::{LatencyHistogram, RuntimeMetric};
use std::time::Duration;

pub(super) enum Measurement<'a> {
    Counter(u64),
    Gauge(u64),
    Seconds(Duration),
    Latency(&'a LatencyHistogram),
}

pub(super) struct Descriptor<'a> {
    pub name: &'static str,
    pub help: &'static str,
    pub measurement: Measurement<'a>,
}

pub(super) fn describe(sample: &RuntimeMetric) -> Descriptor<'_> {
    use Measurement::{Counter, Gauge, Latency, Seconds};
    let (name, help, measurement) = match sample {
        RuntimeMetric::Uptime(value) => (
            "uptime_seconds",
            "Monotonic process lifetime.",
            Seconds(*value),
        ),
        RuntimeMetric::DroppedObservations(value) => (
            "observation_drops",
            "Observation updates not recorded by this process.",
            Counter(*value),
        ),
        RuntimeMetric::TargetCheckEvictions(value) => (
            "target_check_evictions",
            "Target samples evicted from the diagnostic window.",
            Counter(*value),
        ),
        RuntimeMetric::EventEvictions(value) => (
            "event_evictions",
            "Transitions evicted from the diagnostic window.",
            Counter(*value),
        ),
        RuntimeMetric::ReconciliationCycles(value) => (
            "storage_reconciliation_cycles",
            "Completed storage reconciliation cycles observed in this process.",
            Counter(*value),
        ),
        RuntimeMetric::ReconciliationFailures(value) => (
            "storage_reconciliation_failures",
            "Observed storage reconciliation cycles with failed steps.",
            Counter(*value),
        ),
        RuntimeMetric::TargetProbePasses(value) => (
            "target_probe_passes",
            "Passing provider checks observed in this process; not complete content scrubs.",
            Counter(*value),
        ),
        RuntimeMetric::TargetProbeFailures(value) => (
            "target_probe_failures",
            "Failed provider checks observed in this process.",
            Counter(*value),
        ),
        RuntimeMetric::ReconciliationDuration(value) => (
            "storage_reconciliation_duration_seconds",
            "Duration of observed storage reconciliation cycles.",
            Latency(value),
        ),
        RuntimeMetric::TargetProbeDuration(value) => (
            "target_probe_duration_seconds",
            "Duration of observed provider checks aggregated across all targets.",
            Latency(value),
        ),
        RuntimeMetric::LastReconciliationAge(value) => (
            "storage_reconciliation_age_seconds",
            "Monotonic age of the last cycle supplying storage gauges.",
            Seconds(*value),
        ),
        RuntimeMetric::ConfiguredFolders(value) => (
            "storage_configured_folders",
            "Configured folder count at the last cycle; not measured capacity.",
            Gauge(*value),
        ),
        RuntimeMetric::OpenTargets(value) => (
            "storage_open_targets",
            "Open provider handles at the last cycle; not a read availability guarantee.",
            Gauge(*value),
        ),
        RuntimeMetric::PendingReturnScans(value) => (
            "storage_pending_return_scans",
            "Targets awaiting return-scan admission at the last cycle.",
            Gauge(*value),
        ),
        RuntimeMetric::LastReconciliationFailedSteps(value) => (
            "storage_reconciliation_failed_steps",
            "Failed steps in the last completed storage reconciliation cycle.",
            Gauge(*value),
        ),
    };
    Descriptor {
        name,
        help,
        measurement,
    }
}
