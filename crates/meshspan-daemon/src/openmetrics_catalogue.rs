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
    let (name, help) = name_and_help(sample);
    Descriptor {
        name,
        help,
        measurement: measurement(sample),
    }
}

// Keep the versioned public vocabulary separate from typed numeric representation.
fn name_and_help(sample: &RuntimeMetric) -> (&'static str, &'static str) {
    match sample {
        RuntimeMetric::Uptime(_) => ("uptime_seconds", "Monotonic process lifetime."),
        RuntimeMetric::DroppedObservations(_) => (
            "observation_drops",
            "Observation updates not recorded by this process.",
        ),
        RuntimeMetric::TargetCheckEvictions(_) => (
            "target_check_evictions",
            "Target samples evicted from the diagnostic window.",
        ),
        RuntimeMetric::EventEvictions(_) => (
            "event_evictions",
            "Transitions evicted from the diagnostic window.",
        ),
        RuntimeMetric::ReconciliationCycles(_) => (
            "storage_reconciliation_cycles",
            "Completed storage reconciliation cycles observed in this process.",
        ),
        RuntimeMetric::ReconciliationFailures(_) => (
            "storage_reconciliation_failures",
            "Observed storage reconciliation cycles with failed steps.",
        ),
        RuntimeMetric::TargetProbePasses(_) => (
            "target_probe_passes",
            "Passing provider checks observed in this process; not complete content scrubs.",
        ),
        RuntimeMetric::TargetProbeFailures(_) => (
            "target_probe_failures",
            "Failed provider checks observed in this process.",
        ),
        RuntimeMetric::ReconciliationDuration(_) => (
            "storage_reconciliation_duration_seconds",
            "Duration of observed storage reconciliation cycles.",
        ),
        RuntimeMetric::TargetProbeDuration(_) => (
            "target_probe_duration_seconds",
            "Duration of observed provider checks aggregated across all targets.",
        ),
        RuntimeMetric::LastReconciliationAge(_) => (
            "storage_reconciliation_age_seconds",
            "Monotonic age of the last cycle supplying storage gauges.",
        ),
        RuntimeMetric::ConfiguredFolders(_) => (
            "storage_configured_folders",
            "Configured folder count at the last cycle; not measured capacity.",
        ),
        RuntimeMetric::OpenTargets(_) => (
            "storage_open_targets",
            "Open provider handles at the last cycle; not a read availability guarantee.",
        ),
        RuntimeMetric::PendingReturnScans(_) => (
            "storage_pending_return_scans",
            "Targets awaiting return-scan admission at the last cycle.",
        ),
        RuntimeMetric::LastReconciliationFailedSteps(_) => (
            "storage_reconciliation_failed_steps",
            "Failed steps in the last completed storage reconciliation cycle.",
        ),
        RuntimeMetric::HttpsDispatches(_) => (
            "https_dispatches",
            "HTTPS handler dispatches ended, including cancellations.",
        ),
        RuntimeMetric::HttpsServerErrors(_) => (
            "https_server_error_responses",
            "HTTPS dispatches returning a 5xx response.",
        ),
        RuntimeMetric::HttpsCancelledDispatches(_) => (
            "https_cancelled_dispatches",
            "HTTPS dispatch futures dropped before returning a response.",
        ),
        RuntimeMetric::HttpsDispatchDuration(_) => (
            "https_dispatch_duration_seconds",
            "HTTPS handler lifetime; excludes subsequent response-body streaming.",
        ),
        RuntimeMetric::SmbDispatches(_) => (
            "smb_dispatches",
            "Complete SMB payload dispatches ended, including cancellations.",
        ),
        RuntimeMetric::SmbDispatchErrors(_) => (
            "smb_dispatch_errors",
            "SMB handler errors; excludes ordinary protocol error-status responses.",
        ),
        RuntimeMetric::SmbCancelledDispatches(_) => (
            "smb_cancelled_dispatches",
            "SMB dispatch futures dropped before returning.",
        ),
        RuntimeMetric::SmbDispatchDuration(_) => (
            "smb_dispatch_duration_seconds",
            "SMB payload handler lifetime; excludes response socket writes.",
        ),
    }
}

fn measurement(sample: &RuntimeMetric) -> Measurement<'_> {
    match sample {
        RuntimeMetric::Uptime(value) | RuntimeMetric::LastReconciliationAge(value) => {
            Measurement::Seconds(*value)
        }
        RuntimeMetric::ReconciliationDuration(value)
        | RuntimeMetric::TargetProbeDuration(value)
        | RuntimeMetric::HttpsDispatchDuration(value)
        | RuntimeMetric::SmbDispatchDuration(value) => Measurement::Latency(value),
        RuntimeMetric::ConfiguredFolders(value)
        | RuntimeMetric::OpenTargets(value)
        | RuntimeMetric::PendingReturnScans(value)
        | RuntimeMetric::LastReconciliationFailedSteps(value) => Measurement::Gauge(*value),
        RuntimeMetric::DroppedObservations(value)
        | RuntimeMetric::TargetCheckEvictions(value)
        | RuntimeMetric::EventEvictions(value)
        | RuntimeMetric::ReconciliationCycles(value)
        | RuntimeMetric::ReconciliationFailures(value)
        | RuntimeMetric::TargetProbePasses(value)
        | RuntimeMetric::TargetProbeFailures(value)
        | RuntimeMetric::HttpsDispatches(value)
        | RuntimeMetric::HttpsServerErrors(value)
        | RuntimeMetric::HttpsCancelledDispatches(value)
        | RuntimeMetric::SmbDispatches(value)
        | RuntimeMetric::SmbDispatchErrors(value)
        | RuntimeMetric::SmbCancelledDispatches(value) => Measurement::Counter(*value),
    }
}
