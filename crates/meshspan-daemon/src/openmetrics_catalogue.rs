// SPDX-License-Identifier: GPL-2.0-only

//! Version-one public metric names and meanings. No field is derived from an identity or path.

use meshspan_contracts::{LatencyHistogram, RuntimeMetric};
use std::time::Duration;

#[path = "openmetrics_coding.rs"]
mod coding;
#[path = "openmetrics_consensus.rs"]
mod consensus;
#[path = "openmetrics_filesystem.rs"]
mod filesystem;
#[path = "openmetrics_gateway.rs"]
mod gateway;
#[path = "openmetrics_inventory.rs"]
mod inventory;
#[path = "openmetrics_io.rs"]
mod io;
#[path = "openmetrics_lifecycle.rs"]
mod lifecycle;
#[path = "openmetrics_operational.rs"]
mod operational;
#[path = "openmetrics_maintenance_progress.rs"]
mod progress;
#[path = "openmetrics_protection.rs"]
mod protection;

pub(super) enum Measurement<'a> {
    Counter(u64),
    Gauge(u64),
    Bytes(u64),
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
    use meshspan_contracts::GatewayProtocol::{Https, Smb};
    match sample {
        RuntimeMetric::Inventory(value) => inventory::name_and_help(value),
        RuntimeMetric::Lifecycle(kind, value) => lifecycle::name_and_help(*kind, value),
        RuntimeMetric::FilesystemOperation(kind, value) => filesystem::operation(*kind, value),
        RuntimeMetric::FilesystemReadBytes(_) => (
            "filesystem_read_bytes",
            "Verified logical bytes returned to connectors, not client delivery.",
        ),
        RuntimeMetric::FilesystemStagedWriteBytes(_) => (
            "filesystem_staged_write_bytes",
            "Bytes accepted by durable staging, including replay; not published file bytes.",
        ),
        RuntimeMetric::FilePublications(scope, _) => filesystem::publication(*scope),
        RuntimeMetric::Coding(kind, value) => coding::name_and_help(*kind, value),
        RuntimeMetric::GatewayTransfer(protocol, value) => gateway::name_and_help(*protocol, value),
        RuntimeMetric::MaintenanceProgress(value) => progress::name_and_help(value),
        RuntimeMetric::StorageIo(kind, value) => io::name_and_help(*kind, value),
        RuntimeMetric::Protection(value) => protection::name_and_help(value),
        RuntimeMetric::Consensus(value) => consensus::name_and_help(value),
        RuntimeMetric::Maintenance(kind, value) => operational::maintenance(*kind, value),
        RuntimeMetric::StorageUsage(value) => operational::usage(value),
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
        RuntimeMetric::HttpsAuthenticationRequired(_) => (
            "https_authentication_required_responses",
            "HTTPS 401 responses, including absent credentials; not unique users or sign-in attempts.",
        ),
        RuntimeMetric::HttpsForbidden(_) => (
            "https_forbidden_responses",
            "HTTPS 403 responses; excludes concealed-resource 404 responses and TLS admission failures.",
        ),
        RuntimeMetric::HttpsDispatches(_) => gateway::dispatches(Https),
        RuntimeMetric::HttpsServerErrors(_) => gateway::dispatch_errors(Https),
        RuntimeMetric::HttpsCancelledDispatches(_) => gateway::cancelled_dispatches(Https),
        RuntimeMetric::HttpsDispatchDuration(_) => gateway::dispatch_duration(Https),
        RuntimeMetric::SmbDispatches(_) => gateway::dispatches(Smb),
        RuntimeMetric::SmbDispatchErrors(_) => gateway::dispatch_errors(Smb),
        RuntimeMetric::SmbAuthenticationRejections(_) => (
            "smb_authentication_rejections",
            "Parsed SMB credential proofs rejected by shared authentication; excludes malformed handshakes and unavailable authority.",
        ),
        RuntimeMetric::SmbCancelledDispatches(_) => gateway::cancelled_dispatches(Smb),
        RuntimeMetric::SmbDispatchDuration(_) => gateway::dispatch_duration(Smb),
    }
}

fn measurement(sample: &RuntimeMetric) -> Measurement<'_> {
    match sample {
        RuntimeMetric::Inventory(value) => inventory::measurement(value),
        RuntimeMetric::Lifecycle(_, value) => lifecycle::measurement(value),
        RuntimeMetric::FilesystemOperation(_, value) => filesystem::measurement(value),
        RuntimeMetric::Coding(_, value) => coding::measurement(value),
        RuntimeMetric::GatewayTransfer(_, value) => gateway::measurement(value),
        RuntimeMetric::MaintenanceProgress(value) => progress::measurement(value),
        RuntimeMetric::StorageIo(_, value) => io::measurement(value),
        RuntimeMetric::Protection(value) => protection::measurement(value),
        RuntimeMetric::Consensus(value) => consensus::measurement(value),
        RuntimeMetric::Maintenance(_, value) => match value {
            meshspan_contracts::MaintenanceMetric::JobObservationAge(value) => {
                Measurement::Seconds(*value)
            }
            meshspan_contracts::MaintenanceMetric::QueuedJobs(value)
            | meshspan_contracts::MaintenanceMetric::ClaimedJobs(value)
            | meshspan_contracts::MaintenanceMetric::CompletedJobs(value)
            | meshspan_contracts::MaintenanceMetric::ProtectionDebtJobs(value)
            | meshspan_contracts::MaintenanceMetric::LocalityDebtJobs(value) => {
                Measurement::Gauge(*value)
            }
            meshspan_contracts::MaintenanceMetric::PendingDemandBytes(value) => {
                Measurement::Bytes(*value)
            }
            meshspan_contracts::MaintenanceMetric::Attempts(value)
            | meshspan_contracts::MaintenanceMetric::Failures(value) => {
                Measurement::Counter(*value)
            }
            meshspan_contracts::MaintenanceMetric::Duration(value) => Measurement::Latency(value),
        },
        RuntimeMetric::StorageUsage(value) => match value {
            meshspan_contracts::StorageUsageMetric::Age(value) => Measurement::Seconds(*value),
            meshspan_contracts::StorageUsageMetric::SampledTargets(value)
            | meshspan_contracts::StorageUsageMetric::SampledPackTargets(value)
            | meshspan_contracts::StorageUsageMetric::UnavailablePackTargets(value)
            | meshspan_contracts::StorageUsageMetric::SampledFilesystems(value)
            | meshspan_contracts::StorageUsageMetric::UnavailableFilesystemTargets(value)
            | meshspan_contracts::StorageUsageMetric::UnavailableTargets(value) => {
                Measurement::Gauge(*value)
            }
            meshspan_contracts::StorageUsageMetric::CommittedBytes(value)
            | meshspan_contracts::StorageUsageMetric::PackDatabaseBytes(value)
            | meshspan_contracts::StorageUsageMetric::PackReusableBytes(value)
            | meshspan_contracts::StorageUsageMetric::FilesystemTotalBytes(value)
            | meshspan_contracts::StorageUsageMetric::FilesystemAvailableBytes(value)
            | meshspan_contracts::StorageUsageMetric::ReservedBytes(value)
            | meshspan_contracts::StorageUsageMetric::ConfiguredLimitBytes(value)
            | meshspan_contracts::StorageUsageMetric::RepairReserveBytes(value) => {
                Measurement::Bytes(*value)
            }
        },
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
        RuntimeMetric::FilesystemReadBytes(value)
        | RuntimeMetric::FilesystemStagedWriteBytes(value)
        | RuntimeMetric::FilePublications(_, value)
        | RuntimeMetric::DroppedObservations(value)
        | RuntimeMetric::TargetCheckEvictions(value)
        | RuntimeMetric::EventEvictions(value)
        | RuntimeMetric::ReconciliationCycles(value)
        | RuntimeMetric::ReconciliationFailures(value)
        | RuntimeMetric::TargetProbePasses(value)
        | RuntimeMetric::TargetProbeFailures(value)
        | RuntimeMetric::HttpsAuthenticationRequired(value)
        | RuntimeMetric::HttpsForbidden(value)
        | RuntimeMetric::HttpsDispatches(value)
        | RuntimeMetric::HttpsServerErrors(value)
        | RuntimeMetric::HttpsCancelledDispatches(value)
        | RuntimeMetric::SmbDispatches(value)
        | RuntimeMetric::SmbDispatchErrors(value)
        | RuntimeMetric::SmbAuthenticationRejections(value)
        | RuntimeMetric::SmbCancelledDispatches(value) => Measurement::Counter(*value),
    }
}
