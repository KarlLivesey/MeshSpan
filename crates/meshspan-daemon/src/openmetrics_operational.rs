// SPDX-License-Identifier: GPL-2.0-only

//! Fixed public vocabulary for target accounting and selected maintenance attempts.

use meshspan_contracts::{MaintenanceMetric, MaintenanceMetricKind, StorageUsageMetric};

pub(super) fn usage(value: &StorageUsageMetric) -> (&'static str, &'static str) {
    match value {
        StorageUsageMetric::Age(_) => (
            "storage_usage_age_seconds",
            "Age since the last usage sampling pass began.",
        ),
        StorageUsageMetric::SampledTargets(_) => (
            "storage_usage_sampled_targets",
            "Open targets sampled in the last usage pass.",
        ),
        StorageUsageMetric::UnavailableTargets(_) => (
            "storage_usage_unavailable_targets",
            "Open targets without usage evidence in the last pass.",
        ),
        StorageUsageMetric::CommittedBytes(_) => (
            "storage_accounted_committed_bytes",
            "Accounted shard and backup payload bytes; excludes filesystem and pack overhead.",
        ),
        StorageUsageMetric::ReservedBytes(_) => (
            "storage_accounted_reserved_bytes",
            "Active shard and backup holds, including uncertain publication outcomes.",
        ),
        StorageUsageMetric::ConfiguredLimitBytes(_) => (
            "storage_configured_limit_bytes",
            "Sum of target ceilings; shared physical space can overlap.",
        ),
        StorageUsageMetric::RepairReserveBytes(_) => (
            "storage_repair_reserve_bytes",
            "Configured repair headroom; not occupied bytes.",
        ),
    }
}

pub(super) fn maintenance(
    kind: MaintenanceMetricKind,
    value: &MaintenanceMetric,
) -> (&'static str, &'static str) {
    use MaintenanceMetric::{Attempts, Duration, Failures};
    use MaintenanceMetricKind::{Drain, Rebalance, Reconcile, Repair, Scrub};
    let name = match (kind, value) {
        (Repair, Attempts(_)) => "maintenance_repair_attempts",
        (Repair, Failures(_)) => "maintenance_repair_failures",
        (Repair, Duration(_)) => "maintenance_repair_duration_seconds",
        (Drain, Attempts(_)) => "maintenance_drain_attempts",
        (Drain, Failures(_)) => "maintenance_drain_failures",
        (Drain, Duration(_)) => "maintenance_drain_duration_seconds",
        (Rebalance, Attempts(_)) => "maintenance_rebalance_attempts",
        (Rebalance, Failures(_)) => "maintenance_rebalance_failures",
        (Rebalance, Duration(_)) => "maintenance_rebalance_duration_seconds",
        (Reconcile, Attempts(_)) => "maintenance_reconcile_attempts",
        (Reconcile, Failures(_)) => "maintenance_reconcile_failures",
        (Reconcile, Duration(_)) => "maintenance_reconcile_duration_seconds",
        (Scrub, Attempts(_)) => "maintenance_scrub_attempts",
        (Scrub, Failures(_)) => "maintenance_scrub_failures",
        (Scrub, Duration(_)) => "maintenance_scrub_duration_seconds",
    };
    let help = match value {
        Attempts(_) => "Ended selected maintenance attempts; not completed jobs.",
        Failures(_) => "Selected attempts which failed or were interrupted.",
        Duration(_) => "Selected attempt duration; excludes queue residence and selection.",
    };
    (name, help)
}
