// SPDX-License-Identifier: GPL-2.0-only

//! Fixed public vocabulary for target accounting and selected maintenance attempts.

use meshspan_contracts::{MaintenanceMetric, MaintenanceMetricKind, StorageUsageMetric};

pub(super) fn usage(value: &StorageUsageMetric) -> (&'static str, &'static str) {
    match value {
        StorageUsageMetric::SampledPackTargets(_) => (
            "storage_sampled_pack_targets",
            "Targets with pack database extent evidence in the last usage pass.",
        ),
        StorageUsageMetric::UnavailablePackTargets(_) => (
            "storage_unavailable_pack_targets",
            "Targets without pack database evidence, including unsupported providers.",
        ),
        StorageUsageMetric::PackDatabaseBytes(_) => (
            "storage_pack_database_bytes",
            "Logical database page extent including metadata; excludes WAL and filesystem allocation overhead.",
        ),
        StorageUsageMetric::PackReusableBytes(_) => (
            "storage_pack_reusable_bytes",
            "Free-list bytes reusable inside pack databases, not space returned to the host filesystem.",
        ),
        StorageUsageMetric::SampledFilesystems(_) => (
            "storage_sampled_filesystems",
            "Distinct mounted filesystems, not independent disks or storage pools.",
        ),
        StorageUsageMetric::UnavailableFilesystemTargets(_) => (
            "storage_unavailable_filesystem_targets",
            "Targets without filesystem space evidence, including unsupported providers.",
        ),
        StorageUsageMetric::FilesystemTotalBytes(_) => (
            "storage_filesystem_total_bytes",
            "Mounted-filesystem capacity counted once per filesystem; shared thin pools may overlap.",
        ),
        StorageUsageMetric::FilesystemAvailableBytes(_) => (
            "storage_filesystem_available_bytes",
            "Mounted-filesystem space available to this process, counted once per filesystem; not a reservation or independent pool capacity.",
        ),
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
    use MaintenanceMetric::{
        Attempts, ClaimedJobs, CompletedJobs, Duration, Failures, JobObservationAge,
        LocalityDebtJobs, PendingDemandBytes, ProtectionDebtJobs, QueuedJobs,
    };
    use MaintenanceMetricKind::{Drain, Rebalance, Reconcile, Repair, Scrub};
    let name = match (kind, value) {
        (Repair, JobObservationAge(_)) => "maintenance_repair_job_observation_age_seconds",
        (Repair, QueuedJobs(_)) => "maintenance_repair_queued_jobs",
        (Repair, ClaimedJobs(_)) => "maintenance_repair_claimed_jobs",
        (Repair, CompletedJobs(_)) => "maintenance_repair_completed_jobs",
        (Repair, ProtectionDebtJobs(_)) => "maintenance_repair_protection_debt_jobs",
        (Repair, LocalityDebtJobs(_)) => "maintenance_repair_locality_debt_jobs",
        (Repair, PendingDemandBytes(_)) => "maintenance_repair_pending_demand_bytes",
        (Drain, JobObservationAge(_)) => "maintenance_drain_job_observation_age_seconds",
        (Drain, QueuedJobs(_)) => "maintenance_drain_queued_jobs",
        (Drain, ClaimedJobs(_)) => "maintenance_drain_claimed_jobs",
        (Drain, CompletedJobs(_)) => "maintenance_drain_completed_jobs",
        (Drain, ProtectionDebtJobs(_)) => "maintenance_drain_protection_debt_jobs",
        (Drain, LocalityDebtJobs(_)) => "maintenance_drain_locality_debt_jobs",
        (Drain, PendingDemandBytes(_)) => "maintenance_drain_pending_demand_bytes",
        (Rebalance, JobObservationAge(_)) => "maintenance_rebalance_job_observation_age_seconds",
        (Rebalance, QueuedJobs(_)) => "maintenance_rebalance_queued_jobs",
        (Rebalance, ClaimedJobs(_)) => "maintenance_rebalance_claimed_jobs",
        (Rebalance, CompletedJobs(_)) => "maintenance_rebalance_completed_jobs",
        (Rebalance, ProtectionDebtJobs(_)) => "maintenance_rebalance_protection_debt_jobs",
        (Rebalance, LocalityDebtJobs(_)) => "maintenance_rebalance_locality_debt_jobs",
        (Rebalance, PendingDemandBytes(_)) => "maintenance_rebalance_pending_demand_bytes",
        (Reconcile, JobObservationAge(_)) => "maintenance_reconcile_job_observation_age_seconds",
        (Reconcile, QueuedJobs(_)) => "maintenance_reconcile_queued_jobs",
        (Reconcile, ClaimedJobs(_)) => "maintenance_reconcile_claimed_jobs",
        (Reconcile, CompletedJobs(_)) => "maintenance_reconcile_completed_jobs",
        (Reconcile, ProtectionDebtJobs(_)) => "maintenance_reconcile_protection_debt_jobs",
        (Reconcile, LocalityDebtJobs(_)) => "maintenance_reconcile_locality_debt_jobs",
        (Reconcile, PendingDemandBytes(_)) => "maintenance_reconcile_pending_demand_bytes",
        (Scrub, JobObservationAge(_)) => "maintenance_scrub_job_observation_age_seconds",
        (Scrub, QueuedJobs(_)) => "maintenance_scrub_queued_jobs",
        (Scrub, ClaimedJobs(_)) => "maintenance_scrub_claimed_jobs",
        (Scrub, CompletedJobs(_)) => "maintenance_scrub_completed_jobs",
        (Scrub, ProtectionDebtJobs(_)) => "maintenance_scrub_protection_debt_jobs",
        (Scrub, LocalityDebtJobs(_)) => "maintenance_scrub_locality_debt_jobs",
        (Scrub, PendingDemandBytes(_)) => "maintenance_scrub_pending_demand_bytes",
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
        JobObservationAge(_) => {
            "Age since the completed retained-job sampling pass began; not a live queue snapshot."
        }
        QueuedJobs(_) => "Retained jobs awaiting a claim or retry time.",
        ClaimedJobs(_) => {
            "Retained jobs with claims, including expired claims awaiting replacement."
        }
        CompletedJobs(_) => {
            "Retained jobs linked to an authoritative terminal effect; not a lifetime counter."
        }
        ProtectionDebtJobs(_) => {
            "Unfinished jobs with recorded protection debt, not missing shard counts."
        }
        LocalityDebtJobs(_) => {
            "Unfinished jobs with recorded locality debt, not missing shard counts."
        }
        PendingDemandBytes(_) => {
            "Summed execution budgets of unfinished jobs, not bytes left to transfer."
        }
        Attempts(_) => "Ended selected maintenance attempts; not completed jobs.",
        Failures(_) => "Selected attempts which failed or were interrupted.",
        Duration(_) => "Selected attempt duration; excludes queue residence and selection.",
    };
    (name, help)
}
