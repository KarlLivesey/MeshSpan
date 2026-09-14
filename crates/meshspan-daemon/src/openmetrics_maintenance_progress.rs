// SPDX-License-Identifier: GPL-2.0-only

//! Fixed durable-progress quantities, shared by exporter and history.

use super::Measurement;
use meshspan_contracts::MaintenanceProgressMetric as Metric;

pub(super) fn name_and_help(value: &Metric) -> (&'static str, &'static str) {
    match value {
        Metric::UnavailableJobs(_) => (
            "maintenance_progress_unavailable_jobs",
            "Retained jobs without progress evidence on this gateway; progress totals are absent when nonzero.",
        ),
        Metric::RepairedBytes(_) => (
            "maintenance_progress_repaired_bytes",
            "Bytes in committed replacement receipts, once per retained repair job; not wire traffic.",
        ),
        Metric::ScrubObservations(_) => (
            "maintenance_progress_scrub_observations",
            "Inventory records in durable scrub effects or local checkpoints.",
        ),
        Metric::ScrubVerifiedBytes(_) => (
            "maintenance_progress_scrub_verified_bytes",
            "Scrub bytes read and digested in durable effects or local checkpoints.",
        ),
        Metric::ReconciliationObservations(_) => (
            "maintenance_progress_reconciliation_observations",
            "Returning-target inventory records in durable effects or local checkpoints.",
        ),
        Metric::ReconciliationVerifiedBytes(_) => (
            "maintenance_progress_reconciliation_verified_bytes",
            "Returning-target bytes read and digested in durable effects or local checkpoints.",
        ),
        Metric::RebalanceScannedStripes(_) => (
            "maintenance_progress_rebalance_scanned_stripes",
            "Stripes examined in committed rebalance scan pages.",
        ),
        Metric::RebalanceQueuedRepairs(_) => (
            "maintenance_progress_rebalance_queued_repairs",
            "Repairs admitted by committed rebalance pages; not completed transfers.",
        ),
        Metric::SafeDrains(_) => (
            "maintenance_progress_safe_drains",
            "Retained drain jobs whose scope is authoritatively safe to detach; movement bytes belong to repair jobs.",
        ),
    }
}

pub(super) fn measurement(value: &Metric) -> Measurement<'_> {
    match value {
        Metric::RepairedBytes(value)
        | Metric::ScrubVerifiedBytes(value)
        | Metric::ReconciliationVerifiedBytes(value) => Measurement::Bytes(*value),
        Metric::UnavailableJobs(value)
        | Metric::ScrubObservations(value)
        | Metric::ReconciliationObservations(value)
        | Metric::RebalanceScannedStripes(value)
        | Metric::RebalanceQueuedRepairs(value)
        | Metric::SafeDrains(value) => Measurement::Gauge(*value),
    }
}
