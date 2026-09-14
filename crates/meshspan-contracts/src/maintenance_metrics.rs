// SPDX-License-Identifier: GPL-2.0-only

//! Closed maintenance measurement categories, independent of work authority and identities.

use crate::LatencyHistogram;

/// Selected maintenance attempt kind. These numeric values are not a wire encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceMetricKind {
    /// Reconstruction and installation of a replacement shard.
    Repair,
    /// One storage-target drain step.
    Drain,
    /// One placement rebalance step.
    Rebalance,
    /// One returning-target reconciliation page.
    Reconcile,
    /// One integrity scrub page.
    Scrub,
}

impl MaintenanceMetricKind {
    /// Fixed order used by constant-space collectors; not an externally accepted identifier.
    pub const ALL: [Self; 5] = [
        Self::Repair,
        Self::Drain,
        Self::Rebalance,
        Self::Reconcile,
        Self::Scrub,
    ];
}

/// Attempt observations, never the authoritative completed-job count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceMetric {
    /// Age since the completed retained-job sampling pass began; not a live queue snapshot.
    JobObservationAge(std::time::Duration),
    /// Retained jobs awaiting a claim or their retry time.
    QueuedJobs(u64),
    /// Retained jobs with a claim, which may have expired since observation.
    ClaimedJobs(u64),
    /// Retained jobs with an authoritative terminal effect; a gauge, not a lifetime counter.
    CompletedJobs(u64),
    /// Unfinished jobs whose recorded signals contain protection debt, not a shard count.
    ProtectionDebtJobs(u64),
    /// Unfinished jobs whose recorded signals contain locality debt, not a shard count.
    LocalityDebtJobs(u64),
    /// Sum of unfinished jobs' execution memory/IO budgets, not bytes left to transfer.
    PendingDemandBytes(u64),
    /// Ended selected attempts, including failed or interrupted attempts.
    Attempts(u64),
    /// Attempts which did not return normally with successful step evidence.
    Failures(u64),
    /// Monotonic execution duration, excluding queue residence and selection.
    Duration(LatencyHistogram),
}
