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
    /// Ended selected attempts, including failed or interrupted attempts.
    Attempts(u64),
    /// Attempts which did not return normally with successful step evidence.
    Failures(u64),
    /// Monotonic execution duration, excluding queue residence and selection.
    Duration(LatencyHistogram),
}
