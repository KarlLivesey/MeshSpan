// SPDX-License-Identifier: GPL-2.0-only

//! Durable progress observations, distinct from attempts and execution budgets.

/// Gauges over the last complete retained-job observation pass, not lifetime counters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceProgressMetric {
    /// Jobs whose progress could not be observed on this gateway.
    UnavailableJobs(u64),
    /// Bytes in committed replacement-shard receipts, counted once per retained repair job.
    RepairedBytes(u64),
    /// Scrub inventory observations in committed global effects or local checkpoints.
    ScrubObservations(u64),
    /// Scrub bytes read/digested in those effects or checkpoints.
    ScrubVerifiedBytes(u64),
    /// Returning-target inventory observations in effects or local checkpoints.
    ReconciliationObservations(u64),
    /// Returning-target bytes read/digested in effects or local checkpoints.
    ReconciliationVerifiedBytes(u64),
    /// Complete stripes evaluated in committed rebalance scan pages.
    RebalanceScannedStripes(u64),
    /// Repair jobs admitted by committed rebalance scan pages, not completed transfers.
    RebalanceQueuedRepairs(u64),
    /// Retained drain jobs whose scope is authoritatively safe to detach.
    SafeDrains(u64),
}
