// SPDX-License-Identifier: GPL-2.0-only

//! Bounded process-local measurements. No sample carries authority or arbitrary labels.

use std::time::Duration;

use crate::{
    BoundedItems, ContractError, MaintenanceMetric, MaintenanceMetricKind, StorageUsageMetric,
};

/// Version-one latency boundaries, inclusive, in microseconds; the count is the +Inf bucket.
pub const METRIC_LATENCY_BOUNDARIES_MICROS: [u64; 8] = [
    1_000, 5_000, 25_000, 100_000, 500_000, 1_000_000, 5_000_000, 30_000_000,
];

/// Maximum distinct families in a version-one runtime snapshot.
pub const MAX_RUNTIME_METRIC_FAMILIES: usize = 45;

/// Closed access-protocol identity; request paths and client identities are never labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayProtocol {
    /// Native HTTPS request dispatch, excluding TLS admission and response-body streaming.
    Https,
    /// One complete SMB Direct TCP payload dispatch, not each command in a compound packet.
    Smb,
}

/// Handler outcome, not proof of file publication or delivery to a client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayDispatchOutcome {
    /// HTTPS returned a non-5xx response, or SMB dispatch returned normally.
    Returned,
    /// HTTPS returned a 5xx response, or the SMB handler returned an error.
    Failed,
    /// Dispatch was dropped before returning, including task cancellation or unwinding.
    Cancelled,
}

/// One finite handler-lifecycle observation with no request-derived strings or bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayDispatchObservation {
    /// Access adapter which dispatched the request.
    pub protocol: GatewayProtocol,
    /// Outcome observed when dispatch ended.
    pub outcome: GatewayDispatchOutcome,
    /// Monotonic time inside dispatch; excludes subsequent response delivery.
    pub duration: Duration,
}

/// Replaceable best-effort observation sink, independent of access authority.
pub trait GatewayDispatchObserver: Send + Sync {
    /// Records or counts a dropped observation without IO, waiting, or affecting the request.
    fn observe_dispatch(&self, observation: GatewayDispatchObservation);
}

/// A coherent lifetime latency distribution with a fixed cardinality.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LatencyHistogram {
    /// Cumulative counts at each inclusive version-one boundary.
    pub buckets: [u64; 8],
    /// Every accepted observation, including durations above the final finite bucket.
    pub count: u64,
    /// Exact sum of accepted durations, without floating-point accumulation.
    pub sum: Duration,
}

impl LatencyHistogram {
    /// Adds one duration atomically with respect to overflow; the caller owns synchronisation.
    ///
    /// # Errors
    /// Rejects an invalid existing distribution or exhausted count/sum without changing it.
    pub fn observe(&mut self, duration: Duration) -> Result<(), ContractError> {
        self.validate()?;
        let count = self
            .count
            .checked_add(1)
            .ok_or(ContractError::InvalidInput)?;
        let sum = self
            .sum
            .checked_add(duration)
            .ok_or(ContractError::InvalidInput)?;
        for (bucket, boundary) in self
            .buckets
            .iter_mut()
            .zip(METRIC_LATENCY_BOUNDARIES_MICROS)
        {
            if duration <= Duration::from_micros(boundary) {
                // Validation proved bucket <= old count, and count + 1 succeeded.
                *bucket += 1;
            }
        }
        self.count = count;
        self.sum = sum;
        Ok(())
    }

    /// Validates the histogram received from a measurement source.
    ///
    /// # Errors
    /// Rejects non-cumulative buckets, buckets beyond count or a non-zero empty sum.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.buckets.windows(2).any(|pair| pair[0] > pair[1])
            || self.buckets.iter().any(|bucket| *bucket > self.count)
            || (self.count == 0 && !self.sum.is_zero())
        {
            return Err(ContractError::InvalidInput);
        }
        Ok(())
    }
}

/// Closed version-one measurement vocabulary; identities and free-text labels are absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeMetric {
    /// Selected maintenance-attempt observations by fixed kind and measurement.
    Maintenance(MaintenanceMetricKind, MaintenanceMetric),
    /// Last-pass target usage, explicitly separate from physical available space.
    StorageUsage(StorageUsageMetric),
    /// Monotonic process lifetime, not wall-clock or mesh-clock accuracy.
    Uptime(Duration),
    /// Observation updates lost to contention, invalid time or exhausted counters.
    DroppedObservations(u64),
    /// Older target-generation checks removed from the bounded diagnostic window.
    TargetCheckEvictions(u64),
    /// Older transitions removed from the bounded diagnostic event window.
    EventEvictions(u64),
    /// Completed storage reconciliation cycles observed in this process.
    ReconciliationCycles(u64),
    /// Observed cycles with at least one failed step.
    ReconciliationFailures(u64),
    /// Passing provider probes; not proof of a full shard scrub.
    TargetProbePasses(u64),
    /// Failed provider probes.
    TargetProbeFailures(u64),
    /// Lifetime duration distribution of observed reconciliation cycles.
    ReconciliationDuration(LatencyHistogram),
    /// Lifetime duration distribution of observed target probes, aggregated across all targets.
    TargetProbeDuration(LatencyHistogram),
    /// Monotonic age of the cycle which supplied the following last-cycle gauges.
    LastReconciliationAge(Duration),
    /// Configured folder count at the last reconciliation, not live capacity.
    ConfiguredFolders(u64),
    /// Open provider handles at the last reconciliation, not proven read availability.
    OpenTargets(u64),
    /// Targets awaiting return-scan admission at the last reconciliation.
    PendingReturnScans(u64),
    /// Failed steps in the last completed reconciliation cycle.
    LastReconciliationFailedSteps(u64),
    /// HTTPS dispatches which ended, including failures and cancellations.
    HttpsDispatches(u64),
    /// HTTP responses with a 5xx status, not all authentication or domain rejections.
    HttpsServerErrors(u64),
    /// HTTPS dispatch futures dropped before producing a response.
    HttpsCancelledDispatches(u64),
    /// HTTPS dispatch lifetime, excluding subsequent response-body streaming.
    HttpsDispatchDuration(LatencyHistogram),
    /// Complete SMB payload dispatches which ended, including failures and cancellations.
    SmbDispatches(u64),
    /// SMB handler errors; an ordinary SMB error-status response is not a handler error.
    SmbDispatchErrors(u64),
    /// SMB dispatch futures dropped before returning.
    SmbCancelledDispatches(u64),
    /// SMB payload dispatch lifetime, excluding response socket writes.
    SmbDispatchDuration(LatencyHistogram),
}

/// A bounded snapshot; absence means unavailable/unmeasured, never implicitly zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeMetricSnapshot {
    samples: BoundedItems<RuntimeMetric>,
}

impl RuntimeMetricSnapshot {
    /// Checks family count, uniqueness and individual measurement invariants.
    ///
    /// # Errors
    /// Rejects excessive/duplicate families and invalid histograms.
    pub fn new(samples: Vec<RuntimeMetric>) -> Result<Self, ContractError> {
        let snapshot = Self {
            samples: BoundedItems::new(samples, MAX_RUNTIME_METRIC_FAMILIES)
                .map_err(|_| ContractError::InvalidInput)?,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Borrows the fixed-cardinality measurement set.
    #[must_use]
    pub fn samples(&self) -> &[RuntimeMetric] {
        self.samples.as_slice()
    }

    /// Revalidates source evidence at an exporter or history boundary.
    ///
    /// # Errors
    /// Rejects duplicate families or contradictory histograms.
    pub fn validate(&self) -> Result<(), ContractError> {
        for (index, sample) in self.samples().iter().enumerate() {
            if self.samples()[..index]
                .iter()
                .any(|previous| same_family(previous, sample))
            {
                return Err(ContractError::InvalidInput);
            }
            if let RuntimeMetric::ReconciliationDuration(histogram)
            | RuntimeMetric::TargetProbeDuration(histogram)
            | RuntimeMetric::HttpsDispatchDuration(histogram)
            | RuntimeMetric::SmbDispatchDuration(histogram) = sample
            {
                histogram.validate()?;
            }
            if let RuntimeMetric::Maintenance(_, MaintenanceMetric::Duration(histogram)) = sample {
                histogram.validate()?;
            }
        }
        Ok(())
    }
}

fn same_family(left: &RuntimeMetric, right: &RuntimeMetric) -> bool {
    match (left, right) {
        (
            RuntimeMetric::Maintenance(left_kind, left),
            RuntimeMetric::Maintenance(right_kind, right),
        ) => {
            left_kind == right_kind && std::mem::discriminant(left) == std::mem::discriminant(right)
        }
        (RuntimeMetric::StorageUsage(left), RuntimeMetric::StorageUsage(right)) => {
            std::mem::discriminant(left) == std::mem::discriminant(right)
        }
        _ => std::mem::discriminant(left) == std::mem::discriminant(right),
    }
}

/// Replaceable local observation source. Collection must not probe providers or contact peers.
pub trait RuntimeMetricSource: Send + Sync {
    /// Returns a coherent bounded observation without waiting for ongoing domain IO.
    ///
    /// # Errors
    /// Reports unavailable evidence rather than inventing zero or healthy samples.
    fn collect_metrics(&self) -> Result<RuntimeMetricSnapshot, ContractError>;
}

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;
