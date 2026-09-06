// SPDX-License-Identifier: GPL-2.0-only

//! Bounded process-local measurements. No sample carries authority or arbitrary labels.

use std::time::Duration;

use crate::{BoundedItems, ContractError};

/// Version-one latency boundaries, inclusive, in microseconds; the count is the +Inf bucket.
pub const METRIC_LATENCY_BOUNDARIES_MICROS: [u64; 8] = [
    1_000, 5_000, 25_000, 100_000, 500_000, 1_000_000, 5_000_000, 30_000_000,
];

/// Maximum distinct families in a version-one runtime snapshot.
pub const MAX_RUNTIME_METRIC_FAMILIES: usize = 15;

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
                .any(|previous| std::mem::discriminant(previous) == std::mem::discriminant(sample))
            {
                return Err(ContractError::InvalidInput);
            }
            if let RuntimeMetric::ReconciliationDuration(histogram)
            | RuntimeMetric::TargetProbeDuration(histogram) = sample
            {
                histogram.validate()?;
            }
        }
        Ok(())
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
