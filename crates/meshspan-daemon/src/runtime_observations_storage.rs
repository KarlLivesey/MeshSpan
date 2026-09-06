// SPDX-License-Identifier: GPL-2.0-only

//! Worker-fed target accounting and selected-attempt distributions; never admission authority.

use super::RuntimeObservations;
use meshspan_contracts::{
    ContractError, LatencyHistogram, MaintenanceMetric, MaintenanceMetricKind, RuntimeMetric,
    StorageUsageMetric, StorageUsageObservation,
};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) struct StorageUsagePass {
    started: Instant,
    sampled: u64,
    unavailable: u64,
    totals: StorageUsageObservation,
}

impl Default for StorageUsagePass {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            sampled: 0,
            unavailable: 0,
            totals: StorageUsageObservation::default(),
        }
    }
}

impl StorageUsagePass {
    pub(crate) fn observe(&mut self, observation: Result<StorageUsageObservation, ContractError>) {
        let total = observation.ok().and_then(|value| {
            Some(StorageUsageObservation {
                committed_bytes: self
                    .totals
                    .committed_bytes
                    .checked_add(value.committed_bytes)?,
                reserved_bytes: self
                    .totals
                    .reserved_bytes
                    .checked_add(value.reserved_bytes)?,
                configured_limit_bytes: self
                    .totals
                    .configured_limit_bytes
                    .checked_add(value.configured_limit_bytes)?,
                repair_reserve_bytes: self
                    .totals
                    .repair_reserve_bytes
                    .checked_add(value.repair_reserve_bytes)?,
            })
        });
        if let Some(total) = total {
            self.totals = total;
            self.sampled = self.sampled.saturating_add(1);
        } else {
            self.unavailable = self.unavailable.saturating_add(1);
        }
    }

    fn append_metrics(&self, now: Instant, output: &mut Vec<RuntimeMetric>) {
        let mut values = vec![
            StorageUsageMetric::Age(now.saturating_duration_since(self.started)),
            StorageUsageMetric::SampledTargets(self.sampled),
            StorageUsageMetric::UnavailableTargets(self.unavailable),
        ];
        // A partial pass must not masquerade as the whole open-target total.
        if self.unavailable == 0 {
            values.extend([
                StorageUsageMetric::CommittedBytes(self.totals.committed_bytes),
                StorageUsageMetric::ReservedBytes(self.totals.reserved_bytes),
                StorageUsageMetric::ConfiguredLimitBytes(self.totals.configured_limit_bytes),
                StorageUsageMetric::RepairReserveBytes(self.totals.repair_reserve_bytes),
            ]);
        }
        output.extend(values.into_iter().map(RuntimeMetric::StorageUsage));
    }
}

#[derive(Clone, Default)]
struct MaintenanceCounters {
    duration: LatencyHistogram,
    failures: u64,
}

impl MaintenanceCounters {
    fn record(&mut self, failed: bool, elapsed: Duration) -> Result<(), ContractError> {
        let failures = self
            .failures
            .checked_add(u64::from(failed))
            .ok_or(ContractError::ResourceExhausted)?;
        self.duration.observe(elapsed)?;
        self.failures = failures;
        Ok(())
    }
}

#[derive(Clone, Default)]
pub(super) struct StorageMeasurements {
    usage: Option<StorageUsagePass>,
    work: [MaintenanceCounters; 5],
}

impl StorageMeasurements {
    pub(super) fn append_metrics(&self, now: Instant, output: &mut Vec<RuntimeMetric>) {
        for (kind, counters) in MaintenanceMetricKind::ALL.into_iter().zip(&self.work) {
            output.extend([
                RuntimeMetric::Maintenance(
                    kind,
                    MaintenanceMetric::Attempts(counters.duration.count),
                ),
                RuntimeMetric::Maintenance(kind, MaintenanceMetric::Failures(counters.failures)),
                RuntimeMetric::Maintenance(
                    kind,
                    MaintenanceMetric::Duration(counters.duration.clone()),
                ),
            ]);
        }
        if let Some(usage) = &self.usage {
            usage.append_metrics(now, output);
        }
    }
}

impl RuntimeObservations {
    pub(crate) fn record_storage_usage(&self, pass: StorageUsagePass) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        state.storage.usage = Some(pass);
    }

    pub(crate) fn begin_maintenance(&self, kind: MaintenanceMetricKind) -> MaintenanceObservation {
        MaintenanceObservation {
            observations: self.clone(),
            kind,
            started: Instant::now(),
            failed: true,
        }
    }
}

/// Owns one selected attempt, so early error returns cannot bypass the observation.
pub(crate) struct MaintenanceObservation {
    observations: RuntimeObservations,
    kind: MaintenanceMetricKind,
    started: Instant,
    failed: bool,
}

impl MaintenanceObservation {
    pub(crate) fn finish(mut self, result: Result<(), ()>) -> Result<(), ()> {
        self.failed = result.is_err();
        result
    }
}

impl Drop for MaintenanceObservation {
    fn drop(&mut self) {
        let Ok(mut state) = self.observations.0.state.try_lock() else {
            self.observations.drop_update();
            return;
        };
        let Some(counters) = state.storage.work.get_mut(self.kind as usize) else {
            self.observations.drop_update();
            return;
        };
        if counters
            .record(self.failed, self.started.elapsed())
            .is_err()
        {
            self.observations.drop_update();
        }
    }
}

#[cfg(test)]
#[path = "runtime_observations_storage_tests.rs"]
mod tests;
