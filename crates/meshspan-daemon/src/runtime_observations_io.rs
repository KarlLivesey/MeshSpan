// SPDX-License-Identifier: GPL-2.0-only

//! Process-lifetime target IO measurements retained across target reopenings.

use super::RuntimeObservations;
use meshspan_contracts::{
    ContractError, LatencyHistogram, RuntimeMetric, StorageIoKind, StorageIoMetric,
    StorageIoObservation, StorageIoObserver,
};

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub(super) struct IoMeasurements {
    duration: LatencyHistogram,
    failures: u64,
    payload_bytes: u64,
    corruption_reports: u64,
}

impl IoMeasurements {
    fn record(&mut self, observation: StorageIoObservation) -> Result<(), ContractError> {
        let counts = observation.counts.ok_or(ContractError::InvalidInput)?;
        let failures = self
            .failures
            .checked_add(u64::from(observation.failed))
            .ok_or(ContractError::ResourceExhausted)?;
        let payload_bytes = self
            .payload_bytes
            .checked_add(counts.payload_bytes)
            .ok_or(ContractError::ResourceExhausted)?;
        let corruption_reports = self
            .corruption_reports
            .checked_add(counts.corruption_reports)
            .ok_or(ContractError::ResourceExhausted)?;
        self.duration.observe(observation.duration)?;
        self.failures = failures;
        self.payload_bytes = payload_bytes;
        self.corruption_reports = corruption_reports;
        Ok(())
    }

    pub(super) fn append_metrics(&self, kind: StorageIoKind, output: &mut Vec<RuntimeMetric>) {
        output.extend(
            [
                StorageIoMetric::Calls(self.duration.count),
                StorageIoMetric::Failures(self.failures),
                StorageIoMetric::PayloadBytes(self.payload_bytes),
                StorageIoMetric::CorruptionReports(self.corruption_reports),
                StorageIoMetric::Duration(self.duration.clone()),
            ]
            .into_iter()
            .map(|value| RuntimeMetric::StorageIo(kind, value)),
        );
    }
}

impl StorageIoObserver for RuntimeObservations {
    fn observe_storage_io(&self, observation: StorageIoObservation) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        let index = match observation.kind {
            StorageIoKind::Read => 0,
            StorageIoKind::Write => 1,
            StorageIoKind::Scrub => 2,
        };
        let Some(measurements) = state.io.get_mut(index) else {
            self.drop_update();
            return;
        };
        if measurements.record(observation).is_err() {
            self.drop_update();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_contracts::{RuntimeMetricSource, StorageIoCounts};
    use std::time::Duration;

    fn observation(failed: bool) -> StorageIoObservation {
        StorageIoObservation {
            kind: StorageIoKind::Read,
            duration: Duration::from_millis(6),
            failed,
            counts: Some(StorageIoCounts {
                payload_bytes: if failed { 0 } else { 13 },
                corruption_reports: u64::from(failed),
            }),
        }
    }

    #[test]
    fn io_counters_preserve_exact_totals_and_overflow_is_atomic() -> Result<(), ContractError> {
        let mut measurements = IoMeasurements::default();
        measurements.record(observation(false))?;
        measurements.record(observation(true))?;
        assert_eq!(
            (
                measurements.duration.count,
                measurements.failures,
                measurements.payload_bytes,
                measurements.corruption_reports
            ),
            (2, 1, 13, 1)
        );
        assert_eq!(measurements.duration.buckets, [0, 0, 2, 2, 2, 2, 2, 2]);
        measurements.payload_bytes = u64::MAX;
        let previous = measurements.clone();
        assert!(measurements.record(observation(false)).is_err());
        assert_eq!(measurements, previous);
        Ok(())
    }

    #[test]
    fn io_observations_do_not_wait_for_metrics_lock() -> Result<(), Box<dyn std::error::Error>> {
        let observations = RuntimeObservations::default();
        let guard = observations
            .0
            .state
            .lock()
            .map_err(|_| "observation lock")?;
        observations.observe_storage_io(observation(false));
        drop(guard);
        let snapshot = observations.collect_metrics()?;
        assert!(
            snapshot
                .samples()
                .contains(&RuntimeMetric::DroppedObservations(1))
        );
        assert!(snapshot.samples().contains(&RuntimeMetric::StorageIo(
            StorageIoKind::Read,
            StorageIoMetric::Calls(0)
        )));
        Ok(())
    }
}
