// SPDX-License-Identifier: GPL-2.0-only

//! One retained-job pass's durable progress and missing-evidence coverage.

use meshspan_contracts::{MaintenanceProgressMetric as Metric, RuntimeMetric};

#[derive(Clone, Copy, Default)]
pub(crate) struct MaintenanceProgressCounts {
    unavailable: u64,
    repaired: u64,
    scrub_observations: u64,
    scrub_bytes: u64,
    reconciliation_observations: u64,
    reconciliation_bytes: u64,
    scanned_stripes: u64,
    queued_repairs: u64,
    safe_drains: u64,
}

impl MaintenanceProgressCounts {
    pub(crate) fn observe(&mut self, metrics: Option<Vec<Metric>>) -> Result<(), ()> {
        let Some(metrics) = metrics else {
            self.unavailable = self.unavailable.checked_add(1).ok_or(())?;
            return Ok(());
        };
        for metric in metrics {
            let (total, value) = match metric {
                Metric::UnavailableJobs(value) => (&mut self.unavailable, value),
                Metric::RepairedBytes(value) => (&mut self.repaired, value),
                Metric::ScrubObservations(value) => (&mut self.scrub_observations, value),
                Metric::ScrubVerifiedBytes(value) => (&mut self.scrub_bytes, value),
                Metric::ReconciliationObservations(value) => {
                    (&mut self.reconciliation_observations, value)
                }
                Metric::ReconciliationVerifiedBytes(value) => {
                    (&mut self.reconciliation_bytes, value)
                }
                Metric::RebalanceScannedStripes(value) => (&mut self.scanned_stripes, value),
                Metric::RebalanceQueuedRepairs(value) => (&mut self.queued_repairs, value),
                Metric::SafeDrains(value) => (&mut self.safe_drains, value),
            };
            *total = total.checked_add(value).ok_or(())?;
        }
        Ok(())
    }

    pub(super) fn append_metrics(&self, output: &mut Vec<RuntimeMetric>) {
        let mut metrics = vec![Metric::UnavailableJobs(self.unavailable)];
        if self.unavailable == 0 {
            metrics.extend([
                Metric::RepairedBytes(self.repaired),
                Metric::ScrubObservations(self.scrub_observations),
                Metric::ScrubVerifiedBytes(self.scrub_bytes),
                Metric::ReconciliationObservations(self.reconciliation_observations),
                Metric::ReconciliationVerifiedBytes(self.reconciliation_bytes),
                Metric::RebalanceScannedStripes(self.scanned_stripes),
                Metric::RebalanceQueuedRepairs(self.queued_repairs),
                Metric::SafeDrains(self.safe_drains),
            ]);
        }
        output.extend(metrics.into_iter().map(RuntimeMetric::MaintenanceProgress));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_counts_durable_units_once_and_omits_partial_totals() -> Result<(), &'static str> {
        let mut counts = MaintenanceProgressCounts::default();
        counts
            .observe(Some(vec![
                Metric::RepairedBytes(13),
                Metric::ScrubVerifiedBytes(20),
                Metric::ScrubObservations(2),
            ]))
            .map_err(|()| "progress accounting failed")?;
        counts
            .observe(Some(vec![
                Metric::RepairedBytes(17),
                Metric::RebalanceScannedStripes(3),
                Metric::RebalanceQueuedRepairs(1),
            ]))
            .map_err(|()| "second progress accounting failed")?;
        let mut metrics = Vec::new();
        counts.append_metrics(&mut metrics);
        for value in [
            Metric::RepairedBytes(30),
            Metric::ScrubVerifiedBytes(20),
            Metric::ScrubObservations(2),
            Metric::RebalanceScannedStripes(3),
            Metric::RebalanceQueuedRepairs(1),
        ] {
            assert!(metrics.contains(&RuntimeMetric::MaintenanceProgress(value)));
        }
        counts
            .observe(None)
            .map_err(|()| "unknown accounting failed")?;
        metrics.clear();
        counts.append_metrics(&mut metrics);
        assert_eq!(
            metrics,
            vec![RuntimeMetric::MaintenanceProgress(Metric::UnavailableJobs(
                1
            ))]
        );
        let mut exhausted = MaintenanceProgressCounts::default();
        exhausted
            .observe(Some(vec![Metric::RepairedBytes(u64::MAX)]))
            .map_err(|()| "initial maximum")?;
        assert!(
            exhausted
                .observe(Some(vec![Metric::RepairedBytes(1)]))
                .is_err()
        );
        Ok(())
    }
}
