// SPDX-License-Identifier: GPL-2.0-only

//! Completed metadata inventories retain sample age; failed/partial scans never invent zeros.

use super::RuntimeObservations;
use meshspan_contracts::{InventoryMetric as Metric, RuntimeMetric};
use meshspan_metadata::UpdateProgressCounts;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(crate) enum InventoryKind {
    Certificate,
    Backups,
    Updates,
}

#[derive(Clone, Copy)]
pub(crate) struct CertificateInventory {
    pub remaining: Duration,
    pub not_yet_valid: bool,
    pub expired: bool,
    pub required: u64,
    pub installed: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct UpdateInventory {
    /// Running, paused, completed, cancelled retained rollout counts.
    pub states: [u64; 4],
    pub active: Option<UpdateProgressCounts>,
}

#[derive(Clone, Copy)]
pub(crate) enum InventorySample {
    Certificate(Option<CertificateInventory>),
    /// Queued, claimed, recorded, protected and incomplete retained occurrences.
    Backups([u64; 5]),
    Updates(UpdateInventory),
}

#[derive(Clone)]
struct Observed<T> {
    started: Instant,
    value: T,
}

#[derive(Clone, Default)]
pub(super) struct InventoryMeasurements {
    certificate: Option<Observed<Option<CertificateInventory>>>,
    backups: Option<Observed<[u64; 5]>>,
    updates: Option<Observed<UpdateInventory>>,
    failures: [u64; 3],
}

impl RuntimeObservations {
    pub(crate) fn record_inventory(&self, started: Instant, sample: InventorySample) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        match sample {
            InventorySample::Certificate(value) => {
                state.inventory.certificate = Some(Observed { started, value });
            }
            InventorySample::Backups(value) => {
                state.inventory.backups = Some(Observed { started, value });
            }
            InventorySample::Updates(value) => {
                state.inventory.updates = Some(Observed { started, value });
            }
        }
    }

    pub(crate) fn record_inventory_failure(&self, kind: InventoryKind) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        let index = match kind {
            InventoryKind::Certificate => 0,
            InventoryKind::Backups => 1,
            InventoryKind::Updates => 2,
        };
        let count = &mut state.inventory.failures[index];
        if let Some(next) = count.checked_add(1) {
            *count = next;
        } else {
            self.drop_update();
        }
    }
}

impl InventoryMeasurements {
    pub(super) fn append_metrics(&self, captured: Instant, output: &mut Vec<RuntimeMetric>) {
        let [certificates, backups, updates] = self.failures;
        let mut metrics = vec![
            Metric::CertificateObservationFailures(certificates),
            Metric::BackupObservationFailures(backups),
            Metric::UpdateObservationFailures(updates),
        ];
        if let Some(sample) = &self.certificate {
            metrics.push(Metric::CertificateObservationAge(
                captured.saturating_duration_since(sample.started),
            ));
            metrics.push(Metric::CertificateSelected(sample.value.is_some()));
            if let Some(value) = sample.value {
                metrics.extend([
                    Metric::CertificateRemainingValidity(value.remaining),
                    Metric::CertificateNotYetValid(value.not_yet_valid),
                    Metric::CertificateExpired(value.expired),
                    Metric::CertificateRequiredGateways(value.required),
                    Metric::CertificateInstalledGateways(value.installed),
                ]);
            }
        }
        if let Some(sample) = &self.backups {
            let [queued, claimed, recorded, protected, incomplete] = sample.value;
            metrics.extend([
                Metric::BackupsQueued(queued),
                Metric::BackupsClaimed(claimed),
                Metric::BackupsRecorded(recorded),
                Metric::BackupsProtected(protected),
                Metric::BackupsIncomplete(incomplete),
                Metric::BackupObservationAge(captured.saturating_duration_since(sample.started)),
            ]);
        }
        if let Some(sample) = &self.updates {
            let [running, paused, completed, cancelled] = sample.value.states;
            let counts = sample.value.active.unwrap_or_default();
            metrics.extend([
                Metric::UpdatesRunning(running),
                Metric::UpdatesPaused(paused),
                Metric::UpdatesCompleted(completed),
                Metric::UpdatesCancelled(cancelled),
                Metric::UpdateSelected(sample.value.active.is_some()),
                Metric::UpdatePendingNodes(counts.pending),
                Metric::UpdateStagedNodes(counts.staged),
                Metric::UpdateRestartingNodes(counts.restarting),
                Metric::UpdateVerifiedNodes(counts.verified),
                Metric::UpdateFailedNodes(counts.failed),
                Metric::UpdateUnresolvedRestarts(counts.unresolved_restarts),
                Metric::UpdateObservationAge(captured.saturating_duration_since(sample.started)),
            ]);
        }
        output.extend(metrics.into_iter().map(RuntimeMetric::Inventory));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_contracts::RuntimeMetricSource as _;

    #[test]
    fn inventory_preserves_last_complete_values_and_age_when_a_later_pass_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let observations = RuntimeObservations::default();
        let initial = observations.collect_metrics()?;
        assert!(
            !initial.samples().iter().any(|value| matches!(
                value,
                RuntimeMetric::Inventory(Metric::BackupsProtected(_))
            ))
        );
        let started = Instant::now()
            .checked_sub(Duration::from_secs(3))
            .ok_or("clock")?;
        observations.record_inventory(started, InventorySample::Backups([1, 2, 3, 4, 5]));
        observations.record_inventory_failure(InventoryKind::Backups);
        let result = observations.collect_metrics()?;
        for expected in [
            Metric::BackupsQueued(1),
            Metric::BackupsClaimed(2),
            Metric::BackupsRecorded(3),
            Metric::BackupsProtected(4),
            Metric::BackupsIncomplete(5),
            Metric::BackupObservationFailures(1),
        ] {
            assert!(
                result
                    .samples()
                    .contains(&RuntimeMetric::Inventory(expected))
            );
        }
        assert!(result.samples().iter().any(|value| matches!(value,
            RuntimeMetric::Inventory(Metric::BackupObservationAge(age)) if *age >= Duration::from_secs(3))));
        observations.record_inventory(Instant::now(), InventorySample::Certificate(None));
        let result = observations.collect_metrics()?;
        assert!(
            result
                .samples()
                .contains(&RuntimeMetric::Inventory(Metric::CertificateSelected(
                    false
                )))
        );
        assert!(!result.samples().iter().any(|value| matches!(
            value,
            RuntimeMetric::Inventory(Metric::CertificateRemainingValidity(_))
        )));
        Ok(())
    }
}
