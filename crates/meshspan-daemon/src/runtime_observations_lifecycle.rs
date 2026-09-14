// SPDX-License-Identifier: GPL-2.0-only

//! Constant-space lifecycle evidence collected by existing owners, never by scrapes.

use super::RuntimeObservations;
use meshspan_contracts::{
    ContractError, LatencyHistogram, LifecycleKind, LifecycleMetric, LifecycleOutcome,
    RuntimeMetric,
};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
pub(super) struct LifecycleMeasurements {
    outcomes: [u64; 6],
    duration: LatencyHistogram,
    last: Option<Instant>,
}

impl RuntimeObservations {
    pub(crate) fn record_certificate_automation<E>(
        &self,
        result: &Result<crate::CertificateAutomationOutcome, E>,
        duration: Duration,
    ) {
        use crate::{
            CertificateAutomationOutcome as Automation, CertificateOrderDriveOutcome as Drive,
        };
        let outcome = match result {
            Ok(Automation::Idle { renewal: None }) => LifecycleOutcome::Idle,
            Ok(Automation::Idle { renewal: Some(_) }) => LifecycleOutcome::Progress,
            Ok(Automation::Order { drive, .. }) => match drive {
                Drive::ClaimExpired | Drive::Retried { .. } => LifecycleOutcome::Retried,
                Drive::Pending => LifecycleOutcome::Pending,
                Drive::Yielded { .. } => LifecycleOutcome::Progress,
                Drive::Completed(_) => LifecycleOutcome::Completed,
            },
            Err(_) => LifecycleOutcome::Failed,
        };
        self.record_lifecycle(LifecycleKind::CertificateAutomation, outcome, duration);
    }

    pub(crate) fn record_certificate_installation<E>(
        &self,
        result: &Result<crate::PublicCertificateInstallationWorkerOutcome, E>,
        duration: Duration,
    ) {
        use crate::PublicCertificateInstallationWorkerOutcome as Installation;
        let outcome = match result {
            Ok(Installation::Idle | Installation::Current) => LifecycleOutcome::Idle,
            Ok(Installation::Deferred) => LifecycleOutcome::Pending,
            Ok(Installation::Installed(_)) => LifecycleOutcome::Completed,
            Err(_) => LifecycleOutcome::Failed,
        };
        self.record_lifecycle(LifecycleKind::CertificateInstallation, outcome, duration);
    }

    pub(crate) fn record_backup<E>(
        &self,
        result: &Result<crate::MetadataBackupWorkerOutcome, E>,
        duration: Duration,
    ) {
        use crate::MetadataBackupWorkerOutcome as Backup;
        let outcome = match result {
            Ok(Backup::Idle) => LifecycleOutcome::Idle,
            Ok(Backup::Progress { .. }) => LifecycleOutcome::Progress,
            Ok(Backup::AwaitingDestinations { .. } | Backup::Recovering { .. }) => {
                LifecycleOutcome::Pending
            }
            Ok(Backup::Protected { .. }) => LifecycleOutcome::Completed,
            Err(_) => LifecycleOutcome::Failed,
        };
        self.record_lifecycle(LifecycleKind::Backup, outcome, duration);
    }

    pub(crate) fn record_lifecycle(
        &self,
        kind: LifecycleKind,
        outcome: LifecycleOutcome,
        duration: Duration,
    ) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        if state.lifecycle[kind as usize]
            .record(outcome, duration, Instant::now())
            .is_err()
        {
            self.drop_update();
        }
    }
}

impl LifecycleMeasurements {
    fn record(
        &mut self,
        outcome: LifecycleOutcome,
        duration: Duration,
        now: Instant,
    ) -> Result<(), ContractError> {
        let counter = self.outcomes[outcome as usize]
            .checked_add(1)
            .ok_or(ContractError::ResourceExhausted)?;
        self.duration.observe(duration)?;
        self.outcomes[outcome as usize] = counter;
        self.last = Some(now);
        Ok(())
    }

    pub(super) fn append_metrics(
        &self,
        kind: LifecycleKind,
        now: Instant,
        samples: &mut Vec<RuntimeMetric>,
    ) {
        let Some(last) = self.last else {
            return;
        };
        let [idle, pending, progress, completed, retried, failed] = self.outcomes;
        samples.extend(
            [
                LifecycleMetric::Idle(idle),
                LifecycleMetric::Pending(pending),
                LifecycleMetric::Progress(progress),
                LifecycleMetric::Completed(completed),
                LifecycleMetric::Retried(retried),
                LifecycleMetric::Failed(failed),
                LifecycleMetric::Duration(self.duration.clone()),
                LifecycleMetric::ObservationAge(now.saturating_duration_since(last)),
            ]
            .map(|metric| RuntimeMetric::Lifecycle(kind, metric)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_contracts::{RuntimeMetricSnapshot, RuntimeMetricSource};

    #[test]
    fn lifecycle_passes_have_exact_counters_durations_and_missing_sample_semantics()
    -> Result<(), ContractError> {
        let start = Instant::now();
        let mut values = LifecycleMeasurements::default();
        let mut samples = Vec::new();
        values.append_metrics(LifecycleKind::Backup, start, &mut samples);
        assert!(samples.is_empty());
        for outcome in [
            LifecycleOutcome::Idle,
            LifecycleOutcome::Pending,
            LifecycleOutcome::Progress,
            LifecycleOutcome::Completed,
            LifecycleOutcome::Retried,
            LifecycleOutcome::Failed,
        ] {
            values.record(outcome, Duration::from_millis(1), start)?;
        }
        values.append_metrics(
            LifecycleKind::Backup,
            start + Duration::from_secs(7),
            &mut samples,
        );
        assert_eq!(values.outcomes, [1; 6]);
        assert_eq!(values.duration.count, 6);
        assert_eq!(values.duration.sum, Duration::from_millis(6));
        assert_eq!(values.duration.buckets, [6; 8]);
        assert!(samples.contains(&RuntimeMetric::Lifecycle(
            LifecycleKind::Backup,
            LifecycleMetric::ObservationAge(Duration::from_secs(7))
        )));
        let encoded = crate::encode_openmetrics(&RuntimeMetricSnapshot::new(samples)?)?;
        let encoded = std::str::from_utf8(&encoded).map_err(|_| ContractError::Corrupt)?;
        for suffix in [
            "idle",
            "pending",
            "progress",
            "completed",
            "retried",
            "failed",
        ] {
            assert!(encoded.contains(&format!("meshspan_v1_backup_{suffix}_passes_total 1\n")));
        }
        assert!(encoded.contains("meshspan_v1_backup_pass_duration_seconds_sum 0.006000000\n"));
        Ok(())
    }

    #[test]
    fn lifecycle_overflow_does_not_partially_advance_the_sample() -> Result<(), ContractError> {
        let start = Instant::now();
        let mut values = LifecycleMeasurements::default();
        values.record(LifecycleOutcome::Failed, Duration::from_millis(3), start)?;
        values.outcomes[LifecycleOutcome::Failed as usize] = u64::MAX;
        let histogram = values.duration.clone();
        assert!(
            values
                .record(
                    LifecycleOutcome::Failed,
                    Duration::from_secs(2),
                    start + Duration::from_secs(2)
                )
                .is_err()
        );
        assert_eq!(values.duration, histogram);
        assert_eq!(values.last, Some(start));
        assert_eq!(values.outcomes[LifecycleOutcome::Failed as usize], u64::MAX);
        Ok(())
    }

    #[test]
    fn lifecycle_owner_outcomes_are_redacted_and_do_not_wait_for_observation_lock()
    -> Result<(), ContractError> {
        let observations = RuntimeObservations::default();
        observations.record_certificate_automation::<()>(
            &Ok(crate::CertificateAutomationOutcome::Idle { renewal: None }),
            Duration::from_millis(1),
        );
        observations.record_certificate_installation::<()>(
            &Ok(crate::PublicCertificateInstallationWorkerOutcome::Current),
            Duration::from_millis(2),
        );
        observations.record_backup::<&str>(
            &Err("secret-provider-path-and-token"),
            Duration::from_millis(3),
        );
        observations.record_lifecycle(
            LifecycleKind::UpdatePreparation,
            LifecycleOutcome::Completed,
            Duration::from_millis(4),
        );
        let snapshot = observations.collect_metrics()?;
        let count = snapshot
            .samples()
            .iter()
            .filter(|sample| matches!(sample, RuntimeMetric::Lifecycle(..)))
            .count();
        assert_eq!(count, 32);
        let output = crate::encode_openmetrics(&snapshot)?;
        let output = std::str::from_utf8(&output).map_err(|_| ContractError::Corrupt)?;
        assert!(!output.contains("secret-provider-path-and-token"));
        assert!(output.contains("meshspan_v1_certificate_automation_idle_passes_total 1\n"));
        assert!(output.contains("meshspan_v1_certificate_installation_idle_passes_total 1\n"));
        assert!(output.contains("meshspan_v1_backup_failed_passes_total 1\n"));
        assert!(output.contains("meshspan_v1_update_preparation_completed_passes_total 1\n"));
        let held = observations
            .0
            .state
            .lock()
            .map_err(|_| ContractError::InternalContract)?;
        observations.record_lifecycle(
            LifecycleKind::Backup,
            LifecycleOutcome::Completed,
            Duration::ZERO,
        );
        drop(held);
        assert!(
            observations
                .collect_metrics()?
                .samples()
                .contains(&RuntimeMetric::DroppedObservations(1))
        );
        Ok(())
    }
}
