// SPDX-License-Identifier: GPL-2.0-only

//! Aggregate metrics never project target identities or the finite diagnostic event window.

use meshspan_contracts::{
    ContractError, RuntimeMetric, RuntimeMetricSnapshot, RuntimeMetricSource,
};

use super::{RuntimeObservationSource, RuntimeObservations, RuntimeSnapshot};

impl RuntimeMetricSource for RuntimeObservations {
    fn collect_metrics(&self) -> Result<RuntimeMetricSnapshot, ContractError> {
        self.snapshot().ok_or(ContractError::Unavailable)?.metrics()
    }
}

impl RuntimeSnapshot {
    fn metrics(&self) -> Result<RuntimeMetricSnapshot, ContractError> {
        let state = &self.state;
        let mut samples = vec![
            RuntimeMetric::Uptime(self.uptime),
            RuntimeMetric::DroppedObservations(self.dropped),
            RuntimeMetric::TargetCheckEvictions(state.target_evictions),
            RuntimeMetric::EventEvictions(state.event_evictions),
            RuntimeMetric::ReconciliationCycles(state.cycles),
            RuntimeMetric::ReconciliationFailures(state.failed_cycles),
            RuntimeMetric::TargetProbePasses(state.passed_probes),
            RuntimeMetric::TargetProbeFailures(state.failed_probes),
            RuntimeMetric::ReconciliationDuration(state.cycle_duration.clone()),
            RuntimeMetric::TargetProbeDuration(state.probe_duration.clone()),
            RuntimeMetric::HttpsDispatches(state.https.duration.count),
            RuntimeMetric::HttpsServerErrors(state.https.failures),
            RuntimeMetric::HttpsCancelledDispatches(state.https.cancelled),
            RuntimeMetric::HttpsDispatchDuration(state.https.duration.clone()),
            RuntimeMetric::SmbDispatches(state.smb.duration.count),
            RuntimeMetric::SmbDispatchErrors(state.smb.failures),
            RuntimeMetric::SmbCancelledDispatches(state.smb.cancelled),
            RuntimeMetric::SmbDispatchDuration(state.smb.duration.clone()),
        ];
        if let Some(cycle) = &state.cycle {
            let count = |value| u64::try_from(value).map_err(|_| ContractError::InternalContract);
            samples.extend([
                RuntimeMetric::LastReconciliationAge(
                    self.captured
                        .saturating_duration_since(cycle.observation.monotonic),
                ),
                RuntimeMetric::ConfiguredFolders(count(cycle.summary.configured_folders)?),
                RuntimeMetric::OpenTargets(count(cycle.summary.open_targets)?),
                RuntimeMetric::PendingReturnScans(count(cycle.summary.pending_return_scans)?),
                RuntimeMetric::LastReconciliationFailedSteps(count(cycle.summary.failed_steps)?),
            ]);
        }
        RuntimeMetricSnapshot::new(samples)
    }
}
