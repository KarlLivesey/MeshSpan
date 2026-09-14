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
            RuntimeMetric::Protection(meshspan_contracts::ProtectionMetric::ObservationFailures(
                state.protection_failures,
            )),
            RuntimeMetric::Uptime(self.uptime),
            RuntimeMetric::DroppedObservations(self.dropped),
            RuntimeMetric::Consensus(meshspan_contracts::ConsensusMetric::ObservationFailures(
                state.consensus_failures,
            )),
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
            RuntimeMetric::HttpsAuthenticationRequired(state.https.authentication_required),
            RuntimeMetric::HttpsForbidden(state.https.forbidden),
            RuntimeMetric::HttpsCancelledDispatches(state.https.cancelled),
            RuntimeMetric::HttpsDispatchDuration(state.https.duration.clone()),
            RuntimeMetric::SmbDispatches(state.smb.duration.count),
            RuntimeMetric::SmbDispatchErrors(state.smb.failures),
            RuntimeMetric::SmbAuthenticationRejections(state.smb_authentication_rejections),
            RuntimeMetric::SmbCancelledDispatches(state.smb.cancelled),
            RuntimeMetric::SmbDispatchDuration(state.smb.duration.clone()),
        ];
        state.inventory.append_metrics(self.captured, &mut samples);
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
        state.storage.append_metrics(self.captured, &mut samples);
        for (kind, measurements) in meshspan_contracts::LifecycleKind::ALL
            .into_iter()
            .zip(&state.lifecycle)
        {
            measurements.append_metrics(kind, self.captured, &mut samples);
        }
        state.filesystem.append_metrics(&mut samples);
        for (kind, measurements) in [
            meshspan_contracts::CodingOperation::Encode,
            meshspan_contracts::CodingOperation::Reconstruct,
        ]
        .into_iter()
        .zip(&state.coding)
        {
            measurements.append_metrics(kind, &mut samples);
        }
        state
            .https
            .append_transfer(meshspan_contracts::GatewayProtocol::Https, &mut samples);
        state
            .smb
            .append_transfer(meshspan_contracts::GatewayProtocol::Smb, &mut samples);
        for (kind, measurements) in meshspan_contracts::StorageIoKind::ALL
            .into_iter()
            .zip(&state.io)
        {
            measurements.append_metrics(kind, &mut samples);
        }
        if let Some(protection) = &state.protection {
            protection.append_metrics(self.captured, &mut samples);
        }
        if let Some(consensus) = &state.consensus {
            consensus.append_metrics(self.captured, &mut samples);
        }
        RuntimeMetricSnapshot::new(samples)
    }
}
