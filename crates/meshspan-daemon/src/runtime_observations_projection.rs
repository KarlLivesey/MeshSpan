// SPDX-License-Identifier: GPL-2.0-only

//! Explicit redacted projection; typed observations cannot supply arbitrary log fields.

use std::time::Duration;

use meshspan_api_contract::{
    DiagnosticCounter, DiagnosticIdentifier, DiagnosticObservationTime, DiagnosticProbeResult,
    DiagnosticRuntimeEvent, DiagnosticRuntimeEventCode, DiagnosticStorageReconciliation,
    DiagnosticTargetCheck, DiagnosticTargetIdentity, RuntimeDiagnosticsResponse,
};
use meshspan_domain::TargetId;

use super::{ObservationTime, RuntimeEventCode, RuntimeSnapshot};

impl RuntimeSnapshot {
    pub(crate) fn project(&self) -> RuntimeDiagnosticsResponse {
        let state = &self.state;
        RuntimeDiagnosticsResponse {
            uptime_millis: milliseconds(self.uptime),
            observation_sequence: count(state.sequence),
            dropped_updates: count(self.dropped),
            target_check_evictions: count(state.target_evictions),
            event_evictions: count(state.event_evictions),
            reconciliation_cycles: count(state.cycles),
            reconciliation_failures: count(state.failed_cycles),
            target_probe_passes: count(state.passed_probes),
            target_probe_failures: count(state.failed_probes),
            storage_reconciliation: state.cycle.as_ref().map(|cycle| {
                DiagnosticStorageReconciliation {
                    observation: self.observation(cycle.observation),
                    duration_millis: milliseconds(cycle.duration),
                    configured_folders: DiagnosticCounter(
                        cycle.summary.configured_folders.to_string(),
                    ),
                    open_targets: DiagnosticCounter(cycle.summary.open_targets.to_string()),
                    pending_return_scans: DiagnosticCounter(
                        cycle.summary.pending_return_scans.to_string(),
                    ),
                    failed_steps: DiagnosticCounter(cycle.summary.failed_steps.to_string()),
                }
            }),
            target_checks: state
                .targets
                .values()
                .map(|check| DiagnosticTargetCheck {
                    target: target(check.target, check.generation),
                    observation: self.observation(check.observation),
                    duration_millis: milliseconds(check.duration),
                    result: if check.passed {
                        DiagnosticProbeResult::Passed
                    } else {
                        DiagnosticProbeResult::Failed
                    },
                })
                .collect(),
            recent_events: state
                .events
                .iter()
                .rev()
                .map(|event| DiagnosticRuntimeEvent {
                    observation: self.observation(event.observation),
                    code: match event.code {
                        RuntimeEventCode::TargetProbeFailed => {
                            DiagnosticRuntimeEventCode::TargetProbeFailed
                        }
                        RuntimeEventCode::TargetProbeRecovered => {
                            DiagnosticRuntimeEventCode::TargetProbeRecovered
                        }
                        RuntimeEventCode::StorageReconciliationFailed => {
                            DiagnosticRuntimeEventCode::StorageReconciliationFailed
                        }
                        RuntimeEventCode::StorageReconciliationRecovered => {
                            DiagnosticRuntimeEventCode::StorageReconciliationRecovered
                        }
                    },
                    target: event.target.map(|(id, generation)| target(id, generation)),
                })
                .collect(),
        }
    }

    fn observation(&self, observed: ObservationTime) -> DiagnosticObservationTime {
        DiagnosticObservationTime {
            sequence: count(observed.sequence),
            observed_at_epoch_micros: observed.wall.get(),
            age_millis: milliseconds(self.captured.saturating_duration_since(observed.monotonic)),
        }
    }
}

fn target(id: TargetId, generation: u64) -> DiagnosticTargetIdentity {
    DiagnosticTargetIdentity {
        target_id: DiagnosticIdentifier(crate::create_mesh_setup::format_uuid(id.as_bytes())),
        generation: count(generation),
    }
}

fn count(value: u64) -> DiagnosticCounter {
    DiagnosticCounter(value.to_string())
}

fn milliseconds(duration: Duration) -> DiagnosticCounter {
    count(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}
