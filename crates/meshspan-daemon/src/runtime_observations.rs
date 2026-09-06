// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, best-effort process-local evidence; never consulted for storage authority.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use meshspan_contracts::LatencyHistogram;
use meshspan_domain::{TargetId, UnixMicros};

const WINDOW_ITEMS: usize = 100;

/// Replaceable read-only observation source. Implementations must not perform provider IO.
pub(crate) trait RuntimeObservationSource: Send + Sync {
    fn snapshot(&self) -> Option<RuntimeSnapshot>;
}

#[derive(Clone)]
pub(crate) struct RuntimeObservations(Arc<ObservationOwner>);

struct ObservationOwner {
    started: Instant,
    state: Mutex<ObservationState>,
    dropped: AtomicU64,
}

#[derive(Clone, Default)]
struct ObservationState {
    sequence: u64,
    target_evictions: u64,
    event_evictions: u64,
    cycles: u64,
    failed_cycles: u64,
    passed_probes: u64,
    failed_probes: u64,
    cycle_duration: LatencyHistogram,
    probe_duration: LatencyHistogram,
    cycle: Option<StorageCycleObservation>,
    targets: BTreeMap<(TargetId, u64), TargetCheckObservation>,
    events: VecDeque<RuntimeEvent>,
}

pub(crate) struct RuntimeSnapshot {
    pub captured: Instant,
    pub uptime: Duration,
    pub dropped: u64,
    state: ObservationState,
}

#[derive(Clone, Copy)]
pub(crate) struct ObservationTime {
    pub sequence: u64,
    pub wall: UnixMicros,
    pub monotonic: Instant,
}

#[derive(Clone)]
pub(crate) struct TargetCheckObservation {
    pub target: TargetId,
    pub generation: u64,
    pub observation: ObservationTime,
    pub duration: Duration,
    pub passed: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct StorageCycleSummary {
    pub configured_folders: usize,
    pub open_targets: usize,
    pub pending_return_scans: usize,
    pub failed_steps: usize,
}

#[derive(Clone)]
pub(crate) struct StorageCycleObservation {
    pub observation: ObservationTime,
    pub duration: Duration,
    pub summary: StorageCycleSummary,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RuntimeEventCode {
    TargetProbeFailed,
    TargetProbeRecovered,
    StorageReconciliationFailed,
    StorageReconciliationRecovered,
}

#[derive(Clone)]
pub(crate) struct RuntimeEvent {
    pub observation: ObservationTime,
    pub code: RuntimeEventCode,
    pub target: Option<(TargetId, u64)>,
}

impl Default for RuntimeObservations {
    fn default() -> Self {
        Self(Arc::new(ObservationOwner {
            started: Instant::now(),
            state: Mutex::new(ObservationState::default()),
            dropped: AtomicU64::new(0),
        }))
    }
}

impl RuntimeObservations {
    pub(crate) fn record_probe(
        &self,
        target: (TargetId, u64),
        passed: bool,
        duration: Duration,
        completed_at: Option<UnixMicros>,
    ) {
        if target.1 == 0 {
            self.drop_update();
            return;
        }
        self.update(completed_at, |state, observation| {
            state.probe_duration.observe(duration).map_err(|_| ())?;
            let previous = state.targets.get(&target).map(|check| check.passed);
            if previous != Some(passed) && (!passed || previous == Some(false)) {
                state.event(RuntimeEvent {
                    observation,
                    code: if passed {
                        RuntimeEventCode::TargetProbeRecovered
                    } else {
                        RuntimeEventCode::TargetProbeFailed
                    },
                    target: Some(target),
                });
            }
            if !state.targets.contains_key(&target) && state.targets.len() == WINDOW_ITEMS {
                let oldest = state
                    .targets
                    .iter()
                    .min_by_key(|(_, check)| check.observation.sequence)
                    .map(|(key, _)| *key);
                if let Some(oldest) = oldest {
                    state.targets.remove(&oldest);
                    state.target_evictions = state.target_evictions.saturating_add(1);
                }
            }
            state.targets.insert(
                target,
                TargetCheckObservation {
                    target: target.0,
                    generation: target.1,
                    observation,
                    duration,
                    passed,
                },
            );
            let count = if passed {
                &mut state.passed_probes
            } else {
                &mut state.failed_probes
            };
            *count = count.saturating_add(1);
            Ok(())
        });
    }

    pub(crate) fn record_cycle(
        &self,
        summary: StorageCycleSummary,
        duration: Duration,
        completed_at: Option<UnixMicros>,
    ) {
        self.update(completed_at, |state, observation| {
            state.cycle_duration.observe(duration).map_err(|_| ())?;
            let failed = summary.failed_steps > 0;
            let previous = state
                .cycle
                .as_ref()
                .map(|cycle| cycle.summary.failed_steps > 0);
            if previous != Some(failed) && (failed || previous == Some(true)) {
                state.event(RuntimeEvent {
                    observation,
                    code: if failed {
                        RuntimeEventCode::StorageReconciliationFailed
                    } else {
                        RuntimeEventCode::StorageReconciliationRecovered
                    },
                    target: None,
                });
            }
            state.cycles = state.cycles.saturating_add(1);
            if failed {
                state.failed_cycles = state.failed_cycles.saturating_add(1);
            }
            state.cycle = Some(StorageCycleObservation {
                observation,
                duration,
                summary,
            });
            Ok(())
        });
    }

    fn update(
        &self,
        at: Option<UnixMicros>,
        apply: impl FnOnce(&mut ObservationState, ObservationTime) -> Result<(), ()>,
    ) {
        let Some(wall) = at.filter(|at| (0..=9_007_199_254_740_991).contains(&at.get())) else {
            self.drop_update();
            return;
        };
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        let Some(sequence) = state.sequence.checked_add(1) else {
            self.drop_update();
            return;
        };
        if apply(
            &mut state,
            ObservationTime {
                sequence,
                wall,
                monotonic: Instant::now(),
            },
        )
        .is_err()
        {
            self.drop_update();
            return;
        }
        state.sequence = sequence;
    }

    fn drop_update(&self) {
        let _previous =
            self.0
                .dropped
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                    Some(count.saturating_add(1))
                });
    }
}

impl RuntimeObservationSource for RuntimeObservations {
    fn snapshot(&self) -> Option<RuntimeSnapshot> {
        let state = self.0.state.try_lock().ok()?.clone();
        let captured = Instant::now();
        Some(RuntimeSnapshot {
            captured,
            uptime: captured.saturating_duration_since(self.0.started),
            dropped: self.0.dropped.load(Ordering::Relaxed),
            state,
        })
    }
}

impl ObservationState {
    fn event(&mut self, event: RuntimeEvent) {
        if self.events.len() == WINDOW_ITEMS {
            self.events.pop_front();
            self.event_evictions = self.event_evictions.saturating_add(1);
        }
        self.events.push_back(event);
    }
}

#[path = "runtime_observations_projection.rs"]
mod projection;

#[path = "runtime_observations_metrics.rs"]
mod metrics;

#[cfg(test)]
#[path = "runtime_observations_tests.rs"]
mod tests;
