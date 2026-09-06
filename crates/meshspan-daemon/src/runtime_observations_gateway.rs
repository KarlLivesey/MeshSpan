// SPDX-License-Identifier: GPL-2.0-only

//! Constant-space gateway distributions; observation loss never changes dispatch behaviour.

use meshspan_contracts::{
    ContractError, GatewayDispatchObservation, GatewayDispatchObserver, GatewayDispatchOutcome,
    GatewayProtocol, LatencyHistogram,
};

use super::RuntimeObservations;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct GatewayMeasurements {
    pub(super) duration: LatencyHistogram,
    pub(super) failures: u64,
    pub(super) cancelled: u64,
}

impl GatewayMeasurements {
    fn record(&mut self, observation: GatewayDispatchObservation) -> Result<(), ContractError> {
        let failures = self
            .failures
            .checked_add(u64::from(
                observation.outcome == GatewayDispatchOutcome::Failed,
            ))
            .ok_or(ContractError::ResourceExhausted)?;
        let cancelled = self
            .cancelled
            .checked_add(u64::from(
                observation.outcome == GatewayDispatchOutcome::Cancelled,
            ))
            .ok_or(ContractError::ResourceExhausted)?;
        // Histogram addition is itself all-or-nothing. Commit the other counters only after it.
        self.duration.observe(observation.duration)?;
        self.failures = failures;
        self.cancelled = cancelled;
        Ok(())
    }
}

impl GatewayDispatchObserver for RuntimeObservations {
    fn observe_dispatch(&self, observation: GatewayDispatchObservation) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        let measurements = match observation.protocol {
            GatewayProtocol::Https => &mut state.https,
            GatewayProtocol::Smb => &mut state.smb,
        };
        if measurements.record(observation).is_err() {
            self.drop_update();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn gateway_totals_keep_exact_distributions_and_overflow_is_atomic() -> Result<(), ContractError>
    {
        let mut measurements = GatewayMeasurements::default();
        for (outcome, duration) in [
            (GatewayDispatchOutcome::Returned, Duration::from_millis(1)),
            (GatewayDispatchOutcome::Failed, Duration::from_millis(6)),
            (GatewayDispatchOutcome::Cancelled, Duration::from_secs(31)),
        ] {
            measurements.record(GatewayDispatchObservation {
                protocol: GatewayProtocol::Https,
                outcome,
                duration,
            })?;
        }
        assert_eq!((measurements.failures, measurements.cancelled), (1, 1));
        assert_eq!(measurements.duration.count, 3);
        assert_eq!(measurements.duration.buckets, [1, 1, 2, 2, 2, 2, 2, 2]);
        assert_eq!(measurements.duration.sum, Duration::from_millis(31_007));
        measurements.duration.count = u64::MAX;
        let before = measurements.clone();
        assert!(
            measurements
                .record(GatewayDispatchObservation {
                    protocol: GatewayProtocol::Https,
                    outcome: GatewayDispatchOutcome::Failed,
                    duration: Duration::from_millis(1),
                })
                .is_err()
        );
        assert_eq!(measurements, before);
        Ok(())
    }

    #[test]
    fn observation_contention_drops_only_metrics_without_waiting()
    -> Result<(), Box<dyn std::error::Error>> {
        let observations = RuntimeObservations::default();
        let state = observations
            .0
            .state
            .lock()
            .map_err(|_| "poisoned observation lock")?;
        observations.observe_dispatch(GatewayDispatchObservation {
            protocol: GatewayProtocol::Smb,
            outcome: GatewayDispatchOutcome::Returned,
            duration: Duration::ZERO,
        });
        assert_eq!(state.smb.duration.count, 0);
        assert_eq!(
            observations
                .0
                .dropped
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        Ok(())
    }
}
