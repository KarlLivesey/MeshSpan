// SPDX-License-Identifier: GPL-2.0-only

//! Constant-space gateway distributions; observation loss never changes dispatch behaviour.

use meshspan_contracts::{
    ContractError, GatewayDispatchObservation, GatewayDispatchObserver, GatewayDispatchOutcome,
    GatewayProtocol, LatencyHistogram,
};

use super::RuntimeObservations;

impl RuntimeObservations {
    /// Counts a credential rejection only, without changing dispatch counts or waiting for IO.
    pub(crate) fn record_smb_authentication_rejection(&self) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        if let Some(next) = state.smb_authentication_rejections.checked_add(1) {
            state.smb_authentication_rejections = next;
        } else {
            self.drop_update();
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct GatewayMeasurements {
    pub(super) transfer: [u64; 4],
    pub(super) duration: LatencyHistogram,
    pub(super) failures: u64,
    pub(super) cancelled: u64,
    pub(super) authentication_required: u64,
    pub(super) forbidden: u64,
}

impl meshspan_contracts::GatewayTransferObserver for RuntimeObservations {
    fn observe_transfer(
        &self,
        protocol: GatewayProtocol,
        increment: meshspan_contracts::GatewayTransferMetric,
    ) {
        use meshspan_contracts::GatewayTransferMetric;
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        let measurements = match protocol {
            GatewayProtocol::Https => &mut state.https,
            GatewayProtocol::Smb => &mut state.smb,
        };
        let [received, sent, read_errors, write_errors] = &mut measurements.transfer;
        let (counter, increment) = match increment {
            GatewayTransferMetric::ReceivedBytes(value) => (received, value),
            GatewayTransferMetric::SentBytes(value) => (sent, value),
            GatewayTransferMetric::ReadErrors(value) => (read_errors, value),
            GatewayTransferMetric::WriteErrors(value) => (write_errors, value),
        };
        if let Some(value) = counter.checked_add(increment) {
            *counter = value;
        } else {
            self.drop_update();
        }
    }
}

impl GatewayMeasurements {
    pub(super) fn append_transfer(
        &self,
        protocol: GatewayProtocol,
        samples: &mut Vec<meshspan_contracts::RuntimeMetric>,
    ) {
        use meshspan_contracts::{GatewayTransferMetric, RuntimeMetric};
        let [received, sent, read_errors, write_errors] = self.transfer;
        samples.extend(
            [
                GatewayTransferMetric::ReceivedBytes(received),
                GatewayTransferMetric::SentBytes(sent),
                GatewayTransferMetric::ReadErrors(read_errors),
                GatewayTransferMetric::WriteErrors(write_errors),
            ]
            .map(|metric| RuntimeMetric::GatewayTransfer(protocol, metric)),
        );
    }
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
        let authentication_required = self
            .authentication_required
            .checked_add(u64::from(
                observation.outcome == GatewayDispatchOutcome::AuthenticationRequired,
            ))
            .ok_or(ContractError::ResourceExhausted)?;
        let forbidden = self
            .forbidden
            .checked_add(u64::from(
                observation.outcome == GatewayDispatchOutcome::Forbidden,
            ))
            .ok_or(ContractError::ResourceExhausted)?;
        // Histogram addition is itself all-or-nothing. Commit the other counters only after it.
        self.duration.observe(observation.duration)?;
        self.failures = failures;
        self.cancelled = cancelled;
        self.authentication_required = authentication_required;
        self.forbidden = forbidden;
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
