// SPDX-License-Identifier: GPL-2.0-only

use super::RuntimeObservations;
use meshspan_contracts::{
    CodingMetric, CodingOperation, ContractError, LatencyHistogram, RuntimeMetric,
};
use std::time::Duration;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct CodingMeasurements {
    failures: u64,
    input: u64,
    output: u64,
    missing_data: u64,
    duration: LatencyHistogram,
}

#[derive(Clone, Copy)]
pub(crate) struct CodingObservation {
    pub(crate) kind: CodingOperation,
    pub(crate) failed: bool,
    pub(crate) input_bytes: Option<u64>,
    pub(crate) output_bytes: Option<u64>,
    pub(crate) missing_data: bool,
    pub(crate) duration: Duration,
}

impl CodingMeasurements {
    fn record(&mut self, value: CodingObservation) -> Result<(), ContractError> {
        let add = |old: u64, increment: Option<u64>| {
            increment
                .and_then(|increment| old.checked_add(increment))
                .ok_or(ContractError::ResourceExhausted)
        };
        let failures = add(self.failures, Some(u64::from(value.failed)))?;
        let input = add(self.input, value.input_bytes)?;
        let output = add(self.output, value.output_bytes)?;
        let missing_data = add(self.missing_data, Some(u64::from(value.missing_data)))?;
        self.duration.observe(value.duration)?;
        self.failures = failures;
        self.input = input;
        self.output = output;
        self.missing_data = missing_data;
        Ok(())
    }

    pub(super) fn append_metrics(&self, kind: CodingOperation, samples: &mut Vec<RuntimeMetric>) {
        samples.extend(
            [
                CodingMetric::Calls(self.duration.count),
                CodingMetric::Failures(self.failures),
                CodingMetric::InputBytes(self.input),
                CodingMetric::OutputBytes(self.output),
                CodingMetric::MissingDataCalls(self.missing_data),
                CodingMetric::Duration(self.duration.clone()),
            ]
            .map(|value| RuntimeMetric::Coding(kind, value)),
        );
    }
}

impl RuntimeObservations {
    pub(crate) fn observe_coding(&self, observation: CodingObservation) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        let [encode, reconstruct] = &mut state.coding;
        let measurements = match observation.kind {
            CodingOperation::Encode => encode,
            CodingOperation::Reconstruct => reconstruct,
        };
        if measurements.record(observation).is_err() {
            self.drop_update();
        }
    }
}
