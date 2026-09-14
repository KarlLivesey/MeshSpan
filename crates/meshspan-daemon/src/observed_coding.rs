// SPDX-License-Identifier: GPL-2.0-only

//! Composition-only observation of a replaceable coding engine; results remain unchanged.

use crate::runtime_observations::{CodingObservation, RuntimeObservations};
use meshspan_contracts::{
    BoundedBytes, BoundedItems, CodingLayout, CodingOperation, CodingScheme,
    ComponentConfiguration, ComponentLifecycle, ComponentObservation, ComponentTransition,
    ContractError, ImplementationDescriptor, ReconstructionRequest, RequestContext,
};
use meshspan_domain::{Revision, UnixMicros};
use std::time::Instant;

pub(crate) struct ObservedCoding<Coding> {
    inner: Coding,
    observations: RuntimeObservations,
}

impl<Coding> ObservedCoding<Coding> {
    pub(crate) const fn new(inner: Coding, observations: RuntimeObservations) -> Self {
        Self {
            inner,
            observations,
        }
    }
}

impl<Coding: CodingScheme> CodingScheme for ObservedCoding<Coding> {
    fn encode(
        &self,
        context: RequestContext,
        layout: CodingLayout,
        bytes: &BoundedBytes,
    ) -> Result<BoundedItems<BoundedBytes>, ContractError> {
        let started = Instant::now();
        let result = self.inner.encode(context, layout, bytes);
        let duration = started.elapsed();
        let output_bytes = match &result {
            Ok(output) => byte_count(output.as_slice().iter()),
            Err(_) => Some(0),
        };
        self.observations.observe_coding(CodingObservation {
            kind: CodingOperation::Encode,
            failed: result.is_err(),
            input_bytes: Some(bytes.len() as u64),
            output_bytes,
            missing_data: false,
            duration,
        });
        result
    }

    fn reconstruct(&self, request: &ReconstructionRequest) -> Result<BoundedBytes, ContractError> {
        let started = Instant::now();
        let result = self.inner.reconstruct(request);
        let duration = started.elapsed();
        let originals = request
            .available_slices
            .as_slice()
            .get(..usize::from(request.layout.data_slices()));
        let missing_data = originals.is_none_or(|slices| slices.iter().any(Option::is_none));
        self.observations.observe_coding(CodingObservation {
            kind: CodingOperation::Reconstruct,
            failed: result.is_err(),
            input_bytes: byte_count(request.available_slices.as_slice().iter().flatten()),
            output_bytes: Some(result.as_ref().map_or(0, |bytes| bytes.len() as u64)),
            missing_data,
            duration,
        });
        result
    }
}

fn byte_count<'a>(bytes: impl Iterator<Item = &'a BoundedBytes>) -> Option<u64> {
    bytes
        .map(|bytes| bytes.len() as u64)
        .try_fold(0_u64, u64::checked_add)
}

impl<Coding: ComponentLifecycle> ComponentLifecycle for ObservedCoding<Coding> {
    fn describe(&self) -> ImplementationDescriptor {
        self.inner.describe()
    }
    fn validate_configuration(
        &self,
        configuration: &ComponentConfiguration,
    ) -> Result<(), ContractError> {
        self.inner.validate_configuration(configuration)
    }
    fn prepare(
        &mut self,
        configuration: &ComponentConfiguration,
    ) -> Result<ComponentTransition, ContractError> {
        self.inner.prepare(configuration)
    }
    fn activate(&mut self, revision: Revision) -> Result<ComponentTransition, ContractError> {
        self.inner.activate(revision)
    }
    fn drain(&mut self, deadline: UnixMicros) -> Result<ComponentTransition, ContractError> {
        self.inner.drain(deadline)
    }
    fn retire(&mut self, revision: Revision) -> Result<ComponentTransition, ContractError> {
        self.inner.retire(revision)
    }
    fn observe(&self, now: UnixMicros) -> ComponentObservation {
        self.inner.observe(now)
    }
}

#[cfg(test)]
#[path = "observed_coding_tests.rs"]
mod tests;
