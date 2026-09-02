// SPDX-License-Identifier: GPL-2.0-only

//! Bounded systematic Reed-Solomon coding behind the replaceable `MeshSpan` contract.

use meshspan_contracts::{
    BoundedBytes, BoundedItems, CodingLayout, CodingScheme, ComponentConfiguration,
    ComponentLifecycle, ComponentObservation, ComponentTransition, ContractError, ContractKind,
    ContractLimits, ContractVersion, ImplementationDescriptor, ReconstructionRequest,
    RequestContext,
};
use meshspan_domain::{LifecycleState, Revision, UnixMicros};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

const CONTRACT_VERSIONS: &[ContractVersion] = &[ContractVersion::V1_0];
const MAXIMUM_CONTROL_BYTES: usize = 4_096;
const MAXIMUM_SLICES: usize = 24;
const MAXIMUM_SLICE_BYTES: usize = 8 * 1_024 * 1_024;

/// Systematic Reed-Solomon implementation with an explicitly bounded stripe working set.
#[derive(Clone, Copy, Debug)]
pub struct ReedSolomonCoding {
    lifecycle: LifecycleState,
    prepared_revision: Option<Revision>,
    active_revision: Revision,
}

impl Default for ReedSolomonCoding {
    fn default() -> Self {
        Self {
            lifecycle: LifecycleState::Active,
            prepared_revision: None,
            active_revision: Revision::ZERO,
        }
    }
}

impl ReedSolomonCoding {
    /// Creates the compiled coding engine in its active built-in configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn validate_layout(layout: CodingLayout) -> Result<(usize, usize, usize), ContractError> {
        let data = usize::from(layout.data_slices());
        let recovery = usize::from(layout.recovery_slices());
        let slice_bytes =
            usize::try_from(layout.slice_bytes()).map_err(|_| ContractError::InvalidInput)?;
        if data == 0
            || data
                .checked_add(recovery)
                .is_none_or(|total| total > MAXIMUM_SLICES)
            || slice_bytes == 0
            || slice_bytes > MAXIMUM_SLICE_BYTES
            || (recovery != 0 && !ReedSolomonEncoder::supports(data, recovery))
        {
            return Err(ContractError::InvalidInput);
        }
        Ok((data, recovery, slice_bytes))
    }

    fn require_active(&self) -> Result<(), ContractError> {
        if self.lifecycle == LifecycleState::Active {
            Ok(())
        } else {
            Err(ContractError::Unavailable)
        }
    }
}

impl ComponentLifecycle for ReedSolomonCoding {
    fn describe(&self) -> ImplementationDescriptor {
        ImplementationDescriptor {
            implementation_id: "reed-solomon-simd",
            contract: ContractKind::CodingScheme,
            versions: CONTRACT_VERSIONS,
            limits: ContractLimits {
                maximum_control_bytes: MAXIMUM_CONTROL_BYTES,
                maximum_items: MAXIMUM_SLICES,
                maximum_concurrency: 1,
            },
        }
    }

    fn validate_configuration(
        &self,
        configuration: &ComponentConfiguration,
    ) -> Result<(), ContractError> {
        if configuration.schema_version == 1
            && configuration.desired_revision != Revision::ZERO
            && configuration.canonical_bytes.is_empty()
        {
            Ok(())
        } else {
            Err(ContractError::InvalidInput)
        }
    }

    fn prepare(
        &mut self,
        configuration: &ComponentConfiguration,
    ) -> Result<ComponentTransition, ContractError> {
        self.validate_configuration(configuration)?;
        if configuration.desired_revision == self.active_revision {
            return Ok(ComponentTransition::Active);
        }
        self.prepared_revision = Some(configuration.desired_revision);
        Ok(ComponentTransition::Ready)
    }

    fn activate(
        &mut self,
        desired_revision: Revision,
    ) -> Result<ComponentTransition, ContractError> {
        if desired_revision == self.active_revision && self.lifecycle == LifecycleState::Active {
            return Ok(ComponentTransition::Active);
        }
        if self.prepared_revision != Some(desired_revision)
            || self.lifecycle == LifecycleState::Retired
        {
            return Err(ContractError::Stale);
        }
        self.active_revision = desired_revision;
        self.prepared_revision = None;
        self.lifecycle = LifecycleState::Active;
        Ok(ComponentTransition::Active)
    }

    fn drain(&mut self, _deadline: UnixMicros) -> Result<ComponentTransition, ContractError> {
        if self.lifecycle == LifecycleState::Retired {
            return Err(ContractError::Stale);
        }
        self.lifecycle = LifecycleState::Draining;
        Ok(ComponentTransition::Ready)
    }

    fn retire(&mut self, desired_revision: Revision) -> Result<ComponentTransition, ContractError> {
        if desired_revision != self.active_revision || self.lifecycle != LifecycleState::Draining {
            return Err(ContractError::Stale);
        }
        self.lifecycle = LifecycleState::Retired;
        Ok(ComponentTransition::Active)
    }

    fn observe(&self, observed_at: UnixMicros) -> ComponentObservation {
        ComponentObservation {
            desired_revision: self.prepared_revision.unwrap_or(self.active_revision),
            lifecycle: self.lifecycle,
            observed_at,
        }
    }
}

impl CodingScheme for ReedSolomonCoding {
    fn encode(
        &self,
        context: RequestContext,
        layout: CodingLayout,
        logical_bytes: &BoundedBytes,
    ) -> Result<BoundedItems<BoundedBytes>, ContractError> {
        self.require_active()?;
        validate_context(context)?;
        let (data_count, recovery_count, slice_bytes) = Self::validate_layout(layout)?;
        let capacity = data_count
            .checked_mul(slice_bytes)
            .ok_or(ContractError::InvalidInput)?;
        if logical_bytes.is_empty() || logical_bytes.len() > capacity {
            return Err(ContractError::InvalidInput);
        }

        let mut padded = vec![0_u8; capacity];
        padded[..logical_bytes.len()].copy_from_slice(logical_bytes.as_slice());
        let mut slices = padded
            .chunks_exact(slice_bytes)
            .map(|slice| BoundedBytes::copy_from(slice, slice_bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ContractError::InternalContract)?;
        if recovery_count != 0 {
            let mut encoder = ReedSolomonEncoder::new(data_count, recovery_count, slice_bytes)
                .map_err(|_| ContractError::InvalidInput)?;
            for original in &slices {
                encoder
                    .add_original_shard(original.as_slice())
                    .map_err(|_| ContractError::InvalidInput)?;
            }
            let recovery_result = encoder
                .encode()
                .map_err(|_| ContractError::InternalContract)?;
            for recovery in recovery_result.recovery_iter() {
                slices.push(
                    BoundedBytes::copy_from(recovery, slice_bytes)
                        .map_err(|_| ContractError::InternalContract)?,
                );
            }
        }
        BoundedItems::new(slices, MAXIMUM_SLICES).map_err(|_| ContractError::InternalContract)
    }

    fn reconstruct(&self, request: &ReconstructionRequest) -> Result<BoundedBytes, ContractError> {
        self.require_active()?;
        validate_context(request.context)?;
        let (data_count, recovery_count, slice_bytes) = Self::validate_layout(request.layout)?;
        let total_count = data_count + recovery_count;
        if request.available_slices.len() != total_count
            || request.slice_digests.len() != total_count
        {
            return Err(ContractError::InvalidInput);
        }
        let logical_length =
            usize::try_from(request.logical_length).map_err(|_| ContractError::InvalidInput)?;
        let capacity = data_count
            .checked_mul(slice_bytes)
            .ok_or(ContractError::InvalidInput)?;
        if logical_length == 0 || logical_length > capacity {
            return Err(ContractError::InvalidInput);
        }

        let verified = verified_slices(request, slice_bytes)?;
        if verified.iter().filter(|slice| slice.is_some()).count() < data_count {
            return Err(ContractError::Corrupt);
        }
        let originals = recover_originals(&verified, data_count, recovery_count, slice_bytes)?;
        let mut logical = Vec::with_capacity(capacity);
        for original in originals {
            logical.extend_from_slice(&original);
        }
        logical.truncate(logical_length);
        if blake3::hash(&logical).as_bytes() != &request.logical_digest {
            return Err(ContractError::Corrupt);
        }
        BoundedBytes::from_vec(logical, capacity).map_err(|_| ContractError::InternalContract)
    }
}

fn validate_context(context: RequestContext) -> Result<(), ContractError> {
    if context.contract_version != ContractVersion::V1_0 || context.deadline.get() == 0 {
        Err(ContractError::InvalidInput)
    } else {
        Ok(())
    }
}

fn verified_slices(
    request: &ReconstructionRequest,
    slice_bytes: usize,
) -> Result<Vec<Option<&[u8]>>, ContractError> {
    request
        .available_slices
        .as_slice()
        .iter()
        .zip(request.slice_digests.as_slice())
        .map(|(slice, digest)| match slice {
            Some(slice) if slice.len() != slice_bytes => Err(ContractError::InvalidInput),
            Some(slice) if blake3::hash(slice.as_slice()).as_bytes() == digest => {
                Ok(Some(slice.as_slice()))
            }
            Some(_) | None => Ok(None),
        })
        .collect()
}

fn recover_originals(
    slices: &[Option<&[u8]>],
    data_count: usize,
    recovery_count: usize,
    slice_bytes: usize,
) -> Result<Vec<Vec<u8>>, ContractError> {
    if slices[..data_count].iter().all(Option::is_some) {
        return slices[..data_count]
            .iter()
            .map(|slice| {
                slice
                    .map(<[u8]>::to_vec)
                    .ok_or(ContractError::InternalContract)
            })
            .collect();
    }
    if recovery_count == 0 {
        return Err(ContractError::Corrupt);
    }
    let mut decoder = ReedSolomonDecoder::new(data_count, recovery_count, slice_bytes)
        .map_err(|_| ContractError::InvalidInput)?;
    for (index, slice) in slices.iter().enumerate() {
        let Some(slice) = slice else { continue };
        if index < data_count {
            decoder
                .add_original_shard(index, slice)
                .map_err(|_| ContractError::InvalidInput)?;
        } else {
            decoder
                .add_recovery_shard(index - data_count, slice)
                .map_err(|_| ContractError::InvalidInput)?;
        }
    }
    let reconstruction = decoder.decode().map_err(|_| ContractError::Corrupt)?;
    (0..data_count)
        .map(|index| {
            slices[index]
                .map(<[u8]>::to_vec)
                .or_else(|| reconstruction.restored_original(index).map(<[u8]>::to_vec))
                .ok_or(ContractError::InternalContract)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::{
        BoundedBytes, BoundedItems, CodingLayout, CodingScheme, ContractError, ContractVersion,
        ReconstructionRequest, RequestContext,
    };
    use meshspan_domain::{OperationId, UnixMicros};

    use super::ReedSolomonCoding;

    #[test]
    fn every_three_slice_loss_reconstructs_exact_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let coding = ReedSolomonCoding::new();
        let layout = CodingLayout::new(4, 3, 64)?;
        let logical = BoundedBytes::copy_from(&fixture_bytes(), 256)?;
        let slices = coding.encode(context(1)?, layout, &logical)?;
        let digests = slice_digests(&slices)?;

        for first in 0..7 {
            for second in (first + 1)..7 {
                for third in (second + 1)..7 {
                    let available = slices
                        .as_slice()
                        .iter()
                        .enumerate()
                        .map(|(index, slice)| {
                            (![first, second, third].contains(&index)).then(|| slice.clone())
                        })
                        .collect();
                    let reconstructed = coding.reconstruct(&ReconstructionRequest {
                        context: context(2)?,
                        layout,
                        available_slices: BoundedItems::new(available, 24)?,
                        slice_digests: digests.clone(),
                        logical_length: u64::try_from(logical.len())?,
                        logical_digest: *blake3::hash(logical.as_slice()).as_bytes(),
                    })?;
                    assert_eq!(reconstructed, logical);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn corrupt_slice_is_ignored_when_four_verified_slices_survive()
    -> Result<(), Box<dyn std::error::Error>> {
        let coding = ReedSolomonCoding::new();
        let layout = CodingLayout::new(4, 3, 64)?;
        let logical = BoundedBytes::copy_from(&fixture_bytes()[..173], 256)?;
        let slices = coding.encode(context(3)?, layout, &logical)?;
        let digests = slice_digests(&slices)?;
        let mut available = slices
            .as_slice()
            .iter()
            .cloned()
            .map(Some)
            .collect::<Vec<_>>();
        let mut corrupt = available[0]
            .take()
            .ok_or("fixture slice is unexpectedly absent")?
            .into_vec();
        corrupt[0] ^= 1;
        available[0] = Some(BoundedBytes::from_vec(corrupt, 64)?);
        available[1] = None;
        available[5] = None;

        let reconstructed = coding.reconstruct(&ReconstructionRequest {
            context: context(4)?,
            layout,
            available_slices: BoundedItems::new(available, 24)?,
            slice_digests: digests,
            logical_length: u64::try_from(logical.len())?,
            logical_digest: *blake3::hash(logical.as_slice()).as_bytes(),
        })?;
        assert_eq!(reconstructed, logical);
        Ok(())
    }

    #[test]
    fn insufficient_or_misbound_input_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let coding = ReedSolomonCoding::new();
        let layout = CodingLayout::new(2, 1, 8)?;
        let logical = BoundedBytes::copy_from(b"exact bytes", 16)?;
        let slices = coding.encode(context(5)?, layout, &logical)?;
        let digests = slice_digests(&slices)?;
        let available =
            BoundedItems::new(vec![Some(slices.as_slice()[0].clone()), None, None], 24)?;
        let request = ReconstructionRequest {
            context: context(6)?,
            layout,
            available_slices: available,
            slice_digests: digests.clone(),
            logical_length: u64::try_from(logical.len())?,
            logical_digest: *blake3::hash(logical.as_slice()).as_bytes(),
        };
        assert_eq!(coding.reconstruct(&request), Err(ContractError::Corrupt));

        let mut wrong_digest = request;
        let mut changed = wrong_digest.slice_digests.into_inner();
        changed[0][0] ^= 1;
        wrong_digest.slice_digests = BoundedItems::new(changed, 24)?;
        assert_eq!(
            coding.reconstruct(&wrong_digest),
            Err(ContractError::Corrupt)
        );
        Ok(())
    }

    fn context(value: u8) -> Result<RequestContext, Box<dyn std::error::Error>> {
        Ok(RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([value; 16])?,
            deadline: UnixMicros::new(1),
            expected_revision: None,
        })
    }

    fn fixture_bytes() -> Vec<u8> {
        (0_u8..=255).collect()
    }

    fn slice_digests(
        slices: &BoundedItems<BoundedBytes>,
    ) -> Result<BoundedItems<[u8; 32]>, Box<dyn std::error::Error>> {
        Ok(BoundedItems::new(
            slices
                .as_slice()
                .iter()
                .map(|slice| *blake3::hash(slice.as_slice()).as_bytes())
                .collect(),
            24,
        )?)
    }
}
