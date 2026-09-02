// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AcknowledgementPolicyId, AvailabilityCellId, DurationMicros, ProtectionPolicyId,
    ProtectionScenarioId, VolumeId,
};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    AcknowledgementCellRequirement, AcknowledgementCellRole, AcknowledgementConsistencyClass,
    AssignVolumeAcknowledgementPolicy, CreateAcknowledgementPolicy, RecordName, StrongFallbackMode,
};

pub(super) const CREATE_ACKNOWLEDGEMENT_POLICY: u16 = 33;
pub(super) const ASSIGN_VOLUME_ACKNOWLEDGEMENT_POLICY: u16 = 34;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_SCENARIOS: usize = 64;
const MAXIMUM_CELLS: usize = 256;

pub(super) fn encode_create(
    encoder: &mut Encoder,
    value: &CreateAcknowledgementPolicy,
) -> Result<(), MetadataCommandCodecError> {
    if value.required_scenarios.len() > MAXIMUM_SCENARIOS || value.cells.len() > MAXIMUM_CELLS {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    encoder.u16(CREATE_ACKNOWLEDGEMENT_POLICY)?;
    encoder.identifier(value.policy_id.as_bytes())?;
    encoder.text(value.name.display(), MAXIMUM_NAME_BYTES)?;
    encoder.u8(value.consistency as u8)?;
    encoder.u16(value.minimum_durable_targets)?;
    encoder.u16(value.minimum_distinct_nodes)?;
    encoder.optional_u64(value.strong_wait.map(DurationMicros::get))?;
    encoder.u8(value.fallback as u8)?;
    encoder.u16(
        u16::try_from(value.required_scenarios.len())
            .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
    )?;
    for scenario_id in value.required_scenarios.as_slice() {
        encoder.identifier(scenario_id.as_bytes())?;
    }
    encoder.u16(
        u16::try_from(value.cells.len())
            .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
    )?;
    for cell in value.cells.as_slice() {
        encode_cell(encoder, *cell)?;
    }
    Ok(())
}

fn encode_cell(
    encoder: &mut Encoder,
    value: AcknowledgementCellRequirement,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.cell_id.as_bytes())?;
    encoder.u8(value.role as u8)?;
    encoder.optional_u64(value.minimum_durable_targets.map(u64::from))?;
    encoder.optional_u64(value.minimum_distinct_nodes.map(u64::from))?;
    encoder.optional_fixed_16(
        value
            .local_protection_policy_id
            .map(ProtectionPolicyId::as_bytes),
    )
}

pub(super) fn decode_create(
    decoder: &mut Decoder<'_>,
) -> Result<CreateAcknowledgementPolicy, MetadataCommandCodecError> {
    let policy_id = AcknowledgementPolicyId::from_bytes(decoder.identifier()?)?;
    let name = RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)?;
    let consistency = decode_consistency(decoder.u8()?)?;
    let minimum_durable_targets = decoder.u16()?;
    let minimum_distinct_nodes = decoder.u16()?;
    let strong_wait = decoder.optional_u64()?.map(DurationMicros::new);
    let fallback = decode_fallback(decoder.u8()?)?;
    let scenario_count = usize::from(decoder.u16()?);
    if scenario_count > MAXIMUM_SCENARIOS {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut scenarios = Vec::with_capacity(scenario_count);
    for _ in 0..scenario_count {
        scenarios.push(ProtectionScenarioId::from_bytes(decoder.identifier()?)?);
    }
    let cell_count = usize::from(decoder.u16()?);
    if cell_count > MAXIMUM_CELLS {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut cells = Vec::with_capacity(cell_count);
    for _ in 0..cell_count {
        cells.push(decode_cell(decoder)?);
    }
    Ok(CreateAcknowledgementPolicy {
        policy_id,
        name,
        consistency,
        minimum_durable_targets,
        minimum_distinct_nodes,
        strong_wait,
        fallback,
        required_scenarios: BoundedItems::new(scenarios, MAXIMUM_SCENARIOS)?,
        cells: BoundedItems::new(cells, MAXIMUM_CELLS)?,
    })
}

fn decode_cell(
    decoder: &mut Decoder<'_>,
) -> Result<AcknowledgementCellRequirement, MetadataCommandCodecError> {
    Ok(AcknowledgementCellRequirement {
        cell_id: AvailabilityCellId::from_bytes(decoder.identifier()?)?,
        role: decode_cell_role(decoder.u8()?)?,
        minimum_durable_targets: optional_u16(decoder.optional_u64()?)?,
        minimum_distinct_nodes: optional_u16(decoder.optional_u64()?)?,
        local_protection_policy_id: decoder
            .optional_fixed_16()?
            .map(ProtectionPolicyId::from_bytes)
            .transpose()?,
    })
}

pub(super) fn encode_assignment(
    encoder: &mut Encoder,
    value: AssignVolumeAcknowledgementPolicy,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(ASSIGN_VOLUME_ACKNOWLEDGEMENT_POLICY)?;
    encoder.identifier(value.volume_id.as_bytes())?;
    encoder.identifier(value.policy_id.as_bytes())
}

pub(super) fn decode_assignment(
    decoder: &mut Decoder<'_>,
) -> Result<AssignVolumeAcknowledgementPolicy, MetadataCommandCodecError> {
    Ok(AssignVolumeAcknowledgementPolicy {
        volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
        policy_id: AcknowledgementPolicyId::from_bytes(decoder.identifier()?)?,
    })
}

fn decode_consistency(
    value: u8,
) -> Result<AcknowledgementConsistencyClass, MetadataCommandCodecError> {
    match value {
        1 => Ok(AcknowledgementConsistencyClass::Eventual),
        2 => Ok(AcknowledgementConsistencyClass::Strong),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}

fn decode_fallback(value: u8) -> Result<StrongFallbackMode, MetadataCommandCodecError> {
    match value {
        1 => Ok(StrongFallbackMode::RemainPending),
        2 => Ok(StrongFallbackMode::FailAtDeadline),
        3 => Ok(StrongFallbackMode::Eventual),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}

fn decode_cell_role(value: u8) -> Result<AcknowledgementCellRole, MetadataCommandCodecError> {
    match value {
        1 => Ok(AcknowledgementCellRole::RequiredBeforeCommit),
        2 => Ok(AcknowledgementCellRole::Eventual),
        3 => Ok(AcknowledgementCellRole::Excluded),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}

fn optional_u16(value: Option<u64>) -> Result<Option<u16>, MetadataCommandCodecError> {
    value
        .map(|value| u16::try_from(value).map_err(|_| MetadataCommandCodecError::Invalid))
        .transpose()
}
