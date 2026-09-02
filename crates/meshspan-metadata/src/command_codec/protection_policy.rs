// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    FailureScenario, FailureTerm, FaultGroupClassId, ProtectionPolicyId, ProtectionScenarioId,
    VolumeId,
};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    AssignVolumeProtectionPolicy, CreateProtectionPolicy, ProtectionScenarioConfiguration,
    RecordName,
};

pub(super) const CREATE_PROTECTION_POLICY: u16 = 26;
pub(super) const ASSIGN_VOLUME_PROTECTION_POLICY: u16 = 27;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_SCENARIOS: usize = 16;
const MAXIMUM_TERMS_PER_SCENARIO: usize = 16;

pub(super) fn encode_create(
    encoder: &mut Encoder,
    value: &CreateProtectionPolicy,
) -> Result<(), MetadataCommandCodecError> {
    if value.scenarios.is_empty() || value.scenarios.len() > MAXIMUM_SCENARIOS {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.u16(CREATE_PROTECTION_POLICY)?;
    encoder.identifier(value.policy_id.as_bytes())?;
    encoder.text(value.name.display(), MAXIMUM_NAME_BYTES)?;
    encoder.u16(
        u16::try_from(value.scenarios.len())
            .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
    )?;
    for scenario in value.scenarios.as_slice() {
        encode_scenario(encoder, scenario)?;
    }
    Ok(())
}

fn encode_scenario(
    encoder: &mut Encoder,
    value: &ProtectionScenarioConfiguration,
) -> Result<(), MetadataCommandCodecError> {
    let terms = value.scenario.terms();
    if terms.is_empty() || terms.len() > MAXIMUM_TERMS_PER_SCENARIO {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.identifier(value.scenario_id.as_bytes())?;
    encoder.text(value.name.display(), MAXIMUM_NAME_BYTES)?;
    encoder.u16(
        u16::try_from(terms.len()).map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
    )?;
    for term in terms {
        encoder.identifier(term.class_id.as_bytes())?;
        encoder.u16(term.failure_count)?;
    }
    Ok(())
}

pub(super) fn decode_create(
    decoder: &mut Decoder<'_>,
) -> Result<CreateProtectionPolicy, MetadataCommandCodecError> {
    let policy_id = ProtectionPolicyId::from_bytes(decoder.identifier()?)?;
    let name = RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)?;
    let count = usize::from(decoder.u16()?);
    if count == 0 || count > MAXIMUM_SCENARIOS {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let mut scenarios = Vec::with_capacity(count);
    for _ in 0..count {
        scenarios.push(decode_scenario(decoder)?);
    }
    Ok(CreateProtectionPolicy {
        policy_id,
        name,
        scenarios: BoundedItems::new(scenarios, MAXIMUM_SCENARIOS)?,
    })
}

fn decode_scenario(
    decoder: &mut Decoder<'_>,
) -> Result<ProtectionScenarioConfiguration, MetadataCommandCodecError> {
    let scenario_id = ProtectionScenarioId::from_bytes(decoder.identifier()?)?;
    let name = RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)?;
    let count = usize::from(decoder.u16()?);
    if count == 0 || count > MAXIMUM_TERMS_PER_SCENARIO {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let mut terms = Vec::with_capacity(count);
    for _ in 0..count {
        terms.push(FailureTerm {
            class_id: FaultGroupClassId::from_bytes(decoder.identifier()?)?,
            failure_count: decoder.u16()?,
        });
    }
    let scenario = FailureScenario::new(terms).map_err(|_| MetadataCommandCodecError::Invalid)?;
    Ok(ProtectionScenarioConfiguration {
        scenario_id,
        name,
        scenario,
    })
}

pub(super) fn encode_assignment(
    encoder: &mut Encoder,
    value: AssignVolumeProtectionPolicy,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(ASSIGN_VOLUME_PROTECTION_POLICY)?;
    encoder.identifier(value.volume_id.as_bytes())?;
    encoder.identifier(value.policy_id.as_bytes())
}

pub(super) fn decode_assignment(
    decoder: &mut Decoder<'_>,
) -> Result<AssignVolumeProtectionPolicy, MetadataCommandCodecError> {
    Ok(AssignVolumeProtectionPolicy {
        volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
        policy_id: ProtectionPolicyId::from_bytes(decoder.identifier()?)?,
    })
}
