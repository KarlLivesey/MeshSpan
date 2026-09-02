// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AvailabilityCellId, DurationMicros, LocalityPolicyId, LocalityRequirementId,
    ProtectionPolicyId, VolumeId,
};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    AssignVolumeLocalityPolicy, CreateLocalityPolicy, LocalityRequirementConfiguration, RecordName,
};

pub(super) const CREATE_LOCALITY_POLICY: u16 = 31;
pub(super) const ASSIGN_VOLUME_LOCALITY_POLICY: u16 = 32;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_REQUIREMENTS: usize = 64;

pub(super) fn encode_create(
    encoder: &mut Encoder,
    value: &CreateLocalityPolicy,
) -> Result<(), MetadataCommandCodecError> {
    if value.requirements.is_empty() || value.requirements.len() > MAXIMUM_REQUIREMENTS {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.u16(CREATE_LOCALITY_POLICY)?;
    encoder.identifier(value.policy_id.as_bytes())?;
    encoder.text(value.name.display(), MAXIMUM_NAME_BYTES)?;
    encoder.optional_u64(value.maximum_lag.map(DurationMicros::get))?;
    encoder.u16(
        u16::try_from(value.requirements.len())
            .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
    )?;
    for requirement in value.requirements.as_slice() {
        encoder.identifier(requirement.requirement_id.as_bytes())?;
        encoder.identifier(requirement.cell_id.as_bytes())?;
        encoder.optional_fixed_16(
            requirement
                .local_protection_policy_id
                .map(ProtectionPolicyId::as_bytes),
        )?;
    }
    Ok(())
}

pub(super) fn decode_create(
    decoder: &mut Decoder<'_>,
) -> Result<CreateLocalityPolicy, MetadataCommandCodecError> {
    let policy_id = LocalityPolicyId::from_bytes(decoder.identifier()?)?;
    let name = RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)?;
    let maximum_lag = decoder.optional_u64()?.map(DurationMicros::new);
    let count = usize::from(decoder.u16()?);
    if count == 0 || count > MAXIMUM_REQUIREMENTS {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let mut requirements = Vec::with_capacity(count);
    for _ in 0..count {
        requirements.push(LocalityRequirementConfiguration {
            requirement_id: LocalityRequirementId::from_bytes(decoder.identifier()?)?,
            cell_id: AvailabilityCellId::from_bytes(decoder.identifier()?)?,
            local_protection_policy_id: decoder
                .optional_fixed_16()?
                .map(ProtectionPolicyId::from_bytes)
                .transpose()?,
        });
    }
    Ok(CreateLocalityPolicy {
        policy_id,
        name,
        maximum_lag,
        requirements: BoundedItems::new(requirements, MAXIMUM_REQUIREMENTS)?,
    })
}

pub(super) fn encode_assignment(
    encoder: &mut Encoder,
    value: AssignVolumeLocalityPolicy,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(ASSIGN_VOLUME_LOCALITY_POLICY)?;
    encoder.identifier(value.volume_id.as_bytes())?;
    encoder.identifier(value.policy_id.as_bytes())
}

pub(super) fn decode_assignment(
    decoder: &mut Decoder<'_>,
) -> Result<AssignVolumeLocalityPolicy, MetadataCommandCodecError> {
    Ok(AssignVolumeLocalityPolicy {
        volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
        policy_id: LocalityPolicyId::from_bytes(decoder.identifier()?)?,
    })
}
