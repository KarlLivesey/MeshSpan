// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{AvailabilityCellId, HostId, TargetId};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    CreateAvailabilityCell, RecordName, SetHostAvailabilityCellMembership,
    SetTargetAvailabilityCellMembership,
};

pub(super) const CREATE_AVAILABILITY_CELL: u16 = 28;
pub(super) const SET_HOST_AVAILABILITY_CELL_MEMBERSHIP: u16 = 29;
pub(super) const SET_TARGET_AVAILABILITY_CELL_MEMBERSHIP: u16 = 30;
const MAXIMUM_NAME_BYTES: usize = 256;

pub(super) fn encode_create(
    encoder: &mut Encoder,
    value: &CreateAvailabilityCell,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(CREATE_AVAILABILITY_CELL)?;
    encoder.identifier(value.cell_id.as_bytes())?;
    encoder.text(value.name.display(), MAXIMUM_NAME_BYTES)?;
    encoder.optional_fixed_16(value.parent_cell_id.map(AvailabilityCellId::as_bytes))
}

pub(super) fn decode_create(
    decoder: &mut Decoder<'_>,
) -> Result<CreateAvailabilityCell, MetadataCommandCodecError> {
    Ok(CreateAvailabilityCell {
        cell_id: AvailabilityCellId::from_bytes(decoder.identifier()?)?,
        name: RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)?,
        parent_cell_id: decoder
            .optional_fixed_16()?
            .map(AvailabilityCellId::from_bytes)
            .transpose()?,
    })
}

pub(super) fn encode_host_membership(
    encoder: &mut Encoder,
    value: SetHostAvailabilityCellMembership,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(SET_HOST_AVAILABILITY_CELL_MEMBERSHIP)?;
    encoder.identifier(value.cell_id.as_bytes())?;
    encoder.identifier(value.host_id.as_bytes())?;
    encoder.bool(value.present)
}

pub(super) fn decode_host_membership(
    decoder: &mut Decoder<'_>,
) -> Result<SetHostAvailabilityCellMembership, MetadataCommandCodecError> {
    Ok(SetHostAvailabilityCellMembership {
        cell_id: AvailabilityCellId::from_bytes(decoder.identifier()?)?,
        host_id: HostId::from_bytes(decoder.identifier()?)?,
        present: decoder.bool()?,
    })
}

pub(super) fn encode_target_membership(
    encoder: &mut Encoder,
    value: SetTargetAvailabilityCellMembership,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(SET_TARGET_AVAILABILITY_CELL_MEMBERSHIP)?;
    encoder.identifier(value.cell_id.as_bytes())?;
    encoder.identifier(value.target_id.as_bytes())?;
    encoder.bool(value.present)
}

pub(super) fn decode_target_membership(
    decoder: &mut Decoder<'_>,
) -> Result<SetTargetAvailabilityCellMembership, MetadataCommandCodecError> {
    Ok(SetTargetAvailabilityCellMembership {
        cell_id: AvailabilityCellId::from_bytes(decoder.identifier()?)?,
        target_id: TargetId::from_bytes(decoder.identifier()?)?,
        present: decoder.bool()?,
    })
}
