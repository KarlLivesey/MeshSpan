// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{FaultGroupClassId, FaultGroupId, HostId};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{CreateFaultGroup, RecordName, SetHostFaultGroupMembership};

pub(super) const CREATE_FAULT_GROUP: u16 = 22;
pub(super) const SET_HOST_FAULT_GROUP_MEMBERSHIP: u16 = 23;
const MAXIMUM_CLASS_NAME_BYTES: usize = 128;
const MAXIMUM_GROUP_NAME_BYTES: usize = 256;

pub(super) fn encode_create(
    encoder: &mut Encoder,
    value: &CreateFaultGroup,
) -> Result<(), MetadataCommandCodecError> {
    if value.class_name.canonical().len() > MAXIMUM_CLASS_NAME_BYTES {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.u16(CREATE_FAULT_GROUP)?;
    encoder.identifier(value.class_id.as_bytes())?;
    encoder.text(value.class_name.display(), MAXIMUM_CLASS_NAME_BYTES)?;
    encoder.identifier(value.group_id.as_bytes())?;
    encoder.text(value.group_name.display(), MAXIMUM_GROUP_NAME_BYTES)
}

pub(super) fn decode_create(
    decoder: &mut Decoder<'_>,
) -> Result<CreateFaultGroup, MetadataCommandCodecError> {
    Ok(CreateFaultGroup {
        class_id: FaultGroupClassId::from_bytes(decoder.identifier()?)?,
        class_name: RecordName::new(&decoder.text(MAXIMUM_CLASS_NAME_BYTES)?)?,
        group_id: FaultGroupId::from_bytes(decoder.identifier()?)?,
        group_name: RecordName::new(&decoder.text(MAXIMUM_GROUP_NAME_BYTES)?)?,
    })
}

pub(super) fn encode_membership(
    encoder: &mut Encoder,
    value: SetHostFaultGroupMembership,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(SET_HOST_FAULT_GROUP_MEMBERSHIP)?;
    encoder.identifier(value.group_id.as_bytes())?;
    encoder.identifier(value.host_id.as_bytes())?;
    encoder.bool(value.present)
}

pub(super) fn decode_membership(
    decoder: &mut Decoder<'_>,
) -> Result<SetHostFaultGroupMembership, MetadataCommandCodecError> {
    Ok(SetHostFaultGroupMembership {
        group_id: FaultGroupId::from_bytes(decoder.identifier()?)?,
        host_id: HostId::from_bytes(decoder.identifier()?)?,
        present: decoder.bool()?,
    })
}
