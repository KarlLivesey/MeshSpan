// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{ActivationPolicyId, GroupId, PrincipalId, UnixMicros};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{AddGroupMember, CreateGroup, CreateUser, RecordName, RemoveGroupMember};

const CREATE_USER: u16 = 2;
const CREATE_GROUP: u16 = 3;
const ADD_GROUP_MEMBER: u16 = 4;
const REMOVE_GROUP_MEMBER: u16 = 5;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_REASON_BYTES: usize = 4096;

pub(super) fn encode_user(
    encoder: &mut Encoder,
    value: &CreateUser,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(CREATE_USER)?;
    encoder.identifier(value.principal_id.as_bytes())?;
    encode_name(encoder, &value.name)
}

pub(super) fn decode_user(
    decoder: &mut Decoder<'_>,
) -> Result<CreateUser, MetadataCommandCodecError> {
    Ok(CreateUser {
        principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
        name: decode_name(decoder)?,
    })
}

pub(super) fn encode_group(
    encoder: &mut Encoder,
    value: &CreateGroup,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(CREATE_GROUP)?;
    encoder.identifier(value.group_id.as_bytes())?;
    encode_name(encoder, &value.name)?;
    encoder.optional_fixed_16(value.activation_policy_id.map(ActivationPolicyId::as_bytes))
}

pub(super) fn decode_group(
    decoder: &mut Decoder<'_>,
) -> Result<CreateGroup, MetadataCommandCodecError> {
    Ok(CreateGroup {
        group_id: GroupId::from_bytes(decoder.identifier()?)?,
        name: decode_name(decoder)?,
        activation_policy_id: decoder
            .optional_fixed_16()?
            .map(ActivationPolicyId::from_bytes)
            .transpose()?,
    })
}

pub(super) fn encode_add_member(
    encoder: &mut Encoder,
    value: &AddGroupMember,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(ADD_GROUP_MEMBER)?;
    encoder.identifier(value.containing_group_id.as_bytes())?;
    encoder.identifier(value.member_principal_id.as_bytes())?;
    encoder.optional_i64(value.valid_from.map(UnixMicros::get))?;
    encoder.optional_i64(value.valid_until.map(UnixMicros::get))?;
    encoder.bool(value.activation_required)
}

pub(super) fn decode_add_member(
    decoder: &mut Decoder<'_>,
) -> Result<AddGroupMember, MetadataCommandCodecError> {
    Ok(AddGroupMember {
        containing_group_id: GroupId::from_bytes(decoder.identifier()?)?,
        member_principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
        valid_from: decoder.optional_i64()?.map(UnixMicros::new),
        valid_until: decoder.optional_i64()?.map(UnixMicros::new),
        activation_required: decoder.bool()?,
    })
}

pub(super) fn encode_remove_member(
    encoder: &mut Encoder,
    value: &RemoveGroupMember,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(REMOVE_GROUP_MEMBER)?;
    encoder.identifier(value.containing_group_id.as_bytes())?;
    encoder.identifier(value.member_principal_id.as_bytes())?;
    encoder.text(&value.reason, MAXIMUM_REASON_BYTES)
}

pub(super) fn decode_remove_member(
    decoder: &mut Decoder<'_>,
) -> Result<RemoveGroupMember, MetadataCommandCodecError> {
    Ok(RemoveGroupMember {
        containing_group_id: GroupId::from_bytes(decoder.identifier()?)?,
        member_principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
        reason: decoder.text(MAXIMUM_REASON_BYTES)?,
    })
}

fn encode_name(encoder: &mut Encoder, value: &RecordName) -> Result<(), MetadataCommandCodecError> {
    encoder.text(value.display(), MAXIMUM_NAME_BYTES)
}

fn decode_name(decoder: &mut Decoder<'_>) -> Result<RecordName, MetadataCommandCodecError> {
    RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?).map_err(Into::into)
}
