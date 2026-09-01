// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ActivationPolicyId, AssuranceLevel, DurationMicros, GrantId, GroupId, ObjectId, PrincipalId,
    Rights, UnixMicros, VolumeId,
};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    AddGroupMember, CreateActivationPolicy, CreateGroup, CreateUser, GrantInheritance,
    GrantPermission, GrantPermissionWithActivation, PermissionScope, RecordName, RemoveGroupMember,
    RevokePermissionGrant,
};

const CREATE_USER: u16 = 2;
const CREATE_GROUP: u16 = 3;
const ADD_GROUP_MEMBER: u16 = 4;
const REMOVE_GROUP_MEMBER: u16 = 5;
pub(super) const GRANT_PERMISSION: u16 = 19;
pub(super) const GRANT_PERMISSION_WITH_ACTIVATION: u16 = 20;
pub(super) const REVOKE_PERMISSION: u16 = 21;
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

pub(super) fn encode_grant_permission(
    encoder: &mut Encoder,
    value: &GrantPermission,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(GRANT_PERMISSION)?;
    encode_grant_body(encoder, value)
}

pub(super) fn decode_grant_permission(
    decoder: &mut Decoder<'_>,
) -> Result<GrantPermission, MetadataCommandCodecError> {
    decode_grant_body(decoder)
}

pub(super) fn encode_grant_permission_with_activation(
    encoder: &mut Encoder,
    value: &GrantPermissionWithActivation,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(GRANT_PERMISSION_WITH_ACTIVATION)?;
    encode_policy(encoder, value.policy)?;
    encode_grant_body(encoder, &value.grant)
}

pub(super) fn decode_grant_permission_with_activation(
    decoder: &mut Decoder<'_>,
) -> Result<GrantPermissionWithActivation, MetadataCommandCodecError> {
    Ok(GrantPermissionWithActivation {
        policy: decode_policy(decoder)?,
        grant: decode_grant_body(decoder)?,
    })
}

pub(super) fn encode_revoke_permission(
    encoder: &mut Encoder,
    value: &RevokePermissionGrant,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(REVOKE_PERMISSION)?;
    encoder.identifier(value.grant_id.as_bytes())?;
    encoder.text(&value.reason, MAXIMUM_REASON_BYTES)
}

pub(super) fn decode_revoke_permission(
    decoder: &mut Decoder<'_>,
) -> Result<RevokePermissionGrant, MetadataCommandCodecError> {
    Ok(RevokePermissionGrant {
        grant_id: GrantId::from_bytes(decoder.identifier()?)?,
        reason: decoder.text(MAXIMUM_REASON_BYTES)?,
    })
}

fn encode_policy(
    encoder: &mut Encoder,
    value: CreateActivationPolicy,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.policy_id.as_bytes())?;
    encoder.u64(value.maximum_duration.get())?;
    encoder.bool(value.reason_required)?;
    encoder.u8(assurance_code(value.minimum_assurance))?;
    encoder.optional_i64(value.valid_from.map(UnixMicros::get))?;
    encoder.optional_i64(value.valid_until.map(UnixMicros::get))
}

fn decode_policy(
    decoder: &mut Decoder<'_>,
) -> Result<CreateActivationPolicy, MetadataCommandCodecError> {
    Ok(CreateActivationPolicy {
        policy_id: ActivationPolicyId::from_bytes(decoder.identifier()?)?,
        maximum_duration: DurationMicros::new(decoder.u64()?),
        reason_required: decoder.bool()?,
        minimum_assurance: decode_assurance(decoder.u8()?)?,
        valid_from: decoder.optional_i64()?.map(UnixMicros::new),
        valid_until: decoder.optional_i64()?.map(UnixMicros::new),
    })
}

fn encode_grant_body(
    encoder: &mut Encoder,
    value: &GrantPermission,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.grant_id.as_bytes())?;
    encoder.identifier(value.subject_principal_id.as_bytes())?;
    encode_scope(encoder, value.scope)?;
    encoder.u64(u64::from(value.rights.bits()))?;
    encoder.u8(inheritance_code(value.inheritance))?;
    encoder.optional_i64(value.valid_from.map(UnixMicros::get))?;
    encoder.optional_i64(value.valid_until.map(UnixMicros::get))?;
    encoder.optional_fixed_16(value.activation_policy_id.map(ActivationPolicyId::as_bytes))
}

fn decode_grant_body(
    decoder: &mut Decoder<'_>,
) -> Result<GrantPermission, MetadataCommandCodecError> {
    let grant_id = GrantId::from_bytes(decoder.identifier()?)?;
    let subject_principal_id = PrincipalId::from_bytes(decoder.identifier()?)?;
    let scope = decode_scope(decoder)?;
    let rights = u32::try_from(decoder.u64()?).map_err(|_| MetadataCommandCodecError::Invalid)?;
    Ok(GrantPermission {
        grant_id,
        subject_principal_id,
        scope,
        rights: Rights::from_bits(rights).map_err(|_| MetadataCommandCodecError::Invalid)?,
        inheritance: decode_inheritance(decoder.u8()?)?,
        valid_from: decoder.optional_i64()?.map(UnixMicros::new),
        valid_until: decoder.optional_i64()?.map(UnixMicros::new),
        activation_policy_id: decoder
            .optional_fixed_16()?
            .map(ActivationPolicyId::from_bytes)
            .transpose()?,
    })
}

fn encode_scope(
    encoder: &mut Encoder,
    scope: PermissionScope,
) -> Result<(), MetadataCommandCodecError> {
    match scope {
        PermissionScope::Global => encoder.u8(1),
        PermissionScope::Volume(volume_id) => {
            encoder.u8(2)?;
            encoder.identifier(volume_id.as_bytes())
        }
        PermissionScope::Object {
            volume_id,
            object_id,
        } => {
            encoder.u8(3)?;
            encoder.identifier(volume_id.as_bytes())?;
            encoder.identifier(object_id.as_bytes())
        }
    }
}

fn decode_scope(decoder: &mut Decoder<'_>) -> Result<PermissionScope, MetadataCommandCodecError> {
    match decoder.u8()? {
        1 => Ok(PermissionScope::Global),
        2 => Ok(PermissionScope::Volume(VolumeId::from_bytes(
            decoder.identifier()?,
        )?)),
        3 => Ok(PermissionScope::Object {
            volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
            object_id: ObjectId::from_bytes(decoder.identifier()?)?,
        }),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}

const fn assurance_code(value: AssuranceLevel) -> u8 {
    match value {
        AssuranceLevel::SingleFactor => 1,
        AssuranceLevel::MultiFactor => 2,
        AssuranceLevel::RecentStepUp => 3,
    }
}

const fn decode_assurance(value: u8) -> Result<AssuranceLevel, MetadataCommandCodecError> {
    match value {
        1 => Ok(AssuranceLevel::SingleFactor),
        2 => Ok(AssuranceLevel::MultiFactor),
        3 => Ok(AssuranceLevel::RecentStepUp),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}

const fn inheritance_code(value: GrantInheritance) -> u8 {
    match value {
        GrantInheritance::Object => 1,
        GrantInheritance::Descendants => 2,
        GrantInheritance::ObjectAndDescendants => 3,
    }
}

const fn decode_inheritance(value: u8) -> Result<GrantInheritance, MetadataCommandCodecError> {
    match value {
        1 => Ok(GrantInheritance::Object),
        2 => Ok(GrantInheritance::Descendants),
        3 => Ok(GrantInheritance::ObjectAndDescendants),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}

fn encode_name(encoder: &mut Encoder, value: &RecordName) -> Result<(), MetadataCommandCodecError> {
    encoder.text(value.display(), MAXIMUM_NAME_BYTES)
}

fn decode_name(decoder: &mut Decoder<'_>) -> Result<RecordName, MetadataCommandCodecError> {
    RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?).map_err(Into::into)
}
