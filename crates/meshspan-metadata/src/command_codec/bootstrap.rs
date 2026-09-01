// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ApiKeyId, AuthenticationMethodId, HostId, MeshId, NodeId, PrincipalId, RoleId, UnixMicros,
};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    AuthoritativeCommand, BootstrapAppliance, BootstrapMesh, CreateAuthenticationMethod,
    NewAuthenticationCredential, RecordName,
};

const BOOTSTRAP_APPLIANCE: u16 = 1;
const API_KEY: u8 = 4;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_LABEL_BYTES: usize = 256;

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<(), MetadataCommandCodecError> {
    let AuthoritativeCommand::BootstrapAppliance(value) = command else {
        return Err(MetadataCommandCodecError::Unsupported);
    };
    encoder.u16(BOOTSTRAP_APPLIANCE)?;
    encode_mesh(encoder, &value.mesh)?;
    encode_authentication(encoder, &value.authentication)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    if decoder.u16()? != BOOTSTRAP_APPLIANCE {
        return Err(MetadataCommandCodecError::Unsupported);
    }
    Ok(AuthoritativeCommand::BootstrapAppliance(
        BootstrapAppliance {
            mesh: decode_mesh(decoder)?,
            authentication: decode_authentication(decoder)?,
        },
    ))
}

fn encode_mesh(
    encoder: &mut Encoder,
    value: &BootstrapMesh,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.mesh_id.as_bytes())?;
    encode_name(encoder, &value.mesh_name)?;
    encoder.identifier(value.administrator_id.as_bytes())?;
    encode_name(encoder, &value.administrator_name)?;
    encoder.identifier(value.administrator_role_id.as_bytes())?;
    encoder.identifier(value.host_id.as_bytes())?;
    encode_name(encoder, &value.host_name)?;
    encoder.identifier(value.node_id.as_bytes())?;
    encode_name(encoder, &value.node_name)?;
    encode_name(encoder, &value.partition_name)
}

fn decode_mesh(decoder: &mut Decoder<'_>) -> Result<BootstrapMesh, MetadataCommandCodecError> {
    Ok(BootstrapMesh {
        mesh_id: MeshId::from_bytes(decoder.identifier()?)?,
        mesh_name: decode_name(decoder)?,
        administrator_id: PrincipalId::from_bytes(decoder.identifier()?)?,
        administrator_name: decode_name(decoder)?,
        administrator_role_id: RoleId::from_bytes(decoder.identifier()?)?,
        host_id: HostId::from_bytes(decoder.identifier()?)?,
        host_name: decode_name(decoder)?,
        node_id: NodeId::from_bytes(decoder.identifier()?)?,
        node_name: decode_name(decoder)?,
        partition_name: decode_name(decoder)?,
    })
}

fn encode_authentication(
    encoder: &mut Encoder,
    value: &CreateAuthenticationMethod,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.method_id.as_bytes())?;
    encoder.identifier(value.principal_id.as_bytes())?;
    encoder.text(&value.label, MAXIMUM_LABEL_BYTES)?;
    encoder.u8(value.service_scope)?;
    encoder.optional_i64(value.expires_at.map(UnixMicros::get))?;
    let NewAuthenticationCredential::ApiKey {
        key_id,
        key_digest,
        scopes,
        valid_from,
    } = &value.credential
    else {
        return Err(MetadataCommandCodecError::Unsupported);
    };
    encoder.u8(API_KEY)?;
    encoder.identifier(key_id.as_bytes())?;
    encoder.fixed(key_digest)?;
    encoder.u64(*scopes)?;
    encoder.i64(valid_from.get())
}

fn decode_authentication(
    decoder: &mut Decoder<'_>,
) -> Result<CreateAuthenticationMethod, MetadataCommandCodecError> {
    let method_id = AuthenticationMethodId::from_bytes(decoder.identifier()?)?;
    let principal_id = PrincipalId::from_bytes(decoder.identifier()?)?;
    let label = decoder.text(MAXIMUM_LABEL_BYTES)?;
    let service_scope = decoder.u8()?;
    let expires_at = decoder.optional_i64()?.map(UnixMicros::new);
    if decoder.u8()? != API_KEY {
        return Err(MetadataCommandCodecError::Unsupported);
    }
    let credential = NewAuthenticationCredential::ApiKey {
        key_id: ApiKeyId::from_bytes(decoder.identifier()?)?,
        key_digest: decoder.fixed()?,
        scopes: decoder.u64()?,
        valid_from: UnixMicros::new(decoder.i64()?),
    };
    Ok(CreateAuthenticationMethod {
        method_id,
        principal_id,
        label,
        service_scope,
        expires_at,
        credential,
    })
}

fn encode_name(encoder: &mut Encoder, value: &RecordName) -> Result<(), MetadataCommandCodecError> {
    encoder.text(value.display(), MAXIMUM_NAME_BYTES)
}

fn decode_name(decoder: &mut Decoder<'_>) -> Result<RecordName, MetadataCommandCodecError> {
    RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?).map_err(Into::into)
}
