// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{MeshLocalCertificateAuthorityId, UnixMicros};

use super::decoder::Decoder;
use super::encoder::Encoder;
use super::{MetadataCommandCodecError, secret_generation};
use crate::{
    CreateMeshLocalCertificateAuthority, MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES,
    MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND,
};

pub(super) const CREATE_MESH_LOCAL_CERTIFICATE_AUTHORITY: u16 = 60;

pub(super) fn encode_command(
    encoder: &mut Encoder,
    command: &crate::AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    let crate::AuthoritativeCommand::CreateMeshLocalCertificateAuthority(value) = command else {
        return Ok(false);
    };
    validate(value)?;
    encoder.u16(CREATE_MESH_LOCAL_CERTIFICATE_AUTHORITY)?;
    encoder.identifier(value.authority_id.as_bytes())?;
    encoder.u64(value.generation)?;
    encoder.bytes(
        &value.certificate_der,
        MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES,
    )?;
    secret_generation::encode_payload(encoder, &value.authority_key)?;
    encoder.fixed(&value.certificate_digest)?;
    encoder.i64(value.not_before.get())?;
    encoder.i64(value.not_after.get())?;
    Ok(true)
}

pub(super) const fn is_command_kind(kind: u16) -> bool {
    kind == CREATE_MESH_LOCAL_CERTIFICATE_AUTHORITY
}

pub(super) fn decode_command(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<crate::AuthoritativeCommand, MetadataCommandCodecError> {
    if !is_command_kind(kind) {
        return Err(MetadataCommandCodecError::Unsupported);
    }
    let value = CreateMeshLocalCertificateAuthority {
        authority_id: MeshLocalCertificateAuthorityId::from_bytes(decoder.identifier()?)?,
        generation: decoder.u64()?,
        certificate_der: decoder.bytes(MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES)?,
        authority_key: Box::new(secret_generation::decode_payload(decoder)?),
        certificate_digest: decoder.fixed()?,
        not_before: UnixMicros::new(decoder.i64()?),
        not_after: UnixMicros::new(decoder.i64()?),
    };
    validate(&value)?;
    Ok(crate::AuthoritativeCommand::CreateMeshLocalCertificateAuthority(Box::new(value)))
}

fn validate(value: &CreateMeshLocalCertificateAuthority) -> Result<(), MetadataCommandCodecError> {
    secret_generation::validate(&value.authority_key)?;
    let secret_context = value.authority_key.secret.context;
    if value.generation != 1
        || value.certificate_der.is_empty()
        || value.certificate_der.len() > MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES
        || value.certificate_der.first() != Some(&0x30)
        || value.certificate_digest == [0; 32]
        || value.not_before.get() < 0
        || value.not_after <= value.not_before
        || secret_context.kind() != MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND
        || secret_context.id() != value.authority_id.as_bytes()
        || secret_context.generation() != value.generation
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}
