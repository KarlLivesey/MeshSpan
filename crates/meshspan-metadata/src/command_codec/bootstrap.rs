// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{HostId, MeshId, NodeId, PrincipalId, RoleId};

use super::MetadataCommandCodecError;
use super::authentication;
use super::decoder::Decoder;
use super::encoder::Encoder;
use super::{node_wrapping_key, secret_generation};
use crate::{BootstrapAppliance, BootstrapMesh, BootstrapRecoveryIdentity, RecordName};

const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_ROOT_CERTIFICATE_BYTES: usize = 8 * 1_024;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: &BootstrapAppliance,
) -> Result<(), MetadataCommandCodecError> {
    encode_mesh(encoder, &value.mesh)?;
    authentication::encode_payload(encoder, &value.authentication)?;
    encode_recovery(encoder, &value.recovery)?;
    node_wrapping_key::encode_payload(encoder, &value.node_wrapping_key)?;
    secret_generation::encode_payload(encoder, &value.storage_permit_key_generation)?;
    secret_generation::encode_payload(encoder, &value.authentication_root_key_generation)?;
    secret_generation::encode_payload(encoder, &value.online_authority_key_generation)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<BootstrapAppliance, MetadataCommandCodecError> {
    Ok(BootstrapAppliance {
        mesh: decode_mesh(decoder)?,
        authentication: authentication::decode_payload(decoder)?,
        recovery: Box::new(decode_recovery(decoder)?),
        node_wrapping_key: node_wrapping_key::decode_payload(decoder)?,
        storage_permit_key_generation: Box::new(secret_generation::decode_payload(decoder)?),
        authentication_root_key_generation: Box::new(secret_generation::decode_payload(decoder)?),
        online_authority_key_generation: Box::new(secret_generation::decode_payload(decoder)?),
    })
}

fn encode_recovery(
    encoder: &mut Encoder,
    value: &BootstrapRecoveryIdentity,
) -> Result<(), MetadataCommandCodecError> {
    encoder.fixed(&value.public_wrapping_key)?;
    encoder.fixed(&value.key_fingerprint)?;
    encoder.bytes(&value.root_certificate_der, MAXIMUM_ROOT_CERTIFICATE_BYTES)?;
    encoder.fixed(&value.root_certificate_digest)?;
    encoder.bytes(
        &value.online_authority_certificate_der,
        MAXIMUM_ROOT_CERTIFICATE_BYTES,
    )?;
    encoder.fixed(&value.online_authority_certificate_digest)?;
    encoder.fixed(&value.bundle_digest)?;
    encoder.fixed(&value.save_challenge_commitment)
}

fn decode_recovery(
    decoder: &mut Decoder<'_>,
) -> Result<BootstrapRecoveryIdentity, MetadataCommandCodecError> {
    let recovery = BootstrapRecoveryIdentity {
        public_wrapping_key: decoder.fixed()?,
        key_fingerprint: decoder.fixed()?,
        root_certificate_der: decoder.bytes(MAXIMUM_ROOT_CERTIFICATE_BYTES)?,
        root_certificate_digest: decoder.fixed()?,
        online_authority_certificate_der: decoder.bytes(MAXIMUM_ROOT_CERTIFICATE_BYTES)?,
        online_authority_certificate_digest: decoder.fixed()?,
        bundle_digest: decoder.fixed()?,
        save_challenge_commitment: decoder.fixed()?,
    };
    if recovery.root_certificate_der.is_empty()
        || recovery.online_authority_certificate_der.is_empty()
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(recovery)
    }
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

fn encode_name(encoder: &mut Encoder, value: &RecordName) -> Result<(), MetadataCommandCodecError> {
    encoder.text(value.display(), MAXIMUM_NAME_BYTES)
}

fn decode_name(decoder: &mut Decoder<'_>) -> Result<RecordName, MetadataCommandCodecError> {
    RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?).map_err(Into::into)
}
