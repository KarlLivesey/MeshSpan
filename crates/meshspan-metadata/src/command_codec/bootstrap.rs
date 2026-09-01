// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{HostId, MeshId, NodeId, PrincipalId, RoleId};

use super::MetadataCommandCodecError;
use super::authentication;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{BootstrapAppliance, BootstrapMesh, RecordName};

const MAXIMUM_NAME_BYTES: usize = 256;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: &BootstrapAppliance,
) -> Result<(), MetadataCommandCodecError> {
    encode_mesh(encoder, &value.mesh)?;
    authentication::encode_payload(encoder, &value.authentication)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<BootstrapAppliance, MetadataCommandCodecError> {
    Ok(BootstrapAppliance {
        mesh: decode_mesh(decoder)?,
        authentication: authentication::decode_payload(decoder)?,
    })
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
