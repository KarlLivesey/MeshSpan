// SPDX-License-Identifier: GPL-2.0-only

//! Preserve original actor and accepting relay separately during reconciliation.

use super::{Decoder, Encoder, MetadataCommandCodecError};
use meshspan_domain::{
    FederatedMutationAcknowledgement, FederatedMutationEvidence, FederatedPrincipal,
    FederationGrantId, FederationRelationshipId, FederationResourceScope, MeshId, ObjectId,
    OperationId, PrincipalId, Rights, UnixMicros, VolumeId,
};

pub(super) fn encode(
    encoder: &mut Encoder,
    value: &FederatedMutationAcknowledgement,
) -> Result<(), MetadataCommandCodecError> {
    let evidence = value.evidence;
    encoder.identifier(value.source_operation_id.as_bytes())?;
    encoder.identifier(evidence.grant_id().as_bytes())?;
    encoder.identifier(evidence.relationship_id().as_bytes())?;
    encoder.identifier(evidence.actor().home_mesh_id().as_bytes())?;
    encoder.identifier(evidence.actor().principal_id().as_bytes())?;
    encoder.identifier(evidence.accepting_mesh_id().as_bytes())?;
    encode_resource(encoder, evidence.resource())?;
    encoder.u64(evidence.authority_epoch())?;
    encoder.i64(evidence.accepted_at().get())?;
    encoder.u64(u64::from(evidence.required_rights().bits()))?;
    encoder.u64(evidence.storage_bytes())?;
    encoder.fixed(&value.payload_digest)?;
    encoder.u64(value.signer_generation)?;
    encoder.fixed(&value.signature)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<FederatedMutationAcknowledgement, MetadataCommandCodecError> {
    let source_operation_id = OperationId::from_bytes(decoder.identifier()?)?;
    let evidence = FederatedMutationEvidence::new_relayed(
        FederationGrantId::from_bytes(decoder.identifier()?)?,
        FederationRelationshipId::from_bytes(decoder.identifier()?)?,
        FederatedPrincipal::new(
            MeshId::from_bytes(decoder.identifier()?)?,
            PrincipalId::from_bytes(decoder.identifier()?)?,
        ),
        MeshId::from_bytes(decoder.identifier()?)?,
        decode_resource(decoder)?,
        decoder.u64()?,
        UnixMicros::new(decoder.i64()?),
        Rights::from_bits(
            u32::try_from(decoder.u64()?).map_err(|_| MetadataCommandCodecError::Invalid)?,
        )
        .map_err(|_| MetadataCommandCodecError::Invalid)?,
        decoder.u64()?,
    );
    Ok(FederatedMutationAcknowledgement {
        source_operation_id,
        evidence,
        payload_digest: decoder.fixed()?,
        signer_generation: decoder.u64()?,
        signature: decoder.fixed()?,
    })
}

fn encode_resource(
    encoder: &mut Encoder,
    resource: FederationResourceScope,
) -> Result<(), MetadataCommandCodecError> {
    match resource {
        FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id,
        } => {
            encoder.u8(1)?;
            encoder.identifier(owner_mesh_id.as_bytes())?;
            encoder.identifier(volume_id.as_bytes())
        }
        FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id,
            root_object_id,
        } => {
            encoder.u8(2)?;
            encoder.identifier(owner_mesh_id.as_bytes())?;
            encoder.identifier(volume_id.as_bytes())?;
            encoder.identifier(root_object_id.as_bytes())
        }
        FederationResourceScope::File {
            owner_mesh_id,
            volume_id,
            object_id,
        } => {
            encoder.u8(3)?;
            encoder.identifier(owner_mesh_id.as_bytes())?;
            encoder.identifier(volume_id.as_bytes())?;
            encoder.identifier(object_id.as_bytes())
        }
        FederationResourceScope::StorageCapacity { provider_mesh_id } => {
            encoder.u8(4)?;
            encoder.identifier(provider_mesh_id.as_bytes())
        }
    }
}

fn decode_resource(
    decoder: &mut Decoder<'_>,
) -> Result<FederationResourceScope, MetadataCommandCodecError> {
    let kind = decoder.u8()?;
    let owner_mesh_id = MeshId::from_bytes(decoder.identifier()?)?;
    Ok(match kind {
        1 => FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
        },
        2 => FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
            root_object_id: ObjectId::from_bytes(decoder.identifier()?)?,
        },
        3 => FederationResourceScope::File {
            owner_mesh_id,
            volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
            object_id: ObjectId::from_bytes(decoder.identifier()?)?,
        },
        4 => FederationResourceScope::StorageCapacity {
            provider_mesh_id: owner_mesh_id,
        },
        _ => return Err(MetadataCommandCodecError::Invalid),
    })
}
