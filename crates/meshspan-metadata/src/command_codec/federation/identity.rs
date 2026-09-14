// SPDX-License-Identifier: GPL-2.0-only

//! Public federation identity and bounded signed governance ancestry encoding.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{MeshId, UnixMicros};

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{FederationGovernanceEdge, FederationGovernanceProof, FederationTrustIdentity};

const MAXIMUM_ANCESTRY: usize = 4096;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: FederationTrustIdentity,
) -> Result<(), MetadataCommandCodecError> {
    validate(value)?;
    encoder.u64(value.generation)?;
    encoder.fixed(&value.certificate_fingerprint)?;
    encoder.fixed(&value.verifying_key)?;
    encoder.i64(value.valid_from.get())?;
    encoder.i64(value.valid_until.get())
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<FederationTrustIdentity, MetadataCommandCodecError> {
    let value = FederationTrustIdentity {
        generation: decoder.u64()?,
        certificate_fingerprint: decoder.fixed()?,
        verifying_key: decoder.fixed()?,
        valid_from: UnixMicros::new(decoder.i64()?),
        valid_until: UnixMicros::new(decoder.i64()?),
    };
    validate(value)?;
    Ok(value)
}

fn validate(value: FederationTrustIdentity) -> Result<(), MetadataCommandCodecError> {
    if value.generation == 0
        || value.certificate_fingerprint == [0; 32]
        || value.verifying_key == [0; 32]
        || value.valid_until <= value.valid_from
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(())
}

pub(super) fn encode_proof(
    encoder: &mut Encoder,
    value: Option<&FederationGovernanceProof>,
) -> Result<(), MetadataCommandCodecError> {
    encoder.bool(value.is_some())?;
    let Some(value) = value else {
        return Ok(());
    };
    if value.ancestry.len() > MAXIMUM_ANCESTRY {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    encoder.u64(value.remote_authority_epoch)?;
    encoder.u16(
        u16::try_from(value.ancestry.len())
            .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
    )?;
    for edge in value.ancestry.as_slice() {
        encoder.identifier(edge.parent_mesh_id.as_bytes())?;
        encoder.identifier(edge.child_mesh_id.as_bytes())?;
    }
    encoder.u64(value.signer_generation)?;
    encoder.fixed(&value.signature)
}

pub(super) fn decode_proof(
    decoder: &mut Decoder<'_>,
) -> Result<Option<FederationGovernanceProof>, MetadataCommandCodecError> {
    if !decoder.bool()? {
        return Ok(None);
    }
    let remote_authority_epoch = decoder.u64()?;
    let count = usize::from(decoder.u16()?);
    if count > MAXIMUM_ANCESTRY {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut ancestry = Vec::with_capacity(count);
    for _ in 0..count {
        ancestry.push(FederationGovernanceEdge {
            parent_mesh_id: MeshId::from_bytes(decoder.identifier()?)?,
            child_mesh_id: MeshId::from_bytes(decoder.identifier()?)?,
        });
    }
    Ok(Some(FederationGovernanceProof {
        remote_authority_epoch,
        ancestry: BoundedItems::new(ancestry, MAXIMUM_ANCESTRY)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        signer_generation: decoder.u64()?,
        signature: decoder.fixed()?,
    }))
}
