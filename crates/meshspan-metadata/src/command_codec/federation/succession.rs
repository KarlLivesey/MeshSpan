// SPDX-License-Identifier: GPL-2.0-only

//! Explicit, two-sided ownership succession; a timeout never grants ownership.

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{
    AcceptFederationSuccessor, ActivateFederationSuccessor, AuthoritativeCommand,
    DesignateFederationSuccessor, FederationSuccessionEdge, RevokeFederationSuccessorDesignation,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{FederationRelationshipId, FederationSuccessionId, MeshId};

const DESIGNATE: u16 = 108;
const ACCEPT: u16 = 109;
const ACTIVATE: u16 = 110;
const REVOKE: u16 = 111;
const MAXIMUM_ANCESTRY: usize = 4096;

pub(super) fn is_kind(kind: u16) -> bool {
    (DESIGNATE..=REVOKE).contains(&kind)
}

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::DesignateFederationSuccessor(value) => {
            encode_designation(encoder, value)?;
        }
        AuthoritativeCommand::AcceptFederationSuccessor(value) => {
            encoder.u16(ACCEPT)?;
            encoder.identifier(value.succession_id.as_bytes())?;
            encoder.identifier(value.relationship_id.as_bytes())?;
            encoder.identifier(value.retiring_mesh_id.as_bytes())?;
            encoder.identifier(value.successor_mesh_id.as_bytes())?;
            encoder.u64(value.expected_authority_epoch)?;
            encoder.u64(value.succession_epoch)?;
            encoder.fixed(&value.designation_digest)?;
            encoder.u64(value.signer_generation)?;
            encoder.fixed(&value.signature)?;
        }
        AuthoritativeCommand::ActivateFederationSuccessor(value) => {
            encoder.u16(ACTIVATE)?;
            encoder.identifier(value.succession_id.as_bytes())?;
            encoder.identifier(value.relationship_id.as_bytes())?;
            encoder.identifier(value.retiring_mesh_id.as_bytes())?;
            encoder.identifier(value.successor_mesh_id.as_bytes())?;
            encoder.u64(value.expected_authority_epoch)?;
            encoder.u64(value.succession_epoch)?;
            encoder.fixed(&value.designation_digest)?;
            encoder.fixed(&value.acceptance_digest)?;
            encoder.text(&value.reason, 512)?;
        }
        AuthoritativeCommand::RevokeFederationSuccessorDesignation(value) => {
            encoder.u16(REVOKE)?;
            encoder.identifier(value.succession_id.as_bytes())?;
            encoder.identifier(value.relationship_id.as_bytes())?;
            encoder.identifier(value.retiring_mesh_id.as_bytes())?;
            encoder.identifier(value.successor_mesh_id.as_bytes())?;
            encoder.u64(value.expected_authority_epoch)?;
            encoder.u64(value.succession_epoch)?;
            encoder.fixed(&value.designation_digest)?;
            encoder.u64(value.signer_generation)?;
            encoder.text(&value.reason, 512)?;
            encoder.fixed(&value.signature)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decode(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    let succession_id = FederationSuccessionId::from_bytes(decoder.identifier()?)?;
    let relationship_id = FederationRelationshipId::from_bytes(decoder.identifier()?)?;
    let retiring_mesh_id = MeshId::from_bytes(decoder.identifier()?)?;
    let successor_mesh_id = MeshId::from_bytes(decoder.identifier()?)?;
    let expected_authority_epoch = decoder.u64()?;
    let succession_epoch = decoder.u64()?;
    Ok(match kind {
        DESIGNATE => {
            AuthoritativeCommand::DesignateFederationSuccessor(DesignateFederationSuccessor {
                succession_id,
                relationship_id,
                retiring_mesh_id,
                successor_mesh_id,
                expected_authority_epoch,
                succession_epoch,
                ancestry: decode_ancestry(decoder)?,
                signer_generation: decoder.u64()?,
                signature: decoder.fixed()?,
            })
        }
        ACCEPT => AuthoritativeCommand::AcceptFederationSuccessor(AcceptFederationSuccessor {
            succession_id,
            relationship_id,
            retiring_mesh_id,
            successor_mesh_id,
            expected_authority_epoch,
            succession_epoch,
            designation_digest: decoder.fixed()?,
            signer_generation: decoder.u64()?,
            signature: decoder.fixed()?,
        }),
        ACTIVATE => {
            AuthoritativeCommand::ActivateFederationSuccessor(ActivateFederationSuccessor {
                succession_id,
                relationship_id,
                retiring_mesh_id,
                successor_mesh_id,
                expected_authority_epoch,
                succession_epoch,
                designation_digest: decoder.fixed()?,
                acceptance_digest: decoder.fixed()?,
                reason: decoder.text(512)?,
            })
        }
        REVOKE => AuthoritativeCommand::RevokeFederationSuccessorDesignation(
            RevokeFederationSuccessorDesignation {
                succession_id,
                relationship_id,
                retiring_mesh_id,
                successor_mesh_id,
                expected_authority_epoch,
                succession_epoch,
                designation_digest: decoder.fixed()?,
                signer_generation: decoder.u64()?,
                reason: decoder.text(512)?,
                signature: decoder.fixed()?,
            },
        ),
        _ => return Err(MetadataCommandCodecError::Unsupported),
    })
}

fn encode_designation(
    encoder: &mut Encoder,
    value: &DesignateFederationSuccessor,
) -> Result<(), MetadataCommandCodecError> {
    if value.ancestry.len() > MAXIMUM_ANCESTRY {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    encoder.u16(DESIGNATE)?;
    encoder.identifier(value.succession_id.as_bytes())?;
    encoder.identifier(value.relationship_id.as_bytes())?;
    encoder.identifier(value.retiring_mesh_id.as_bytes())?;
    encoder.identifier(value.successor_mesh_id.as_bytes())?;
    encoder.u64(value.expected_authority_epoch)?;
    encoder.u64(value.succession_epoch)?;
    encoder.u16(
        u16::try_from(value.ancestry.len())
            .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
    )?;
    for edge in value.ancestry.as_slice() {
        encoder.identifier(edge.retiring_mesh_id.as_bytes())?;
        encoder.identifier(edge.successor_mesh_id.as_bytes())?;
    }
    encoder.u64(value.signer_generation)?;
    encoder.fixed(&value.signature)
}

fn decode_ancestry(
    decoder: &mut Decoder<'_>,
) -> Result<BoundedItems<FederationSuccessionEdge>, MetadataCommandCodecError> {
    let count = usize::from(decoder.u16()?);
    if count > MAXIMUM_ANCESTRY {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut edges = Vec::with_capacity(count);
    for _ in 0..count {
        edges.push(FederationSuccessionEdge {
            retiring_mesh_id: MeshId::from_bytes(decoder.identifier()?)?,
            successor_mesh_id: MeshId::from_bytes(decoder.identifier()?)?,
        });
    }
    BoundedItems::new(edges, MAXIMUM_ANCESTRY).map_err(|_| MetadataCommandCodecError::Invalid)
}
