// SPDX-License-Identifier: GPL-2.0-only

//! Signed home-swarm actor statements; signatures remain state-machine authority.

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{
    AuthoritativeCommand, FederatedActorKind, FederatedActorState, RecordFederatedActorAttestation,
    RecordName,
};
use meshspan_domain::{FederationRelationshipId, MeshId, PrincipalId};

const ATTEST: u16 = 107;

pub(super) const fn is_kind(kind: u16) -> bool {
    kind == ATTEST
}

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    let AuthoritativeCommand::RecordFederatedActorAttestation(value) = command else {
        return Ok(false);
    };
    encoder.u16(ATTEST)?;
    encoder.identifier(value.relationship_id.as_bytes())?;
    encoder.identifier(value.home_mesh_id.as_bytes())?;
    encoder.identifier(value.principal_id.as_bytes())?;
    encoder.u8(value.kind.code())?;
    encoder.text(value.name.display(), 256)?;
    encoder.u8(value.state.code())?;
    encoder.u64(value.identity_revision)?;
    encoder.u64(value.authority_epoch)?;
    encoder.u64(value.signer_generation)?;
    encoder.fixed(&value.signature)?;
    Ok(true)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    let relationship_id = FederationRelationshipId::from_bytes(decoder.identifier()?)?;
    let home_mesh_id = MeshId::from_bytes(decoder.identifier()?)?;
    let principal_id = PrincipalId::from_bytes(decoder.identifier()?)?;
    let kind = match decoder.u8()? {
        1 => FederatedActorKind::User,
        2 => FederatedActorKind::Group,
        3 => FederatedActorKind::Service,
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    let display = decoder.text(256)?;
    let name = RecordName::new(&display).map_err(|_| MetadataCommandCodecError::Invalid)?;
    if name.display() != display {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let state = match decoder.u8()? {
        1 => FederatedActorState::Active,
        2 => FederatedActorState::Suspended,
        3 => FederatedActorState::Retired,
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    Ok(AuthoritativeCommand::RecordFederatedActorAttestation(
        RecordFederatedActorAttestation {
            relationship_id,
            home_mesh_id,
            principal_id,
            kind,
            name,
            state,
            identity_revision: decoder.u64()?,
            authority_epoch: decoder.u64()?,
            signer_generation: decoder.u64()?,
            signature: decoder.fixed()?,
        },
    ))
}
