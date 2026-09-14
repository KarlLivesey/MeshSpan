// SPDX-License-Identifier: GPL-2.0-only

//! Federation relationship commands carried by the owning swarm's consensus only.

mod actors;
mod assignments;
mod grants;
mod identity;
mod mutations;
mod pairing;
mod storage;
mod succession;
#[cfg(test)]
mod tests;

use meshspan_domain::{FederationRelationshipId, FederationRelationshipKind, MeshId};

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{
    ApproveFederationRelationship, AuthoritativeCommand, FederationGovernanceDirection,
    FederationIdentityOwner, ProposeFederationRelationship, RecordName,
    RecoverFederationRelationship, RestrictFederationRelationship, RetireFederationRelationship,
    RevokeFederationRelationship, RotateFederationTrustIdentity,
};

const PROPOSE: u16 = 91;
const APPROVE: u16 = 92;
const ROTATE_IDENTITY: u16 = 93;
const RESTRICT: u16 = 94;
const RECOVER: u16 = 95;
const REVOKE: u16 = 96;
const RETIRE: u16 = 97;

pub(super) fn is_kind(kind: u16) -> bool {
    (PROPOSE..=RETIRE).contains(&kind)
        || grants::is_kind(kind)
        || storage::is_kind(kind)
        || assignments::is_kind(kind)
        || actors::is_kind(kind)
        || mutations::is_kind(kind)
        || succession::is_kind(kind)
        || pairing::is_kind(kind)
}

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    if grants::encode(encoder, command)?
        || storage::encode(encoder, command)?
        || assignments::encode(encoder, command)?
        || actors::encode(encoder, command)?
        || mutations::encode(encoder, command)?
        || succession::encode(encoder, command)?
        || pairing::encode(encoder, command)?
    {
        return Ok(true);
    }
    match command {
        AuthoritativeCommand::ProposeFederationRelationship(value) => {
            encode_proposal(encoder, value)?;
        }
        AuthoritativeCommand::ApproveFederationRelationship(value) => {
            encoder.u16(APPROVE)?;
            encoder.identifier(value.relationship_id.as_bytes())?;
            encoder.u64(value.expected_authority_epoch)?;
            identity::encode(encoder, value.local_identity)?;
            identity::encode(encoder, value.remote_identity)?;
            identity::encode_proof(encoder, value.governance_proof.as_ref())?;
        }
        AuthoritativeCommand::RotateFederationTrustIdentity(value) => {
            encoder.u16(ROTATE_IDENTITY)?;
            encoder.identifier(value.relationship_id.as_bytes())?;
            encoder.u64(value.expected_authority_epoch)?;
            encoder.u8(value.owner.code())?;
            identity::encode(encoder, value.identity)?;
        }
        AuthoritativeCommand::RestrictFederationRelationship(value) => encode_transition(
            encoder,
            RESTRICT,
            value.relationship_id,
            (value.expected_authority_epoch, value.authority_epoch),
            &value.reason,
        )?,
        AuthoritativeCommand::RecoverFederationRelationship(value) => encode_transition(
            encoder,
            RECOVER,
            value.relationship_id,
            (value.expected_authority_epoch, value.authority_epoch),
            &value.reason,
        )?,
        AuthoritativeCommand::RevokeFederationRelationship(value) => encode_transition(
            encoder,
            REVOKE,
            value.relationship_id,
            (value.expected_authority_epoch, value.authority_epoch),
            &value.reason,
        )?,
        AuthoritativeCommand::RetireFederationRelationship(value) => encode_transition(
            encoder,
            RETIRE,
            value.relationship_id,
            (value.expected_authority_epoch, value.authority_epoch),
            &value.reason,
        )?,
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decode(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    if grants::is_kind(kind) {
        return grants::decode(kind, decoder);
    }
    if storage::is_kind(kind) {
        return storage::decode(kind, decoder);
    }
    if assignments::is_kind(kind) {
        return assignments::decode(kind, decoder);
    }
    if actors::is_kind(kind) {
        return actors::decode(decoder);
    }
    if mutations::is_kind(kind) {
        return mutations::decode(kind, decoder);
    }
    if succession::is_kind(kind) {
        return succession::decode(kind, decoder);
    }
    if pairing::is_kind(kind) {
        return pairing::decode(kind, decoder);
    }
    let relationship_id = FederationRelationshipId::from_bytes(decoder.identifier()?)?;
    match kind {
        PROPOSE => decode_proposal(decoder, relationship_id),
        APPROVE => Ok(AuthoritativeCommand::ApproveFederationRelationship(
            ApproveFederationRelationship {
                relationship_id,
                expected_authority_epoch: decoder.u64()?,
                local_identity: identity::decode(decoder)?,
                remote_identity: identity::decode(decoder)?,
                governance_proof: identity::decode_proof(decoder)?,
            },
        )),
        ROTATE_IDENTITY => {
            let expected_authority_epoch = decoder.u64()?;
            let owner = match decoder.u8()? {
                1 => FederationIdentityOwner::Local,
                2 => FederationIdentityOwner::Remote,
                _ => return Err(MetadataCommandCodecError::Invalid),
            };
            Ok(AuthoritativeCommand::RotateFederationTrustIdentity(
                RotateFederationTrustIdentity {
                    relationship_id,
                    expected_authority_epoch,
                    owner,
                    identity: identity::decode(decoder)?,
                },
            ))
        }
        RESTRICT..=RETIRE => decode_transition(decoder, kind, relationship_id),
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn encode_proposal(
    encoder: &mut Encoder,
    value: &ProposeFederationRelationship,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(PROPOSE)?;
    encoder.identifier(value.relationship_id.as_bytes())?;
    encoder.identifier(value.remote_mesh_id.as_bytes())?;
    encoder.text(value.remote_name.display(), 256)?;
    encoder.u8(match value.kind {
        FederationRelationshipKind::Horizontal => 1,
        FederationRelationshipKind::Governance => 2,
    })?;
    encoder.u8(value.governance_direction.code())
}

fn decode_proposal(
    decoder: &mut Decoder<'_>,
    relationship_id: FederationRelationshipId,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    let remote_mesh_id = MeshId::from_bytes(decoder.identifier()?)?;
    let name = decoder.text(256)?;
    let remote_name = RecordName::new(&name).map_err(|_| MetadataCommandCodecError::Invalid)?;
    if remote_name.display() != name {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let kind = match decoder.u8()? {
        1 => FederationRelationshipKind::Horizontal,
        2 => FederationRelationshipKind::Governance,
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    let governance_direction = match decoder.u8()? {
        0 => FederationGovernanceDirection::None,
        1 => FederationGovernanceDirection::LocalGovernsRemote,
        2 => FederationGovernanceDirection::RemoteGovernsLocal,
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    Ok(AuthoritativeCommand::ProposeFederationRelationship(
        ProposeFederationRelationship {
            relationship_id,
            remote_mesh_id,
            remote_name,
            kind,
            governance_direction,
        },
    ))
}

fn encode_transition(
    encoder: &mut Encoder,
    kind: u16,
    relationship: FederationRelationshipId,
    epochs: (u64, u64),
    reason: &str,
) -> Result<(), MetadataCommandCodecError> {
    validate_transition(epochs, reason)?;
    encoder.u16(kind)?;
    encoder.identifier(relationship.as_bytes())?;
    encoder.u64(epochs.0)?;
    encoder.u64(epochs.1)?;
    encoder.text(reason, 512)
}

fn decode_transition(
    decoder: &mut Decoder<'_>,
    kind: u16,
    relationship_id: FederationRelationshipId,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    let expected_authority_epoch = decoder.u64()?;
    let authority_epoch = decoder.u64()?;
    let reason = decoder.text(512)?;
    validate_transition((expected_authority_epoch, authority_epoch), &reason)?;
    Ok(match kind {
        RESTRICT => {
            AuthoritativeCommand::RestrictFederationRelationship(RestrictFederationRelationship {
                relationship_id,
                expected_authority_epoch,
                authority_epoch,
                reason,
            })
        }
        RECOVER => {
            AuthoritativeCommand::RecoverFederationRelationship(RecoverFederationRelationship {
                relationship_id,
                expected_authority_epoch,
                authority_epoch,
                reason,
            })
        }
        REVOKE => {
            AuthoritativeCommand::RevokeFederationRelationship(RevokeFederationRelationship {
                relationship_id,
                expected_authority_epoch,
                authority_epoch,
                reason,
            })
        }
        RETIRE => {
            AuthoritativeCommand::RetireFederationRelationship(RetireFederationRelationship {
                relationship_id,
                expected_authority_epoch,
                authority_epoch,
                reason,
            })
        }
        _ => return Err(MetadataCommandCodecError::Unsupported),
    })
}

fn validate_transition(epochs: (u64, u64), reason: &str) -> Result<(), MetadataCommandCodecError> {
    if epochs.0 == 0
        || epochs.1 <= epochs.0
        || reason.trim().is_empty()
        || reason.chars().any(char::is_control)
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(())
}
