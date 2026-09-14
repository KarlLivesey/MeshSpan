// SPDX-License-Identifier: GPL-2.0-only

//! Invitation verifiers and cancellation, without bearer material in consensus.

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{
    AuthoritativeCommand, CancelFederationPairingInvitation, IssueFederationPairingInvitation,
};
use meshspan_domain::{FederationRelationshipId, NodeId, Revision, UnixMicros};

const ISSUE: u16 = 116;
const CANCEL: u16 = 117;
const PREPARE: u16 = 118;
const BEGIN: u16 = 119;

pub(super) fn is_kind(kind: u16) -> bool {
    (ISSUE..=BEGIN).contains(&kind)
}

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::BeginFederationConnection(value) => {
            encoder.u16(BEGIN)?;
            encoder.identifier(value.relationship_id.as_bytes())?;
            encoder.identifier(value.inviting_mesh_id.as_bytes())?;
            encoder.fixed(&value.material_verifier)?;
            encoder.text(&value.remote_endpoint, 512)?;
            encoder.fixed(&value.certificate_fingerprint)?;
            encoder.i64(value.expires_at.get())?;
            encoder.bytes(
                &crate::encode_federation_pairing_peer(&value.local)?,
                18 * 1024,
            )?;
        }
        AuthoritativeCommand::PrepareFederationConnection(value) => {
            encoder.u16(PREPARE)?;
            encoder.identifier(value.relationship_id.as_bytes())?;
            encoder.identifier(value.inviting_mesh_id.as_bytes())?;
            encoder.fixed(&value.material_verifier)?;
            encoder.bool(value.expected_invitation_revision.is_some())?;
            if let Some(revision) = value.expected_invitation_revision {
                encoder.u64(revision.get())?;
            }
            encoder.bytes(
                &crate::encode_federation_pairing_peer(&value.local)?,
                18 * 1024,
            )?;
            encoder.bytes(
                &crate::encode_federation_pairing_peer(&value.remote)?,
                18 * 1024,
            )?;
        }
        AuthoritativeCommand::IssueFederationPairingInvitation(value) => {
            encoder.u16(ISSUE)?;
            encoder.identifier(value.relationship_id.as_bytes())?;
            encoder.identifier(value.issuing_node_id.as_bytes())?;
            encoder.u64(value.issuance_key_generation)?;
            encoder.fixed(&value.material_verifier)?;
            encoder.text(&value.endpoint, 512)?;
            encoder.fixed(&value.certificate_fingerprint)?;
            encoder.i64(value.expires_at.get())?;
        }
        AuthoritativeCommand::CancelFederationPairingInvitation(value) => {
            encoder.u16(CANCEL)?;
            encoder.identifier(value.relationship_id.as_bytes())?;
            encoder.u64(value.expected_invitation_revision.get())?;
            encoder.text(&value.reason, 512)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decode(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    Ok(match kind {
        BEGIN => {
            AuthoritativeCommand::BeginFederationConnection(crate::BeginFederationConnection {
                relationship_id: FederationRelationshipId::from_bytes(decoder.identifier()?)?,
                inviting_mesh_id: meshspan_domain::MeshId::from_bytes(decoder.identifier()?)?,
                material_verifier: decoder.fixed()?,
                remote_endpoint: decoder.text(512)?,
                certificate_fingerprint: decoder.fixed()?,
                expires_at: UnixMicros::new(decoder.i64()?),
                local: crate::decode_federation_pairing_peer(&decoder.bytes(18 * 1024)?)?,
            })
        }
        PREPARE => {
            AuthoritativeCommand::PrepareFederationConnection(crate::PrepareFederationConnection {
                relationship_id: FederationRelationshipId::from_bytes(decoder.identifier()?)?,
                inviting_mesh_id: meshspan_domain::MeshId::from_bytes(decoder.identifier()?)?,
                material_verifier: decoder.fixed()?,
                expected_invitation_revision: if decoder.bool()? {
                    Some(Revision::new(decoder.u64()?))
                } else {
                    None
                },
                local: crate::decode_federation_pairing_peer(&decoder.bytes(18 * 1024)?)?,
                remote: crate::decode_federation_pairing_peer(&decoder.bytes(18 * 1024)?)?,
            })
        }
        ISSUE => AuthoritativeCommand::IssueFederationPairingInvitation(
            IssueFederationPairingInvitation {
                relationship_id: FederationRelationshipId::from_bytes(decoder.identifier()?)?,
                issuing_node_id: NodeId::from_bytes(decoder.identifier()?)?,
                issuance_key_generation: decoder.u64()?,
                material_verifier: decoder.fixed()?,
                endpoint: decoder.text(512)?,
                certificate_fingerprint: decoder.fixed()?,
                expires_at: UnixMicros::new(decoder.i64()?),
            },
        ),
        CANCEL => AuthoritativeCommand::CancelFederationPairingInvitation(
            CancelFederationPairingInvitation {
                relationship_id: FederationRelationshipId::from_bytes(decoder.identifier()?)?,
                expected_invitation_revision: Revision::new(decoder.u64()?),
                reason: decoder.text(512)?,
            },
        ),
        _ => return Err(MetadataCommandCodecError::Unsupported),
    })
}
