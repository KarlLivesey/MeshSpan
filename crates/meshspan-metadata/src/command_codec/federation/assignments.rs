// SPDX-License-Identifier: GPL-2.0-only

//! Recipient-local assignment and temporary activation commands.

use super::super::identity::{assurance_code, decode_assurance};
use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{
    ActivateFederationGrantAssignment, AuthoritativeCommand, CreateFederationGrantAssignment,
    RevokeFederationGrantAssignment, RevokeFederationGrantAssignmentActivation,
};
use meshspan_domain::{
    ActivationId, ActivationPolicyId, DurationMicros, FederationAssignmentId, FederationGrantId,
    PrincipalId, Rights, UnixMicros,
};

const CREATE: u16 = 103;
const REVOKE: u16 = 104;
const ACTIVATE: u16 = 105;
const REVOKE_ACTIVATION: u16 = 106;

pub(super) fn is_kind(kind: u16) -> bool {
    (CREATE..=REVOKE_ACTIVATION).contains(&kind)
}

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::CreateFederationGrantAssignment(value) => {
            encoder.u16(CREATE)?;
            encoder.identifier(value.assignment_id.as_bytes())?;
            encoder.identifier(value.grant_id.as_bytes())?;
            encoder.identifier(value.subject_principal_id.as_bytes())?;
            encoder.u64(u64::from(value.rights.bits()))?;
            encoder.optional_i64(value.valid_from.map(UnixMicros::get))?;
            encoder.optional_i64(value.valid_until.map(UnixMicros::get))?;
            encoder
                .optional_fixed_16(value.activation_policy_id.map(ActivationPolicyId::as_bytes))?;
        }
        AuthoritativeCommand::RevokeFederationGrantAssignment(value) => {
            encoder.u16(REVOKE)?;
            encoder.identifier(value.assignment_id.as_bytes())?;
            encoder.text(&value.reason, 512)?;
        }
        AuthoritativeCommand::ActivateFederationGrantAssignment(value) => {
            encoder.u16(ACTIVATE)?;
            encoder.identifier(value.activation_id.as_bytes())?;
            encoder.identifier(value.principal_id.as_bytes())?;
            encoder.identifier(value.assignment_id.as_bytes())?;
            encoder.identifier(value.policy_id.as_bytes())?;
            encoder.text(&value.reason, 512)?;
            encoder.u64(value.duration.get())?;
            encoder.i64(value.session_expires_at.get())?;
            encoder.u8(assurance_code(value.assurance))?;
            encoder.fixed(&value.authentication_digest)?;
        }
        AuthoritativeCommand::RevokeFederationGrantAssignmentActivation(value) => {
            encoder.u16(REVOKE_ACTIVATION)?;
            encoder.identifier(value.activation_id.as_bytes())?;
            encoder.identifier(value.principal_id.as_bytes())?;
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
        CREATE => {
            AuthoritativeCommand::CreateFederationGrantAssignment(CreateFederationGrantAssignment {
                assignment_id: FederationAssignmentId::from_bytes(decoder.identifier()?)?,
                grant_id: FederationGrantId::from_bytes(decoder.identifier()?)?,
                subject_principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
                rights: Rights::from_bits(
                    u32::try_from(decoder.u64()?)
                        .map_err(|_| MetadataCommandCodecError::Invalid)?,
                )
                .map_err(|_| MetadataCommandCodecError::Invalid)?,
                valid_from: decoder.optional_i64()?.map(UnixMicros::new),
                valid_until: decoder.optional_i64()?.map(UnixMicros::new),
                activation_policy_id: decoder
                    .optional_fixed_16()?
                    .map(ActivationPolicyId::from_bytes)
                    .transpose()?,
            })
        }
        REVOKE => {
            AuthoritativeCommand::RevokeFederationGrantAssignment(RevokeFederationGrantAssignment {
                assignment_id: FederationAssignmentId::from_bytes(decoder.identifier()?)?,
                reason: decoder.text(512)?,
            })
        }
        ACTIVATE => AuthoritativeCommand::ActivateFederationGrantAssignment(
            ActivateFederationGrantAssignment {
                activation_id: ActivationId::from_bytes(decoder.identifier()?)?,
                principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
                assignment_id: FederationAssignmentId::from_bytes(decoder.identifier()?)?,
                policy_id: ActivationPolicyId::from_bytes(decoder.identifier()?)?,
                reason: decoder.text(512)?,
                duration: DurationMicros::new(decoder.u64()?),
                session_expires_at: UnixMicros::new(decoder.i64()?),
                assurance: decode_assurance(decoder.u8()?)?,
                authentication_digest: decoder.fixed()?,
            },
        ),
        REVOKE_ACTIVATION => AuthoritativeCommand::RevokeFederationGrantAssignmentActivation(
            RevokeFederationGrantAssignmentActivation {
                activation_id: ActivationId::from_bytes(decoder.identifier()?)?,
                principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
                reason: decoder.text(512)?,
            },
        ),
        _ => return Err(MetadataCommandCodecError::Unsupported),
    })
}
