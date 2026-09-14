// SPDX-License-Identifier: GPL-2.0-only

use super::{MetadataCommandCodecError, authentication, decoder::Decoder, encoder::Encoder};
use crate::{
    AuthoritativeCommand, IssueUserEnrollment, RedeemUserEnrollment, RevokeUserEnrollment,
};
use meshspan_domain::{OperationId, PrincipalId, Revision, UnixMicros};

pub(super) const ISSUE: u16 = 135;
pub(super) const REVOKE: u16 = 136;
pub(super) const REDEEM: u16 = 137;

pub(super) fn encode_command(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::IssueUserEnrollment(value) => encode_issue(encoder, value)?,
        AuthoritativeCommand::RevokeUserEnrollment(value) => encode_revoke(encoder, value)?,
        AuthoritativeCommand::RedeemUserEnrollment(value) => encode_redeem(encoder, value)?,
        _ => return Ok(false),
    }
    Ok(true)
}

fn encode_issue(
    encoder: &mut Encoder,
    value: &IssueUserEnrollment,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(ISSUE)?;
    encoder.identifier(value.principal_id.as_bytes())?;
    encoder.u64(value.expected_principal_revision.get())?;
    encoder.fixed(&value.token_digest)?;
    encoder.i64(value.expires_at.get())
}
fn encode_revoke(
    encoder: &mut Encoder,
    value: &RevokeUserEnrollment,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(REVOKE)?;
    encoder.identifier(value.enrollment_operation_id.as_bytes())?;
    encoder.u64(value.expected_revision.get())
}
fn encode_redeem(
    encoder: &mut Encoder,
    value: &RedeemUserEnrollment,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(REDEEM)?;
    encoder.identifier(value.enrollment_operation_id.as_bytes())?;
    encoder.fixed(&value.token_digest)?;
    authentication::encode_payload(encoder, &value.method)
}
pub(super) fn decode(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    match kind {
        ISSUE => Ok(AuthoritativeCommand::IssueUserEnrollment(
            IssueUserEnrollment {
                principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
                expected_principal_revision: Revision::new(decoder.u64()?),
                token_digest: decoder.fixed()?,
                expires_at: UnixMicros::new(decoder.i64()?),
            },
        )),
        REVOKE => Ok(AuthoritativeCommand::RevokeUserEnrollment(
            RevokeUserEnrollment {
                enrollment_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
                expected_revision: Revision::new(decoder.u64()?),
            },
        )),
        REDEEM => Ok(AuthoritativeCommand::RedeemUserEnrollment(
            RedeemUserEnrollment {
                enrollment_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
                token_digest: decoder.fixed()?,
                method: authentication::decode_payload(decoder)?,
            },
        )),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}
