// SPDX-License-Identifier: GPL-2.0-only

//! Complete grant definitions and their immutable replacement/revocation commands.

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::repository::{decode_grant_definition, encode_grant_definition};
use crate::{
    AuthoritativeCommand, IssueFederationGrant, ReplaceFederationGrant, RevokeFederationGrant,
};
use meshspan_domain::FederationGrantId;

const ISSUE: u16 = 98;
const REPLACE: u16 = 99;
const REVOKE: u16 = 100;
const MAXIMUM_DEFINITION_BYTES: usize = 16_384;

pub(super) fn is_kind(kind: u16) -> bool {
    (ISSUE..=REVOKE).contains(&kind)
}

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::IssueFederationGrant(value) => {
            encoder.u16(ISSUE)?;
            encode_definition(encoder, value)?;
        }
        AuthoritativeCommand::ReplaceFederationGrant(value) => {
            encoder.u16(REPLACE)?;
            encoder.identifier(value.predecessor_grant_id.as_bytes())?;
            encode_definition(
                encoder,
                &IssueFederationGrant {
                    grant: value.grant.clone(),
                    restrictions: value.restrictions.clone(),
                },
            )?;
            encoder.bool(value.restricts_authority)?;
            encoder.text(&value.reason, 512)?;
        }
        AuthoritativeCommand::RevokeFederationGrant(value) => {
            encoder.u16(REVOKE)?;
            encoder.identifier(value.grant_id.as_bytes())?;
            encoder.u64(value.expected_authority_epoch)?;
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
        ISSUE => AuthoritativeCommand::IssueFederationGrant(decode_definition(decoder)?),
        REPLACE => {
            let predecessor_grant_id = FederationGrantId::from_bytes(decoder.identifier()?)?;
            let definition = decode_definition(decoder)?;
            AuthoritativeCommand::ReplaceFederationGrant(ReplaceFederationGrant {
                predecessor_grant_id,
                grant: definition.grant,
                restrictions: definition.restrictions,
                restricts_authority: decoder.bool()?,
                reason: decoder.text(512)?,
            })
        }
        REVOKE => AuthoritativeCommand::RevokeFederationGrant(RevokeFederationGrant {
            grant_id: FederationGrantId::from_bytes(decoder.identifier()?)?,
            expected_authority_epoch: decoder.u64()?,
            reason: decoder.text(512)?,
        }),
        _ => return Err(MetadataCommandCodecError::Unsupported),
    })
}

fn encode_definition(
    encoder: &mut Encoder,
    value: &IssueFederationGrant,
) -> Result<(), MetadataCommandCodecError> {
    let bytes = encode_grant_definition(value).map_err(|_| MetadataCommandCodecError::Invalid)?;
    encoder.bytes(&bytes, MAXIMUM_DEFINITION_BYTES)
}

fn decode_definition(
    decoder: &mut Decoder<'_>,
) -> Result<IssueFederationGrant, MetadataCommandCodecError> {
    decode_grant_definition(&decoder.bytes(MAXIMUM_DEFINITION_BYTES)?)
        .map_err(|_| MetadataCommandCodecError::Invalid)
}
