// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{HostId, JoinGrantId, NodeId, UnixMicros};
use meshspan_secret_envelope::WrappingPublicKey;
use sha2::{Digest, Sha256};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{ActivateNode, ConsumeJoinGrant, IssueJoinGrant, JoinRoles, RecordName};

pub(super) const ISSUE_JOIN_GRANT: u16 = 16;
pub(super) const CONSUME_JOIN_GRANT: u16 = 17;
pub(super) const ACTIVATE_NODE: u16 = 18;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_ENDPOINT_BYTES: usize = 512;
const MAXIMUM_CERTIFICATE_BYTES: usize = 64 * 1_024;

pub(super) fn encode_issue(
    encoder: &mut Encoder,
    value: &IssueJoinGrant,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(ISSUE_JOIN_GRANT)?;
    encoder.identifier(value.join_grant_id.as_bytes())?;
    encoder.fixed(&value.secret_digest)?;
    encoder.u8(value.allowed_roles.bits())?;
    encoder.u16(value.maximum_uses)?;
    encoder.i64(value.expires_at.get())
}

pub(super) fn decode_issue(
    decoder: &mut Decoder<'_>,
) -> Result<IssueJoinGrant, MetadataCommandCodecError> {
    let value = IssueJoinGrant {
        join_grant_id: JoinGrantId::from_bytes(decoder.identifier()?)?,
        secret_digest: decoder.fixed()?,
        allowed_roles: JoinRoles::new(decoder.u8()?)?,
        maximum_uses: decoder.u16()?,
        expires_at: UnixMicros::new(decoder.i64()?),
    };
    if value.secret_digest == [0; 32] || !(1..=1_000).contains(&value.maximum_uses) {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(value)
    }
}

pub(super) fn encode_consume(
    encoder: &mut Encoder,
    value: &ConsumeJoinGrant,
) -> Result<(), MetadataCommandCodecError> {
    validate_consume(value)?;
    encoder.u16(CONSUME_JOIN_GRANT)?;
    encoder.identifier(value.join_grant_id.as_bytes())?;
    encoder.fixed(&value.secret_digest)?;
    encoder.identifier(value.host_id.as_bytes())?;
    encode_optional_name(encoder, value.new_host_name.as_ref())?;
    encoder.identifier(value.node_id.as_bytes())?;
    encoder.text(value.node_name.display(), MAXIMUM_NAME_BYTES)?;
    encoder.u64(value.incarnation)?;
    encoder.u8(value.requested_roles.bits())?;
    encoder.fixed(&value.wrapping_public_key)?;
    encoder.text(&value.private_endpoint, MAXIMUM_ENDPOINT_BYTES)?;
    encoder.bytes(&value.certificate_der, MAXIMUM_CERTIFICATE_BYTES)?;
    encoder.fixed(&value.certificate_fingerprint)?;
    encoder.i64(value.certificate_valid_until.get())
}

pub(super) fn decode_consume(
    decoder: &mut Decoder<'_>,
) -> Result<ConsumeJoinGrant, MetadataCommandCodecError> {
    let value = ConsumeJoinGrant {
        join_grant_id: JoinGrantId::from_bytes(decoder.identifier()?)?,
        secret_digest: decoder.fixed()?,
        host_id: HostId::from_bytes(decoder.identifier()?)?,
        new_host_name: decode_optional_name(decoder)?,
        node_id: NodeId::from_bytes(decoder.identifier()?)?,
        node_name: RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)?,
        incarnation: decoder.u64()?,
        requested_roles: JoinRoles::new(decoder.u8()?)?,
        wrapping_public_key: decoder.fixed()?,
        private_endpoint: decoder.text(MAXIMUM_ENDPOINT_BYTES)?,
        certificate_der: decoder.bytes(MAXIMUM_CERTIFICATE_BYTES)?,
        certificate_fingerprint: decoder.fixed()?,
        certificate_valid_until: UnixMicros::new(decoder.i64()?),
    };
    validate_consume(&value)?;
    Ok(value)
}

pub(super) fn encode_activate(
    encoder: &mut Encoder,
    value: &ActivateNode,
) -> Result<(), MetadataCommandCodecError> {
    validate_activate(value)?;
    encoder.u16(ACTIVATE_NODE)?;
    encoder.identifier(value.node_id.as_bytes())?;
    encoder.u64(value.incarnation)?;
    encoder.text(&value.private_endpoint, MAXIMUM_ENDPOINT_BYTES)?;
    encoder.fixed(&value.capability_digest)
}

pub(super) fn decode_activate(
    decoder: &mut Decoder<'_>,
) -> Result<ActivateNode, MetadataCommandCodecError> {
    let value = ActivateNode {
        node_id: NodeId::from_bytes(decoder.identifier()?)?,
        incarnation: decoder.u64()?,
        private_endpoint: decoder.text(MAXIMUM_ENDPOINT_BYTES)?,
        capability_digest: decoder.fixed()?,
    };
    validate_activate(&value)?;
    Ok(value)
}

fn encode_optional_name(
    encoder: &mut Encoder,
    value: Option<&RecordName>,
) -> Result<(), MetadataCommandCodecError> {
    match value {
        Some(value) => {
            encoder.bool(true)?;
            encoder.text(value.display(), MAXIMUM_NAME_BYTES)
        }
        None => encoder.bool(false),
    }
}

fn decode_optional_name(
    decoder: &mut Decoder<'_>,
) -> Result<Option<RecordName>, MetadataCommandCodecError> {
    if decoder.bool()? {
        RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)
            .map(Some)
            .map_err(Into::into)
    } else {
        Ok(None)
    }
}

fn validate_consume(value: &ConsumeJoinGrant) -> Result<(), MetadataCommandCodecError> {
    WrappingPublicKey::from_bytes(value.wrapping_public_key)
        .map_err(|_| MetadataCommandCodecError::Invalid)?;
    if value.secret_digest == [0; 32]
        || value.incarnation == 0
        || value.private_endpoint.is_empty()
        || value.certificate_der.is_empty()
        || value.certificate_fingerprint != <[u8; 32]>::from(Sha256::digest(&value.certificate_der))
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_activate(value: &ActivateNode) -> Result<(), MetadataCommandCodecError> {
    if value.incarnation == 0
        || value.private_endpoint.is_empty()
        || value.capability_digest == [0; 32]
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}
