// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::NodeId;
use meshspan_secret_envelope::WrappingPublicKey;

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::RegisterNodeWrappingKey;

pub(super) const REGISTER_NODE_WRAPPING_KEY: u16 = 13;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: &RegisterNodeWrappingKey,
) -> Result<(), MetadataCommandCodecError> {
    validate(value)?;
    encoder.u16(REGISTER_NODE_WRAPPING_KEY)?;
    encoder.identifier(value.node_id.as_bytes())?;
    encoder.u64(value.generation)?;
    encoder.fixed(&value.public_key)?;
    encoder.fixed(&value.key_fingerprint)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<RegisterNodeWrappingKey, MetadataCommandCodecError> {
    let value = RegisterNodeWrappingKey {
        node_id: NodeId::from_bytes(decoder.identifier()?)?,
        generation: decoder.u64()?,
        public_key: decoder.fixed()?,
        key_fingerprint: decoder.fixed()?,
    };
    validate(&value)?;
    Ok(value)
}

fn validate(value: &RegisterNodeWrappingKey) -> Result<(), MetadataCommandCodecError> {
    let public_key = WrappingPublicKey::from_bytes(value.public_key)
        .map_err(|_| MetadataCommandCodecError::Invalid)?;
    if value.generation == 0 || public_key.fingerprint() != value.key_fingerprint {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}
