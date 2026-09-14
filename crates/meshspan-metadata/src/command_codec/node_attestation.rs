// SPDX-License-Identifier: GPL-2.0-only

//! Register node-owned evidence signing keys through the canonical consensus path.

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::RegisterCleanupAttestationKey;
use meshspan_domain::NodeId;

pub(super) const REGISTER: u16 = 123;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: RegisterCleanupAttestationKey,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(REGISTER)?;
    encoder.identifier(value.node_id.as_bytes())?;
    encoder.u64(value.generation)?;
    encoder.fixed(&value.verifying_key)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<RegisterCleanupAttestationKey, MetadataCommandCodecError> {
    Ok(RegisterCleanupAttestationKey {
        node_id: NodeId::from_bytes(decoder.identifier()?)?,
        generation: decoder.u64()?,
        verifying_key: decoder.fixed()?,
    })
}
