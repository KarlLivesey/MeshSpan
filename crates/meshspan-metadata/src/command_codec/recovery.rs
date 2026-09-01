// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::MeshId;

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::ConfirmRecoveryBundleSaved;

pub(super) const CONFIRM_RECOVERY_BUNDLE_SAVED: u16 = 15;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: ConfirmRecoveryBundleSaved,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(CONFIRM_RECOVERY_BUNDLE_SAVED)?;
    encoder.identifier(value.mesh_id.as_bytes())?;
    encoder.fixed(&value.bundle_digest)?;
    encoder.fixed(&value.save_challenge_commitment)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<ConfirmRecoveryBundleSaved, MetadataCommandCodecError> {
    Ok(ConfirmRecoveryBundleSaved {
        mesh_id: MeshId::from_bytes(decoder.identifier()?)?,
        bundle_digest: decoder.fixed()?,
        save_challenge_commitment: decoder.fixed()?,
    })
}
