// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{ObjectId, OwnerSetId, PrincipalId, VolumeId};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use super::secret_generation;
use crate::{CreateVolume, RecordName};

pub(super) const CREATE_VOLUME: u16 = 11;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_OWNERS: usize = 1_024;

pub(super) fn encode_volume(
    encoder: &mut Encoder,
    value: &CreateVolume,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(CREATE_VOLUME)?;
    encoder.identifier(value.volume_id.as_bytes())?;
    encoder.text(value.name.display(), MAXIMUM_NAME_BYTES)?;
    encoder.identifier(value.root_object_id.as_bytes())?;
    encoder.identifier(value.owner_set_id.as_bytes())?;
    let owner_count = u16::try_from(value.owners.len())
        .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?;
    if owner_count == 0 || usize::from(owner_count) > MAXIMUM_OWNERS {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    encoder.u16(owner_count)?;
    for owner in value.owners.as_slice() {
        encoder.identifier(owner.as_bytes())?;
    }
    secret_generation::encode_payload(encoder, &value.key_generation)
}

pub(super) fn decode_volume(
    decoder: &mut Decoder<'_>,
) -> Result<CreateVolume, MetadataCommandCodecError> {
    let volume_id = VolumeId::from_bytes(decoder.identifier()?)?;
    let name = RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)?;
    let root_object_id = ObjectId::from_bytes(decoder.identifier()?)?;
    let owner_set_id = OwnerSetId::from_bytes(decoder.identifier()?)?;
    let owner_count = usize::from(decoder.u16()?);
    if owner_count == 0 || owner_count > MAXIMUM_OWNERS {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut owners = Vec::with_capacity(owner_count);
    for _ in 0..owner_count {
        owners.push(PrincipalId::from_bytes(decoder.identifier()?)?);
    }
    let key_generation = Box::new(secret_generation::decode_payload(decoder)?);
    Ok(CreateVolume {
        volume_id,
        name,
        root_object_id,
        owner_set_id,
        owners: BoundedItems::new(owners, MAXIMUM_OWNERS)?,
        key_generation,
    })
}
