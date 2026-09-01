// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{ComponentInstanceId, HostId, NodeId, TargetId};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{CreateComponent, RecordName, RegisterStorageTarget, StorageUsageLimit};

pub(super) const REGISTER_STORAGE_TARGET: u16 = 12;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_IMPLEMENTATION_ID_BYTES: usize = 80;
const MAXIMUM_CONFIGURATION_BYTES: usize = 512 * 1_024;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: &RegisterStorageTarget,
) -> Result<(), MetadataCommandCodecError> {
    value.usage_limit.validate()?;
    value.provider.validate_shape(MAXIMUM_CONFIGURATION_BYTES)?;
    validate_fingerprints(value)?;
    if value.generation == 0 {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.u16(REGISTER_STORAGE_TARGET)?;
    encoder.identifier(value.target_id.as_bytes())?;
    encoder.identifier(value.node_id.as_bytes())?;
    encoder.identifier(value.host_id.as_bytes())?;
    encode_provider(encoder, &value.provider)?;
    encoder.text(value.name.display(), MAXIMUM_NAME_BYTES)?;
    encoder.u64(value.generation)?;
    encoder.fixed(&value.marker_fingerprint)?;
    encode_optional_fingerprint(encoder, value.backing_device_fingerprint)?;
    encode_optional_fingerprint(encoder, value.filesystem_fingerprint)?;
    match value.usage_limit {
        StorageUsageLimit::Percent(percent) => {
            encoder.u8(1)?;
            encoder.u64(u64::from(percent))
        }
        StorageUsageLimit::Bytes(bytes) => {
            encoder.u8(2)?;
            encoder.u64(bytes)
        }
    }
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<RegisterStorageTarget, MetadataCommandCodecError> {
    let value = RegisterStorageTarget {
        target_id: TargetId::from_bytes(decoder.identifier()?)?,
        node_id: NodeId::from_bytes(decoder.identifier()?)?,
        host_id: HostId::from_bytes(decoder.identifier()?)?,
        provider: decode_provider(decoder)?,
        name: RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)?,
        generation: decoder.u64()?,
        marker_fingerprint: decoder.fixed()?,
        backing_device_fingerprint: decode_optional_fingerprint(decoder)?,
        filesystem_fingerprint: decode_optional_fingerprint(decoder)?,
        usage_limit: match decoder.u8()? {
            1 => StorageUsageLimit::Percent(
                u8::try_from(decoder.u64()?).map_err(|_| MetadataCommandCodecError::Invalid)?,
            ),
            2 => StorageUsageLimit::Bytes(decoder.u64()?),
            _ => return Err(MetadataCommandCodecError::Invalid),
        },
    };
    value.usage_limit.validate()?;
    value.provider.validate_shape(MAXIMUM_CONFIGURATION_BYTES)?;
    validate_fingerprints(&value)?;
    if value.generation == 0 {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(value)
}

fn encode_provider(
    encoder: &mut Encoder,
    provider: &CreateComponent,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(provider.instance_id.as_bytes())?;
    encoder.u8(provider.component_kind)?;
    encoder.text(provider.name.display(), MAXIMUM_NAME_BYTES)?;
    encoder.text(&provider.implementation_id, MAXIMUM_IMPLEMENTATION_ID_BYTES)?;
    encoder.u16(provider.contract_major)?;
    encoder.u16(provider.contract_minor)?;
    encoder.u64(u64::from(provider.schema_version))?;
    encoder.bytes(
        &provider.canonical_configuration,
        MAXIMUM_CONFIGURATION_BYTES,
    )?;
    encoder.fixed(&provider.configuration_digest)
}

fn decode_provider(
    decoder: &mut Decoder<'_>,
) -> Result<CreateComponent, MetadataCommandCodecError> {
    Ok(CreateComponent {
        instance_id: ComponentInstanceId::from_bytes(decoder.identifier()?)?,
        component_kind: decoder.u8()?,
        name: RecordName::new(&decoder.text(MAXIMUM_NAME_BYTES)?)?,
        implementation_id: decoder.text(MAXIMUM_IMPLEMENTATION_ID_BYTES)?,
        contract_major: decoder.u16()?,
        contract_minor: decoder.u16()?,
        schema_version: u32::try_from(decoder.u64()?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        canonical_configuration: decoder.bytes(MAXIMUM_CONFIGURATION_BYTES)?,
        configuration_digest: decoder.fixed()?,
    })
}

fn encode_optional_fingerprint(
    encoder: &mut Encoder,
    fingerprint: Option<[u8; 32]>,
) -> Result<(), MetadataCommandCodecError> {
    match fingerprint {
        Some(value) => {
            encoder.bool(true)?;
            encoder.fixed(&value)
        }
        None => encoder.bool(false),
    }
}

fn decode_optional_fingerprint(
    decoder: &mut Decoder<'_>,
) -> Result<Option<[u8; 32]>, MetadataCommandCodecError> {
    if decoder.bool()? {
        decoder.fixed().map(Some)
    } else {
        Ok(None)
    }
}

fn validate_fingerprints(value: &RegisterStorageTarget) -> Result<(), MetadataCommandCodecError> {
    if value.marker_fingerprint == [0; 32]
        || value.backing_device_fingerprint == Some([0; 32])
        || value.filesystem_fingerprint == Some([0; 32])
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}
