// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{NodeId, ObjectId, SmbExportId, VolumeId};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{PublishSmbExport, RecordName, SmbExportGatewaySelection, WithdrawSmbExport};

pub(super) const PUBLISH_SMB_EXPORT: u16 = 24;
pub(super) const WITHDRAW_SMB_EXPORT: u16 = 25;
const MAXIMUM_SHARE_NAME_BYTES: usize = 240;
const MAXIMUM_GATEWAYS: usize = 1_024;
const MAXIMUM_REASON_BYTES: usize = 1_024;

pub(super) fn encode_publish(
    encoder: &mut Encoder,
    value: &PublishSmbExport,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(PUBLISH_SMB_EXPORT)?;
    encoder.identifier(value.export_id.as_bytes())?;
    encoder.identifier(value.volume_id.as_bytes())?;
    encoder.identifier(value.root_object_id.as_bytes())?;
    encoder.text(value.share_name.display(), MAXIMUM_SHARE_NAME_BYTES)?;
    match &value.gateways {
        SmbExportGatewaySelection::AllEligible => encoder.u8(1)?,
        SmbExportGatewaySelection::Selected(nodes) => {
            if nodes.as_slice().is_empty() || nodes.as_slice().len() > MAXIMUM_GATEWAYS {
                return Err(MetadataCommandCodecError::Invalid);
            }
            encoder.u8(2)?;
            encoder.u16(
                u16::try_from(nodes.as_slice().len())
                    .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
            )?;
            for node in nodes.as_slice() {
                encoder.identifier(node.as_bytes())?;
            }
        }
    }
    encoder.bool(value.encryption_required)
}

pub(super) fn decode_publish(
    decoder: &mut Decoder<'_>,
) -> Result<PublishSmbExport, MetadataCommandCodecError> {
    let export_id = SmbExportId::from_bytes(decoder.identifier()?)?;
    let volume_id = VolumeId::from_bytes(decoder.identifier()?)?;
    let root_object_id = ObjectId::from_bytes(decoder.identifier()?)?;
    let share_name = RecordName::new(&decoder.text(MAXIMUM_SHARE_NAME_BYTES)?)?;
    let gateways = match decoder.u8()? {
        1 => SmbExportGatewaySelection::AllEligible,
        2 => {
            let count = usize::from(decoder.u16()?);
            if count == 0 || count > MAXIMUM_GATEWAYS {
                return Err(MetadataCommandCodecError::Invalid);
            }
            let mut nodes = Vec::with_capacity(count);
            for _ in 0..count {
                nodes.push(NodeId::from_bytes(decoder.identifier()?)?);
            }
            SmbExportGatewaySelection::Selected(BoundedItems::new(nodes, MAXIMUM_GATEWAYS)?)
        }
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    Ok(PublishSmbExport {
        export_id,
        volume_id,
        root_object_id,
        share_name,
        gateways,
        encryption_required: decoder.bool()?,
    })
}

pub(super) fn encode_withdraw(
    encoder: &mut Encoder,
    value: &WithdrawSmbExport,
) -> Result<(), MetadataCommandCodecError> {
    if value.reason.trim().is_empty() {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.u16(WITHDRAW_SMB_EXPORT)?;
    encoder.identifier(value.export_id.as_bytes())?;
    encoder.text(&value.reason, MAXIMUM_REASON_BYTES)
}

pub(super) fn decode_withdraw(
    decoder: &mut Decoder<'_>,
) -> Result<WithdrawSmbExport, MetadataCommandCodecError> {
    let export_id = SmbExportId::from_bytes(decoder.identifier()?)?;
    let reason = decoder.text(MAXIMUM_REASON_BYTES)?;
    if reason.trim().is_empty() {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(WithdrawSmbExport { export_id, reason })
}
