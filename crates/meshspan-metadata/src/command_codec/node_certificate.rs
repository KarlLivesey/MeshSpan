// SPDX-License-Identifier: GPL-2.0-only

use super::{MetadataCommandCodecError, decoder::Decoder, encoder::Encoder};
use crate::{
    AcknowledgeNodeCertificateInstallation, AuthoritativeCommand, RetireNodeCertificate,
    StageNodeCertificate,
};
use meshspan_domain::{NodeId, Revision, UnixMicros};

pub(super) const STAGE: u16 = 77;
pub(super) const ACKNOWLEDGE: u16 = 78;
pub(super) const RETIRE: u16 = 79;

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::StageNodeCertificate(value) => {
            encoder.u16(STAGE)?;
            encoder.identifier(value.node_id.as_bytes())?;
            encoder.u64(value.incarnation)?;
            encoder.u64(value.previous_generation)?;
            encoder.u64(value.generation)?;
            encoder.u64(value.issuer_generation)?;
            encoder.bytes(&value.certificate_der, 65_536)?;
            encoder.i64(value.valid_from.get())?;
            encoder.i64(value.valid_until.get())?;
        }
        AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(value) => {
            encoder.u16(ACKNOWLEDGE)?;
            encoder.identifier(value.node_id.as_bytes())?;
            encoder.u64(value.incarnation)?;
            encoder.u64(value.generation)?;
            encoder.fixed(&value.certificate_fingerprint)?;
            encoder.u64(value.staged_revision.get())?;
            encoder.bytes(&value.signature, 72)?;
        }
        AuthoritativeCommand::RetireNodeCertificate(value) => {
            encoder.u16(RETIRE)?;
            encoder.identifier(value.node_id.as_bytes())?;
            encoder.u64(value.incarnation)?;
            encoder.u64(value.generation)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decode(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    let node_id = NodeId::from_bytes(decoder.identifier()?)?;
    let incarnation = decoder.u64()?;
    let generation = decoder.u64()?;
    if incarnation == 0 || generation == 0 || generation >= i64::MAX as u64 {
        return Err(MetadataCommandCodecError::Invalid);
    }
    match kind {
        STAGE => {
            let value = StageNodeCertificate {
                node_id,
                incarnation,
                previous_generation: generation,
                generation: decoder.u64()?,
                issuer_generation: decoder.u64()?,
                certificate_der: decoder.bytes(65_536)?,
                valid_from: UnixMicros::new(decoder.i64()?),
                valid_until: UnixMicros::new(decoder.i64()?),
            };
            if value.generation <= value.previous_generation
                || value.issuer_generation == 0
                || value.certificate_der.is_empty()
                || value.valid_from.get() < 0
                || value.valid_until <= value.valid_from
            {
                return Err(MetadataCommandCodecError::Invalid);
            }
            Ok(AuthoritativeCommand::StageNodeCertificate(value))
        }
        ACKNOWLEDGE => {
            let value = AcknowledgeNodeCertificateInstallation {
                node_id,
                incarnation,
                generation,
                certificate_fingerprint: decoder.fixed()?,
                staged_revision: Revision::new(decoder.u64()?),
                signature: decoder.bytes(72)?,
            };
            if value.staged_revision == Revision::ZERO
                || value.signature.is_empty()
                || value.certificate_fingerprint == [0; 32]
            {
                return Err(MetadataCommandCodecError::Invalid);
            }
            Ok(AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(value))
        }
        RETIRE => Ok(AuthoritativeCommand::RetireNodeCertificate(
            RetireNodeCertificate {
                node_id,
                incarnation,
                generation,
            },
        )),
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}
