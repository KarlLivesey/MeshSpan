// SPDX-License-Identifier: GPL-2.0-only

//! Admission and quarantine preserve the same signed remote acknowledgement.

mod evidence;

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{
    AdmitFederatedMutation, AuthoritativeCommand, FederationQuarantineResolution,
    ResolveFederatedMutationQuarantine, RetainFederatedMutationQuarantine,
    SurfaceFederatedMutationQuarantine,
};
use meshspan_domain::{NamespaceCommitId, OperationId, QuarantineId};

const RETAIN: u16 = 112;
const ADMIT: u16 = 113;
const SURFACE: u16 = 114;
const RESOLVE: u16 = 115;

pub(super) fn is_kind(kind: u16) -> bool {
    (RETAIN..=RESOLVE).contains(&kind)
}

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::RetainFederatedMutationQuarantine(value) => {
            encoder.u16(RETAIN)?;
            encoder.identifier(value.quarantine_id.as_bytes())?;
            evidence::encode(encoder, &value.acknowledgement)?;
        }
        AuthoritativeCommand::AdmitFederatedMutation(value) => {
            encoder.u16(ADMIT)?;
            encoder.identifier(value.namespace_commit_id.as_bytes())?;
            evidence::encode(encoder, &value.acknowledgement)?;
        }
        AuthoritativeCommand::SurfaceFederatedMutationQuarantine(value) => {
            encoder.u16(SURFACE)?;
            encoder.identifier(value.quarantine_id.as_bytes())?;
            encoder.identifier(value.source_operation_id.as_bytes())?;
        }
        AuthoritativeCommand::ResolveFederatedMutationQuarantine(value) => {
            encoder.u16(RESOLVE)?;
            encoder.identifier(value.quarantine_id.as_bytes())?;
            encoder.identifier(value.source_operation_id.as_bytes())?;
            encoder.u8(value.resolution.code())?;
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
        RETAIN => AuthoritativeCommand::RetainFederatedMutationQuarantine(
            RetainFederatedMutationQuarantine {
                quarantine_id: QuarantineId::from_bytes(decoder.identifier()?)?,
                acknowledgement: evidence::decode(decoder)?,
            },
        ),
        ADMIT => AuthoritativeCommand::AdmitFederatedMutation(AdmitFederatedMutation {
            namespace_commit_id: NamespaceCommitId::from_bytes(decoder.identifier()?)?,
            acknowledgement: evidence::decode(decoder)?,
        }),
        SURFACE => AuthoritativeCommand::SurfaceFederatedMutationQuarantine(
            SurfaceFederatedMutationQuarantine {
                quarantine_id: QuarantineId::from_bytes(decoder.identifier()?)?,
                source_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
            },
        ),
        RESOLVE => AuthoritativeCommand::ResolveFederatedMutationQuarantine(
            ResolveFederatedMutationQuarantine {
                quarantine_id: QuarantineId::from_bytes(decoder.identifier()?)?,
                source_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
                resolution: match decoder.u8()? {
                    1 => FederationQuarantineResolution::Restore,
                    2 => FederationQuarantineResolution::RestoreAsCopy,
                    3 => FederationQuarantineResolution::Discard,
                    _ => return Err(MetadataCommandCodecError::Invalid),
                },
                reason: decoder.text(512)?,
            },
        ),
        _ => return Err(MetadataCommandCodecError::Unsupported),
    })
}
