// SPDX-License-Identifier: GPL-2.0-only

use super::{MAXIMUM_COMMAND_BYTES, MetadataCommandCodecError, decoder::Decoder, encoder::Encoder};
use crate::{
    AuthoritativeCommand, AuthoritativeCommandContext, NodeCapabilityPrior, NodeCommandContext,
    RefreshNodeCapabilities,
};
use meshspan_domain::{AuditEventId, NodeId, OperationId, Revision, UnixMicros};

const MAGIC: [u8; 4] = *b"MSN\x01";

/// One authoritative entry with an explicitly authenticated actor kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedAuthoritativeEntry {
    /// Context committed in the canonical envelope.
    pub context: AuthoritativeCommandContext,
    /// Typed command applied by the shared transaction pipeline.
    pub command: AuthoritativeCommand,
}

/// Whether the exact metadata command version has a compatibility decoder.
#[must_use]
pub const fn is_supported_metadata_command_version(version: u16) -> bool {
    matches!(version, 18..=20)
}

/// Decodes a closed supported version without treating new commands as historical entries.
///
/// # Errors
/// Rejects unknown versions, malformed input and commands newer than the declared version.
pub fn decode_authoritative_entry_for_version(
    version: u16,
    bytes: &[u8],
) -> Result<DecodedAuthoritativeEntry, MetadataCommandCodecError> {
    if !is_supported_metadata_command_version(version) {
        return Err(MetadataCommandCodecError::Unsupported);
    }
    if bytes.starts_with(&MAGIC) {
        if version < 19 {
            return Err(MetadataCommandCodecError::Unsupported);
        }
        return decode_node(bytes);
    }
    let decoded = super::decode_authoritative_command(bytes)?;
    if version < 20 && matches!(decoded.command, AuthoritativeCommand::PlanShardRepair(_)) {
        return Err(MetadataCommandCodecError::Unsupported);
    }
    if version == 18
        && matches!(
            decoded.command,
            AuthoritativeCommand::IssueUserEnrollment(_)
                | AuthoritativeCommand::RevokeUserEnrollment(_)
                | AuthoritativeCommand::RedeemUserEnrollment(_)
                | AuthoritativeCommand::RefreshNodeCapabilities(_)
        )
    {
        return Err(MetadataCommandCodecError::Unsupported);
    }
    Ok(DecodedAuthoritativeEntry {
        context: AuthoritativeCommandContext::Principal(decoded.context),
        command: decoded.command,
    })
}

/// Encodes the narrow node command envelope without inventing a principal actor.
///
/// # Errors
/// Rejects commands outside the node self-report family and malformed bounded input.
pub fn encode_authoritative_node_command(
    context: NodeCommandContext,
    command: &AuthoritativeCommand,
) -> Result<Vec<u8>, MetadataCommandCodecError> {
    let AuthoritativeCommand::RefreshNodeCapabilities(value) = command else {
        return Err(MetadataCommandCodecError::Unsupported);
    };
    if context.actor_node_id != value.node_id {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let mut encoder = Encoder::new(MAXIMUM_COMMAND_BYTES);
    encoder.fixed(&MAGIC)?;
    encoder.identifier(context.operation_id.as_bytes())?;
    encoder.identifier(context.actor_node_id.as_bytes())?;
    encoder.identifier(context.audit_event_id.as_bytes())?;
    encoder.i64(context.occurred_at.get())?;
    encoder.optional_u64(context.expected_revision.map(Revision::get))?;
    encode(&mut encoder, value)?;
    Ok(encoder.finish())
}

fn decode_node(bytes: &[u8]) -> Result<DecodedAuthoritativeEntry, MetadataCommandCodecError> {
    if bytes.len() > MAXIMUM_COMMAND_BYTES {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.fixed::<4>()? != MAGIC {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let context = NodeCommandContext {
        operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        actor_node_id: NodeId::from_bytes(decoder.identifier()?)?,
        audit_event_id: AuditEventId::from_bytes(decoder.identifier()?)?,
        occurred_at: UnixMicros::new(decoder.i64()?),
        expected_revision: decoder.optional_u64()?.map(Revision::new),
    };
    if decoder.u16()? != 138 {
        return Err(MetadataCommandCodecError::Unsupported);
    }
    let value = decode(&mut decoder)?;
    decoder.finish()?;
    let command = AuthoritativeCommand::RefreshNodeCapabilities(value);
    if encode_authoritative_node_command(context, &command)? != bytes {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(DecodedAuthoritativeEntry {
        context: AuthoritativeCommandContext::Node(context),
        command,
    })
}

pub(super) fn encode(
    encoder: &mut Encoder,
    value: &RefreshNodeCapabilities,
) -> Result<(), MetadataCommandCodecError> {
    if value.incarnation == 0
        || value.certificate_generation == 0
        || value.certificate_fingerprint == [0; 32]
        || value.capability_digest == [0; 32]
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.u16(138)?;
    encoder.identifier(value.node_id.as_bytes())?;
    encoder.u64(value.incarnation)?;
    encoder.u64(value.certificate_generation)?;
    encoder.fixed(&value.certificate_fingerprint)?;
    encoder.fixed(&value.capability_digest)?;
    match value.prior {
        NodeCapabilityPrior::ExistingPresentation {
            revision,
            capability_digest,
        } => {
            encoder.u8(1)?;
            encoder.u64(revision.get())?;
            encoder.fixed(&capability_digest)
        }
        NodeCapabilityPrior::InitialActivation {
            revision,
            capability_digest,
        } => {
            encoder.u8(2)?;
            encoder.u64(revision.get())?;
            encoder.fixed(&capability_digest)
        }
        NodeCapabilityPrior::InitialAdmittedCertificate {
            revision,
            generation,
            certificate_fingerprint,
        } => {
            encoder.u8(3)?;
            encoder.u64(revision.get())?;
            encoder.u64(generation)?;
            encoder.fixed(&certificate_fingerprint)
        }
    }
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<RefreshNodeCapabilities, MetadataCommandCodecError> {
    let node_id = NodeId::from_bytes(decoder.identifier()?)?;
    let incarnation = decoder.u64()?;
    let certificate_generation = decoder.u64()?;
    let certificate_fingerprint = decoder.fixed()?;
    let capability_digest = decoder.fixed()?;
    let prior = match decoder.u8()? {
        1 => NodeCapabilityPrior::ExistingPresentation {
            revision: Revision::new(decoder.u64()?),
            capability_digest: decoder.fixed()?,
        },
        2 => NodeCapabilityPrior::InitialActivation {
            revision: Revision::new(decoder.u64()?),
            capability_digest: decoder.fixed()?,
        },
        3 => NodeCapabilityPrior::InitialAdmittedCertificate {
            revision: Revision::new(decoder.u64()?),
            generation: decoder.u64()?,
            certificate_fingerprint: decoder.fixed()?,
        },
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    Ok(RefreshNodeCapabilities {
        node_id,
        incarnation,
        certificate_generation,
        certificate_fingerprint,
        capability_digest,
        prior,
    })
}
