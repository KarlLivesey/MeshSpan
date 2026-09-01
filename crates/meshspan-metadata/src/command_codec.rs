// SPDX-License-Identifier: GPL-2.0-only

//! Bounded canonical bytes for authoritative commands carried by consensus.

mod bootstrap;
mod decoder;
mod encoder;

use meshspan_domain::{AuditEventId, OperationId, PrincipalId, Revision, UnixMicros};
use thiserror::Error;

use self::decoder::Decoder;
use self::encoder::Encoder;
use crate::{AuthoritativeCommand, CommandContext};

/// First closed metadata-command wire format.
pub const METADATA_COMMAND_VERSION: u16 = 1;

const MAGIC: [u8; 4] = *b"MSC\x01";
const MAXIMUM_COMMAND_BYTES: usize = 1024 * 1024;

/// One completely decoded replicated state-machine input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedAuthoritativeCommand {
    /// Context committed with the command rather than reconstructed at apply time.
    pub context: CommandContext,
    /// Validated typed command.
    pub command: AuthoritativeCommand,
}

/// Encodes one supported command into deterministic, bounded bytes.
///
/// # Errors
///
/// Rejects unsupported command families and values exceeding the closed format's bounds.
pub fn encode_authoritative_command(
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<Vec<u8>, MetadataCommandCodecError> {
    let mut encoder = Encoder::new(MAXIMUM_COMMAND_BYTES);
    encoder.fixed(&MAGIC)?;
    encoder.identifier(context.operation_id.as_bytes())?;
    encoder.identifier(context.actor_principal_id.as_bytes())?;
    encoder.identifier(context.audit_event_id.as_bytes())?;
    encoder.i64(context.occurred_at.get())?;
    encoder.optional_u64(context.expected_revision.map(Revision::get))?;
    bootstrap::encode(&mut encoder, command)?;
    Ok(encoder.finish())
}

/// Decodes one exact closed-format command and rejects trailing or non-canonical input.
///
/// # Errors
///
/// Rejects malformed, oversized, unsupported or semantically invalid input.
pub fn decode_authoritative_command(
    bytes: &[u8],
) -> Result<DecodedAuthoritativeCommand, MetadataCommandCodecError> {
    if bytes.len() > MAXIMUM_COMMAND_BYTES {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.fixed::<4>()? != MAGIC {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let operation_id = OperationId::from_bytes(decoder.identifier()?)?;
    let actor_principal_id = PrincipalId::from_bytes(decoder.identifier()?)?;
    let audit_event_id = AuditEventId::from_bytes(decoder.identifier()?)?;
    let occurred_at = UnixMicros::new(decoder.i64()?);
    let expected_revision = decoder.optional_u64()?.map(Revision::new);
    let command = bootstrap::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(DecodedAuthoritativeCommand {
        context: CommandContext {
            operation_id,
            actor_principal_id,
            audit_event_id,
            occurred_at,
            expected_revision,
        },
        command,
    })
}

/// Closed failures for hostile replicated command bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MetadataCommandCodecError {
    /// Bytes are truncated, non-canonical or semantically invalid.
    #[error("metadata command bytes are invalid")]
    Invalid,
    /// The typed command family has no representation in this codec version.
    #[error("metadata command is not supported by this codec version")]
    Unsupported,
    /// A bounded field or the complete command exceeds its maximum.
    #[error("metadata command exceeds a format bound")]
    CapacityExceeded,
}

impl From<meshspan_domain::IdentifierError> for MetadataCommandCodecError {
    fn from(_: meshspan_domain::IdentifierError) -> Self {
        Self::Invalid
    }
}

impl From<crate::RecordNameError> for MetadataCommandCodecError {
    fn from(_: crate::RecordNameError) -> Self {
        Self::Invalid
    }
}

#[cfg(test)]
mod tests;
