// SPDX-License-Identifier: GPL-2.0-only

//! Independently bounded voting-history bodies; control framing retains its negotiated limit.

use meshspan_protobuf::{DecodeLimits, Message as _};
use sha2::{Digest as _, Sha256};

use crate::v1::consensus_bulk_start::Metadata;
use crate::v1::control_envelope::Message;
use crate::v1::{
    ConsensusBulkEntries, ConsensusBulkReceipt, ConsensusBulkStart, ConsensusTransferSupport,
    ControlEnvelope,
};
use crate::validation::{
    valid_digest, valid_identifier, validate_control_envelope, validate_header, validate_position,
};
use crate::{WireContractError, WireLimits};

/// Maximum aggregate generic command bytes in one consensus transfer (metadata commands remain 1 MiB).
pub const MAXIMUM_CONSENSUS_COMMAND_BYTES: usize = 16 * 1024 * 1024;
/// Maximum records in one voting append or committed-prefix transfer.
pub const MAXIMUM_CONSENSUS_BULK_ENTRIES: usize = MAXIMUM_CONSENSUS_BULK_ENTRIES_U32 as usize;
const MAXIMUM_CONSENSUS_BULK_ENTRIES_U32: u32 = 64;
/// Aggregate command bytes plus bounded record/correlation headers.
pub const MAXIMUM_CONSENSUS_BULK_BODY_BYTES: usize = MAXIMUM_CONSENSUS_COMMAND_BYTES + 16 * 1024;

/// A reconstructed append/prefix validated against its exact bulk descriptor and body.
#[derive(Debug)]
pub struct ValidatedConsensusBulk(ControlEnvelope);

impl ValidatedConsensusBulk {
    /// Borrows the validated message without allocating a control frame.
    #[must_use]
    pub const fn as_inner(&self) -> &ControlEnvelope {
        &self.0
    }
}

/// Returns the exact locally implemented version and resource bounds.
#[must_use]
pub const fn consensus_transfer_support() -> ConsensusTransferSupport {
    ConsensusTransferSupport {
        format_version: 1,
        maximum_command_bytes: MAXIMUM_CONSENSUS_COMMAND_BYTES as u64,
        maximum_body_bytes: MAXIMUM_CONSENSUS_BULK_BODY_BYTES as u64,
        maximum_entries: MAXIMUM_CONSENSUS_BULK_ENTRIES_U32,
    }
}

/// Encodes a canonical bounded body after the caller has reserved its allocation budget.
///
/// # Errors
/// Rejects invalid identifiers, versions, record counts or aggregate command bytes.
pub fn encode_consensus_bulk_entries(
    body: &ConsensusBulkEntries,
) -> Result<Vec<u8>, WireContractError> {
    validate_body(body)?;
    let bytes = body
        .encode_to_vec()
        .map_err(|_| WireContractError::FrameTooLarge)?;
    if bytes.len() > MAXIMUM_CONSENSUS_BULK_BODY_BYTES {
        return Err(WireContractError::FrameTooLarge);
    }
    Ok(bytes)
}

/// Decodes and binds a body to its descriptor before returning any consensus message.
///
/// # Errors
/// Rejects malformed/noncanonical bodies, count/phase substitutions and invalid entry ordering.
/// Entry content digests and current mTLS authority are rechecked by the cluster adapter.
pub fn decode_consensus_bulk(
    start: ConsensusBulkStart,
    bytes: &[u8],
) -> Result<ValidatedConsensusBulk, WireContractError> {
    self::start(&start)?;
    if start.byte_length != bytes.len() as u64
        || Sha256::digest(bytes).as_slice() != start.body_digest
    {
        return Err(WireContractError::InvalidMessage);
    }
    let body = ConsensusBulkEntries::decode_with_limits(
        bytes,
        DecodeLimits {
            maximum_message_bytes: MAXIMUM_CONSENSUS_BULK_BODY_BYTES,
            maximum_field_bytes: MAXIMUM_CONSENSUS_BULK_BODY_BYTES,
            maximum_fields: 2048,
            maximum_repeated_items: MAXIMUM_CONSENSUS_BULK_ENTRIES,
            maximum_depth: 5,
        },
    )
    .map_err(|_| WireContractError::Malformed)?;
    if body.entries.len() != start.entry_count as usize
        || start
            .header
            .as_ref()
            .is_none_or(|header| header.request_id != body.request_id)
        || encode_consensus_bulk_entries(&body)? != bytes
    {
        return Err(WireContractError::InvalidMessage);
    }
    let message = match start.metadata.ok_or(WireContractError::InvalidMessage)? {
        Metadata::Append(mut append) => {
            append.entries = body.entries;
            Message::AppendRequest(append)
        }
        Metadata::Prefix(mut prefix) => {
            prefix.entries = body.entries;
            Message::CommittedPrefix(prefix)
        }
    };
    let envelope = ControlEnvelope {
        header: start.header,
        message: Some(message),
    };
    // Semantic command bounds only. This never encodes or accepts an enlarged control frame.
    validate_control_envelope(&envelope, semantic_limits()?)?;
    Ok(ValidatedConsensusBulk(envelope))
}

pub(crate) fn support(value: Option<&ConsensusTransferSupport>) -> Result<(), WireContractError> {
    if let Some(value) = value
        && (value.format_version == 0
            || value.maximum_command_bytes == 0
            || value.maximum_body_bytes < value.maximum_command_bytes
            || value.maximum_entries == 0)
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

pub(crate) fn start(value: &ConsensusBulkStart) -> Result<(), WireContractError> {
    validate_header(
        value
            .header
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?,
    )?;
    valid_digest(&value.body_digest)?;
    if value.format_version != 1
        || value.byte_length == 0
        || value.byte_length > MAXIMUM_CONSENSUS_BULK_BODY_BYTES as u64
        || value.entry_count == 0
        || value.entry_count > MAXIMUM_CONSENSUS_BULK_ENTRIES_U32
    {
        return Err(WireContractError::InvalidMessage);
    }
    match value
        .metadata
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?
    {
        Metadata::Append(append) => {
            if !append.entries.is_empty() {
                return Err(WireContractError::InvalidMessage);
            }
            validate_control_envelope(
                &ControlEnvelope {
                    header: value.header.clone(),
                    message: Some(Message::AppendRequest(append.clone())),
                },
                semantic_limits()?,
            )
        }
        Metadata::Prefix(prefix) => {
            valid_digest(&prefix.previous_digest)?;
            valid_digest(&prefix.quorum_plan_digest)?;
            validate_position(prefix.previous.as_ref(), true)?;
            let previous = prefix
                .previous
                .as_ref()
                .ok_or(WireContractError::InvalidMessage)?;
            if !prefix.entries.is_empty()
                || prefix.membership_epoch == 0
                || previous.index.checked_add(u64::from(value.entry_count))
                    != Some(prefix.committed_index)
                || (previous.index == 0 && prefix.previous_digest != [0; 32])
            {
                return Err(WireContractError::InvalidMessage);
            }
            Ok(())
        }
    }
}

pub(crate) fn receipt(value: &ConsensusBulkReceipt) -> Result<(), WireContractError> {
    valid_identifier(&value.request_id)?;
    valid_digest(&value.body_digest)
}

fn validate_body(body: &ConsensusBulkEntries) -> Result<(), WireContractError> {
    valid_identifier(&body.request_id)?;
    if body.format_version != 1
        || body.entries.is_empty()
        || body.entries.len() > MAXIMUM_CONSENSUS_BULK_ENTRIES
    {
        return Err(WireContractError::InvalidMessage);
    }
    let mut bytes = 0_usize;
    for entry in &body.entries {
        validate_position(entry.position.as_ref(), false)?;
        valid_identifier(&entry.operation_id)?;
        valid_digest(&entry.command_digest)?;
        let command = entry
            .command
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?;
        bytes = bytes
            .checked_add(command.canonical_bytes.len())
            .ok_or(WireContractError::FrameTooLarge)?;
        if command.format_version == 0
            || command.format_version > u32::from(u16::MAX)
            || bytes > MAXIMUM_CONSENSUS_COMMAND_BYTES
        {
            return Err(WireContractError::InvalidMessage);
        }
    }
    Ok(())
}

fn semantic_limits() -> Result<WireLimits, WireContractError> {
    WireLimits::new(
        MAXIMUM_CONSENSUS_COMMAND_BYTES,
        64 * 1024,
        MAXIMUM_CONSENSUS_BULK_ENTRIES,
        4096,
    )
}

#[cfg(test)]
#[path = "consensus_bulk_tests.rs"]
mod tests;
