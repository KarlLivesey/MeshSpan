// SPDX-License-Identifier: GPL-2.0-only

//! Bounded same-swarm history transfer contracts, separate from consensus and control payloads.

use meshspan_protobuf::{DecodeLimits, Message};

use crate::v1::{
    FetchMetadataReplicaPage, MetadataReplicaBody, MetadataReplicaCursor, MetadataReplicaPageHeader,
};
use crate::validation::{valid_digest, valid_identifier, validate_header, validate_wire_error};
use crate::{WireContractError, WireLimits};

/// Maximum records in one applied-history transfer.
pub const MAXIMUM_METADATA_REPLICA_ENTRIES: usize = 64;
/// Maximum aggregate semantic-command bytes in one history body.
pub const MAXIMUM_METADATA_REPLICA_COMMAND_BYTES: usize = 16 * 1_024 * 1_024;
/// Command budget plus bounded cursor and 64 record headers; not a control-frame allowance.
pub const MAXIMUM_METADATA_REPLICA_BODY_BYTES: usize =
    MAXIMUM_METADATA_REPLICA_COMMAND_BYTES + 16 * 1_024;

/// Encodes a structurally validated history body for separately framed bulk transfer.
///
/// # Errors
/// Rejects invalid cursor, record bounds/continuity, versions or an excessive encoded body.
pub fn encode_metadata_replica_body(
    body: &MetadataReplicaBody,
) -> Result<Vec<u8>, WireContractError> {
    validate_body(body)?;
    let bytes = body
        .encode_to_vec()
        .map_err(|_| WireContractError::FrameTooLarge)?;
    if bytes.len() > MAXIMUM_METADATA_REPLICA_BODY_BYTES {
        return Err(WireContractError::FrameTooLarge);
    }
    Ok(bytes)
}

/// Decodes a canonical history body with independent allocation/work bounds.
///
/// This verifies wire structure, not committed authority or semantic command validity.
/// The application must independently verify its source, phase and each command digest.
///
/// # Errors
/// Rejects excess, ambiguity, noncanonical encodings and malformed record/cursor fields.
pub fn decode_metadata_replica_body(
    bytes: &[u8],
) -> Result<MetadataReplicaBody, WireContractError> {
    let body = MetadataReplicaBody::decode_with_limits(
        bytes,
        DecodeLimits {
            maximum_message_bytes: MAXIMUM_METADATA_REPLICA_BODY_BYTES,
            maximum_field_bytes: MAXIMUM_METADATA_REPLICA_BODY_BYTES,
            maximum_fields: 2_048,
            maximum_repeated_items: MAXIMUM_METADATA_REPLICA_ENTRIES,
            maximum_depth: 5,
        },
    )
    .map_err(|_| WireContractError::Malformed)?;
    if encode_metadata_replica_body(&body)? != bytes {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(body)
}

pub(crate) fn request(value: &FetchMetadataReplicaPage) -> Result<(), WireContractError> {
    let header = value
        .header
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    validate_header(header)?;
    let after = cursor(value.after.as_ref())?;
    if after.partition_id != header.partition_id {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

pub(crate) fn header(
    value: &MetadataReplicaPageHeader,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.request_id)?;
    if let Some(error) = &value.rejection {
        validate_wire_error(error)?;
        if value.after.is_some()
            || value.byte_length != 0
            || !value.digest.is_empty()
            || value.maximum_frame_bytes != 0
        {
            return Err(WireContractError::InvalidMessage);
        }
        return Ok(());
    }
    cursor(value.after.as_ref())?;
    valid_digest(&value.digest)?;
    if value.byte_length == 0
        || value.byte_length > MAXIMUM_METADATA_REPLICA_BODY_BYTES as u64
        || value.maximum_frame_bytes == 0
        || value.maximum_frame_bytes > limits.maximum_data_frame_bytes() as u64
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

fn cursor(
    value: Option<&MetadataReplicaCursor>,
) -> Result<&MetadataReplicaCursor, WireContractError> {
    let value = value.ok_or(WireContractError::InvalidMessage)?;
    valid_identifier(&value.partition_id)?;
    valid_digest(&value.plan_digest)?;
    valid_digest(&value.applied_digest)?;
    let applied = value
        .applied
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    if value.membership_epoch == 0
        || (applied.index == 0) != (applied.term == 0)
        || (applied.index == 0 && value.applied_digest != [0; 32])
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(value)
}

fn validate_body(body: &MetadataReplicaBody) -> Result<(), WireContractError> {
    let after = cursor(body.after.as_ref())?;
    if body.format_version != 1 || body.entries.len() > MAXIMUM_METADATA_REPLICA_ENTRIES {
        return Err(WireContractError::InvalidMessage);
    }
    let applied = after
        .applied
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    let mut index = applied.index;
    let mut term = applied.term;
    let mut bytes = 0_usize;
    for entry in &body.entries {
        valid_identifier(&entry.operation_id)?;
        valid_digest(&entry.command_digest)?;
        let position = entry
            .position
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?;
        let command = entry
            .command
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?;
        bytes = bytes
            .checked_add(command.canonical_bytes.len())
            .ok_or(WireContractError::FrameTooLarge)?;
        if command.format_version == 0
            || command.format_version > u32::from(u16::MAX)
            || bytes > MAXIMUM_METADATA_REPLICA_COMMAND_BYTES
            || position.term == 0
            || position.term < term
            || index.checked_add(1) != Some(position.index)
        {
            return Err(WireContractError::InvalidMessage);
        }
        index = position.index;
        term = position.term;
    }
    Ok(())
}

#[cfg(test)]
#[path = "metadata_replica_tests.rs"]
mod tests;
