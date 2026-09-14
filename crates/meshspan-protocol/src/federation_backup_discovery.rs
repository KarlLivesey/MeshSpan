// SPDX-License-Identifier: GPL-2.0-only

//! Canonical bounded continuation shared by allocation discovery clients and servers.

use crate::{WireContractError, v1::FederatedBackupAllocationCursor};
use meshspan_protobuf::{DecodeLimits, Message};

/// Encodes a validated continuation without granting authority to its contents.
///
/// # Errors
/// Rejects invalid version, scope, revision, interval or encoding bounds.
pub fn encode_backup_allocation_cursor(
    value: &FederatedBackupAllocationCursor,
) -> Result<Vec<u8>, WireContractError> {
    validate(value)?;
    let bytes = value
        .encode_to_vec()
        .map_err(|_| WireContractError::FrameTooLarge)?;
    if bytes.len() > 128 {
        return Err(WireContractError::FrameTooLarge);
    }
    Ok(bytes)
}

/// Decodes one canonical continuation with a small independent allocation/work budget.
/// Callers must also bind its relationship, epoch, grant, size and revision to the request.
///
/// # Errors
/// Rejects oversized, noncanonical, ambiguous or semantically invalid continuations.
pub fn decode_backup_allocation_cursor(
    bytes: &[u8],
) -> Result<FederatedBackupAllocationCursor, WireContractError> {
    let value = FederatedBackupAllocationCursor::decode_with_limits(
        bytes,
        DecodeLimits {
            maximum_message_bytes: 128,
            maximum_field_bytes: 16,
            maximum_fields: 9,
            maximum_repeated_items: 1,
            maximum_depth: 1,
        },
    )
    .map_err(|_| WireContractError::InvalidMessage)?;
    if encode_backup_allocation_cursor(&value)? != bytes {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(value)
}

fn validate(value: &FederatedBackupAllocationCursor) -> Result<(), WireContractError> {
    for id in [
        &value.relationship_id,
        &value.grant_id,
        &value.allocation_id,
    ] {
        crate::validation::valid_identifier(id)?;
    }
    if value.format_version != 1
        || value.authority_epoch == 0
        || value.snapshot_revision == 0
        || value.required_bytes == 0
        || value.required_bytes > i64::MAX.unsigned_abs()
        || value.valid_from_unix_micros <= 0
        || value.valid_until_unix_micros <= value.valid_from_unix_micros
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}
