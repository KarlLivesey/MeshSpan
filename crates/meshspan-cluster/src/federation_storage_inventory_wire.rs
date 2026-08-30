// SPDX-License-Identifier: GPL-2.0-only

//! Canonical private-wire encoding for scoped federated provider inventory.

use meshspan_contracts::{
    FederatedStorageInventoryRecord, ShardIdentity, validate_federated_storage_inventory_record,
};
use meshspan_domain::{FederationStorageAllocationId, UnixMicros};
use meshspan_metadata::FederationStorageInventoryCursor;
use meshspan_protocol::v1::VersionedPayload;
use thiserror::Error;

const FORMAT_VERSION: u32 = 1;
const RECORD_DOMAIN: &[u8] = b"meshspan.federation.storage-inventory-record\0";
const CURSOR_DOMAIN: &[u8] = b"meshspan.federation.storage-inventory-cursor\0";
const RECORD_FIELDS_LENGTH: usize = 32 + 16 + 32 + 8 + 2 + 4 + 8 + 32 + 8;
const CURSOR_FIELDS_LENGTH: usize = 32 + 32 + 8 + 2 + 4;

/// Encodes one exact active provider record without filenames, users or volume keys.
///
/// # Errors
///
/// Rejects any malformed semantic record before bytes are produced.
pub fn version_federated_storage_inventory_record(
    record: FederatedStorageInventoryRecord,
) -> Result<VersionedPayload, FederationStorageInventoryWireError> {
    validate_federated_storage_inventory_record(record)
        .map_err(|_| FederationStorageInventoryWireError::Invalid)?;
    let mut bytes = Vec::with_capacity(RECORD_DOMAIN.len() + RECORD_FIELDS_LENGTH);
    bytes.extend_from_slice(RECORD_DOMAIN);
    bytes.extend_from_slice(&record.scope_digest);
    bytes.extend_from_slice(&record.allocation_id.as_bytes());
    push_shard(&mut bytes, record.shard);
    bytes.extend_from_slice(&record.length.to_be_bytes());
    bytes.extend_from_slice(&record.digest);
    bytes.extend_from_slice(&record.committed_at.get().to_be_bytes());
    Ok(VersionedPayload {
        format_version: FORMAT_VERSION,
        canonical_bytes: bytes,
    })
}

/// Decodes one exact active provider inventory record.
///
/// # Errors
///
/// Rejects unknown versions, wrong domains/lengths, trailing bytes and malformed fields.
pub fn decode_federated_storage_inventory_record(
    payload: &VersionedPayload,
) -> Result<FederatedStorageInventoryRecord, FederationStorageInventoryWireError> {
    if payload.format_version != FORMAT_VERSION
        || payload.canonical_bytes.len() != RECORD_DOMAIN.len() + RECORD_FIELDS_LENGTH
        || !payload.canonical_bytes.starts_with(RECORD_DOMAIN)
    {
        return Err(FederationStorageInventoryWireError::Invalid);
    }
    let mut reader = Reader::new(&payload.canonical_bytes[RECORD_DOMAIN.len()..]);
    let record = FederatedStorageInventoryRecord {
        scope_digest: reader.array()?,
        allocation_id: FederationStorageAllocationId::from_bytes(reader.array()?)
            .map_err(|_| FederationStorageInventoryWireError::Invalid)?,
        shard: reader.shard()?,
        length: reader.u64()?,
        digest: reader.array()?,
        committed_at: UnixMicros::new(reader.i64()?),
    };
    reader.finish()?;
    validate_federated_storage_inventory_record(record)
        .map_err(|_| FederationStorageInventoryWireError::Invalid)?;
    Ok(record)
}

pub(crate) fn encode_inventory_cursor(cursor: FederationStorageInventoryCursor) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CURSOR_DOMAIN.len() + CURSOR_FIELDS_LENGTH);
    bytes.extend_from_slice(CURSOR_DOMAIN);
    bytes.extend_from_slice(&cursor.scope_digest);
    push_shard(&mut bytes, cursor.shard);
    bytes
}

pub(crate) fn decode_inventory_cursor(
    bytes: &[u8],
) -> Result<Option<FederationStorageInventoryCursor>, FederationStorageInventoryWireError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != CURSOR_DOMAIN.len() + CURSOR_FIELDS_LENGTH
        || !bytes.starts_with(CURSOR_DOMAIN)
    {
        return Err(FederationStorageInventoryWireError::Invalid);
    }
    let mut reader = Reader::new(&bytes[CURSOR_DOMAIN.len()..]);
    let cursor = FederationStorageInventoryCursor {
        scope_digest: reader.array()?,
        shard: reader.shard()?,
    };
    reader.finish()?;
    if cursor.scope_digest == [0; 32] {
        Err(FederationStorageInventoryWireError::Invalid)
    } else {
        Ok(Some(cursor))
    }
}

fn push_shard(bytes: &mut Vec<u8>, shard: ShardIdentity) {
    bytes.extend_from_slice(&shard.manifest_digest);
    bytes.extend_from_slice(&shard.stripe_index.to_be_bytes());
    bytes.extend_from_slice(&shard.shard_index.to_be_bytes());
    bytes.extend_from_slice(&shard.generation.to_be_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; LENGTH], FederationStorageInventoryWireError> {
        let end = self
            .offset
            .checked_add(LENGTH)
            .ok_or(FederationStorageInventoryWireError::Invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FederationStorageInventoryWireError::Invalid)?
            .try_into()
            .map_err(|_| FederationStorageInventoryWireError::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, FederationStorageInventoryWireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, FederationStorageInventoryWireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, FederationStorageInventoryWireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64, FederationStorageInventoryWireError> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    fn shard(&mut self) -> Result<ShardIdentity, FederationStorageInventoryWireError> {
        let shard = ShardIdentity {
            manifest_digest: self.array()?,
            stripe_index: self.u64()?,
            shard_index: self.u16()?,
            generation: self.u32()?,
        };
        if shard.manifest_digest == [0; 32] || shard.generation == 0 {
            Err(FederationStorageInventoryWireError::Invalid)
        } else {
            Ok(shard)
        }
    }

    fn finish(self) -> Result<(), FederationStorageInventoryWireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(FederationStorageInventoryWireError::Invalid)
        }
    }
}

/// Stable rejection for non-canonical federation inventory bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationStorageInventoryWireError {
    /// Version, domain, length, identity or semantic record shape is invalid.
    #[error("federated storage inventory encoding is invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::{FederatedStorageInventoryRecord, ShardIdentity};
    use meshspan_domain::{FederationStorageAllocationId, UnixMicros};
    use meshspan_metadata::FederationStorageInventoryCursor;

    use super::{
        decode_federated_storage_inventory_record, decode_inventory_cursor,
        encode_inventory_cursor, version_federated_storage_inventory_record,
    };

    #[test]
    fn record_and_cursor_are_exact_and_reject_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = record()?;
        let encoded = version_federated_storage_inventory_record(record)?;
        assert_eq!(decode_federated_storage_inventory_record(&encoded)?, record);
        let mut trailing = encoded.clone();
        trailing.canonical_bytes.push(0);
        assert!(decode_federated_storage_inventory_record(&trailing).is_err());
        let cursor = FederationStorageInventoryCursor {
            scope_digest: record.scope_digest,
            shard: record.shard,
        };
        let encoded_cursor = encode_inventory_cursor(cursor);
        assert_eq!(decode_inventory_cursor(&encoded_cursor)?, Some(cursor));
        assert!(decode_inventory_cursor(&encoded_cursor[..encoded_cursor.len() - 1]).is_err());
        Ok(())
    }

    fn record() -> Result<FederatedStorageInventoryRecord, meshspan_domain::IdentifierError> {
        Ok(FederatedStorageInventoryRecord {
            scope_digest: [1; 32],
            allocation_id: FederationStorageAllocationId::from_bytes([2; 16])?,
            shard: ShardIdentity {
                manifest_digest: [3; 32],
                stripe_index: 4,
                shard_index: 5,
                generation: 6,
            },
            length: 7,
            digest: [8; 32],
            committed_at: UnixMicros::new(9),
        })
    }
}
