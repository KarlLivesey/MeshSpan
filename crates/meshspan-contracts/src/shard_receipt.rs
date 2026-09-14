// SPDX-License-Identifier: GPL-2.0-only

//! Shared fixed-width version-one physical receipt encoding, independent of transport and SQL.

use crate::{ContractError, ShardIdentity, ShardReceipt};
use meshspan_domain::{OperationId, TargetId};

/// Size of a version-one physical shard receipt, excluding enclosing framing.
pub const SHARD_RECEIPT_V1_BYTES: usize = 126;

/// Encodes a physical receipt without claiming it is valid or durable.
/// The enclosing protocol/storage format owns its version and authentication.
#[must_use]
pub fn encode_shard_receipt_v1(receipt: ShardReceipt) -> [u8; SHARD_RECEIPT_V1_BYTES] {
    let mut bytes = [0; SHARD_RECEIPT_V1_BYTES];
    bytes[..16].copy_from_slice(&receipt.operation_id.as_bytes());
    bytes[16..48].copy_from_slice(&receipt.shard.manifest_digest);
    bytes[48..56].copy_from_slice(&receipt.shard.stripe_index.to_be_bytes());
    bytes[56..58].copy_from_slice(&receipt.shard.shard_index.to_be_bytes());
    bytes[58..62].copy_from_slice(&receipt.shard.generation.to_be_bytes());
    bytes[62..70].copy_from_slice(&receipt.length.to_be_bytes());
    bytes[70..102].copy_from_slice(&receipt.digest);
    bytes[102..118].copy_from_slice(&receipt.target_id.as_bytes());
    bytes[118..126].copy_from_slice(&receipt.target_generation.to_be_bytes());
    bytes
}

/// Decodes one exact receipt using the existing version-one data-plane bounds.
/// This checks structure only, never authority, actual bytes or current protection.
/// # Errors
/// Rejects truncation/trailing data, invalid identifiers, zero generations, length or digests.
pub fn decode_shard_receipt_v1(bytes: &[u8]) -> Result<ShardReceipt, ContractError> {
    let bytes: &[u8; SHARD_RECEIPT_V1_BYTES] =
        bytes.try_into().map_err(|_| ContractError::InvalidInput)?;
    let receipt = ShardReceipt {
        operation_id: OperationId::from_bytes(field(&bytes[..16])?)
            .map_err(|_| ContractError::InvalidInput)?,
        shard: ShardIdentity {
            manifest_digest: field(&bytes[16..48])?,
            stripe_index: u64::from_be_bytes(field(&bytes[48..56])?),
            shard_index: u16::from_be_bytes(field(&bytes[56..58])?),
            generation: u32::from_be_bytes(field(&bytes[58..62])?),
        },
        length: u64::from_be_bytes(field(&bytes[62..70])?),
        digest: field(&bytes[70..102])?,
        target_id: TargetId::from_bytes(field(&bytes[102..118])?)
            .map_err(|_| ContractError::InvalidInput)?,
        target_generation: u64::from_be_bytes(field(&bytes[118..126])?),
    };
    if receipt.shard.manifest_digest == [0; 32]
        || receipt.shard.generation == 0
        || receipt.length == 0
        || receipt.digest == [0; 32]
        || receipt.target_generation == 0
    {
        return Err(ContractError::InvalidInput);
    }
    Ok(receipt)
}

fn field<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ContractError> {
    bytes.try_into().map_err(|_| ContractError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_receipt_v1_matches_independent_wire_fixture() -> Result<(), ContractError> {
        let mut bytes = [0; 126];
        bytes[..16].fill(1);
        bytes[16..48].fill(2);
        bytes[55] = 3;
        bytes[57] = 4;
        bytes[61] = 5;
        bytes[69] = 6;
        bytes[70..102].fill(7);
        bytes[102..118].fill(8);
        bytes[125] = 9;
        let receipt = decode_shard_receipt_v1(&bytes)?;
        assert_eq!(receipt.operation_id.as_bytes(), [1; 16]);
        assert_eq!(receipt.shard.manifest_digest, [2; 32]);
        assert_eq!(receipt.shard.stripe_index, 3);
        assert_eq!(receipt.shard.shard_index, 4);
        assert_eq!(receipt.shard.generation, 5);
        assert_eq!(receipt.length, 6);
        assert_eq!(receipt.digest, [7; 32]);
        assert_eq!(receipt.target_id.as_bytes(), [8; 16]);
        assert_eq!(receipt.target_generation, 9);
        assert_eq!(encode_shard_receipt_v1(receipt), bytes);
        Ok(())
    }

    #[test]
    fn shard_receipt_v1_rejects_invalid_structure() {
        let valid = [1; 126];
        for length in 0..126 {
            assert!(decode_shard_receipt_v1(&valid[..length]).is_err());
        }
        assert!(decode_shard_receipt_v1(&[1; 127]).is_err());
        for range in [0..16, 16..48, 58..62, 62..70, 70..102, 102..118, 118..126] {
            let mut invalid = valid;
            invalid[range].fill(0);
            assert!(decode_shard_receipt_v1(&invalid).is_err());
        }
        let mut valid_zero_indices = valid;
        valid_zero_indices[48..58].fill(0);
        assert!(decode_shard_receipt_v1(&valid_zero_indices).is_ok());
    }
}
