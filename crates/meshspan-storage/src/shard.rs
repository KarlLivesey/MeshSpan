// SPDX-License-Identifier: GPL-2.0-only

//! Canonical fixed-width shard identities and provider receipt encoding.

use meshspan_contracts::{ShardIdentity, ShardReceipt, TombstoneReceipt};
use meshspan_domain::{OperationId, TargetId};

use crate::TargetJournalError;

pub(crate) const SHARD_KEY_BYTES: usize = 46;
const RECEIPT_BYTES: usize = 126;
const TOMBSTONE_RECEIPT_BYTES: usize = 150;

pub(crate) fn encode_shard(shard: ShardIdentity) -> [u8; SHARD_KEY_BYTES] {
    let mut bytes = [0; SHARD_KEY_BYTES];
    bytes[..32].copy_from_slice(&shard.manifest_digest);
    bytes[32..40].copy_from_slice(&shard.stripe_index.to_be_bytes());
    bytes[40..42].copy_from_slice(&shard.shard_index.to_be_bytes());
    bytes[42..46].copy_from_slice(&shard.generation.to_be_bytes());
    bytes
}

pub(crate) fn decode_shard(bytes: &[u8]) -> Result<ShardIdentity, TargetJournalError> {
    if bytes.len() != SHARD_KEY_BYTES {
        return Err(TargetJournalError::CorruptState);
    }
    Ok(ShardIdentity {
        manifest_digest: copy_array(&bytes[..32])?,
        stripe_index: u64::from_be_bytes(copy_array(&bytes[32..40])?),
        shard_index: u16::from_be_bytes(copy_array(&bytes[40..42])?),
        generation: u32::from_be_bytes(copy_array(&bytes[42..46])?),
    })
}

pub(crate) fn encode_receipt(receipt: ShardReceipt) -> [u8; RECEIPT_BYTES] {
    let mut bytes = [0; RECEIPT_BYTES];
    bytes[..16].copy_from_slice(&receipt.operation_id.as_bytes());
    bytes[16..62].copy_from_slice(&encode_shard(receipt.shard));
    bytes[62..70].copy_from_slice(&receipt.length.to_be_bytes());
    bytes[70..102].copy_from_slice(&receipt.digest);
    bytes[102..118].copy_from_slice(&receipt.target_id.as_bytes());
    bytes[118..126].copy_from_slice(&receipt.target_generation.to_be_bytes());
    bytes
}

pub(crate) fn decode_receipt(bytes: &[u8]) -> Result<ShardReceipt, TargetJournalError> {
    if bytes.len() != RECEIPT_BYTES {
        return Err(TargetJournalError::CorruptState);
    }
    Ok(ShardReceipt {
        operation_id: OperationId::from_bytes(copy_array(&bytes[..16])?)
            .map_err(|_| TargetJournalError::CorruptState)?,
        shard: decode_shard(&bytes[16..62])?,
        length: u64::from_be_bytes(copy_array(&bytes[62..70])?),
        digest: copy_array(&bytes[70..102])?,
        target_id: TargetId::from_bytes(copy_array(&bytes[102..118])?)
            .map_err(|_| TargetJournalError::CorruptState)?,
        target_generation: u64::from_be_bytes(copy_array(&bytes[118..126])?),
    })
}

pub(crate) fn encode_tombstone_receipt(receipt: TombstoneReceipt) -> [u8; TOMBSTONE_RECEIPT_BYTES] {
    let mut bytes = [0; TOMBSTONE_RECEIPT_BYTES];
    bytes[..16].copy_from_slice(&receipt.operation_id.as_bytes());
    bytes[16..62].copy_from_slice(&encode_shard(receipt.shard));
    bytes[62..78].copy_from_slice(&receipt.target_id.as_bytes());
    bytes[78..86].copy_from_slice(&receipt.target_generation.to_be_bytes());
    bytes[86..118].copy_from_slice(&receipt.permit_digest);
    bytes[118..150].copy_from_slice(&receipt.tombstone_digest);
    bytes
}

pub(crate) fn decode_tombstone_receipt(
    bytes: &[u8],
) -> Result<TombstoneReceipt, TargetJournalError> {
    if bytes.len() != TOMBSTONE_RECEIPT_BYTES {
        return Err(TargetJournalError::CorruptState);
    }
    Ok(TombstoneReceipt {
        operation_id: OperationId::from_bytes(copy_array(&bytes[..16])?)
            .map_err(|_| TargetJournalError::CorruptState)?,
        shard: decode_shard(&bytes[16..62])?,
        target_id: TargetId::from_bytes(copy_array(&bytes[62..78])?)
            .map_err(|_| TargetJournalError::CorruptState)?,
        target_generation: u64::from_be_bytes(copy_array(&bytes[78..86])?),
        permit_digest: copy_array(&bytes[86..118])?,
        tombstone_digest: copy_array(&bytes[118..150])?,
    })
}

fn copy_array<const LENGTH: usize>(value: &[u8]) -> Result<[u8; LENGTH], TargetJournalError> {
    value
        .try_into()
        .map_err(|_| TargetJournalError::CorruptState)
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::{ShardIdentity, ShardReceipt, TombstoneReceipt};
    use meshspan_domain::{OperationId, TargetId};

    use super::{
        decode_receipt, decode_shard, decode_tombstone_receipt, encode_receipt, encode_shard,
        encode_tombstone_receipt,
    };

    #[test]
    fn shard_and_receipt_encodings_are_exact_and_round_trip()
    -> Result<(), Box<dyn std::error::Error>> {
        let shard = ShardIdentity {
            manifest_digest: [1; 32],
            stripe_index: u64::MAX,
            shard_index: u16::MAX,
            generation: u32::MAX,
        };
        assert_eq!(decode_shard(&encode_shard(shard))?, shard);
        let receipt = ShardReceipt {
            operation_id: OperationId::from_bytes([2; 16])?,
            shard,
            length: u64::MAX,
            digest: [3; 32],
            target_id: TargetId::from_bytes([4; 16])?,
            target_generation: u64::MAX,
        };
        assert_eq!(decode_receipt(&encode_receipt(receipt))?, receipt);
        let tombstone = TombstoneReceipt {
            operation_id: receipt.operation_id,
            shard,
            target_id: receipt.target_id,
            target_generation: receipt.target_generation,
            permit_digest: [5; 32],
            tombstone_digest: [6; 32],
        };
        assert_eq!(
            decode_tombstone_receipt(&encode_tombstone_receipt(tombstone))?,
            tombstone
        );
        assert!(decode_shard(&[0; 45]).is_err());
        assert!(decode_receipt(&[0; 125]).is_err());
        assert!(decode_tombstone_receipt(&[0; 149]).is_err());
        Ok(())
    }
}
