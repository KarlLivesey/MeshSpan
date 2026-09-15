// SPDX-License-Identifier: GPL-2.0-only

//! Canonical physical intent shared by consensus persistence and the private data adapter.

use crate::{
    ContractError, ContractVersion, RequestContext, ReservationClass, ShardPutIntent, ShardReceipt,
    decode_shard_receipt_v1, encode_shard_receipt_v1,
};
use meshspan_domain::{Revision, UnixMicros};

/// Version-one intent size without enclosing persistence or protocol framing.
pub const SHARD_PUT_INTENT_V1_BYTES: usize = 152;

/// Encodes selected identity fields, not a receipt or permission to write.
/// The first 126 bytes reuse the existing physical-identity encoding only.
#[must_use]
pub fn encode_shard_put_intent_v1(intent: ShardPutIntent) -> [u8; SHARD_PUT_INTENT_V1_BYTES] {
    let mut bytes = [0; SHARD_PUT_INTENT_V1_BYTES];
    bytes[..126].copy_from_slice(&encode_shard_receipt_v1(ShardReceipt {
        operation_id: intent.context.operation_id,
        shard: intent.shard,
        length: intent.expected_length,
        digest: intent.expected_digest,
        target_id: intent.target_id,
        target_generation: intent.target_generation,
    }));
    bytes[126..134].copy_from_slice(&intent.context.deadline.get().to_be_bytes());
    bytes[134] = u8::from(intent.context.expected_revision.is_some());
    bytes[135..143].copy_from_slice(
        &intent
            .context
            .expected_revision
            .unwrap_or(Revision::ZERO)
            .get()
            .to_be_bytes(),
    );
    bytes[143] = match intent.reservation_class {
        ReservationClass::ForegroundWrite => 1,
        ReservationClass::Repair => 2,
        ReservationClass::Relocation => 3,
    };
    bytes[144..152].copy_from_slice(&intent.maximum_bytes.to_be_bytes());
    bytes
}

/// Decodes one exact intent without granting authority or trusting any bytes to exist.
/// # Errors
/// Rejects malformed/trailing data, invalid identifiers, versions, classes and capacity bounds.
pub fn decode_shard_put_intent_v1(bytes: &[u8]) -> Result<ShardPutIntent, ContractError> {
    let bytes: &[u8; SHARD_PUT_INTENT_V1_BYTES] =
        bytes.try_into().map_err(|_| ContractError::InvalidInput)?;
    let identity = decode_shard_receipt_v1(&bytes[..126])?;
    let deadline = UnixMicros::new(i64::from_be_bytes(field(&bytes[126..134])?));
    let revision = u64::from_be_bytes(field(&bytes[135..143])?);
    let expected_revision = match (bytes[134], revision) {
        (0, 0) => None,
        (1, value) => Some(Revision::new(value)),
        _ => return Err(ContractError::InvalidInput),
    };
    let reservation_class = match bytes[143] {
        1 => ReservationClass::ForegroundWrite,
        2 => ReservationClass::Repair,
        3 => ReservationClass::Relocation,
        _ => return Err(ContractError::InvalidInput),
    };
    let maximum_bytes = u64::from_be_bytes(field(&bytes[144..152])?);
    if deadline.get() <= 0 || identity.length > maximum_bytes {
        return Err(ContractError::InvalidInput);
    }
    Ok(ShardPutIntent {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: identity.operation_id,
            deadline,
            expected_revision,
        },
        target_id: identity.target_id,
        target_generation: identity.target_generation,
        reservation_class,
        maximum_bytes,
        shard: identity.shard,
        expected_length: identity.length,
        expected_digest: identity.digest,
    })
}

fn field<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ContractError> {
    bytes.try_into().map_err(|_| ContractError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StorageReservation;

    fn fixture() -> [u8; 152] {
        let mut bytes = [0; 152];
        bytes[..16].fill(1);
        bytes[16..48].fill(2);
        bytes[55] = 3;
        bytes[57] = 4;
        bytes[61] = 5;
        bytes[69] = 6;
        bytes[70..102].fill(7);
        bytes[102..118].fill(8);
        bytes[125] = 9;
        bytes[133] = 10;
        bytes[134] = 1;
        bytes[142] = 11;
        bytes[143] = 2;
        bytes[151] = 12;
        bytes
    }

    #[test]
    fn physical_intent_matches_independent_fixture() -> Result<(), ContractError> {
        let bytes = fixture();
        let intent = decode_shard_put_intent_v1(&bytes)?;
        assert_eq!(intent.context.operation_id.as_bytes(), [1; 16]);
        assert_eq!(intent.shard.manifest_digest, [2; 32]);
        assert_eq!(intent.shard.stripe_index, 3);
        assert_eq!(intent.shard.shard_index, 4);
        assert_eq!(intent.shard.generation, 5);
        assert_eq!(intent.expected_length, 6);
        assert_eq!(intent.expected_digest, [7; 32]);
        assert_eq!(intent.target_id.as_bytes(), [8; 16]);
        assert_eq!(intent.target_generation, 9);
        assert_eq!(intent.context.deadline.get(), 10);
        assert_eq!(intent.context.expected_revision, Some(Revision::new(11)));
        assert_eq!(intent.reservation_class, ReservationClass::Repair);
        assert_eq!(intent.maximum_bytes, 12);
        assert_eq!(encode_shard_put_intent_v1(intent), bytes);
        Ok(())
    }

    #[test]
    fn physical_intent_rejects_invalid_structure() {
        let bytes = fixture();
        for length in 0..152 {
            assert!(decode_shard_put_intent_v1(&bytes[..length]).is_err());
        }
        assert!(decode_shard_put_intent_v1(&[1; 153]).is_err());
        for range in [
            0..16,
            16..48,
            58..62,
            62..70,
            70..102,
            102..118,
            118..126,
            126..134,
            143..144,
            144..152,
        ] {
            let mut invalid = bytes;
            invalid[range].fill(0);
            assert!(decode_shard_put_intent_v1(&invalid).is_err());
        }
        for (offset, value) in [(134, 0), (134, 2), (143, 4), (151, 5), (126, 128)] {
            let mut invalid = bytes;
            invalid[offset] = value;
            assert!(decode_shard_put_intent_v1(&invalid).is_err());
        }
    }

    #[test]
    fn physical_intent_keeps_absent_and_zero_revisions_distinct() -> Result<(), ContractError> {
        let mut bytes = fixture();
        bytes[135..143].fill(0);
        assert_eq!(
            decode_shard_put_intent_v1(&bytes)?
                .context
                .expected_revision,
            Some(Revision::ZERO)
        );
        bytes[134] = 0;
        assert_eq!(
            decode_shard_put_intent_v1(&bytes)?
                .context
                .expected_revision,
            None
        );
        Ok(())
    }

    #[test]
    fn admission_rejects_invalid_intent_before_binding_reservation() -> Result<(), ContractError> {
        let intent = decode_shard_put_intent_v1(&fixture())?;
        let reservation = StorageReservation {
            operation_id: intent.context.operation_id,
            target_id: intent.target_id,
            target_generation: intent.target_generation,
            class: intent.reservation_class,
            maximum_bytes: intent.maximum_bytes,
            expires_at: intent.context.deadline,
            reservation_digest: [13; 32],
        };
        assert_eq!(intent.admitted(reservation)?.reservation, reservation);
        for invalid in [
            ShardPutIntent {
                expected_length: 0,
                ..intent
            },
            ShardPutIntent {
                expected_length: 13,
                ..intent
            },
            ShardPutIntent {
                expected_digest: [0; 32],
                ..intent
            },
        ] {
            assert_eq!(
                invalid.admitted(reservation),
                Err(ContractError::InvalidInput)
            );
        }
        for invalid in [
            StorageReservation {
                class: ReservationClass::ForegroundWrite,
                ..reservation
            },
            StorageReservation {
                maximum_bytes: 13,
                ..reservation
            },
            StorageReservation {
                expires_at: UnixMicros::new(9),
                ..reservation
            },
            StorageReservation {
                reservation_digest: [0; 32],
                ..reservation
            },
        ] {
            assert_eq!(intent.admitted(invalid), Err(ContractError::InvalidInput));
        }
        Ok(())
    }
}
