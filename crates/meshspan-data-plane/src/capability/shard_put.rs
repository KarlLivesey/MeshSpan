// SPDX-License-Identifier: GPL-2.0-only

//! Version-one exact put identity, separate from renewed request authority.

use meshspan_contracts::{ContractVersion, RequestContext, ShardPutIdentity};
use meshspan_domain::{OperationId, Revision, UnixMicros};

use super::{CapabilityCodecError, Reader, decode_reservation, encode_reservation, push_shard};

const IDENTITY_BYTES: usize = 208;

pub(crate) fn encode_put_identity(original: ShardPutIdentity) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(IDENTITY_BYTES);
    bytes.extend_from_slice(&original.context.operation_id.as_bytes());
    bytes.extend_from_slice(&original.context.deadline.get().to_be_bytes());
    bytes.push(u8::from(original.context.expected_revision.is_some()));
    bytes.extend_from_slice(
        &original
            .context
            .expected_revision
            .unwrap_or(Revision::ZERO)
            .get()
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&encode_reservation(original.reservation));
    push_shard(&mut bytes, original.shard);
    bytes.extend_from_slice(&original.expected_length.to_be_bytes());
    bytes.extend_from_slice(&original.expected_digest);
    bytes
}

pub(crate) fn decode_put_identity(bytes: &[u8]) -> Result<ShardPutIdentity, CapabilityCodecError> {
    if bytes.len() != IDENTITY_BYTES {
        return Err(CapabilityCodecError::Invalid);
    }
    let mut reader = Reader::new(bytes);
    let operation_id =
        OperationId::from_bytes(reader.array()?).map_err(|_| CapabilityCodecError::Invalid)?;
    let deadline = UnixMicros::new(reader.i64()?);
    let revision_present = reader.u8()?;
    let revision = reader.u64()?;
    let expected_revision = match (revision_present, revision) {
        (0, 0) => None,
        (1, value) => Some(Revision::new(value)),
        _ => return Err(CapabilityCodecError::Invalid),
    };
    let reservation = decode_reservation(&reader.array::<89>()?)?;
    let original = ShardPutIdentity {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id,
            deadline,
            expected_revision,
        },
        reservation,
        shard: reader.shard()?,
        expected_length: reader.u64()?,
        expected_digest: reader.array()?,
    };
    reader.finish()?;
    if operation_id != reservation.operation_id
        || deadline.get() <= 0
        || deadline > reservation.expires_at
        || original.expected_length == 0
        || original.expected_length > reservation.maximum_bytes
        || original.expected_digest == [0; 32]
    {
        return Err(CapabilityCodecError::Invalid);
    }
    Ok(original)
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_contracts::{ReservationClass, ShardIdentity, StorageReservation};
    use meshspan_domain::TargetId;

    #[test]
    fn exact_identity_round_trips_and_rejects_noncanonical_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = fixture()?;
        let bytes = encode_put_identity(identity);
        assert_eq!(bytes.len(), 208);
        assert_eq!(decode_put_identity(&bytes)?, identity);
        for length in 0..bytes.len() {
            assert!(decode_put_identity(&bytes[..length]).is_err());
        }
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(decode_put_identity(&extended).is_err());
        for (offset, value) in [(24, 2), (24, 0), (73, 255)] {
            let mut changed = bytes.clone();
            changed[offset] = value;
            assert!(decode_put_identity(&changed).is_err());
        }
        for range in [
            0..16,
            33..49,
            49..65,
            65..73,
            74..82,
            82..90,
            90..122,
            122..154,
            164..168,
            168..176,
            176..208,
        ] {
            let mut changed = bytes.clone();
            changed[range].fill(0);
            assert!(decode_put_identity(&changed).is_err());
        }
        for revision in [None, Some(Revision::ZERO)] {
            let mut original = identity;
            original.context.expected_revision = revision;
            assert_eq!(
                decode_put_identity(&encode_put_identity(original))?,
                original
            );
        }
        Ok(())
    }

    #[test]
    fn request_digest_retains_the_existing_version_one_byte_layout()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = fixture()?;
        let mut canonical = b"meshspan.storage.put-request.v1".to_vec();
        canonical.extend([1; 16]);
        canonical.extend(100_i64.to_be_bytes());
        canonical.push(1);
        canonical.extend(5_u64.to_be_bytes());
        canonical.extend([9; 32]);
        canonical.extend([3; 32]);
        canonical.extend(4_u64.to_be_bytes());
        canonical.extend(6_u16.to_be_bytes());
        canonical.extend(7_u32.to_be_bytes());
        canonical.extend(8_u64.to_be_bytes());
        canonical.extend([10; 32]);
        assert_eq!(
            identity.request_digest(),
            *blake3::hash(&canonical).as_bytes()
        );
        Ok(())
    }

    fn fixture() -> Result<ShardPutIdentity, Box<dyn std::error::Error>> {
        let operation_id = OperationId::from_bytes([1; 16])?;
        Ok(ShardPutIdentity {
            context: RequestContext {
                contract_version: ContractVersion::V1_0,
                operation_id,
                deadline: UnixMicros::new(100),
                expected_revision: Some(Revision::new(5)),
            },
            reservation: StorageReservation {
                operation_id,
                target_id: TargetId::from_bytes([2; 16])?,
                target_generation: 3,
                class: ReservationClass::Repair,
                maximum_bytes: 8,
                expires_at: UnixMicros::new(100),
                reservation_digest: [9; 32],
            },
            shard: ShardIdentity {
                manifest_digest: [3; 32],
                stripe_index: 4,
                shard_index: 6,
                generation: 7,
            },
            expected_length: 8,
            expected_digest: [10; 32],
        })
    }
}
