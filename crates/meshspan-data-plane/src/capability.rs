// SPDX-License-Identifier: GPL-2.0-only

//! Canonical fixed-width encodings for opaque private-wire storage capabilities.

mod federation;

pub use federation::{decode_federated_shard_permit, encode_federated_shard_permit};

use meshspan_contracts::{
    ReclamationReceipt, RemovalPermit, ReservationClass, ScrubObservation, ScrubOutcome,
    ShardIdentity, ShardReadPermit, ShardReceipt, ShardWritePermit, StorageReservation,
    TombstoneReceipt, reclamation_receipt_digest, validate_exact_scrub_observation,
};
use meshspan_domain::{MeshId, OperationId, Revision, TargetId, UnixMicros};
use thiserror::Error;

const WRITE_PERMIT_BYTES: usize = 159;
const READ_PERMIT_BYTES: usize = 150;
const RESERVATION_BYTES: usize = 89;
const SHARD_RECEIPT_BYTES: usize = 126;
const REMOVAL_PERMIT_BYTES: usize = 158;
const TOMBSTONE_RECEIPT_BYTES: usize = 150;
const RECLAMATION_RECEIPT_BYTES: usize = 198;
const SCRUB_OBSERVATION_BYTES: usize = 129;

/// Stable rejection for malformed or non-canonical capability bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilityCodecError {
    /// Byte length, identifier, enum discriminant or required positive field is invalid.
    #[error("storage capability encoding is invalid")]
    Invalid,
}

/// Encodes one exact write capability without a self-describing or ambiguous representation.
#[must_use]
pub fn encode_write_permit(permit: ShardWritePermit) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(WRITE_PERMIT_BYTES);
    push_common(
        &mut bytes,
        permit.operation_id,
        permit.mesh_id,
        permit.target_id,
    );
    bytes.extend_from_slice(&permit.target_generation.to_be_bytes());
    push_shard(&mut bytes, permit.shard);
    bytes.push(class_code(permit.reservation_class));
    bytes.extend_from_slice(&permit.maximum_bytes.to_be_bytes());
    bytes.extend_from_slice(&permit.authorization_revision.get().to_be_bytes());
    bytes.extend_from_slice(&permit.expires_at.get().to_be_bytes());
    bytes.extend_from_slice(&permit.permit_digest);
    bytes
}

/// Decodes one exact canonical write capability.
///
/// # Errors
///
/// Rejects every truncated, excessive, zero-sentinel or unknown-discriminant encoding.
pub fn decode_write_permit(bytes: &[u8]) -> Result<ShardWritePermit, CapabilityCodecError> {
    if bytes.len() != WRITE_PERMIT_BYTES {
        return Err(CapabilityCodecError::Invalid);
    }
    let mut reader = Reader::new(bytes);
    let (operation_id, mesh_id, target_id) = read_common(&mut reader)?;
    let target_generation = reader.u64()?;
    let shard = reader.shard()?;
    let reservation_class = decode_class(reader.u8()?)?;
    let maximum_bytes = reader.u64()?;
    let authorization_revision = Revision::new(reader.u64()?);
    let expires_at = UnixMicros::new(reader.i64()?);
    let permit_digest = reader.array()?;
    reader.finish()?;
    if target_generation == 0
        || maximum_bytes == 0
        || authorization_revision.get() == 0
        || expires_at.get() <= 0
        || permit_digest == [0; 32]
    {
        return Err(CapabilityCodecError::Invalid);
    }
    Ok(ShardWritePermit {
        operation_id,
        mesh_id,
        target_id,
        target_generation,
        shard,
        reservation_class,
        maximum_bytes,
        authorization_revision,
        expires_at,
        permit_digest,
    })
}

/// Encodes one exact read capability without a self-describing or ambiguous representation.
#[must_use]
pub fn encode_read_permit(permit: ShardReadPermit) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(READ_PERMIT_BYTES);
    push_common(
        &mut bytes,
        permit.operation_id,
        permit.mesh_id,
        permit.target_id,
    );
    bytes.extend_from_slice(&permit.target_generation.to_be_bytes());
    push_shard(&mut bytes, permit.shard);
    bytes.extend_from_slice(&permit.authorization_revision.get().to_be_bytes());
    bytes.extend_from_slice(&permit.expires_at.get().to_be_bytes());
    bytes.extend_from_slice(&permit.permit_digest);
    bytes
}

/// Decodes one exact canonical read capability.
///
/// # Errors
///
/// Rejects every truncated, excessive or zero-sentinel encoding.
pub fn decode_read_permit(bytes: &[u8]) -> Result<ShardReadPermit, CapabilityCodecError> {
    if bytes.len() != READ_PERMIT_BYTES {
        return Err(CapabilityCodecError::Invalid);
    }
    let mut reader = Reader::new(bytes);
    let (operation_id, mesh_id, target_id) = read_common(&mut reader)?;
    let target_generation = reader.u64()?;
    let shard = reader.shard()?;
    let authorization_revision = Revision::new(reader.u64()?);
    let expires_at = UnixMicros::new(reader.i64()?);
    let permit_digest = reader.array()?;
    reader.finish()?;
    if target_generation == 0
        || authorization_revision.get() == 0
        || expires_at.get() <= 0
        || permit_digest == [0; 32]
    {
        return Err(CapabilityCodecError::Invalid);
    }
    Ok(ShardReadPermit {
        operation_id,
        mesh_id,
        target_id,
        target_generation,
        shard,
        authorization_revision,
        expires_at,
        permit_digest,
    })
}

/// Encodes one exact removal capability without a self-describing representation.
#[must_use]
pub fn encode_removal_permit(permit: RemovalPermit) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(REMOVAL_PERMIT_BYTES);
    push_common(
        &mut bytes,
        permit.operation_id,
        permit.mesh_id,
        permit.target_id,
    );
    bytes.extend_from_slice(&permit.target_generation.to_be_bytes());
    push_shard(&mut bytes, permit.shard);
    bytes.extend_from_slice(&permit.authority_epoch.to_be_bytes());
    bytes.extend_from_slice(&permit.catalogue_revision.get().to_be_bytes());
    bytes.extend_from_slice(&permit.expires_at.get().to_be_bytes());
    bytes.extend_from_slice(&permit.permit_digest);
    bytes
}

/// Decodes one exact canonical removal capability.
///
/// # Errors
///
/// Rejects every truncated, excessive or zero-sentinel encoding.
pub fn decode_removal_permit(bytes: &[u8]) -> Result<RemovalPermit, CapabilityCodecError> {
    if bytes.len() != REMOVAL_PERMIT_BYTES {
        return Err(CapabilityCodecError::Invalid);
    }
    let mut reader = Reader::new(bytes);
    let (operation_id, mesh_id, target_id) = read_common(&mut reader)?;
    let target_generation = reader.u64()?;
    let shard = reader.shard()?;
    let authority_epoch = reader.u64()?;
    let catalogue_revision = Revision::new(reader.u64()?);
    let expires_at = UnixMicros::new(reader.i64()?);
    let permit_digest = reader.array()?;
    reader.finish()?;
    if target_generation == 0
        || authority_epoch == 0
        || catalogue_revision == Revision::ZERO
        || expires_at.get() <= 0
        || permit_digest == [0; 32]
    {
        return Err(CapabilityCodecError::Invalid);
    }
    Ok(RemovalPermit {
        operation_id,
        mesh_id,
        target_id,
        shard,
        target_generation,
        authority_epoch,
        catalogue_revision,
        expires_at,
        permit_digest,
    })
}

pub(crate) fn encode_tombstone_receipt(receipt: TombstoneReceipt) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(TOMBSTONE_RECEIPT_BYTES);
    bytes.extend_from_slice(&receipt.operation_id.as_bytes());
    push_shard(&mut bytes, receipt.shard);
    bytes.extend_from_slice(&receipt.target_id.as_bytes());
    bytes.extend_from_slice(&receipt.target_generation.to_be_bytes());
    bytes.extend_from_slice(&receipt.permit_digest);
    bytes.extend_from_slice(&receipt.tombstone_digest);
    bytes
}

pub(crate) fn decode_tombstone_receipt(
    bytes: &[u8],
) -> Result<TombstoneReceipt, CapabilityCodecError> {
    if bytes.len() != TOMBSTONE_RECEIPT_BYTES {
        return Err(CapabilityCodecError::Invalid);
    }
    let mut reader = Reader::new(bytes);
    let receipt = TombstoneReceipt {
        operation_id: OperationId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        shard: reader.shard()?,
        target_id: TargetId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        target_generation: reader.u64()?,
        permit_digest: reader.array()?,
        tombstone_digest: reader.array()?,
    };
    reader.finish()?;
    if receipt.target_generation == 0
        || receipt.permit_digest == [0; 32]
        || receipt.tombstone_digest == [0; 32]
    {
        Err(CapabilityCodecError::Invalid)
    } else {
        Ok(receipt)
    }
}

pub(crate) fn encode_reclamation_receipt(receipt: ReclamationReceipt) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RECLAMATION_RECEIPT_BYTES);
    bytes.extend_from_slice(&encode_tombstone_receipt(receipt.tombstone));
    bytes.extend_from_slice(&receipt.bytes_unlinked_at.get().to_be_bytes());
    bytes.extend_from_slice(&receipt.reclaimed_bytes.to_be_bytes());
    bytes.extend_from_slice(&receipt.reclamation_digest);
    bytes
}

pub(crate) fn decode_reclamation_receipt(
    bytes: &[u8],
) -> Result<ReclamationReceipt, CapabilityCodecError> {
    let receipt = decode_reclamation_evidence(bytes)?;
    if receipt.reclamation_digest
        == reclamation_receipt_digest(
            receipt.tombstone,
            receipt.bytes_unlinked_at,
            receipt.reclaimed_bytes,
        )
    {
        Ok(receipt)
    } else {
        Err(CapabilityCodecError::Invalid)
    }
}

pub(crate) fn decode_reclamation_evidence(
    bytes: &[u8],
) -> Result<ReclamationReceipt, CapabilityCodecError> {
    if bytes.len() != RECLAMATION_RECEIPT_BYTES {
        return Err(CapabilityCodecError::Invalid);
    }
    let tombstone = decode_tombstone_receipt(&bytes[..TOMBSTONE_RECEIPT_BYTES])?;
    let mut reader = Reader::new(&bytes[TOMBSTONE_RECEIPT_BYTES..]);
    let receipt = ReclamationReceipt {
        tombstone,
        bytes_unlinked_at: UnixMicros::new(reader.i64()?),
        reclaimed_bytes: reader.u64()?,
        reclamation_digest: reader.array()?,
    };
    reader.finish()?;
    if receipt.bytes_unlinked_at.get() <= 0
        || receipt.reclaimed_bytes == 0
        || receipt.reclamation_digest == [0; 32]
    {
        Err(CapabilityCodecError::Invalid)
    } else {
        Ok(receipt)
    }
}

pub(crate) fn encode_scrub_observation(
    observation: ScrubObservation,
) -> Result<Vec<u8>, CapabilityCodecError> {
    validate_exact_scrub_observation(observation).map_err(|_| CapabilityCodecError::Invalid)?;
    let mut bytes = Vec::with_capacity(SCRUB_OBSERVATION_BYTES);
    push_shard(&mut bytes, observation.shard);
    push_optional_measurement(
        &mut bytes,
        observation.expected_length,
        observation.expected_digest,
    );
    push_optional_measurement(
        &mut bytes,
        observation.observed_length,
        observation.observed_digest,
    );
    bytes.push(scrub_outcome_code(observation.outcome));
    Ok(bytes)
}

pub(crate) fn decode_scrub_observation(
    bytes: &[u8],
) -> Result<ScrubObservation, CapabilityCodecError> {
    if bytes.len() != SCRUB_OBSERVATION_BYTES {
        return Err(CapabilityCodecError::Invalid);
    }
    let mut reader = Reader::new(bytes);
    let shard = reader.shard()?;
    let expected = read_optional_measurement(&mut reader, true)?;
    let observed = read_optional_measurement(&mut reader, false)?;
    let outcome = decode_scrub_outcome(reader.u8()?)?;
    reader.finish()?;
    let observation = ScrubObservation {
        shard,
        expected_length: expected.map(|value| value.0),
        expected_digest: expected.map(|value| value.1),
        observed_length: observed.map(|value| value.0),
        observed_digest: observed.map(|value| value.1),
        outcome,
    };
    validate_exact_scrub_observation(observation).map_err(|_| CapabilityCodecError::Invalid)?;
    Ok(observation)
}

pub(crate) fn encode_reservation(reservation: StorageReservation) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RESERVATION_BYTES);
    bytes.extend_from_slice(&reservation.operation_id.as_bytes());
    bytes.extend_from_slice(&reservation.target_id.as_bytes());
    bytes.extend_from_slice(&reservation.target_generation.to_be_bytes());
    bytes.push(class_code(reservation.class));
    bytes.extend_from_slice(&reservation.maximum_bytes.to_be_bytes());
    bytes.extend_from_slice(&reservation.expires_at.get().to_be_bytes());
    bytes.extend_from_slice(&reservation.reservation_digest);
    bytes
}

pub(crate) fn encode_shard_receipt(receipt: ShardReceipt) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SHARD_RECEIPT_BYTES);
    bytes.extend_from_slice(&receipt.operation_id.as_bytes());
    push_shard(&mut bytes, receipt.shard);
    bytes.extend_from_slice(&receipt.length.to_be_bytes());
    bytes.extend_from_slice(&receipt.digest);
    bytes.extend_from_slice(&receipt.target_id.as_bytes());
    bytes.extend_from_slice(&receipt.target_generation.to_be_bytes());
    bytes
}

pub(crate) fn decode_shard_receipt(bytes: &[u8]) -> Result<ShardReceipt, CapabilityCodecError> {
    if bytes.len() != SHARD_RECEIPT_BYTES {
        return Err(CapabilityCodecError::Invalid);
    }
    let mut reader = Reader::new(bytes);
    let receipt = ShardReceipt {
        operation_id: OperationId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        shard: reader.shard()?,
        length: reader.u64()?,
        digest: reader.array()?,
        target_id: TargetId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        target_generation: reader.u64()?,
    };
    reader.finish()?;
    if receipt.length == 0 || receipt.digest == [0; 32] || receipt.target_generation == 0 {
        Err(CapabilityCodecError::Invalid)
    } else {
        Ok(receipt)
    }
}

fn push_common(bytes: &mut Vec<u8>, operation: OperationId, mesh: MeshId, target: TargetId) {
    bytes.extend_from_slice(&operation.as_bytes());
    bytes.extend_from_slice(&mesh.as_bytes());
    bytes.extend_from_slice(&target.as_bytes());
}

fn read_common(
    reader: &mut Reader<'_>,
) -> Result<(OperationId, MeshId, TargetId), CapabilityCodecError> {
    let operation =
        OperationId::from_bytes(reader.array()?).map_err(|_| CapabilityCodecError::Invalid)?;
    let mesh = MeshId::from_bytes(reader.array()?).map_err(|_| CapabilityCodecError::Invalid)?;
    let target =
        TargetId::from_bytes(reader.array()?).map_err(|_| CapabilityCodecError::Invalid)?;
    Ok((operation, mesh, target))
}

fn push_shard(bytes: &mut Vec<u8>, shard: ShardIdentity) {
    bytes.extend_from_slice(&shard.manifest_digest);
    bytes.extend_from_slice(&shard.stripe_index.to_be_bytes());
    bytes.extend_from_slice(&shard.shard_index.to_be_bytes());
    bytes.extend_from_slice(&shard.generation.to_be_bytes());
}

fn push_optional_measurement(bytes: &mut Vec<u8>, length: Option<u64>, digest: Option<[u8; 32]>) {
    if let Some((length, digest)) = length.zip(digest) {
        bytes.push(1);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&digest);
    } else {
        bytes.push(0);
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&[0; 32]);
    }
}

fn read_optional_measurement(
    reader: &mut Reader<'_>,
    require_positive_length: bool,
) -> Result<Option<(u64, [u8; 32])>, CapabilityCodecError> {
    let present = reader.u8()?;
    let length = reader.u64()?;
    let digest = reader.array()?;
    match present {
        0 if length == 0 && digest == [0; 32] => Ok(None),
        1 if digest != [0; 32] && (!require_positive_length || length > 0) => {
            Ok(Some((length, digest)))
        }
        _ => Err(CapabilityCodecError::Invalid),
    }
}

const fn scrub_outcome_code(outcome: ScrubOutcome) -> u8 {
    match outcome {
        ScrubOutcome::Healthy => 1,
        ScrubOutcome::Missing => 2,
        ScrubOutcome::Corrupt => 3,
        ScrubOutcome::Unreadable => 4,
        ScrubOutcome::Unexpected => 5,
        ScrubOutcome::Deferred => 6,
    }
}

const fn decode_scrub_outcome(value: u8) -> Result<ScrubOutcome, CapabilityCodecError> {
    match value {
        1 => Ok(ScrubOutcome::Healthy),
        2 => Ok(ScrubOutcome::Missing),
        3 => Ok(ScrubOutcome::Corrupt),
        4 => Ok(ScrubOutcome::Unreadable),
        5 => Ok(ScrubOutcome::Unexpected),
        6 => Ok(ScrubOutcome::Deferred),
        _ => Err(CapabilityCodecError::Invalid),
    }
}

const fn class_code(class: ReservationClass) -> u8 {
    match class {
        ReservationClass::ForegroundWrite => 1,
        ReservationClass::Repair => 2,
        ReservationClass::Relocation => 3,
    }
}

const fn decode_class(value: u8) -> Result<ReservationClass, CapabilityCodecError> {
    match value {
        1 => Ok(ReservationClass::ForegroundWrite),
        2 => Ok(ReservationClass::Repair),
        3 => Ok(ReservationClass::Relocation),
        _ => Err(CapabilityCodecError::Invalid),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], CapabilityCodecError> {
        let end = self
            .offset
            .checked_add(SIZE)
            .ok_or(CapabilityCodecError::Invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CapabilityCodecError::Invalid)?
            .try_into()
            .map_err(|_| CapabilityCodecError::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CapabilityCodecError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, CapabilityCodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CapabilityCodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CapabilityCodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64, CapabilityCodecError> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    fn shard(&mut self) -> Result<ShardIdentity, CapabilityCodecError> {
        let shard = ShardIdentity {
            manifest_digest: self.array()?,
            stripe_index: self.u64()?,
            shard_index: self.u16()?,
            generation: self.u32()?,
        };
        if shard.manifest_digest == [0; 32] || shard.generation == 0 {
            Err(CapabilityCodecError::Invalid)
        } else {
            Ok(shard)
        }
    }

    fn finish(self) -> Result<(), CapabilityCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CapabilityCodecError::Invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::{
        ReclamationReceipt, RemovalPermit, ReservationClass, ScrubObservation, ScrubOutcome,
        ShardIdentity, ShardReadPermit, ShardWritePermit, TombstoneReceipt,
        reclamation_receipt_digest, tombstone_receipt_digest,
    };
    use meshspan_domain::{MeshId, OperationId, Revision, TargetId, UnixMicros};

    use super::{
        decode_read_permit, decode_reclamation_evidence, decode_reclamation_receipt,
        decode_removal_permit, decode_scrub_observation, decode_tombstone_receipt,
        decode_write_permit, encode_read_permit, encode_reclamation_receipt, encode_removal_permit,
        encode_scrub_observation, encode_tombstone_receipt, encode_write_permit,
    };

    #[test]
    fn permit_encodings_round_trip_and_reject_non_exact_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let read = read_permit()?;
        let write = ShardWritePermit {
            operation_id: read.operation_id,
            mesh_id: read.mesh_id,
            target_id: read.target_id,
            target_generation: read.target_generation,
            shard: read.shard,
            reservation_class: ReservationClass::ForegroundWrite,
            maximum_bytes: 14,
            authorization_revision: read.authorization_revision,
            expires_at: read.expires_at,
            permit_digest: [15; 32],
        };
        assert_eq!(decode_read_permit(&encode_read_permit(read))?, read);
        assert_eq!(decode_write_permit(&encode_write_permit(write))?, write);
        let mut excessive = encode_write_permit(write);
        excessive.push(0);
        assert!(decode_write_permit(&excessive).is_err());
        let truncated = &encode_read_permit(read)[..149];
        assert!(decode_read_permit(truncated).is_err());
        Ok(())
    }

    #[test]
    fn removal_lifecycle_encodings_are_exact_and_self_checking()
    -> Result<(), Box<dyn std::error::Error>> {
        let permit = removal_permit()?;
        let tombstone = TombstoneReceipt {
            operation_id: permit.operation_id,
            shard: permit.shard,
            target_id: permit.target_id,
            target_generation: permit.target_generation,
            permit_digest: permit.permit_digest,
            tombstone_digest: tombstone_receipt_digest(permit),
        };
        let mut reclamation = ReclamationReceipt {
            tombstone,
            bytes_unlinked_at: UnixMicros::new(12),
            reclaimed_bytes: 13,
            reclamation_digest: [0; 32],
        };
        reclamation.reclamation_digest = reclamation_receipt_digest(
            tombstone,
            reclamation.bytes_unlinked_at,
            reclamation.reclaimed_bytes,
        );

        assert_eq!(
            decode_removal_permit(&encode_removal_permit(permit))?,
            permit
        );
        assert_eq!(
            decode_tombstone_receipt(&encode_tombstone_receipt(tombstone))?,
            tombstone
        );
        assert_eq!(
            decode_reclamation_receipt(&encode_reclamation_receipt(reclamation))?,
            reclamation
        );
        reject_every_non_exact_length(encode_removal_permit(permit), decode_removal_permit);
        reject_every_non_exact_length(
            encode_tombstone_receipt(tombstone),
            decode_tombstone_receipt,
        );
        reject_every_non_exact_length(
            encode_reclamation_receipt(reclamation),
            decode_reclamation_receipt,
        );
        let mut forged = encode_reclamation_receipt(reclamation);
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(decode_reclamation_receipt(&forged).is_err());
        let opaque = decode_reclamation_evidence(&forged)?;
        assert_eq!(opaque.tombstone, reclamation.tombstone);
        assert_ne!(opaque.reclamation_digest, reclamation.reclamation_digest);
        Ok(())
    }

    #[test]
    fn scrub_observation_encoding_is_exact_and_rejects_impossible_shapes()
    -> Result<(), Box<dyn std::error::Error>> {
        let healthy = ScrubObservation {
            shard: read_permit()?.shard,
            expected_length: Some(12),
            expected_digest: Some([13; 32]),
            observed_length: Some(12),
            observed_digest: Some([13; 32]),
            outcome: ScrubOutcome::Healthy,
        };
        let encoded = encode_scrub_observation(healthy)?;
        assert_eq!(decode_scrub_observation(&encoded)?, healthy);
        reject_every_non_exact_length(encoded, decode_scrub_observation);

        let missing = ScrubObservation {
            observed_length: None,
            observed_digest: None,
            outcome: ScrubOutcome::Missing,
            ..healthy
        };
        assert_eq!(
            decode_scrub_observation(&encode_scrub_observation(missing)?)?,
            missing
        );
        let corrupt = ScrubObservation {
            observed_digest: Some([14; 32]),
            outcome: ScrubOutcome::Corrupt,
            ..healthy
        };
        assert_eq!(
            decode_scrub_observation(&encode_scrub_observation(corrupt)?)?,
            corrupt
        );
        assert!(
            encode_scrub_observation(ScrubObservation {
                expected_digest: None,
                ..healthy
            })
            .is_err()
        );
        assert!(
            encode_scrub_observation(ScrubObservation {
                observed_digest: None,
                ..healthy
            })
            .is_err()
        );
        assert!(
            encode_scrub_observation(ScrubObservation {
                observed_digest: Some([14; 32]),
                ..healthy
            })
            .is_err()
        );
        assert!(
            encode_scrub_observation(ScrubObservation {
                outcome: ScrubOutcome::Corrupt,
                ..healthy
            })
            .is_err()
        );
        assert!(
            encode_scrub_observation(ScrubObservation {
                outcome: ScrubOutcome::Unexpected,
                ..healthy
            })
            .is_err()
        );
        Ok(())
    }

    fn reject_every_non_exact_length<T>(
        bytes: Vec<u8>,
        decode: fn(&[u8]) -> Result<T, super::CapabilityCodecError>,
    ) {
        for length in 0..bytes.len() {
            assert!(
                decode(&bytes[..length]).is_err(),
                "accepted length {length}"
            );
        }
        let mut excessive = bytes;
        excessive.push(0);
        assert!(decode(&excessive).is_err());
    }

    fn read_permit() -> Result<ShardReadPermit, Box<dyn std::error::Error>> {
        Ok(ShardReadPermit {
            operation_id: OperationId::from_bytes([1; 16])?,
            mesh_id: MeshId::from_bytes([2; 16])?,
            target_id: TargetId::from_bytes([3; 16])?,
            target_generation: 4,
            shard: ShardIdentity {
                manifest_digest: [5; 32],
                stripe_index: 6,
                shard_index: 7,
                generation: 8,
            },
            authorization_revision: Revision::new(9),
            expires_at: UnixMicros::new(10),
            permit_digest: [11; 32],
        })
    }

    fn removal_permit() -> Result<RemovalPermit, Box<dyn std::error::Error>> {
        let read = read_permit()?;
        Ok(RemovalPermit {
            operation_id: read.operation_id,
            mesh_id: read.mesh_id,
            target_id: read.target_id,
            shard: read.shard,
            target_generation: read.target_generation,
            authority_epoch: 9,
            catalogue_revision: Revision::new(10),
            expires_at: UnixMicros::new(11),
            permit_digest: [12; 32],
        })
    }
}
