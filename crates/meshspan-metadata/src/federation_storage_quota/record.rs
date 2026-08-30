// SPDX-License-Identifier: GPL-2.0-only

//! Independently validated reads of node-local federated quota evidence.

use meshspan_contracts::ShardIdentity;
use meshspan_domain::{
    FederationGrantId, FederationStorageAction, FederationStorageAllocationId, MeshId, OperationId,
    TargetId, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction};

use super::{
    COMMITTED, FederationStorageQuotaError, FederationStorageUsage,
    FederationStorageWriteReservation, FederationStorageWriteState, RELEASED, RESERVED,
    valid_digest,
};

type ReservationRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    i64,
    Vec<u8>,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    Option<i64>,
);

pub(super) fn load_reservation(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<FederationStorageWriteReservation>, FederationStorageQuotaError> {
    let row = connection
        .query_row(
            "SELECT allocation_id, remote_mesh_id, scope_digest, request_digest,
                    capability_nonce, manifest_digest, stripe_index, shard_index,
                    shard_generation, action, maximum_bytes, permit_digest, expires_at, state,
                    affected_bytes, charged_bytes, content_digest, result_digest,
                    absence_evidence_digest, issued_at, completed_at
             FROM local_federation_storage_reservations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| decode_reservation(operation_id, row))
        .transpose()
}

fn decode_reservation(
    operation_id: OperationId,
    row: ReservationRow,
) -> Result<FederationStorageWriteReservation, FederationStorageQuotaError> {
    let state = match row.13 {
        RESERVED => FederationStorageWriteState::Reserved,
        COMMITTED => FederationStorageWriteState::Committed,
        RELEASED => FederationStorageWriteState::Released,
        _ => return Err(FederationStorageQuotaError::CorruptState),
    };
    let record = FederationStorageWriteReservation {
        operation_id,
        allocation_id: FederationStorageAllocationId::from_bytes(exact(row.0)?)
            .map_err(|_| FederationStorageQuotaError::CorruptState)?,
        remote_mesh_id: MeshId::from_bytes(exact(row.1)?)
            .map_err(|_| FederationStorageQuotaError::CorruptState)?,
        scope_digest: exact(row.2)?,
        request_digest: exact(row.3)?,
        capability_nonce: exact(row.4)?,
        shard: ShardIdentity {
            manifest_digest: exact(row.5)?,
            stripe_index: nonnegative(row.6)?,
            shard_index: u16::try_from(row.7)
                .map_err(|_| FederationStorageQuotaError::CorruptState)?,
            generation: u32::try_from(row.8)
                .map_err(|_| FederationStorageQuotaError::CorruptState)?,
        },
        action: FederationStorageAction::from_code(
            u8::try_from(row.9).map_err(|_| FederationStorageQuotaError::CorruptState)?,
        )
        .map_err(|_| FederationStorageQuotaError::CorruptState)?,
        maximum_bytes: positive(row.10)?,
        permit_digest: exact(row.11)?,
        expires_at: UnixMicros::new(row.12),
        state,
        affected_bytes: row.14.map(positive).transpose()?,
        charged_bytes: row.15.map(nonnegative).transpose()?,
        content_digest: row.16.map(exact).transpose()?,
        result_digest: row.17.map(exact).transpose()?,
        absence_evidence_digest: row.18.map(exact).transpose()?,
        issued_at: UnixMicros::new(row.19),
        completed_at: row.20.map(UnixMicros::new),
    };
    validate_stored_reservation(&record)?;
    Ok(record)
}

fn validate_stored_reservation(
    record: &FederationStorageWriteReservation,
) -> Result<(), FederationStorageQuotaError> {
    let valid_base = record.action.reserves_capacity()
        && record.shard.generation > 0
        && record.issued_at.get() > 0
        && record.expires_at > record.issued_at
        && record.maximum_bytes > 0
        && valid_digest(record.scope_digest)
        && valid_digest(record.request_digest)
        && valid_digest(record.capability_nonce)
        && valid_digest(record.permit_digest);
    let valid_state = match record.state {
        FederationStorageWriteState::Reserved => {
            record.affected_bytes.is_none()
                && record.charged_bytes.is_none()
                && record.content_digest.is_none()
                && record.result_digest.is_none()
                && record.absence_evidence_digest.is_none()
                && record.completed_at.is_none()
        }
        FederationStorageWriteState::Committed => {
            record
                .affected_bytes
                .is_some_and(|value| value <= record.maximum_bytes)
                && record
                    .charged_bytes
                    .zip(record.affected_bytes)
                    .is_some_and(|(charged, affected)| charged <= affected)
                && record.content_digest.is_some_and(valid_digest)
                && record.result_digest.is_some_and(valid_digest)
                && record.absence_evidence_digest.is_none()
                && record
                    .completed_at
                    .is_some_and(|value| value >= record.issued_at)
        }
        FederationStorageWriteState::Released => {
            record.affected_bytes.is_none()
                && record.charged_bytes.is_none()
                && record.content_digest.is_none()
                && record.result_digest.is_none()
                && record.absence_evidence_digest.is_some_and(valid_digest)
                && record
                    .completed_at
                    .is_some_and(|value| value >= record.expires_at)
        }
    };
    if valid_base && valid_state {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::CorruptState)
    }
}

pub(super) fn load_usage(
    connection: &Connection,
    allocation_id: FederationStorageAllocationId,
) -> Result<Option<FederationStorageUsage>, FederationStorageQuotaError> {
    let row = connection
        .query_row(
            "SELECT maximum_bytes, committed_bytes, reserved_bytes
             FROM local_federation_storage_usage WHERE allocation_id = ?1",
            [allocation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(maximum, committed, reserved)| {
        let usage = FederationStorageUsage {
            allocation_id,
            maximum_bytes: positive(maximum)?,
            committed_bytes: nonnegative(committed)?,
            reserved_bytes: nonnegative(reserved)?,
        };
        if usage.reserved_bytes <= usage.maximum_bytes.saturating_sub(usage.committed_bytes) {
            Ok(usage)
        } else {
            Err(FederationStorageQuotaError::CorruptState)
        }
    })
    .transpose()
}

pub(super) struct UsageIdentity {
    pub(super) grant_id: FederationGrantId,
    pub(super) remote_mesh_id: meshspan_domain::MeshId,
    pub(super) target_id: TargetId,
    pub(super) target_generation: u64,
}

pub(super) fn load_usage_identity(
    transaction: &Transaction<'_>,
    allocation_id: FederationStorageAllocationId,
) -> Result<UsageIdentity, FederationStorageQuotaError> {
    let row = transaction.query_row(
        "SELECT grant_id, remote_mesh_id, target_id, target_generation
         FROM local_federation_storage_usage WHERE allocation_id = ?1",
        [allocation_id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    Ok(UsageIdentity {
        grant_id: FederationGrantId::from_bytes(exact(row.0)?)
            .map_err(|_| FederationStorageQuotaError::CorruptState)?,
        remote_mesh_id: meshspan_domain::MeshId::from_bytes(exact(row.1)?)
            .map_err(|_| FederationStorageQuotaError::CorruptState)?,
        target_id: TargetId::from_bytes(exact(row.2)?)
            .map_err(|_| FederationStorageQuotaError::CorruptState)?,
        target_generation: positive(row.3)?,
    })
}

pub(super) fn positive(value: i64) -> Result<u64, FederationStorageQuotaError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(FederationStorageQuotaError::CorruptState)
}

fn nonnegative(value: i64) -> Result<u64, FederationStorageQuotaError> {
    u64::try_from(value).map_err(|_| FederationStorageQuotaError::CorruptState)
}

pub(super) fn exact<const N: usize>(
    bytes: Vec<u8>,
) -> Result<[u8; N], FederationStorageQuotaError> {
    bytes
        .try_into()
        .map_err(|_| FederationStorageQuotaError::CorruptState)
}
