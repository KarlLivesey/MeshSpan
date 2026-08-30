// SPDX-License-Identifier: GPL-2.0-only

//! Atomic writes for the node-local federated storage quota ledger.

use meshspan_domain::UnixMicros;
use rusqlite::{OptionalExtension, Transaction, params};

use super::{
    FederationStorageQuotaError, FederationStorageWriteAbsence, FederationStorageWriteCompletion,
    FederationStorageWriteReservation, FederationStorageWriteReservationRequest,
};
use crate::FederationStorageAllocationAuthority;
use crate::federation_storage_quota::record::{exact, load_usage_identity, positive};

pub(super) fn validate_reservation_replay(
    stored: &FederationStorageWriteReservation,
    authority: FederationStorageAllocationAuthority,
    request: FederationStorageWriteReservationRequest,
) -> Result<(), FederationStorageQuotaError> {
    let matches = stored.allocation_id == authority.allocation().allocation_id()
        && stored.remote_mesh_id == request.remote_mesh_id
        && stored.scope_digest == request.scope_digest
        && stored.request_digest == request.request_digest
        && stored.capability_nonce == request.capability_nonce
        && stored.shard == request.shard
        && stored.action == request.action
        && stored.maximum_bytes == authority.requested_bytes()
        && stored.permit_digest == request.permit_digest
        && stored.expires_at == request.expires_at
        && stored.issued_at == request.issued_at;
    if matches {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::Conflict)
    }
}

pub(super) fn reject_nonce_reuse(
    transaction: &Transaction<'_>,
    nonce: [u8; 32],
) -> Result<(), FederationStorageQuotaError> {
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM local_federation_storage_reservations WHERE capability_nonce = ?1
         )",
        [nonce.as_slice()],
        |row| row.get(0),
    )?;
    if exists == 0 {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::Conflict)
    }
}

pub(super) fn install_or_validate_usage(
    transaction: &Transaction<'_>,
    authority: FederationStorageAllocationAuthority,
    updated_at: UnixMicros,
) -> Result<(), FederationStorageQuotaError> {
    let allocation = authority.allocation();
    transaction.execute(
        "INSERT OR IGNORE INTO local_federation_storage_usage(
            allocation_id, relationship_id, remote_mesh_id, grant_id, provider_node_id,
            target_id, target_generation, maximum_bytes, committed_bytes, reserved_bytes,
            valid_from, valid_until, relationship_authority_epoch, grant_revision,
            allocation_revision, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            allocation.allocation_id().as_bytes().as_slice(),
            authority.relationship_id().as_bytes().as_slice(),
            authority.remote_mesh_id().as_bytes().as_slice(),
            allocation.grant_id().as_bytes().as_slice(),
            allocation.provider_node_id().as_bytes().as_slice(),
            allocation.target_id().as_bytes().as_slice(),
            to_i64(allocation.target_generation())?,
            to_i64(allocation.maximum_bytes())?,
            allocation.valid_from().get(),
            allocation.valid_until().get(),
            to_i64(authority.relationship_authority_epoch())?,
            to_i64(authority.grant_revision().get())?,
            to_i64(authority.allocation_revision().get())?,
            updated_at.get()
        ],
    )?;
    let matches: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_federation_storage_usage
         WHERE allocation_id = ?1 AND relationship_id = ?2 AND remote_mesh_id = ?3
           AND grant_id = ?4 AND provider_node_id = ?5 AND target_id = ?6
           AND target_generation = ?7 AND maximum_bytes = ?8 AND valid_from = ?9
           AND valid_until = ?10 AND relationship_authority_epoch = ?11
           AND grant_revision = ?12 AND allocation_revision = ?13)",
        params![
            allocation.allocation_id().as_bytes().as_slice(),
            authority.relationship_id().as_bytes().as_slice(),
            authority.remote_mesh_id().as_bytes().as_slice(),
            allocation.grant_id().as_bytes().as_slice(),
            allocation.provider_node_id().as_bytes().as_slice(),
            allocation.target_id().as_bytes().as_slice(),
            to_i64(allocation.target_generation())?,
            to_i64(allocation.maximum_bytes())?,
            allocation.valid_from().get(),
            allocation.valid_until().get(),
            to_i64(authority.relationship_authority_epoch())?,
            to_i64(authority.grant_revision().get())?,
            to_i64(authority.allocation_revision().get())?
        ],
        |row| row.get(0),
    )?;
    if matches == 1 {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::Conflict)
    }
}

pub(super) fn hold_capacity(
    transaction: &Transaction<'_>,
    authority: FederationStorageAllocationAuthority,
    updated_at: UnixMicros,
) -> Result<(), FederationStorageQuotaError> {
    let updated_rows = transaction.execute(
        "UPDATE local_federation_storage_usage
         SET reserved_bytes = reserved_bytes + ?1, updated_at = ?2
         WHERE allocation_id = ?3 AND ?1 <= maximum_bytes - committed_bytes - reserved_bytes",
        params![
            to_i64(authority.requested_bytes())?,
            updated_at.get(),
            authority.allocation().allocation_id().as_bytes().as_slice()
        ],
    )?;
    if updated_rows == 1 {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::CapacityExceeded)
    }
}

pub(super) fn insert_reservation(
    transaction: &Transaction<'_>,
    authority: FederationStorageAllocationAuthority,
    request: FederationStorageWriteReservationRequest,
) -> Result<(), FederationStorageQuotaError> {
    transaction.execute(
        "INSERT INTO local_federation_storage_reservations(
            operation_id, allocation_id, remote_mesh_id, scope_digest, request_digest,
            capability_nonce, manifest_digest, stripe_index, shard_index, shard_generation,
            action, maximum_bytes, permit_digest, expires_at, state, issued_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 1, ?15)",
        params![
            request.operation_id.as_bytes().as_slice(),
            authority.allocation().allocation_id().as_bytes().as_slice(),
            request.remote_mesh_id.as_bytes().as_slice(),
            request.scope_digest.as_slice(),
            request.request_digest.as_slice(),
            request.capability_nonce.as_slice(),
            request.shard.manifest_digest.as_slice(),
            to_i64(request.shard.stripe_index)?,
            i64::from(request.shard.shard_index),
            i64::from(request.shard.generation),
            i64::from(request.action.code()),
            to_i64(authority.requested_bytes())?,
            request.permit_digest.as_slice(),
            request.expires_at.get(),
            request.issued_at.get()
        ],
    )?;
    Ok(())
}

pub(super) fn persist_unique_shard(
    transaction: &Transaction<'_>,
    stored: &FederationStorageWriteReservation,
    completion: FederationStorageWriteCompletion,
) -> Result<u64, FederationStorageQuotaError> {
    let usage = load_usage_identity(transaction, stored.allocation_id)?;
    if usage.remote_mesh_id != stored.remote_mesh_id {
        return Err(FederationStorageQuotaError::CorruptState);
    }
    let existing = transaction
        .query_row(
            "SELECT length, content_digest FROM local_federation_storage_shards
             WHERE remote_mesh_id = ?1 AND scope_digest = ?2 AND target_id = ?3
               AND target_generation = ?4 AND manifest_digest = ?5 AND stripe_index = ?6
               AND shard_index = ?7 AND shard_generation = ?8
               AND NOT EXISTS(
                   SELECT 1 FROM local_federation_storage_lifecycle AS lifecycle
                   WHERE lifecycle.remote_mesh_id = local_federation_storage_shards.remote_mesh_id
                     AND lifecycle.scope_digest = local_federation_storage_shards.scope_digest
                     AND lifecycle.target_id = local_federation_storage_shards.target_id
                     AND lifecycle.target_generation = local_federation_storage_shards.target_generation
                     AND lifecycle.manifest_digest = local_federation_storage_shards.manifest_digest
                     AND lifecycle.stripe_index = local_federation_storage_shards.stripe_index
                     AND lifecycle.shard_index = local_federation_storage_shards.shard_index
                     AND lifecycle.shard_generation = local_federation_storage_shards.shard_generation
               )",
            params![
                usage.remote_mesh_id.as_bytes().as_slice(),
                stored.scope_digest.as_slice(),
                usage.target_id.as_bytes().as_slice(),
                to_i64(usage.target_generation)?,
                stored.shard.manifest_digest.as_slice(),
                to_i64(stored.shard.stripe_index)?,
                i64::from(stored.shard.shard_index),
                i64::from(stored.shard.generation)
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    if let Some((length, digest)) = existing {
        if positive(length)? == completion.affected_bytes
            && exact::<32>(digest)? == completion.content_digest
        {
            return Ok(0);
        }
        return Err(FederationStorageQuotaError::Conflict);
    }
    transaction.execute(
        "INSERT INTO local_federation_storage_shards(
            grant_id, remote_mesh_id, scope_digest, target_id, target_generation, manifest_digest, stripe_index,
            shard_index, shard_generation, allocation_id, length, content_digest,
            committed_operation_id, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            usage.grant_id.as_bytes().as_slice(),
            usage.remote_mesh_id.as_bytes().as_slice(),
            stored.scope_digest.as_slice(),
            usage.target_id.as_bytes().as_slice(),
            to_i64(usage.target_generation)?,
            stored.shard.manifest_digest.as_slice(),
            to_i64(stored.shard.stripe_index)?,
            i64::from(stored.shard.shard_index),
            i64::from(stored.shard.generation),
            stored.allocation_id.as_bytes().as_slice(),
            to_i64(completion.affected_bytes)?,
            completion.content_digest.as_slice(),
            stored.operation_id.as_bytes().as_slice(),
            completion.completed_at.get()
        ],
    )?;
    Ok(completion.affected_bytes)
}

pub(super) fn replace_reservation_with_committed_usage(
    transaction: &Transaction<'_>,
    stored: &FederationStorageWriteReservation,
    charged: u64,
    completion: FederationStorageWriteCompletion,
) -> Result<(), FederationStorageQuotaError> {
    let usage_rows = transaction.execute(
        "UPDATE local_federation_storage_usage SET
            reserved_bytes = reserved_bytes - ?1,
            committed_bytes = committed_bytes + ?2, updated_at = ?3
         WHERE allocation_id = ?4 AND reserved_bytes >= ?1
           AND ?2 <= maximum_bytes - committed_bytes",
        params![
            to_i64(stored.maximum_bytes)?,
            to_i64(charged)?,
            completion.completed_at.get(),
            stored.allocation_id.as_bytes().as_slice()
        ],
    )?;
    if usage_rows != 1 {
        return Err(FederationStorageQuotaError::CorruptState);
    }
    let reservation_rows = transaction.execute(
        "UPDATE local_federation_storage_reservations SET state = 2, affected_bytes = ?1,
            charged_bytes = ?2, content_digest = ?3, result_digest = ?4, completed_at = ?5
         WHERE operation_id = ?6 AND state = 1 AND permit_digest = ?7",
        params![
            to_i64(completion.affected_bytes)?,
            to_i64(charged)?,
            completion.content_digest.as_slice(),
            completion.result_digest.as_slice(),
            completion.completed_at.get(),
            completion.operation_id.as_bytes().as_slice(),
            completion.permit_digest.as_slice()
        ],
    )?;
    if reservation_rows == 1 {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::Conflict)
    }
}

pub(super) fn release_capacity(
    transaction: &Transaction<'_>,
    stored: &FederationStorageWriteReservation,
    absence: FederationStorageWriteAbsence,
) -> Result<(), FederationStorageQuotaError> {
    let usage_rows = transaction.execute(
        "UPDATE local_federation_storage_usage
         SET reserved_bytes = reserved_bytes - ?1, updated_at = ?2
         WHERE allocation_id = ?3 AND reserved_bytes >= ?1",
        params![
            to_i64(stored.maximum_bytes)?,
            absence.completed_at.get(),
            stored.allocation_id.as_bytes().as_slice()
        ],
    )?;
    if usage_rows != 1 {
        return Err(FederationStorageQuotaError::CorruptState);
    }
    let reservation_rows = transaction.execute(
        "UPDATE local_federation_storage_reservations SET state = 3,
            absence_evidence_digest = ?1, completed_at = ?2
         WHERE operation_id = ?3 AND state = 1 AND permit_digest = ?4",
        params![
            absence.absence_evidence_digest.as_slice(),
            absence.completed_at.get(),
            absence.operation_id.as_bytes().as_slice(),
            absence.permit_digest.as_slice()
        ],
    )?;
    if reservation_rows == 1 {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::Conflict)
    }
}

pub(super) fn validate_completion_replay(
    stored: &FederationStorageWriteReservation,
    completion: FederationStorageWriteCompletion,
) -> Result<(), FederationStorageQuotaError> {
    if stored.permit_digest == completion.permit_digest
        && stored.affected_bytes == Some(completion.affected_bytes)
        && stored.content_digest == Some(completion.content_digest)
        && stored.result_digest == Some(completion.result_digest)
        && stored.completed_at == Some(completion.completed_at)
    {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::Conflict)
    }
}

pub(super) fn validate_release_replay(
    stored: &FederationStorageWriteReservation,
    absence: FederationStorageWriteAbsence,
) -> Result<(), FederationStorageQuotaError> {
    if stored.permit_digest == absence.permit_digest
        && stored.absence_evidence_digest == Some(absence.absence_evidence_digest)
        && stored.completed_at == Some(absence.completed_at)
    {
        Ok(())
    } else {
        Err(FederationStorageQuotaError::Conflict)
    }
}

fn to_i64(value: u64) -> Result<i64, FederationStorageQuotaError> {
    i64::try_from(value).map_err(|_| FederationStorageQuotaError::Invalid)
}
