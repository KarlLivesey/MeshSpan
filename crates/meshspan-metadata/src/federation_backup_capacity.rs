// SPDX-License-Identifier: GPL-2.0-only

//! Exact backup charges sharing the existing bilateral allocation budget with shards.

use meshspan_contracts::{BackupObjectIdentity, MAXIMUM_BACKUP_CAPACITY_PAGE};
use meshspan_domain::{BackupDestinationId, BackupId, FederationStorageAllocationId, UnixMicros};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::federation_storage_quota::{hold_capacity, install_or_validate_usage};
use crate::{
    FederationStorageAllocationAuthority, FederationStorageQuotaDisposition,
    FederationStorageQuotaError, LocalDatabase,
};

/// Durable accounting state, not proof of provider IO or permission to perform it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederatedBackupCapacityState {
    /// Capacity held before IO; bytes may or may not have been published.
    Held,
    /// Exact durable provider publication was reported by the trusted provider owner.
    Stored,
    /// Exclusive recovery proved no object/staging bytes; an exact retry may reserve again.
    Cancelled,
    /// Exact physical deletion completed; this identity cannot be reused.
    Released,
}

impl LocalDatabase {
    /// Holds one object's exact bytes against fresh bilateral allocation authority.
    ///
    /// # Errors
    /// Rejects wrong-node, stale allocation, invalid object, changed retry or exhausted capacity.
    /// Shard reservations and backup reservations consume the same counters atomically.
    pub fn reserve_federated_backup_capacity(
        &mut self,
        authority: FederationStorageAllocationAuthority,
        object: BackupObjectIdentity,
    ) -> Result<FederationStorageQuotaDisposition, FederationStorageQuotaError> {
        validate_object(object)?;
        let allocation = authority.allocation();
        let now = authority.observed_at();
        if allocation.provider_node_id() != self.node_id()
            || authority.requested_bytes() != object.byte_length
            || now < authority.valid_from()
            || now >= authority.valid_until()
        {
            return Err(FederationStorageQuotaError::Invalid);
        }
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        install_or_validate_usage(&tx, authority, now)?;
        let previous = load(&tx, allocation.allocation_id(), object)?;
        match previous {
            Some(FederatedBackupCapacityState::Held | FederatedBackupCapacityState::Stored) => {
                tx.commit()?;
                return Ok(FederationStorageQuotaDisposition::Replayed);
            }
            Some(FederatedBackupCapacityState::Released) => {
                return Err(FederationStorageQuotaError::Conflict);
            }
            None | Some(FederatedBackupCapacityState::Cancelled) => {}
        }
        hold_capacity(&tx, authority, now)?;
        tx.execute(
            "INSERT INTO local_federation_backup_capacity(allocation_id,destination_id,
             provider_generation,backup_id,byte_length,digest,state,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,1,?7)
             ON CONFLICT(allocation_id,destination_id,provider_generation,backup_id)
             DO UPDATE SET state=1,updated_at=excluded.updated_at",
            params![
                allocation.allocation_id().as_bytes().as_slice(),
                object.destination_id.as_bytes().as_slice(),
                number(object.provider_generation)?,
                object.backup_id.as_bytes().as_slice(),
                number(object.byte_length)?,
                object.digest.as_slice(),
                now.get()
            ],
        )?;
        tx.commit()?;
        Ok(FederationStorageQuotaDisposition::Applied)
    }

    /// Moves a hold to used bytes only after exact durable provider publication.
    ///
    /// # Errors
    /// Rejects missing/changed/released holds or corrupt counters. Never accepts remote IO claims;
    /// the caller must be the local provider owner which verified and published the object.
    pub fn commit_federated_backup_capacity(
        &mut self,
        allocation: FederationStorageAllocationId,
        object: BackupObjectIdentity,
        now: UnixMicros,
    ) -> Result<FederationStorageQuotaDisposition, FederationStorageQuotaError> {
        transition(self, allocation, object, Transition::Commit, now)
    }

    /// Cancels a held object only after exclusive local recovery proves complete absence.
    ///
    /// # Errors
    /// Rejects stored/released/changed objects or corrupt counters. Expiry alone is insufficient;
    /// this provider-owner operation is never exposed as a remote cancellation request.
    pub fn cancel_federated_backup_capacity(
        &mut self,
        allocation: FederationStorageAllocationId,
        object: BackupObjectIdentity,
        now: UnixMicros,
    ) -> Result<FederationStorageQuotaDisposition, FederationStorageQuotaError> {
        transition(self, allocation, object, Transition::Cancel, now)
    }

    /// Releases used capacity only after the local provider confirms exact physical removal.
    ///
    /// # Errors
    /// Rejects held/cancelled/changed objects or corrupt counters. It grants no deletion authority.
    pub fn release_federated_backup_capacity(
        &mut self,
        allocation: FederationStorageAllocationId,
        object: BackupObjectIdentity,
        now: UnixMicros,
    ) -> Result<FederationStorageQuotaDisposition, FederationStorageQuotaError> {
        transition(self, allocation, object, Transition::Release, now)
    }

    /// Reads independently checked state for the exact object, never by locator alone.
    ///
    /// # Errors
    /// Rejects invalid/changed identity, corrupt rows and unavailable storage.
    pub fn federated_backup_capacity_state(
        &self,
        allocation: FederationStorageAllocationId,
        object: BackupObjectIdentity,
    ) -> Result<Option<FederatedBackupCapacityState>, FederationStorageQuotaError> {
        validate_object(object)?;
        load(self.connection(), allocation, object)
    }

    /// Pages bounded unresolved holds for one exact allocation/destination incarnation.
    ///
    /// # Errors
    /// Rejects invalid generations, corrupt rows or database failures. Returned objects are
    /// recovery candidates, not proof that bytes are absent or permission to discard them.
    pub fn pending_federated_backup_capacity(
        &self,
        allocation: FederationStorageAllocationId,
        destination: BackupDestinationId,
        generation: u64,
        after: Option<BackupId>,
    ) -> Result<Vec<BackupObjectIdentity>, FederationStorageQuotaError> {
        if generation == 0 {
            return Err(FederationStorageQuotaError::Invalid);
        }
        let mut query = self.connection().prepare(
            "SELECT backup_id,byte_length,digest FROM local_federation_backup_capacity
             WHERE allocation_id=?1 AND destination_id=?2 AND provider_generation=?3 AND state=1
               AND (?4 IS NULL OR backup_id>?4) ORDER BY backup_id LIMIT ?5",
        )?;
        let rows = query.query_map(
            params![
                allocation.as_bytes().as_slice(),
                destination.as_bytes().as_slice(),
                number(generation)?,
                after.map(|id| id.as_bytes().to_vec()),
                i64::try_from(MAXIMUM_BACKUP_CAPACITY_PAGE)
                    .map_err(|_| FederationStorageQuotaError::Invalid)?
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (id, length, digest) = row?;
            let object = BackupObjectIdentity {
                backup_id: BackupId::from_bytes(
                    id.try_into()
                        .map_err(|_| FederationStorageQuotaError::CorruptState)?,
                )
                .map_err(|_| FederationStorageQuotaError::CorruptState)?,
                destination_id: destination,
                provider_generation: generation,
                byte_length: u64::try_from(length)
                    .map_err(|_| FederationStorageQuotaError::CorruptState)?,
                digest: digest
                    .try_into()
                    .map_err(|_| FederationStorageQuotaError::CorruptState)?,
            };
            validate_object(object).map_err(|_| FederationStorageQuotaError::CorruptState)?;
            Ok(object)
        })
        .collect()
    }
}

enum Transition {
    Commit,
    Cancel,
    Release,
}

fn transition(
    database: &mut LocalDatabase,
    allocation: FederationStorageAllocationId,
    object: BackupObjectIdentity,
    action: Transition,
    now: UnixMicros,
) -> Result<FederationStorageQuotaDisposition, FederationStorageQuotaError> {
    validate_object(object)?;
    if now.get() <= 0 {
        return Err(FederationStorageQuotaError::Invalid);
    }
    let tx = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let previous = load(&tx, allocation, object)?.ok_or(FederationStorageQuotaError::Conflict)?;
    let (required, next, code, reserved_delta, committed_delta) =
        action.effects(number(object.byte_length)?);
    if previous == next {
        tx.commit()?;
        return Ok(FederationStorageQuotaDisposition::Replayed);
    }
    if previous != required {
        return Err(FederationStorageQuotaError::Conflict);
    }
    let updated = tx.execute(
        "UPDATE local_federation_storage_usage SET reserved_bytes=reserved_bytes+?1,
         committed_bytes=committed_bytes+?2,updated_at=?3 WHERE allocation_id=?4
         AND reserved_bytes+?1>=0 AND committed_bytes+?2>=0",
        params![
            reserved_delta,
            committed_delta,
            now.get(),
            allocation.as_bytes().as_slice()
        ],
    )?;
    if updated != 1 {
        return Err(FederationStorageQuotaError::CorruptState);
    }
    tx.execute(
        "UPDATE local_federation_backup_capacity SET state=?1,updated_at=?2
         WHERE allocation_id=?3 AND destination_id=?4 AND provider_generation=?5 AND backup_id=?6",
        params![
            code,
            now.get(),
            allocation.as_bytes().as_slice(),
            object.destination_id.as_bytes().as_slice(),
            number(object.provider_generation)?,
            object.backup_id.as_bytes().as_slice()
        ],
    )?;
    tx.commit()?;
    Ok(FederationStorageQuotaDisposition::Applied)
}

impl Transition {
    const fn effects(
        self,
        bytes: i64,
    ) -> (
        FederatedBackupCapacityState,
        FederatedBackupCapacityState,
        i64,
        i64,
        i64,
    ) {
        use FederatedBackupCapacityState::{Cancelled, Held, Released, Stored};
        match self {
            Self::Commit => (Held, Stored, 2, -bytes, bytes),
            Self::Cancel => (Held, Cancelled, 3, -bytes, 0),
            Self::Release => (Stored, Released, 4, 0, -bytes),
        }
    }
}

fn load(
    database: &Connection,
    allocation: FederationStorageAllocationId,
    object: BackupObjectIdentity,
) -> Result<Option<FederatedBackupCapacityState>, FederationStorageQuotaError> {
    let row = database
        .query_row(
            "SELECT byte_length,digest,state FROM local_federation_backup_capacity
         WHERE allocation_id=?1 AND destination_id=?2 AND provider_generation=?3 AND backup_id=?4",
            params![
                allocation.as_bytes().as_slice(),
                object.destination_id.as_bytes().as_slice(),
                number(object.provider_generation)?,
                object.backup_id.as_bytes().as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(length, digest, state)| {
        if length != number(object.byte_length)? || digest.as_slice() != object.digest {
            return Err(FederationStorageQuotaError::Conflict);
        }
        match state {
            1 => Ok(FederatedBackupCapacityState::Held),
            2 => Ok(FederatedBackupCapacityState::Stored),
            3 => Ok(FederatedBackupCapacityState::Cancelled),
            4 => Ok(FederatedBackupCapacityState::Released),
            _ => Err(FederationStorageQuotaError::CorruptState),
        }
    })
    .transpose()
}

fn validate_object(object: BackupObjectIdentity) -> Result<(), FederationStorageQuotaError> {
    number(object.byte_length)?;
    number(object.provider_generation)?;
    if object.byte_length == 0 || object.provider_generation == 0 || object.digest == [0; 32] {
        Err(FederationStorageQuotaError::Invalid)
    } else {
        Ok(())
    }
}

fn number(value: u64) -> Result<i64, FederationStorageQuotaError> {
    i64::try_from(value).map_err(|_| FederationStorageQuotaError::Invalid)
}
