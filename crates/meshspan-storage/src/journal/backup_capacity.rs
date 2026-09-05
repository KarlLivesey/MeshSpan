// SPDX-License-Identifier: GPL-2.0-only

//! Backup charges in the same atomic counters used by shard admission.

use meshspan_contracts::{BackupObjectIdentity, ReservationClass};
use meshspan_domain::{BackupDestinationId, BackupId};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{CapacityObservation, TargetJournal, TargetJournalError, admit_capacity, to_i64};

const HELD: i64 = 1;
const STORED: i64 = 2;
const RELEASED: i64 = 3;

impl TargetJournal {
    /// Returns one bounded, identity-ordered page of a destination's unpublished holds.
    ///
    /// # Errors
    /// Rejects a stale target generation or malformed persistent accounting.
    pub fn pending_backup_holds(
        &self,
        destination: BackupDestinationId,
        generation: u64,
        after: Option<BackupId>,
    ) -> Result<Vec<BackupObjectIdentity>, TargetJournalError> {
        if generation != self.marker.generation() {
            return Err(TargetJournalError::InvalidInput);
        }
        let lower = after.map_or([0; 16], BackupId::as_bytes);
        let mut statement = self.connection.prepare(
            "SELECT backup_id, byte_length, digest FROM backup_capacity
             WHERE destination_id = ?1 AND backup_id > ?2 AND provider_generation = ?3 AND state = 1
             ORDER BY backup_id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                destination.as_bytes().as_slice(),
                lower.as_slice(),
                to_i64(generation)?,
                to_i64(meshspan_contracts::MAXIMUM_BACKUP_CAPACITY_PAGE as u64)?
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        let mut objects = Vec::new();
        for row in rows {
            let (id, bytes, digest) = row?;
            let object = BackupObjectIdentity {
                backup_id: BackupId::from_bytes(
                    id.try_into()
                        .map_err(|_| TargetJournalError::CorruptState)?,
                )
                .map_err(|_| TargetJournalError::CorruptState)?,
                destination_id: destination,
                provider_generation: generation,
                byte_length: u64::try_from(bytes).map_err(|_| TargetJournalError::CorruptState)?,
                digest: digest
                    .try_into()
                    .map_err(|_| TargetJournalError::CorruptState)?,
            };
            self.validate_backup_object(object)?;
            objects.push(object);
        }
        Ok(objects)
    }

    /// Cancels only a held object after provider-owned proof that no bytes were published.
    /// Unlike retirement, cancellation leaves the identity available for a newly admitted retry.
    ///
    /// # Errors
    /// Rejects changed identity, committed/retired objects and inconsistent counters.
    pub fn cancel_unpublished_backup(
        &mut self,
        object: BackupObjectIdentity,
    ) -> Result<(), TargetJournalError> {
        self.validate_backup_object(object)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        match load(&transaction, object)? {
            None => return Ok(()),
            Some(HELD) => {}
            Some(_) => return Err(TargetJournalError::OperationConflict),
        }
        changed(transaction.execute(
            "UPDATE target_state SET reserved_bytes = reserved_bytes - ?1
             WHERE singleton = 1 AND reserved_bytes >= ?1",
            [to_i64(object.byte_length)?],
        )?)?;
        changed(transaction.execute(
            "DELETE FROM backup_capacity WHERE destination_id = ?1 AND backup_id = ?2 AND provider_generation = ?3 AND state = 1",
            params![object.destination_id.as_bytes().as_slice(), object.backup_id.as_bytes().as_slice(), to_i64(object.provider_generation)?])?)?;
        transaction.commit()?;
        Ok(())
    }

    /// Reserves one immutable backup in the target's common quota and repair headroom.
    ///
    /// # Errors
    /// Rejects malformed or changed objects, retired charges and exhausted capacity.
    pub fn reserve_backup_capacity(
        &mut self,
        object: BackupObjectIdentity,
        observation: CapacityObservation,
    ) -> Result<(), TargetJournalError> {
        self.validate_backup_object(object)?;
        let observation = observation.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        match load(&transaction, object)? {
            Some(HELD | STORED) => return Ok(()),
            Some(_) => return Err(TargetJournalError::OperationConflict),
            None => {}
        }
        admit_capacity(
            &transaction,
            self.policy,
            ReservationClass::ForegroundWrite,
            object.byte_length,
            observation,
        )?;
        insert(&transaction, object, HELD)?;
        transaction.commit()?;
        Ok(())
    }

    /// Converts one exact held backup to committed usage, without admitting more space.
    ///
    /// # Errors
    /// Rejects a missing, retired or conflicting object and invalid counters.
    pub fn commit_backup_capacity(
        &mut self,
        object: BackupObjectIdentity,
    ) -> Result<(), TargetJournalError> {
        self.validate_backup_object(object)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        match load(&transaction, object)? {
            Some(STORED) => return Ok(()),
            Some(HELD) => move_to_stored(&transaction, object)?,
            _ => return Err(TargetJournalError::OperationConflict),
        }
        transaction.commit()?;
        Ok(())
    }

    /// Charges an existing provider-catalogue object even if policy was reduced below usage.
    ///
    /// # Errors
    /// Rejects conflicting/retired objects and arithmetic or persistence failures.
    pub fn reconcile_backup_capacity(
        &mut self,
        object: BackupObjectIdentity,
    ) -> Result<(), TargetJournalError> {
        self.validate_backup_object(object)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        match load(&transaction, object)? {
            Some(STORED) => return Ok(()),
            Some(HELD) => move_to_stored(&transaction, object)?,
            Some(_) => return Err(TargetJournalError::OperationConflict),
            None => {
                let bytes = to_i64(object.byte_length)?;
                changed(transaction.execute(
                    "UPDATE target_state SET committed_bytes = committed_bytes + ?1
                     WHERE singleton = 1 AND committed_bytes <= ?2",
                    params![bytes, i64::MAX - bytes],
                )?)?;
                insert(&transaction, object, STORED)?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Releases an exact backup charge after confirmed physical deletion, once only.
    ///
    /// # Errors
    /// Rejects changed object identity or corrupt accounting. Unknown pre-upgrade objects
    /// have no charge to release; retained release rows prevent accidental reuse.
    pub fn release_backup_capacity(
        &mut self,
        object: BackupObjectIdentity,
    ) -> Result<(), TargetJournalError> {
        self.validate_backup_object(object)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = load(&transaction, object)?;
        let sql = match state {
            Some(HELD) => {
                "UPDATE target_state SET reserved_bytes = reserved_bytes - ?1 WHERE singleton = 1 AND reserved_bytes >= ?1"
            }
            Some(STORED) => {
                "UPDATE target_state SET committed_bytes = committed_bytes - ?1 WHERE singleton = 1 AND committed_bytes >= ?1"
            }
            Some(RELEASED) => return Ok(()),
            None => {
                insert(&transaction, object, RELEASED)?;
                transaction.commit()?;
                return Ok(());
            }
            Some(_) => return Err(TargetJournalError::CorruptState),
        };
        changed(transaction.execute(sql, [to_i64(object.byte_length)?])?)?;
        set_state(&transaction, object, RELEASED)?;
        transaction.commit()?;
        Ok(())
    }

    fn validate_backup_object(
        &self,
        object: BackupObjectIdentity,
    ) -> Result<(), TargetJournalError> {
        if object.provider_generation != self.marker.generation()
            || object.byte_length == 0
            || object.digest == [0; 32]
        {
            return Err(TargetJournalError::InvalidInput);
        }
        to_i64(object.byte_length)?;
        Ok(())
    }
}

fn load(
    transaction: &Transaction<'_>,
    object: BackupObjectIdentity,
) -> Result<Option<i64>, TargetJournalError> {
    let row = transaction
        .query_row(
            "SELECT byte_length, digest, state FROM backup_capacity
         WHERE destination_id = ?1 AND backup_id = ?2 AND provider_generation = ?3",
            params![
                object.destination_id.as_bytes().as_slice(),
                object.backup_id.as_bytes().as_slice(),
                to_i64(object.provider_generation)?
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
    row.map(|(bytes, digest, state)| {
        if bytes != to_i64(object.byte_length)? || digest.as_slice() != object.digest {
            return Err(TargetJournalError::OperationConflict);
        }
        Ok(state)
    })
    .transpose()
}

fn insert(
    transaction: &Transaction<'_>,
    object: BackupObjectIdentity,
    state: i64,
) -> Result<(), TargetJournalError> {
    changed(transaction.execute(
        "INSERT INTO backup_capacity(destination_id, backup_id, provider_generation, byte_length, digest, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![object.destination_id.as_bytes().as_slice(), object.backup_id.as_bytes().as_slice(), to_i64(object.provider_generation)?, to_i64(object.byte_length)?, object.digest.as_slice(), state],
    )?)
}

fn set_state(
    transaction: &Transaction<'_>,
    object: BackupObjectIdentity,
    state: i64,
) -> Result<(), TargetJournalError> {
    changed(transaction.execute(
        "UPDATE backup_capacity SET state = ?4 WHERE destination_id = ?1 AND backup_id = ?2 AND provider_generation = ?3",
        params![object.destination_id.as_bytes().as_slice(), object.backup_id.as_bytes().as_slice(), to_i64(object.provider_generation)?, state],
    )?)
}

fn move_to_stored(
    transaction: &Transaction<'_>,
    object: BackupObjectIdentity,
) -> Result<(), TargetJournalError> {
    let bytes = to_i64(object.byte_length)?;
    changed(transaction.execute(
        "UPDATE target_state SET reserved_bytes = reserved_bytes - ?1, committed_bytes = committed_bytes + ?1
         WHERE singleton = 1 AND reserved_bytes >= ?1 AND committed_bytes <= ?2", params![bytes, i64::MAX - bytes],
    )?)?;
    set_state(transaction, object, STORED)
}

fn changed(rows: usize) -> Result<(), TargetJournalError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(TargetJournalError::CorruptState)
    }
}
