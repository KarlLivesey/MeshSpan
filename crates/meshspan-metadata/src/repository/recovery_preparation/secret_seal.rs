// SPDX-License-Identifier: GPL-2.0-only

//! Complete, ordered commitment to a prepared secret inventory, not recovery admission.

use meshspan_domain::{OperationId, UnixMicros};
use meshspan_recovery_bundle::RecoveredAuthority;
use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use super::{RecoveryControlKeys, key_journal::bounded_blob, secret_journal::secret_digest};
use crate::{
    AuthoritativeRepository, PageLimit, RepositoryError, command_codec::recovery_material,
};

/// Claimed retained-secret inventory for a pending recovery, verified by repository sealing.
/// This commitment includes the prepared control pair and all source secret generations;
/// it is only one input to the complete signed replacement manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoverySecretInventory {
    /// Number of original retained generations, excluding the newly prepared control pair.
    pub generation_count: u64,
    /// Domain-separated ordered commitment bound to this recovery and its control pair.
    pub digest: [u8; 32],
}

/// Streaming public-manifest commitment computed before recovery authorisation is signed.
/// This does not prove source completeness: repository sealing independently compares every
/// generation with the verified source. Retain the exact prepared ciphertext for later staging.
pub struct RecoverySecretInventoryBuilder {
    id: OperationId,
    digest: Sha256,
    count: u64,
    previous: Option<(u16, [u8; 16], u64)>,
}

impl RecoverySecretInventoryBuilder {
    /// Starts a planned inventory bound to one recovery and its exact control pair.
    /// # Errors
    /// Rejects malformed or excessive control material.
    pub fn new(id: OperationId, control: &RecoveryControlKeys) -> Result<Self, RepositoryError> {
        let mut digest = Sha256::new();
        digest.update(b"MeshSpan complete recovery secret inventory v1\0");
        digest.update(id.as_bytes());
        digest.update(Sha256::digest(
            recovery_material::encode(control).map_err(|_| RepositoryError::InvalidCommand)?,
        ));
        Ok(Self {
            id,
            digest,
            count: 0,
            previous: None,
        })
    }

    /// Adds the next exact generation in canonical kind/identity/generation order.
    /// # Errors
    /// Rejects duplicates, reverse order, invalid framing and count overflow.
    pub fn push(
        &mut self,
        material: &crate::CommitSecretGeneration,
    ) -> Result<(), RepositoryError> {
        let context = material.secret.context;
        let next = (context.kind(), context.id(), context.generation());
        if self.previous.is_some_and(|previous| previous >= next) {
            return Err(RepositoryError::InvalidCommand);
        }
        let bytes = recovery_material::encode_secret(material)
            .map_err(|_| RepositoryError::InvalidCommand)?;
        let count = self
            .count
            .checked_add(1)
            .filter(|count| *count <= i64::MAX.unsigned_abs())
            .ok_or(RepositoryError::CapacityExceeded)?;
        self.digest.update(secret_digest(self.id, &bytes));
        self.count = count;
        self.previous = Some(next);
        Ok(())
    }

    /// Finishes the proposed commitment; source completeness is not established here.
    /// # Errors
    /// Rejects an empty inventory.
    pub fn finish(mut self) -> Result<RecoverySecretInventory, RepositoryError> {
        if self.count == 0 {
            return Err(RepositoryError::InvalidCommand);
        }
        self.digest.update(self.count.to_be_bytes());
        Ok(RecoverySecretInventory {
            generation_count: self.count,
            digest: self.digest.finalize().into(),
        })
    }
}

impl AuthoritativeRepository {
    /// Verifies and seals every prepared retained generation against the exact source inventory.
    /// Uses bounded indexed pages and one generation at a time inside the isolated recovery
    /// transaction. Missing generations fail; interruption before commit leaves no seal.
    /// Replays fully reverify the inventory. No key becomes active through this operation.
    /// # Errors
    /// Rejects incomplete/changed preparation, failed decryption, conflicting seals and IO.
    pub fn seal_recovery_secret_inventory(
        &mut self,
        recovery: &RecoveredAuthority,
        sealed_at: UnixMicros,
    ) -> Result<RecoverySecretInventory, RepositoryError> {
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        let id = self.require_prepared_recovery(recovery)?;
        let control = self
            .load_recovery_control_keys(recovery, id)?
            .ok_or(RepositoryError::InvalidCommand)?;
        let inventory = self.verify_recovery_secret_inventory(recovery, id, &control)?;
        let existing = transaction
            .query_row(
                "SELECT recovery_id, generation_count, inventory_digest
             FROM partition_recovery_secret_inventory WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        bounded_blob(row, 0, 16)?,
                        row.get::<_, i64>(1)?,
                        bounded_blob(row, 2, 32)?,
                    ))
                },
            )
            .optional()?;
        if let Some((stored_id, count, digest)) = existing {
            if stored_id != id.as_bytes()
                || u64::try_from(count).ok() != Some(inventory.generation_count)
                || digest != inventory.digest
            {
                return Err(RepositoryError::CorruptState);
            }
        } else {
            transaction.execute(
                "INSERT INTO partition_recovery_secret_inventory(
                    singleton, recovery_id, generation_count, inventory_digest, sealed_at
                 ) VALUES (1, ?1, ?2, ?3, ?4)",
                params![
                    id.as_bytes().as_slice(),
                    i64::try_from(inventory.generation_count)
                        .map_err(|_| RepositoryError::CorruptState)?,
                    inventory.digest.as_slice(),
                    sealed_at.get()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(inventory)
    }

    pub(super) fn verify_recovery_secret_inventory(
        &self,
        recovery: &RecoveredAuthority,
        id: OperationId,
        control: &RecoveryControlKeys,
    ) -> Result<RecoverySecretInventory, RepositoryError> {
        let mut inventory = RecoverySecretInventoryBuilder::new(id, control)?;
        let limit = PageLimit::new(128)?;
        let mut after = None;
        loop {
            let page = self.secret_generation_contexts(after, limit)?;
            for context in page.items {
                let material = self
                    .load_retained_recovery_secret(recovery, context, control, id)?
                    .ok_or(RepositoryError::InvalidCommand)?;
                inventory.push(&material)?;
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        let stored_count: i64 = self.database.connection().query_row(
            "SELECT COUNT(*) FROM partition_recovery_secret_material",
            [],
            |row| row.get(0),
        )?;
        let inventory = inventory.finish()?;
        if u64::try_from(stored_count).ok() != Some(inventory.generation_count) {
            return Err(RepositoryError::CorruptState);
        }
        Ok(inventory)
    }
}
