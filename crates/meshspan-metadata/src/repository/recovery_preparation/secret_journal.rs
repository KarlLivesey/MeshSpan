// SPDX-License-Identifier: GPL-2.0-only

//! Restartable per-generation recovery preparation, preserving the source's exact ciphertext.

use meshspan_domain::{OperationId, UnixMicros};
use meshspan_recovery_bundle::RecoveredAuthority;
use meshspan_secret_envelope::SecretContext;
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use super::{
    RecoveryControlKeys,
    key_journal::{bounded_blob, open_secret},
};
use crate::{
    AuthoritativeRepository, CommitSecretGeneration, RepositoryError,
    command_codec::recovery_material,
};

impl AuthoritativeRepository {
    /// Retains one source generation for the already selected recovery recipients.
    /// Staging is restartable and exact-byte idempotent. It neither replaces the source
    /// ciphertext nor changes active recipient grants. Recipient installation must still
    /// prove decryption on each replacement node before service admission.
    /// # Errors
    /// Rejects unprepared recovery, absent control material, changed ciphertext, missing
    /// offline decryption, mismatched recipients, conflicting replay and storage failure.
    pub fn stage_recovery_secret(
        &mut self,
        recovery: &RecoveredAuthority,
        material: &CommitSecretGeneration,
        staged_at: UnixMicros,
    ) -> Result<[u8; 32], RepositoryError> {
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        let id = self.require_prepared_recovery(recovery)?;
        let control = self
            .load_recovery_control_keys(recovery, id)?
            .ok_or(RepositoryError::InvalidCommand)?;
        let bytes = recovery_material::encode_secret(material)
            .map_err(|_| RepositoryError::InvalidCommand)?;
        self.validate_retained_recovery_secret(recovery, material, &control)?;
        let context = material.secret.context;
        let digest = secret_digest(id, &bytes);
        match read_material(&transaction, id, context)? {
            Some(existing) if existing != bytes => return Err(RepositoryError::OperationConflict),
            Some(_) => {}
            None => {
                transaction.execute(
                    "INSERT INTO partition_recovery_secret_material(
                        singleton, recovery_id, secret_kind, secret_id, generation,
                        material, material_digest, staged_at
                     ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        id.as_bytes().as_slice(),
                        context.kind(),
                        context.id().as_slice(),
                        i64::try_from(context.generation())
                            .map_err(|_| RepositoryError::InvalidCommand)?,
                        bytes,
                        digest.as_slice(),
                        staged_at.get()
                    ],
                )?;
            }
        }
        transaction.commit()?;
        Ok(digest)
    }

    /// Reopens one exact prepared generation through the offline recovery authority.
    /// No plaintext is returned and absence is not proof that the inventory is complete.
    /// # Errors
    /// Rejects changed preparation/source/ciphertext/recipients, failed decryption and IO.
    pub fn staged_recovery_secret(
        &self,
        recovery: &RecoveredAuthority,
        context: SecretContext,
    ) -> Result<Option<CommitSecretGeneration>, RepositoryError> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let id = self.require_prepared_recovery(recovery)?;
        let control = self
            .load_recovery_control_keys(recovery, id)?
            .ok_or(RepositoryError::InvalidCommand)?;
        let material = self.load_retained_recovery_secret(recovery, context, &control, id)?;
        transaction.commit()?;
        Ok(material)
    }

    pub(super) fn load_retained_recovery_secret(
        &self,
        recovery: &RecoveredAuthority,
        context: SecretContext,
        control: &RecoveryControlKeys,
        id: OperationId,
    ) -> Result<Option<CommitSecretGeneration>, RepositoryError> {
        read_material(self.database.connection(), id, context)?
            .map(|bytes| {
                let material = recovery_material::decode_secret(&bytes)
                    .map_err(|_| RepositoryError::CorruptState)?;
                if material.secret.context != context {
                    return Err(RepositoryError::CorruptState);
                }
                self.validate_retained_recovery_secret(recovery, &material, control)
                    .map_err(|_| RepositoryError::CorruptState)?;
                Ok(material)
            })
            .transpose()
    }

    fn validate_retained_recovery_secret(
        &self,
        recovery: &RecoveredAuthority,
        material: &CommitSecretGeneration,
        control: &RecoveryControlKeys,
    ) -> Result<(), RepositoryError> {
        let source = self
            .secret_generation(material.secret.context)?
            .ok_or(RepositoryError::InvalidCommand)?;
        if material.secret != source.secret.parts()
            || !material
                .recipients
                .iter()
                .map(|r| r.recipient_public_key)
                .eq(control
                    .online_authority_key
                    .recipients
                    .iter()
                    .map(|r| r.recipient_public_key))
        {
            return Err(RepositoryError::InvalidCommand);
        }
        // Authentication is checked even for opaque historical kinds. This does not
        // reactivate old operational keys or prove remote recipients have installed them.
        drop(open_secret(recovery, material)?);
        Ok(())
    }
}

pub(super) fn secret_digest(id: OperationId, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"MeshSpan retained recovery secret v1\0");
    digest.update(id.as_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

fn read_material(
    connection: &Connection,
    id: OperationId,
    context: SecretContext,
) -> Result<Option<Vec<u8>>, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT recovery_id, material, material_digest FROM partition_recovery_secret_material
         WHERE secret_kind = ?1 AND secret_id = ?2 AND generation = ?3",
            params![
                context.kind(),
                context.id().as_slice(),
                i64::try_from(context.generation()).map_err(|_| RepositoryError::InvalidCommand)?
            ],
            |row| {
                Ok((
                    bounded_blob(row, 0, 16)?,
                    bounded_blob(row, 1, 1024 * 1024)?,
                    bounded_blob(row, 2, 32)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_id, bytes, digest)) = row else {
        return Ok(None);
    };
    if stored_id != id.as_bytes() || digest != secret_digest(id, &bytes) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(bytes))
}
