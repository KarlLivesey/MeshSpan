// SPDX-License-Identifier: GPL-2.0-only

//! Exact offline key preparation; never an active secret head or service-admission receipt.

use meshspan_certificates::{OnlineCertificateAuthority, validate_online_authority_certificate};
use meshspan_domain::{OperationId, UnixMicros};
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveryAuthorization};
use meshspan_secret_envelope::{EncryptedSecret, RecipientKeyEnvelope, SecretPlaintext};
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use super::RecoveryControlKeys;
use crate::command_codec::recovery_material;
use crate::{AuthoritativeRepository, CommitSecretGeneration, RepositoryError};

impl AuthoritativeRepository {
    /// Reads the offline root's exact signed preparation intent for a restarting coordinator.
    /// Revalidates the stored source position, identities and supported recovery lineage.
    /// This is not evidence of readiness or permission to start consensus.
    /// # Errors
    /// Rejects missing or corrupt preparation, another recovery identity and database failures.
    pub fn recovery_preparation_authorization(
        &self,
        recovery: &RecoveredAuthority,
    ) -> Result<RecoveryAuthorization, RepositoryError> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let authorization = self.prepared_recovery_authorization(recovery)?;
        transaction.commit()?;
        Ok(authorization)
    }

    /// Retains exact encrypted control keys in an isolated, authorised recovery copy.
    /// Replaying identical material returns the same digest; another proposal conflicts.
    /// This digest binds the recovery ID and key material, not the complete replacement
    /// manifest. Membership, inventory, credential fencing and admission remain separate.
    /// # Errors
    /// Rejects unprepared/changed source state, invalid keys or recipients, conflicting
    /// material and persistence failure. No active key heads or source revisions change.
    pub fn stage_recovery_control_keys(
        &mut self,
        recovery: &RecoveredAuthority,
        material: &RecoveryControlKeys,
        staged_at: UnixMicros,
    ) -> Result<[u8; 32], RepositoryError> {
        // A shared connection borrow allows typed read validation inside this same
        // immediate transaction. This entry point owns it; nested transactions fail.
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        let id = self.require_prepared_recovery(recovery)?;
        let bytes =
            recovery_material::encode(material).map_err(|_| RepositoryError::InvalidCommand)?;
        self.validate_recovery_control_keys(recovery, material)?;
        let digest = material_digest(id, &bytes);
        match read_material(&transaction, id)? {
            Some(existing) if existing != bytes => return Err(RepositoryError::OperationConflict),
            Some(_) => {}
            None => {
                transaction.execute(
                    "INSERT INTO partition_recovery_control_material(
                        singleton, recovery_id, material, material_digest, staged_at
                     ) VALUES (1, ?1, ?2, ?3, ?4)",
                    params![
                        id.as_bytes().as_slice(),
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

    /// Loads exact prepared ciphertext, rechecking its source, digest and offline decryption.
    /// `None` means this authorised preparation has not yet staged control material.
    /// It never returns plaintext or grants permission to start a service.
    /// # Errors
    /// Rejects absent/invalid preparation, another recovery authority, malformed records,
    /// invalid cryptographic material and unavailable storage.
    pub fn staged_recovery_control_keys(
        &self,
        recovery: &RecoveredAuthority,
    ) -> Result<Option<RecoveryControlKeys>, RepositoryError> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let id = self.require_prepared_recovery(recovery)?;
        let material = self.load_recovery_control_keys(recovery, id)?;
        transaction.commit()?;
        Ok(material)
    }

    pub(super) fn load_recovery_control_keys(
        &self,
        recovery: &RecoveredAuthority,
        id: OperationId,
    ) -> Result<Option<RecoveryControlKeys>, RepositoryError> {
        read_material(self.database.connection(), id)?
            .map(|bytes| {
                let material =
                    recovery_material::decode(&bytes).map_err(|_| RepositoryError::CorruptState)?;
                self.validate_recovery_control_keys(recovery, &material)
                    .map_err(|_| RepositoryError::CorruptState)?;
                Ok::<_, RepositoryError>(material)
            })
            .transpose()
    }

    pub(super) fn require_prepared_recovery(
        &self,
        recovery: &RecoveredAuthority,
    ) -> Result<OperationId, RepositoryError> {
        Ok(self
            .prepared_recovery_authorization(recovery)?
            .claims()
            .recovery_id)
    }

    pub(super) fn prepared_recovery_authorization(
        &self,
        recovery: &RecoveredAuthority,
    ) -> Result<RecoveryAuthorization, RepositoryError> {
        self.require_recovery_identity(recovery)?;
        self.read_recovery_preparation(recovery.root_certificate_der())
    }

    /// Verifies an installed preparation using only the independently trusted public root.
    /// Checks the exact persisted source position and identity, without admitting services.
    /// # Errors
    /// Rejects another root, missing/changed preparation or invalid source state.
    pub fn verify_recovery_preparation(
        &self,
        trusted_root: &[u8],
    ) -> Result<RecoveryAuthorization, RepositoryError> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let authorization = self.read_recovery_preparation(trusted_root)?;
        transaction.commit()?;
        Ok(authorization)
    }

    pub(super) fn read_recovery_preparation(
        &self,
        trusted_root: &[u8],
    ) -> Result<RecoveryAuthorization, RepositoryError> {
        let mesh = self.local_mesh_id()?.ok_or(RepositoryError::CorruptState)?;
        if self
            .mesh_recovery_authority(mesh)?
            .ok_or(RepositoryError::CorruptState)?
            .root_certificate_der
            != trusted_root
        {
            return Err(RepositoryError::InvalidCommand);
        }
        let connection = self.database.connection();
        let encoded = connection
            .query_row(
                "SELECT authorization FROM partition_recovery_preparation WHERE singleton = 1",
                [],
                |row| bounded_blob(row, 0, 284),
            )
            .optional()?
            .ok_or(RepositoryError::InvalidCommand)?;
        let authorization = RecoveryAuthorization::decode(trusted_root, &encoded)
            .map_err(|_| RepositoryError::CorruptState)?;
        let claims = authorization.claims();
        if claims.mesh_id != mesh
            || claims.partition_id != self.database.partition_id()
            || claims.previous_epoch != 0
            || claims.recovery_epoch != 1
        {
            return Err(RepositoryError::CorruptState);
        }
        let matches: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM partition_recovery_preparation p
             JOIN applied_state a ON a.singleton = p.singleton
             WHERE p.singleton = 1 AND p.partition_id = ?1 AND a.partition_id = ?1
               AND p.mesh_id = ?2 AND p.recovery_id = ?3 AND p.recovery_epoch = ?4
               AND p.source_backup_id = ?5 AND a.last_log_index = ?6
               AND a.last_log_term = ?7 AND a.state_revision = ?8)",
            params![
                claims.partition_id.as_bytes().as_slice(),
                mesh.as_bytes().as_slice(),
                claims.recovery_id.as_bytes().as_slice(),
                i64::try_from(claims.recovery_epoch).map_err(|_| RepositoryError::CorruptState)?,
                claims.backup_id.as_bytes().as_slice(),
                i64::try_from(claims.source_log_index)
                    .map_err(|_| RepositoryError::CorruptState)?,
                i64::try_from(claims.source_log_term).map_err(|_| RepositoryError::CorruptState)?,
                i64::try_from(claims.source_revision.get())
                    .map_err(|_| RepositoryError::CorruptState)?
            ],
            |row| row.get(0),
        )?;
        if !matches {
            return Err(RepositoryError::CorruptState);
        }
        Ok(authorization)
    }

    fn validate_recovery_control_keys(
        &self,
        recovery: &RecoveredAuthority,
        material: &RecoveryControlKeys,
    ) -> Result<(), RepositoryError> {
        let (online, permit) = self.recovery_control_contexts(recovery.mesh_id())?;
        let online_key = &material.online_authority_key;
        let permit_key = &material.storage_permit_key;
        let permit_recipients: std::collections::BTreeSet<_> = permit_key
            .recipients
            .iter()
            .map(|recipient| recipient.recipient_public_key)
            .collect();
        if online_key.secret.context != online
            || permit_key.secret.context != permit
            || online_key.recipients.len() < 2
            || !online_key
                .recipients
                .iter()
                .all(|online| permit_recipients.contains(&online.recipient_public_key))
        {
            return Err(RepositoryError::InvalidCommand);
        }
        let private = open_secret(recovery, online_key)?;
        OnlineCertificateAuthority::from_pkcs8_and_certificate(
            private.expose(),
            &material.online_certificate_der,
        )
        .map_err(|_| RepositoryError::InvalidCommand)?;
        validate_online_authority_certificate(
            &material.online_certificate_der,
            recovery.root_certificate_der(),
        )
        .map_err(|_| RepositoryError::InvalidCommand)?;
        let permit = open_secret(recovery, permit_key)?;
        if permit.expose().len() != 32 || permit.expose().iter().all(|byte| *byte == 0) {
            return Err(RepositoryError::InvalidCommand);
        }
        Ok(())
    }
}

pub(super) fn open_secret(
    recovery: &RecoveredAuthority,
    material: &CommitSecretGeneration,
) -> Result<SecretPlaintext, RepositoryError> {
    let secret = EncryptedSecret::from_parts(material.secret.clone())
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let recipients = material
        .recipients
        .iter()
        .map(|r| RecipientKeyEnvelope::from_parts(r.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RepositoryError::InvalidCommand)?;
    recovery
        .open_secret(&secret, &recipients)
        .map_err(|_| RepositoryError::InvalidCommand)
}

fn material_digest(id: OperationId, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"MeshSpan prepared recovery control material v1\0");
    digest.update(id.as_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

fn read_material(
    connection: &Connection,
    id: OperationId,
) -> Result<Option<Vec<u8>>, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT recovery_id, material, material_digest
         FROM partition_recovery_control_material WHERE singleton = 1",
            [],
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
    if stored_id != id.as_bytes() || digest != material_digest(id, &bytes) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(bytes))
}

pub(super) fn bounded_blob(
    row: &rusqlite::Row<'_>,
    index: usize,
    maximum: usize,
) -> rusqlite::Result<Vec<u8>> {
    let value = row.get_ref(index)?.as_blob()?;
    if value.is_empty() || value.len() > maximum {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(value.to_vec())
}
