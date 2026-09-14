// SPDX-License-Identifier: GPL-2.0-only

//! Offline exact-source preparation. No quorum reset or live admission is performed here.

use meshspan_domain::UnixMicros;
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveryAuthorization};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::{
    EncryptedPartitionBackupManifest, EncryptedRestorePaths, RepositoryError,
    restore_encrypted_partition_backup,
};

#[cfg(test)]
mod tests;

mod certificates;
pub(super) mod consensus_activation;
mod consensus_permission;
mod credential_fence;
mod key_export;
mod key_installation;
mod key_journal;
mod keys;
mod node_key_projection;
mod replacement_plan;
mod restorations;
mod secret_journal;
mod secret_seal;
mod state_installation;
mod targets;
pub use credential_fence::RecoveryCredentialFence;
pub use key_installation::RecoveryKeyInstallation;
pub use keys::RecoveryControlKeys;
pub use restorations::RecoveryRestorationReceipt;
pub use secret_seal::{RecoverySecretInventory, RecoverySecretInventoryBuilder};
pub use state_installation::RecoveryStateInstallation;

/// Restores a new isolated database and retains its independently authenticated recovery intent.
/// The prepared copy refuses consensus startup, including after reopening. The caller must
/// validate replacement and inventory manifests before signing; their digests are only bound
/// here, not proof of available shards, valid replacement membership or completed admission.
/// No input database is overwritten and no service is started. Failed staging paths must not
/// be reused; they follow the existing restore API's disposable-workspace contract.
/// Staging paths must be inside a caller-owned private workspace, not shared writable folders.
/// # Errors
/// Rejects changed source claims, another root/recipient, existing paths, prior preparation,
/// unsupported recovery lineage, invalid encrypted backup or database persistence failure.
pub fn prepare_authorized_partition_recovery(
    paths: EncryptedRestorePaths<'_>,
    manifest: EncryptedPartitionBackupManifest,
    authority: &RecoveredAuthority,
    authorization: &RecoveryAuthorization,
    prepared_at: UnixMicros,
) -> Result<(), RepositoryError> {
    verify_source_claims(&manifest, authorization)?;
    let encoded = authorization
        .encode()
        .map_err(|_| RepositoryError::InvalidCommand)?;
    RecoveryAuthorization::decode(authority.root_certificate_der(), &encoded)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let mut database =
        restore_encrypted_partition_backup(paths, manifest, authority.wrapping_key(), prepared_at)?;
    let stored = super::recovery_authority::current(&database, manifest.partition.mesh_id)?
        .ok_or(RepositoryError::InvalidCommand)?;
    if stored.root_certificate_der != authority.root_certificate_der()
        || stored.public_wrapping_key != authority.public_wrapping_key()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if pending(&transaction)? {
        return Err(RepositoryError::InvalidCommand);
    }
    let claims = authorization.claims();
    transaction.execute(
        "INSERT INTO partition_recovery_preparation(
            singleton, partition_id, mesh_id, recovery_id, recovery_epoch,
            source_backup_id, authorization, prepared_at
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            claims.partition_id.as_bytes().as_slice(),
            claims.mesh_id.as_bytes().as_slice(),
            claims.recovery_id.as_bytes().as_slice(),
            i64::try_from(claims.recovery_epoch).map_err(|_| RepositoryError::InvalidCommand)?,
            claims.backup_id.as_bytes().as_slice(),
            encoded,
            prepared_at.get()
        ],
    )?;
    transaction.commit()?;
    database.check_integrity()?;
    Ok(())
}

fn verify_source_claims(
    manifest: &EncryptedPartitionBackupManifest,
    authorization: &RecoveryAuthorization,
) -> Result<(), RepositoryError> {
    let claims = authorization.claims();
    let source = manifest.partition;
    if claims.mesh_id != source.mesh_id || claims.partition_id != source.partition_id
        || claims.backup_id != source.backup_id || claims.backup_digest != manifest.encrypted.digest
        || claims.source_log_index != source.applied_position.index
        || claims.source_log_term != source.applied_position.term
        || claims.source_revision != source.state_revision
        // No activated recovery lineage exists yet. Never infer one from an untrusted proposal.
        || claims.previous_epoch != 0 || claims.recovery_epoch != 1
    {
        return Err(RepositoryError::BackupMismatch);
    }
    Ok(())
}

pub(super) fn pending(connection: &Connection) -> Result<bool, RepositoryError> {
    let prepared = connection
        .query_row(
            "SELECT 1 FROM partition_recovery_preparation LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(prepared && consensus_activation::read_activation(connection)?.is_none())
}
