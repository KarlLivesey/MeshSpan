// SPDX-License-Identifier: GPL-2.0-only

//! Offline coordinator journal of selected nodes' key-installation attestations.

use std::io::Write;

use meshspan_certificates::NodePublicIdentity;
use meshspan_domain::{NodeId, UnixMicros};
use meshspan_recovery_bundle::RecoveredAuthority;
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use super::{credential_fence::read_fence, key_journal::bounded_blob};
use crate::{
    AuthoritativeRepository, RecoveryKeyBundleError, RecoveryKeyBundleVerification, RepositoryError,
};

/// Verified node attestation retained in the isolated recovery copy, not service admission.
/// The timestamp is coordinator receipt time, not proof of when a remote disk was written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryKeyInstallation {
    /// Exact selected node; its signed incarnation and recovery are rechecked on every load.
    pub node_id: NodeId,
    /// Digest of the complete encrypted transfer independently reconstructed by the coordinator.
    pub bundle_digest: [u8; 32],
    /// First successful durable receipt time; retries do not extend it.
    pub recorded_at: UnixMicros,
}

impl AuthoritativeRepository {
    /// Records the selected node's DER P-256 signature from `install-recovery-keys`.
    /// The coordinator reconstructs the entire expected message and bundle digest from its
    /// signed, sealed, fenced preparation; no caller-supplied hash or count is trusted.
    /// Exact retries retain the first receipt. No live state, key head or membership changes.
    /// # Errors
    /// Rejects missing or changed preparation, an unselected node, invalid or substituted
    /// signatures, conflicting receipts, time before fencing, corruption and failed persistence.
    /// Failed writes roll back; all IO is local inside one transaction.
    pub fn record_recovery_key_installation(
        &mut self,
        recovery: &RecoveredAuthority,
        node_id: NodeId,
        signature: &[u8],
        recorded_at: UnixMicros,
    ) -> Result<RecoveryKeyInstallation, RecoveryKeyBundleError> {
        if !(8..=72).contains(&signature.len()) {
            return Err(RecoveryKeyBundleError::Invalid);
        }
        let connection = self.database.connection();
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
            .map_err(RepositoryError::from)?;
        let expected = self.expected_recovery_key_installation(recovery, node_id)?;
        expected.verify(signature)?;
        if let Some((saved, saved_signature)) = read_installation(connection, node_id)? {
            expected.verify_saved(&saved, &saved_signature)?;
            if saved_signature != signature {
                return Err(RecoveryKeyBundleError::Authority);
            }
            transaction.commit().map_err(RepositoryError::from)?;
            return Ok(saved);
        }
        if recorded_at < expected.fenced_at {
            return Err(RecoveryKeyBundleError::Invalid);
        }
        let receipt = RecoveryKeyInstallation {
            node_id,
            bundle_digest: expected.bundle.bundle_digest(),
            recorded_at,
        };
        connection.execute(
            "INSERT INTO partition_recovery_key_installations
             (node_id, preparation, bundle_digest, signature, recorded_at) VALUES (?1, 1, ?2, ?3, ?4)",
            params![node_id.as_bytes().as_slice(), receipt.bundle_digest.as_slice(),
                signature, recorded_at.get()],
        ).map_err(RepositoryError::from)?;
        transaction.commit().map_err(RepositoryError::from)?;
        Ok(receipt)
    }

    /// Revalidates one selected node's persisted attestation against the current preparation.
    /// `None` means the selected node has not acknowledged; it must not count as installed.
    /// # Errors
    /// Rejects unselected nodes, invalid preparation, corrupted signatures/digests and read IO.
    /// A successful result remains only a key-installation claim, not readiness or admission.
    pub fn recovery_key_installation(
        &self,
        recovery: &RecoveredAuthority,
        node_id: NodeId,
    ) -> Result<Option<RecoveryKeyInstallation>, RecoveryKeyBundleError> {
        let transaction = self
            .database
            .connection()
            .unchecked_transaction()
            .map_err(RepositoryError::from)?;
        let expected = self.expected_recovery_key_installation(recovery, node_id)?;
        let saved = read_installation(&transaction, node_id)?;
        if let Some((receipt, signature)) = &saved {
            expected.verify_saved(receipt, signature)?;
        }
        transaction.commit().map_err(RepositoryError::from)?;
        Ok(saved.map(|(receipt, _)| receipt))
    }

    fn expected_recovery_key_installation(
        &self,
        recovery: &RecoveredAuthority,
        node_id: NodeId,
    ) -> Result<ExpectedInstallation, RecoveryKeyBundleError> {
        let mut sink = DigestSink(Sha256::new());
        let certificate = self.write_recovery_key_bundle(recovery, node_id, &mut sink)?;
        let plan = self
            .load_recovery_replacement_plan(recovery)?
            .ok_or(RecoveryKeyBundleError::Authority)?;
        let node = plan
            .nodes
            .iter()
            .find(|node| node.node_id == node_id)
            .ok_or(RecoveryKeyBundleError::Authority)?;
        let fence =
            read_fence(self.database.connection())?.ok_or(RecoveryKeyBundleError::Authority)?;
        Ok(ExpectedInstallation {
            identity: NodePublicIdentity::from_sec1(&node.identity_public_key)
                .map_err(|_| RecoveryKeyBundleError::Authority)?,
            bundle: RecoveryKeyBundleVerification::from_plan(
                &plan,
                node_id,
                sink.0.finalize().into(),
                certificate,
            )?,
            fenced_at: fence.fenced_at,
        })
    }
}

struct ExpectedInstallation {
    identity: NodePublicIdentity,
    bundle: RecoveryKeyBundleVerification,
    fenced_at: UnixMicros,
}

impl ExpectedInstallation {
    fn verify(&self, signature: &[u8]) -> Result<(), RecoveryKeyBundleError> {
        self.identity
            .verify_enrolment_transcript(&self.bundle.installation_message(), signature)
            .map_err(|_| RecoveryKeyBundleError::Authority)
    }

    fn verify_saved(
        &self,
        receipt: &RecoveryKeyInstallation,
        signature: &[u8],
    ) -> Result<(), RecoveryKeyBundleError> {
        if receipt.bundle_digest != self.bundle.bundle_digest()
            || receipt.recorded_at < self.fenced_at
        {
            return Err(RepositoryError::CorruptState.into());
        }
        self.verify(signature)
    }
}

fn read_installation(
    connection: &Connection,
    node_id: NodeId,
) -> Result<Option<(RecoveryKeyInstallation, Vec<u8>)>, RepositoryError> {
    Ok(connection
        .query_row(
            "SELECT bundle_digest, signature, recorded_at FROM partition_recovery_key_installations
         WHERE node_id = ?1",
            [node_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    RecoveryKeyInstallation {
                        node_id,
                        bundle_digest: row.get(0)?,
                        recorded_at: UnixMicros::new(row.get(2)?),
                    },
                    bounded_blob(row, 1, 72)?,
                ))
            },
        )
        .optional()?)
}

struct DigestSink(Sha256);
impl Write for DigestSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
