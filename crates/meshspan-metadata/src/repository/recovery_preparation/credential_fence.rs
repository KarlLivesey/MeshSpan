// SPDX-License-Identifier: GPL-2.0-only

//! Offline-root revocation of transient authority in an isolated recovery copy.

use crate::repository::apply::to_i64;
use meshspan_domain::{OperationId, Revision, UnixMicros};
use meshspan_recovery_bundle::RecoveredAuthority;
use meshspan_secret_envelope::SecretContext;
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};

use crate::{
    AuthoritativeRepository, ONLINE_AUTHORITY_KEY_SECRET_KIND, RepositoryError,
    STORAGE_PERMIT_KEY_SECRET_KIND, SecretGenerationRecord,
};

/// Durable offline-root revocation evidence. Counts include unexpired and expired, unrevoked
/// source credentials. This receipt does not prove installation or permit service admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCredentialFence {
    /// Exact root-authorised recovery operation.
    pub recovery_id: OperationId,
    /// Signed replacement selection and prepared-key commitment.
    pub manifest_digest: [u8; 32],
    /// All temporary activations at or below this revision are fenced, not deleted.
    pub source_revision: Revision,
    /// Recorded mesh time of the offline operation, never consensus order.
    pub fenced_at: UnixMicros,
    /// Lowest usable online-authority key generation after recovery.
    pub online_generation: u64,
    /// Lowest usable storage-permit key generation after recovery.
    pub permit_generation: u64,
    /// Sessions revoked in this copy.
    pub sessions: u64,
    /// Enrolment grants revoked in this copy.
    pub join_grants: u64,
    /// Local group/permission activations fenced by the source revision.
    pub activations: u64,
    /// Federated assignment activations fenced by the source revision.
    pub federation_activations: u64,
    /// Previously current or overlapping node certificates retired.
    pub node_certificates: u64,
    /// Pending federation pairing invitations cancelled.
    pub pairing_invitations: u64,
}

impl AuthoritativeRepository {
    /// Atomically fences transient credentials only after the signed replacement plan and
    /// complete prepared keys have been revalidated. Accounts, authentication methods, durable
    /// permissions, federation relationships and retained ciphertext survive. Old activation
    /// evidence remains intact; readers exclude it through the root-authorised revision fence.
    /// Exact replay returns the original receipt. No source applied revision or live key head
    /// advances, and the isolated copy still cannot start consensus.
    /// # Errors
    /// Rejects unprepared/changed sources, missing signed selections, time preceding issuance
    /// or staging, corrupt receipts and failed writes. Failure rolls back the entire fence.
    pub fn fence_recovery_credentials(
        &mut self,
        recovery: &RecoveredAuthority,
        fenced_at: UnixMicros,
    ) -> Result<RecoveryCredentialFence, RepositoryError> {
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        let plan = self
            .load_recovery_replacement_plan(recovery)?
            .ok_or(RepositoryError::InvalidCommand)?;
        let authorization = self.prepared_recovery_authorization(recovery)?;
        let control = self
            .load_recovery_control_keys(recovery, plan.recovery_id)?
            .ok_or(RepositoryError::CorruptState)?;
        let mut receipt = RecoveryCredentialFence {
            recovery_id: plan.recovery_id,
            manifest_digest: authorization.claims().replacement_manifest_digest,
            source_revision: authorization.claims().source_revision,
            fenced_at,
            online_generation: control.online_authority_key.secret.context.generation(),
            permit_generation: control.storage_permit_key.secret.context.generation(),
            sessions: 0,
            join_grants: 0,
            activations: 0,
            federation_activations: 0,
            node_certificates: 0,
            pairing_invitations: 0,
        };
        if let Some(saved) = read_fence(&transaction)? {
            if saved.recovery_id != receipt.recovery_id
                || saved.manifest_digest != receipt.manifest_digest
                || saved.source_revision != receipt.source_revision
                || saved.online_generation != receipt.online_generation
                || saved.permit_generation != receipt.permit_generation
            {
                return Err(RepositoryError::CorruptState);
            }
            transaction.commit()?;
            return Ok(saved);
        }
        validate_source_credentials(&transaction, &receipt)?;
        revoke_source_credentials(&transaction, &mut receipt)?;
        persist_fence(&transaction, &receipt)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Loads an encrypted generation for online use, enforcing the recovery authority floors.
    /// Historical CA/permit ciphertext remains accessible to offline inventory through
    /// `secret_generation`, but must never be used to validate old capabilities after recovery.
    /// Content/authentication and other historical generations are not discarded by this fence.
    /// # Errors
    /// Rejects malformed fence/secret records or database failure. Returns `None` for a fenced
    /// operational generation or absent secret. A returned envelope is not a permission grant.
    pub fn runtime_secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, RepositoryError> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let floor = read_fence(&transaction)?.map_or(0, |fence| match context.kind() {
            ONLINE_AUTHORITY_KEY_SECRET_KIND => fence.online_generation,
            STORAGE_PERMIT_KEY_SECRET_KIND => fence.permit_generation,
            _ => 0,
        });
        let result = if context.generation() < floor {
            None
        } else {
            self.secret_generation(context)?
        };
        transaction.commit()?;
        Ok(result)
    }
}

fn validate_source_credentials(
    connection: &Connection,
    receipt: &RecoveryCredentialFence,
) -> Result<(), RepositoryError> {
    // Reject a time before any source credential's issuance, not a clamped invented timestamp.
    // A revision beyond the signed backup is corruption, not a credential we may overlook.
    let invalid: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM (
            SELECT issued_at AS issued, revision FROM authentication_sessions WHERE revoked_at IS NULL
            UNION ALL SELECT created_at, revision FROM join_grants WHERE revoked_at IS NULL
            UNION ALL SELECT activated_at, revision FROM access_activations WHERE revoked_at IS NULL
            UNION ALL SELECT activated_at, revision FROM federation_grant_assignment_activations WHERE revoked_at IS NULL
            UNION ALL SELECT issued_at, revision FROM federation_pairing_invitations WHERE state = 1
         ) WHERE issued > ?1 OR revision > ?2)
         OR EXISTS(SELECT 1 FROM node_certificates WHERE state IN (1, 2) AND revision > ?2)
         OR EXISTS(SELECT 1 FROM partition_recovery_replacement_plan WHERE staged_at > ?1)",
        params![receipt.fenced_at.get(), to_i64(receipt.source_revision.get())?], |row| row.get(0),
    )?;
    if invalid {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn revoke_source_credentials(
    transaction: &Transaction<'_>,
    receipt: &mut RecoveryCredentialFence,
) -> Result<(), RepositoryError> {
    receipt.sessions = count(transaction.execute(
        "UPDATE authentication_sessions SET revoked_at = ?1 WHERE revoked_at IS NULL",
        [receipt.fenced_at.get()],
    )?)?;
    receipt.join_grants = count(transaction.execute(
        "UPDATE join_grants SET revoked_at = ?1 WHERE revoked_at IS NULL",
        [receipt.fenced_at.get()],
    )?)?;
    (receipt.activations, receipt.federation_activations) = transaction.query_row(
        "SELECT (SELECT COUNT(*) FROM access_activations WHERE revoked_at IS NULL),
                (SELECT COUNT(*) FROM federation_grant_assignment_activations WHERE revoked_at IS NULL)",
        [], |row| Ok((unsigned(row, 0)?, unsigned(row, 1)?)),
    )?;
    receipt.node_certificates = count(transaction.execute(
        "UPDATE node_certificates SET state = 3 WHERE state IN (1, 2)",
        [],
    )?)?;
    transaction.execute(
        "UPDATE node_certificate_rotations SET state = CASE state WHEN 1 THEN 4 ELSE 3 END
         WHERE state IN (1, 2)",
        [],
    )?;
    receipt.pairing_invitations = count(transaction.execute(
        "UPDATE federation_pairing_invitations SET state = 3, cancellation_reason = 'offline disaster recovery'
         WHERE state = 1", [],
    )?)?;
    Ok(())
}

fn persist_fence(
    connection: &Connection,
    receipt: &RecoveryCredentialFence,
) -> Result<(), RepositoryError> {
    connection.execute(
        "INSERT INTO partition_recovery_credential_fence(
            singleton, recovery_id, manifest_digest, source_revision, fenced_at,
            online_generation, permit_generation, sessions, join_grants, activations,
            federation_activations, node_certificates, pairing_invitations
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            receipt.recovery_id.as_bytes().as_slice(),
            receipt.manifest_digest.as_slice(),
            to_i64(receipt.source_revision.get())?,
            receipt.fenced_at.get(),
            to_i64(receipt.online_generation)?,
            to_i64(receipt.permit_generation)?,
            to_i64(receipt.sessions)?,
            to_i64(receipt.join_grants)?,
            to_i64(receipt.activations)?,
            to_i64(receipt.federation_activations)?,
            to_i64(receipt.node_certificates)?,
            to_i64(receipt.pairing_invitations)?
        ],
    )?;
    Ok(())
}

pub(super) fn read_fence(
    connection: &Connection,
) -> Result<Option<RecoveryCredentialFence>, RepositoryError> {
    let stored = connection
        .query_row(
            "SELECT recovery_id, manifest_digest, source_revision, fenced_at, online_generation,
                permit_generation, sessions, join_grants, activations, federation_activations,
                node_certificates, pairing_invitations FROM partition_recovery_credential_fence",
            [],
            |row| {
                let id: [u8; 16] = row.get(0)?;
                Ok(RecoveryCredentialFence {
                    recovery_id: OperationId::from_bytes(id)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    manifest_digest: row.get(1)?,
                    source_revision: Revision::new(unsigned(row, 2)?),
                    fenced_at: UnixMicros::new(row.get(3)?),
                    online_generation: unsigned(row, 4)?,
                    permit_generation: unsigned(row, 5)?,
                    sessions: unsigned(row, 6)?,
                    join_grants: unsigned(row, 7)?,
                    activations: unsigned(row, 8)?,
                    federation_activations: unsigned(row, 9)?,
                    node_certificates: unsigned(row, 10)?,
                    pairing_invitations: unsigned(row, 11)?,
                })
            },
        )
        .optional()?;
    if stored.as_ref().is_some_and(|r| {
        r.source_revision.get() == 0
            || r.manifest_digest == [0; 32]
            || r.online_generation < 2
            || r.permit_generation < 2
    }) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(stored)
}

fn count(value: usize) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn unsigned(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}
