// SPDX-License-Identifier: GPL-2.0-only

//! Durable offline-root consensus decision after all selected nodes attest to one state set.

use crate::{AuthoritativeRepository, RepositoryError as Error};
use meshspan_domain::UnixMicros;
use meshspan_recovery_bundle::{
    RecoveredAuthority, RecoveryConsensusAdmission, RecoveryConsensusAdmissionClaims,
    RecoveryStateTransfer,
};
use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};

impl AuthoritativeRepository {
    /// Records one root-signed permission to form the selected replacement consensus group.
    /// All selected nodes must have acknowledged their explicitly expected common state.
    /// Exact retries return the original signature; a different state cannot replace the decision.
    /// This does not activate the epoch, advance metadata or remove any admission fence.
    /// The caller must export this permission and separately verify/apply it at each replacement.
    /// # Errors
    /// Rejects incomplete/substituted attestations, conflicting decisions, invalid root/time,
    /// corrupted retained permission and failed writes. No decision escapes a failed transaction.
    pub fn authorize_recovery_consensus(
        &mut self,
        authority: &RecoveredAuthority,
        expected: &[RecoveryStateTransfer],
        now: UnixMicros,
    ) -> Result<RecoveryConsensusAdmission, Error> {
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        self.check_recovery_state_installations(authority, expected)?;
        let first = expected.first().ok_or(Error::InvalidCommand)?.claims();
        let claims = RecoveryConsensusAdmissionClaims {
            authorization: first.authorization.clone(),
            state_digest: first.state_digest,
            state_length: first.state_length,
        };
        let latest: i64 = transaction.query_row(
            "SELECT MAX(recorded_at) FROM partition_recovery_state_installations",
            [],
            |row| row.get(0),
        )?;
        if now.get() < latest {
            return Err(Error::InvalidCommand);
        }
        let stored = transaction.query_row(
            "SELECT permission FROM partition_recovery_consensus_permission WHERE singleton = 1",
            [], |row| super::key_journal::bounded_blob(row, 0, 512),
        ).optional()?;
        let permission = if let Some(encoded) = stored {
            let permission =
                RecoveryConsensusAdmission::decode(authority.root_certificate_der(), &encoded)
                    .map_err(|_| Error::CorruptState)?;
            if permission.claims() != &claims {
                return Err(Error::OperationConflict);
            }
            permission
        } else {
            let permission = authority
                .authorize_recovery_consensus(claims)
                .map_err(|_| Error::InvalidCommand)?;
            transaction.execute(
                "INSERT INTO partition_recovery_consensus_permission
                (singleton, preparation, permission, recorded_at) VALUES (1, 1, ?1, ?2)",
                params![
                    permission.encode().map_err(|_| Error::InvalidCommand)?,
                    now.get()
                ],
            )?;
            permission
        };
        transaction.commit()?;
        Ok(permission)
    }
}
