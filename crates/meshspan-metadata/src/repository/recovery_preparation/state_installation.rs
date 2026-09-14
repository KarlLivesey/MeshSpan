// SPDX-License-Identifier: GPL-2.0-only

//! Exact selected-package installation evidence; old packages do not satisfy a new set.

use crate::{AuthoritativeRepository, RecoveryReplacementPlan, RepositoryError as Error};
use meshspan_certificates::NodePublicIdentity;
use meshspan_domain::{NodeId, UnixMicros};
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveryAuthorization, RecoveryStateTransfer};
use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};
use std::collections::BTreeSet;

/// A node's verified installation claim for one exact root-authorised state package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryStateInstallation {
    /// Selected node; its incarnation is bound by the signed transfer.
    pub node_id: NodeId,
    /// Complete encrypted state digest, not just the original recovery/backup identifier.
    pub state_digest: [u8; 32],
    /// First durable collection time. This is neither fresh disk health nor remote write time.
    pub recorded_at: UnixMicros,
}

impl AuthoritativeRepository {
    /// Retains one selected node's signature over the exact expected state installation message.
    /// Different authorised packages retain separate history; none becomes implicitly "latest".
    /// The expected transfer must come from the coordinator, not be selected by the node report.
    /// # Errors
    /// Rejects wrong recovery/node/incarnation, invalid signatures, conflicting replay, time
    /// before credential fencing and failed persistence. Partial insertion rolls back.
    pub fn record_recovery_state_installation(
        &mut self,
        authority: &RecoveredAuthority,
        expected: &RecoveryStateTransfer,
        signature: &[u8],
        now: UnixMicros,
    ) -> Result<RecoveryStateInstallation, Error> {
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        let selection = self.installation_selection(authority)?;
        selection.verify(expected, signature)?;
        if now < selection.not_before {
            return Err(Error::InvalidCommand);
        }
        let receipt = if let Some((saved, stored_signature)) =
            self.load_state_installation(&selection, expected)?
        {
            if stored_signature != signature {
                return Err(Error::OperationConflict);
            }
            saved
        } else {
            let claims = expected.claims();
            transaction.execute("INSERT INTO partition_recovery_state_installations (node_id, state_digest, preparation, transfer, signature, recorded_at) VALUES (?1, ?2, 1, ?3, ?4, ?5)",
                params![claims.node_id.as_bytes().as_slice(), claims.state_digest.as_slice(), expected.encode().map_err(|_| Error::InvalidCommand)?, signature, now.get()])?;
            RecoveryStateInstallation {
                node_id: claims.node_id,
                state_digest: claims.state_digest,
                recorded_at: now,
            }
        };
        transaction.commit()?;
        Ok(receipt)
    }

    /// Requires every selected replacement node to have installed its explicitly expected package.
    /// The caller supplies the intended set; stored older packages never select it. This requires
    /// one common encrypted state digest/length across the set as well as each node signature.
    /// It proves installation attestations only, not current availability, package freshness relative to
    /// later preparation changes, policy satisfaction or authority to clear the recovery fence.
    /// # Errors
    /// Rejects missing/duplicate/unselected nodes, missing or substituted package evidence,
    /// changed signatures/preparation and persistence failures. No metadata is changed.
    pub fn require_recovery_state_installations(
        &self,
        authority: &RecoveredAuthority,
        expected: &[RecoveryStateTransfer],
    ) -> Result<(), Error> {
        let transaction = self.database.connection().unchecked_transaction()?;
        self.check_recovery_state_installations(authority, expected)?;
        transaction.commit()?;
        Ok(())
    }

    // The caller holds one read/write transaction across verification and any derived decision.
    pub(super) fn check_recovery_state_installations(
        &self,
        authority: &RecoveredAuthority,
        expected: &[RecoveryStateTransfer],
    ) -> Result<(), Error> {
        let selection = self.installation_selection(authority)?;
        if expected.len() != selection.plan.nodes.len() {
            return Err(Error::InvalidCommand);
        }
        let first = expected.first().ok_or(Error::InvalidCommand)?.claims();
        let mut nodes = BTreeSet::new();
        for transfer in expected {
            if transfer.claims().state_digest != first.state_digest
                || transfer.claims().state_length != first.state_length
                || !nodes.insert(transfer.claims().node_id)
                || self
                    .load_state_installation(&selection, transfer)?
                    .is_none()
            {
                return Err(Error::InvalidCommand);
            }
        }
        Ok(())
    }

    fn load_state_installation(
        &self,
        selection: &InstallationSelection<'_>,
        expected: &RecoveryStateTransfer,
    ) -> Result<Option<(RecoveryStateInstallation, Vec<u8>)>, Error> {
        let claims = expected.claims();
        let row = self.database.connection().query_row("SELECT transfer, signature, recorded_at FROM partition_recovery_state_installations WHERE node_id = ?1 AND state_digest = ?2",
            params![claims.node_id.as_bytes().as_slice(), claims.state_digest.as_slice()], |row| Ok((super::key_journal::bounded_blob(row, 0, 512)?, super::key_journal::bounded_blob(row, 1, 72)?, UnixMicros::new(row.get(2)?)))).optional()?;
        let Some((encoded, signature, recorded_at)) = row else {
            return Ok(None);
        };
        if encoded != expected.encode().map_err(|_| Error::InvalidCommand)? {
            return Err(Error::OperationConflict);
        }
        selection.verify(expected, &signature)?;
        if recorded_at < selection.not_before {
            return Err(Error::CorruptState);
        }
        Ok(Some((
            RecoveryStateInstallation {
                node_id: claims.node_id,
                state_digest: claims.state_digest,
                recorded_at,
            },
            signature,
        )))
    }

    fn installation_selection<'a>(
        &self,
        authority: &'a RecoveredAuthority,
    ) -> Result<InstallationSelection<'a>, Error> {
        let authorization = self.prepared_recovery_authorization(authority)?;
        let plan = self
            .load_recovery_replacement_plan(authority)?
            .ok_or(Error::InvalidCommand)?;
        let fence = super::credential_fence::read_fence(self.database.connection())?
            .ok_or(Error::InvalidCommand)?;
        if fence.recovery_id != plan.recovery_id
            || fence.manifest_digest != authorization.claims().replacement_manifest_digest
            || fence.source_revision != authorization.claims().source_revision
        {
            return Err(Error::CorruptState);
        }
        Ok(InstallationSelection {
            root: authority.root_certificate_der(),
            authorization,
            plan,
            not_before: fence.fenced_at,
        })
    }
}

// The complete sealed inventory is validated once per transaction, not once per selected node.
struct InstallationSelection<'a> {
    root: &'a [u8],
    authorization: RecoveryAuthorization,
    plan: RecoveryReplacementPlan,
    not_before: UnixMicros,
}

impl InstallationSelection<'_> {
    fn verify(&self, expected: &RecoveryStateTransfer, signature: &[u8]) -> Result<(), Error> {
        if !(8..=72).contains(&signature.len()) {
            return Err(Error::InvalidCommand);
        }
        let decoded = RecoveryStateTransfer::decode(
            self.root,
            &expected.encode().map_err(|_| Error::InvalidCommand)?,
        )
        .map_err(|_| Error::InvalidCommand)?;
        if decoded.claims().authorization != self.authorization {
            return Err(Error::InvalidCommand);
        }
        let index = self
            .plan
            .nodes
            .binary_search_by_key(&decoded.claims().node_id, |node| node.node_id)
            .map_err(|_| Error::InvalidCommand)?;
        let node = self
            .plan
            .nodes
            .get(index)
            .filter(|node| node.incarnation == decoded.claims().incarnation)
            .ok_or(Error::InvalidCommand)?;
        NodePublicIdentity::from_sec1(&node.identity_public_key)
            .map_err(|_| Error::InvalidCommand)?
            .verify_enrolment_transcript(
                &decoded
                    .installation_message()
                    .map_err(|_| Error::InvalidCommand)?,
                signature,
            )
            .map_err(|_| Error::InvalidCommand)
    }
}
