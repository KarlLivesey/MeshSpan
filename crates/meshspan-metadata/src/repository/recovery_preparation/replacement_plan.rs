// SPDX-License-Identifier: GPL-2.0-only

//! Root-authenticated replacement selection, not a normal membership transition or activation.

use std::collections::BTreeSet;

use meshspan_domain::UnixMicros;
use meshspan_recovery_bundle::RecoveredAuthority;
use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};

use super::key_journal::bounded_blob;
use crate::{AuthoritativeRepository, JoinRoles, RecoveryReplacementPlan, RepositoryError};

impl AuthoritativeRepository {
    /// Retains the exact replacement plan already authorised by the saved offline root.
    /// Rechecks the complete prepared secret inventory, gateway recipient mapping, successor
    /// membership epoch and source incarnation/name constraints before one atomic write.
    /// This does not prove remote installation, target inventory, reachability or admission.
    /// # Errors
    /// Rejects unsigned/substituted selections, incomplete keys, stale identities and IO.
    pub fn stage_recovery_replacement_plan(
        &mut self,
        recovery: &RecoveredAuthority,
        plan: &RecoveryReplacementPlan,
        staged_at: UnixMicros,
    ) -> Result<[u8; 32], RepositoryError> {
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        let bytes = plan.encode().map_err(|_| RepositoryError::InvalidCommand)?;
        let digest = self.validate_recovery_replacement_plan(recovery, plan)?;
        let existing = transaction.query_row(
            "SELECT recovery_id, manifest, manifest_digest FROM partition_recovery_replacement_plan WHERE singleton = 1",
            [], |row| Ok((bounded_blob(row, 0, 16)?, bounded_blob(row, 1, 2 * 1024 * 1024)?, bounded_blob(row, 2, 32)?)),
        ).optional()?;
        if let Some((id, manifest, stored_digest)) = existing {
            if id != plan.recovery_id.as_bytes() || manifest != bytes || stored_digest != digest {
                return Err(RepositoryError::CorruptState);
            }
        } else {
            transaction.execute(
                "INSERT INTO partition_recovery_replacement_plan(singleton, recovery_id, manifest, manifest_digest, staged_at)
                 VALUES (1, ?1, ?2, ?3, ?4)",
                params![plan.recovery_id.as_bytes().as_slice(), bytes, digest.as_slice(), staged_at.get()],
            )?;
        }
        transaction.commit()?;
        Ok(digest)
    }

    /// Loads and revalidates a saved root-authorised replacement plan without granting service.
    /// # Errors
    /// Rejects corrupted, unsigned or stale records and unavailable source evidence.
    pub fn staged_recovery_replacement_plan(
        &self,
        recovery: &RecoveredAuthority,
    ) -> Result<Option<RecoveryReplacementPlan>, RepositoryError> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let result = self.load_recovery_replacement_plan(recovery)?;
        transaction.commit()?;
        Ok(result)
    }

    // The caller owns the transaction so fencing can validate and mutate one snapshot.
    pub(super) fn load_recovery_replacement_plan(
        &self,
        recovery: &RecoveredAuthority,
    ) -> Result<Option<RecoveryReplacementPlan>, RepositoryError> {
        self.require_prepared_recovery(recovery)?;
        let stored = self.database.connection().query_row(
            "SELECT recovery_id, manifest, manifest_digest FROM partition_recovery_replacement_plan WHERE singleton = 1",
            [], |row| Ok((bounded_blob(row, 0, 16)?, bounded_blob(row, 1, 2 * 1024 * 1024)?, bounded_blob(row, 2, 32)?)),
        ).optional()?;
        stored
            .map(|(id, bytes, digest)| {
                let plan = RecoveryReplacementPlan::decode(&bytes)
                    .map_err(|_| RepositoryError::CorruptState)?;
                if id != plan.recovery_id.as_bytes()
                    || digest != self.validate_recovery_replacement_plan(recovery, &plan)?
                {
                    return Err(RepositoryError::CorruptState);
                }
                Ok(plan)
            })
            .transpose()
    }

    fn validate_recovery_replacement_plan(
        &self,
        recovery: &RecoveredAuthority,
        plan: &RecoveryReplacementPlan,
    ) -> Result<[u8; 32], RepositoryError> {
        let authorization = self.prepared_recovery_authorization(recovery)?;
        let claims = authorization.claims();
        let digest = plan.digest().map_err(|_| RepositoryError::InvalidCommand)?;
        if plan.mesh_id != claims.mesh_id
            || plan.partition_id != claims.partition_id
            || plan.recovery_id != claims.recovery_id
            || plan.recovery_epoch != claims.recovery_epoch
            || digest != claims.replacement_manifest_digest
        {
            return Err(RepositoryError::InvalidCommand);
        }
        let source = self
            .load_active_consensus_quorum_plan()
            .map_err(|_| RepositoryError::CorruptState)?
            .ok_or(RepositoryError::CorruptState)?;
        if source.membership_epoch().checked_add(1) != Some(plan.quorum.membership_epoch()) {
            return Err(RepositoryError::InvalidCommand);
        }
        self.validate_recovery_plan_recipients(recovery, plan)?;
        for node in &plan.nodes {
            self.validate_replacement_source_node(node)?;
        }
        Ok(digest)
    }

    fn validate_recovery_plan_recipients(
        &self,
        recovery: &RecoveredAuthority,
        plan: &RecoveryReplacementPlan,
    ) -> Result<(), RepositoryError> {
        let control = self
            .load_recovery_control_keys(recovery, plan.recovery_id)?
            .ok_or(RepositoryError::InvalidCommand)?;
        let mut recipients = BTreeSet::from([recovery.public_wrapping_key().as_bytes()]);
        let mut permit_recipients = recipients.clone();
        for node in &plan.nodes {
            if node.wrapping_public_key == recovery.public_wrapping_key() {
                return Err(RepositoryError::InvalidCommand);
            }
            if node.roles.bits() & JoinRoles::GATEWAY != 0 {
                recipients.insert(node.wrapping_public_key.as_bytes());
            }
            if node.roles.bits() & (JoinRoles::GATEWAY | JoinRoles::STORAGE) != 0 {
                permit_recipients.insert(node.wrapping_public_key.as_bytes());
            }
        }
        if recipients
            != control
                .online_authority_key
                .recipients
                .iter()
                .map(|r| r.recipient_public_key)
                .collect()
            || permit_recipients
                != control
                    .storage_permit_key
                    .recipients
                    .iter()
                    .map(|r| r.recipient_public_key)
                    .collect()
            || self.verify_recovery_secret_inventory(recovery, plan.recovery_id, &control)?
                != plan.secrets
        {
            return Err(RepositoryError::InvalidCommand);
        }
        let sealed: bool = self.database.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM partition_recovery_secret_inventory
             WHERE singleton = 1 AND recovery_id = ?1 AND generation_count = ?2 AND inventory_digest = ?3)",
            params![plan.recovery_id.as_bytes().as_slice(),
                i64::try_from(plan.secrets.generation_count).map_err(|_| RepositoryError::InvalidCommand)?,
                plan.secrets.digest.as_slice()], |row| row.get(0),
        )?;
        if !sealed {
            return Err(RepositoryError::InvalidCommand);
        }
        Ok(())
    }

    fn validate_replacement_source_node(
        &self,
        node: &crate::RecoveryReplacementNode,
    ) -> Result<(), RepositoryError> {
        let connection = self.database.connection();
        let previous: Option<i64> = connection
            .query_row(
                "SELECT current_incarnation FROM nodes WHERE node_id = ?1",
                [node.node_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if previous.is_some_and(|value| {
            u64::try_from(value).map_or(true, |value| node.incarnation <= value)
        }) {
            return Err(RepositoryError::InvalidCommand);
        }
        let conflict: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM nodes WHERE canonical_name = ?1 AND node_id != ?2)
             OR EXISTS(SELECT 1 FROM hosts WHERE canonical_name = ?3 AND host_id != ?4)",
            params![
                node.node_name.canonical(),
                node.node_id.as_bytes().as_slice(),
                node.host_name.canonical(),
                node.host_id.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )?;
        if conflict {
            return Err(RepositoryError::InvalidCommand);
        }
        Ok(())
    }
}
