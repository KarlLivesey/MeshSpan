// SPDX-License-Identifier: GPL-2.0-only

//! Coordinator validation of node-probed replacement folders; no live target registration.

use meshspan_certificates::NodePublicIdentity;
use meshspan_domain::{NodeId, TargetId, UnixMicros};
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveryAuthorization};
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};

use crate::{
    AuthoritativeRepository, JoinRoles, PageLimit, PreparedRecoveryTarget, RecoveryReplacementPlan,
    RepositoryError as Error,
};

impl AuthoritativeRepository {
    /// Loads and revalidates one selected node's staged target, never an active provider.
    /// # Errors
    /// Rejects changed signatures, preparation, identities or persistence errors.
    pub fn recovery_target(
        &self,
        authority: &RecoveredAuthority,
        target: TargetId,
    ) -> Result<Option<PreparedRecoveryTarget>, Error> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let result = self.load_recovery_target(authority, target)?;
        transaction.commit()?;
        Ok(result)
    }

    pub(super) fn load_recovery_target(
        &self,
        authority: &RecoveredAuthority,
        target: TargetId,
    ) -> Result<Option<PreparedRecoveryTarget>, Error> {
        let bytes = self
            .database
            .connection()
            .query_row(
                "SELECT report FROM partition_recovery_targets WHERE target_id = ?1",
                [target.as_bytes().as_slice()],
                |row| super::key_journal::bounded_blob(row, 0, 512),
            )
            .optional()?;
        let result = if let Some(bytes) = bytes {
            let (record, signature) =
                PreparedRecoveryTarget::decode_report(authority.root_certificate_der(), &bytes)?;
            self.validate_recovery_target(authority, &record, &signature)?;
            if record.target_id != target {
                return Err(Error::CorruptState);
            }
            Some(record)
        } else {
            None
        };
        Ok(result)
    }

    /// Retains one exact selected-node target attestation in the isolated preparation.
    /// No storage target, provider component or placement route becomes active. Exact retry
    /// retains the first record; conflicting IDs or bytes never overwrite an earlier choice.
    /// # Errors
    /// Rejects foreign/stale nodes, invalid signatures, source-target reuse, unfenced state,
    /// conflicting retries, time before fencing, excessive node targets or persistence failure.
    pub fn record_recovery_target(
        &mut self,
        authority: &RecoveredAuthority,
        report: &[u8],
        now: UnixMicros,
    ) -> Result<PreparedRecoveryTarget, Error> {
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        let (target, signature) =
            PreparedRecoveryTarget::decode_report(authority.root_certificate_der(), report)?;
        self.validate_recovery_target(authority, &target, &signature)?;
        let fence =
            super::credential_fence::read_fence(&transaction)?.ok_or(Error::InvalidCommand)?;
        if now < fence.fenced_at {
            return Err(Error::InvalidCommand);
        }
        let existing: Option<Vec<u8>> = transaction.query_row(
            "SELECT report FROM partition_recovery_targets WHERE target_id = ?1 OR operation_id = ?2",
            params![target.target_id.as_bytes().as_slice(), target.operation_id.as_bytes().as_slice()],
            |row| super::key_journal::bounded_blob(row, 0, 512)).optional()?;
        if let Some(existing) = existing {
            if existing != report {
                return Err(Error::OperationConflict);
            }
        } else {
            let count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM partition_recovery_targets WHERE node_id = ?1",
                [target.node_id.as_bytes().as_slice()],
                |row| row.get(0),
            )?;
            if count >= 1024 {
                return Err(Error::InvalidCommand);
            }
            transaction.execute("INSERT INTO partition_recovery_targets (target_id, operation_id, node_id, preparation, report, recorded_at)
                VALUES (?1, ?2, ?3, 1, ?4, ?5)", params![target.target_id.as_bytes().as_slice(),
                target.operation_id.as_bytes().as_slice(), target.node_id.as_bytes().as_slice(), report, now.get()])?;
        }
        transaction.commit()?;
        Ok(target)
    }

    /// Reads a bounded target-ID-ordered page for one selected replacement node.
    /// Continue after the last returned ID; an empty page ends enumeration. Every report
    /// is reverified against this preparation, not trusted because it was previously stored.
    /// # Errors
    /// Rejects invalid preparation, another node, changed evidence or persistence failure.
    pub fn recovery_targets(
        &self,
        authority: &RecoveredAuthority,
        node: NodeId,
        after: Option<TargetId>,
        limit: PageLimit,
    ) -> Result<Vec<PreparedRecoveryTarget>, Error> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let plan = self
            .load_recovery_replacement_plan(authority)?
            .ok_or(Error::InvalidCommand)?;
        require_storage_node(&plan, node)?;
        let mut statement = transaction.prepare(
            "SELECT target_id, operation_id, report FROM partition_recovery_targets
            WHERE node_id = ?1 AND (?2 IS NULL OR target_id > ?2) ORDER BY target_id LIMIT ?3",
        )?;
        let records = statement
            .query_map(
                params![
                    node.as_bytes().as_slice(),
                    after.map(|id| id.as_bytes().to_vec()),
                    i64::try_from(limit.get()).map_err(|_| Error::InvalidCommand)?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        super::key_journal::bounded_blob(row, 2, 512)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let mut targets = Vec::with_capacity(records.len());
        for (id, operation, bytes) in records {
            let (target, signature) =
                PreparedRecoveryTarget::decode_report(authority.root_certificate_der(), &bytes)?;
            self.validate_recovery_target(authority, &target, &signature)?;
            if target.node_id != node
                || target.target_id.as_bytes().as_slice() != id
                || target.operation_id.as_bytes().as_slice() != operation
            {
                return Err(Error::CorruptState);
            }
            targets.push(target);
        }
        drop(statement);
        transaction.commit()?;
        Ok(targets)
    }

    fn validate_recovery_target(
        &self,
        authority: &RecoveredAuthority,
        target: &PreparedRecoveryTarget,
        signature: &[u8],
    ) -> Result<(), Error> {
        let authorization = self.prepared_recovery_authorization(authority)?;
        let fence = super::credential_fence::read_fence(self.database.connection())?
            .ok_or(Error::InvalidCommand)?;
        if fence.recovery_id != authorization.claims().recovery_id
            || fence.manifest_digest != authorization.claims().replacement_manifest_digest
            || fence.source_revision != authorization.claims().source_revision
        {
            return Err(Error::CorruptState);
        }
        let plan = self
            .load_recovery_replacement_plan(authority)?
            .ok_or(Error::InvalidCommand)?;
        verify_target(
            self.database.connection(),
            &authorization,
            &plan,
            target,
            signature,
        )
    }
}

// The projection caller already validated the source plan before changing canonical nodes.
// Reuse the identical target/signature checks without reinterpreting that changed source.
pub(super) fn verify_target(
    connection: &Connection,
    authorization: &RecoveryAuthorization,
    plan: &RecoveryReplacementPlan,
    target: &PreparedRecoveryTarget,
    signature: &[u8],
) -> Result<(), Error> {
    let node = require_storage_node(plan, target.node_id)?;
    if &target.authorization != authorization || target.incarnation != node.incarnation {
        return Err(Error::InvalidCommand);
    }
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM storage_targets WHERE target_id = ?1)",
        [target.target_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if exists {
        return Err(Error::InvalidCommand);
    }
    NodePublicIdentity::from_sec1(&node.identity_public_key)
        .map_err(|_| Error::InvalidCommand)?
        .verify_enrolment_transcript(&target.installation_message()?, signature)
        .map_err(|_| Error::InvalidCommand)
}

fn require_storage_node(
    plan: &RecoveryReplacementPlan,
    node: NodeId,
) -> Result<&crate::RecoveryReplacementNode, Error> {
    plan.nodes
        .iter()
        .find(|candidate| {
            candidate.node_id == node && candidate.roles.bits() & JoinRoles::STORAGE != 0
        })
        .ok_or(Error::InvalidCommand)
}
