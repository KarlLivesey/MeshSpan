// SPDX-License-Identifier: GPL-2.0-only

//! Root-authorised replacement epoch, distinct from quorum-committed membership changes.

mod install;

use super::key_journal::bounded_blob;
use crate::{AuthoritativeRepository, RecoveryReplacementPlan, RepositoryError as Error};
use meshspan_consensus::{ActiveQuorumPlan, LogPosition};
use meshspan_domain::{Revision, UnixMicros};
use meshspan_recovery_bundle::{
    RecoveryAuthorization, RecoveryConsensusAdmission, RecoveryStateTransfer,
};
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior};

pub(in crate::repository) struct Activation {
    pub(in crate::repository) permission: RecoveryConsensusAdmission,
    pub(in crate::repository) plan: RecoveryReplacementPlan,
    previous_plan: ActiveQuorumPlan,
    initial_term: u64,
    revision: Revision,
    activated_at: UnixMicros,
}

impl AuthoritativeRepository {
    /// Resolves a transferred node's public identity from its root-signed replacement manifest.
    /// This remains usable after activation and does not itself grant any service permission.
    /// # Errors
    /// Rejects another trust anchor, transfer, preparation, node or incarnation.
    pub fn recovery_replacement_node(
        &self,
        root: &[u8],
        transfer: &RecoveryStateTransfer,
    ) -> Result<crate::RecoveryReplacementNode, Error> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let decoded = RecoveryStateTransfer::decode(
            root,
            &transfer.encode().map_err(|_| Error::InvalidCommand)?,
        )
        .map_err(|_| Error::InvalidCommand)?;
        let mesh = self.local_mesh_id()?.ok_or(Error::CorruptState)?;
        if self
            .mesh_recovery_authority(mesh)?
            .ok_or(Error::CorruptState)?
            .root_certificate_der
            != root
        {
            return Err(Error::InvalidCommand);
        }
        let prepared = transaction.query_row(
            "SELECT authorization FROM partition_recovery_preparation WHERE singleton = 1",
            [],
            |row| bounded_blob(row, 0, 284),
        )?;
        if prepared
            != decoded
                .claims()
                .authorization
                .encode()
                .map_err(|_| Error::CorruptState)?
        {
            return Err(Error::InvalidCommand);
        }
        let plan = read_plan(&transaction, &decoded.claims().authorization)?;
        let node = plan
            .nodes
            .into_iter()
            .find(|node| {
                node.node_id == decoded.claims().node_id
                    && node.incarnation == decoded.claims().incarnation
            })
            .ok_or(Error::InvalidCommand)?;
        transaction.commit()?;
        Ok(node)
    }

    /// Applies an independently signed consensus permission to its installed canonical candidate.
    /// The caller must have verified the actual archive against the transfer and installed the
    /// recipient's node-owned keys. This method rechecks signatures, source, sealed projection
    /// and replacement selection, atomically installing membership, vote, revision and receipt.
    /// It preserves the backed-up applied log, discards only its later tail, and never invents a
    /// quorum-committed entry. Exact retries do not reset a subsequently advanced vote or log.
    /// This permits consensus; current target/certificate readiness remains a separate gate.
    /// # Errors
    /// Rejects mismatched permission/transfer/root, an unprojected candidate, stale selection,
    /// corrupt source state, conflicting replay or failed writes without partial activation.
    pub fn activate_recovery_consensus(
        &mut self,
        root: &[u8],
        permission: &RecoveryConsensusAdmission,
        transfer: &RecoveryStateTransfer,
        now: UnixMicros,
    ) -> Result<Revision, Error> {
        verify_delivery(root, permission, transfer)?;
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        if let Some(saved) = read_activation(&transaction)? {
            if saved.permission != *permission {
                return Err(Error::OperationConflict);
            }
            transaction.commit()?;
            return Ok(saved.revision);
        }
        let authorization = self.read_recovery_preparation(root)?;
        if authorization != permission.claims().authorization {
            return Err(Error::InvalidCommand);
        }
        let plan = read_plan(&transaction, &authorization)?;
        let revision = authorization
            .claims()
            .source_revision
            .next()
            .map_err(|_| Error::CapacityExceeded)?;
        verify_projection(&transaction, &plan, revision, now)?;
        let previous_plan = self
            .load_active_consensus_quorum_plan()
            .map_err(|_| Error::CorruptState)?
            .ok_or(Error::CorruptState)?;
        if previous_plan.membership_epoch().checked_add(1) != Some(plan.quorum.membership_epoch()) {
            return Err(Error::InvalidCommand);
        }
        let source = super::super::consensus::load_state_from_connection(
            &transaction,
            &plan.partition_id.as_bytes(),
            previous_plan.membership_epoch(),
        )
        .map_err(|_| Error::CorruptState)?;
        let initial_term = source
            .current_term
            .checked_add(1)
            .ok_or(Error::CapacityExceeded)?;
        let activation = Activation {
            permission: permission.clone(),
            plan,
            previous_plan,
            initial_term,
            revision,
            activated_at: now,
        };
        install::apply(&transaction, &activation)?;
        transaction.commit()?;
        Ok(revision)
    }

    /// Reads and verifies the durable root-origin activation without requiring the private root.
    /// Later normal consensus changes do not erase this recovery lineage.
    /// # Errors
    /// Rejects a foreign root, corrupted permission/selection or regressed applied state.
    pub fn recovery_consensus_admission(
        &self,
        root: &[u8],
    ) -> Result<Option<RecoveryConsensusAdmission>, Error> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let activation = read_activation(&transaction)?;
        if let Some(activation) = &activation {
            RecoveryConsensusAdmission::decode(
                root,
                &activation
                    .permission
                    .encode()
                    .map_err(|_| Error::CorruptState)?,
            )
            .map_err(|_| Error::InvalidCommand)?;
        }
        transaction.commit()?;
        Ok(activation.map(|value| value.permission))
    }
}

fn verify_delivery(
    root: &[u8],
    permission: &RecoveryConsensusAdmission,
    transfer: &RecoveryStateTransfer,
) -> Result<(), Error> {
    let decoded = RecoveryConsensusAdmission::decode(
        root,
        &permission.encode().map_err(|_| Error::InvalidCommand)?,
    )
    .map_err(|_| Error::InvalidCommand)?;
    let transfer =
        RecoveryStateTransfer::decode(root, &transfer.encode().map_err(|_| Error::InvalidCommand)?)
            .map_err(|_| Error::InvalidCommand)?;
    if decoded.claims().authorization != transfer.claims().authorization
        || decoded.claims().state_digest != transfer.claims().state_digest
        || decoded.claims().state_length != transfer.claims().state_length
    {
        return Err(Error::InvalidCommand);
    }
    Ok(())
}

fn read_plan(
    connection: &Connection,
    authorization: &RecoveryAuthorization,
) -> Result<RecoveryReplacementPlan, Error> {
    let (id, manifest, digest) = connection.query_row(
        "SELECT recovery_id, manifest, manifest_digest FROM partition_recovery_replacement_plan WHERE singleton = 1",
        [], |row| Ok((bounded_blob(row, 0, 16)?, bounded_blob(row, 1, 2 * 1024 * 1024)?, bounded_blob(row, 2, 32)?)),
    )?;
    let plan = RecoveryReplacementPlan::decode(&manifest).map_err(|_| Error::CorruptState)?;
    let claims = authorization.claims();
    if id != plan.recovery_id.as_bytes()
        || digest != claims.replacement_manifest_digest
        || plan.digest().map_err(|_| Error::CorruptState)? != claims.replacement_manifest_digest
        || plan.mesh_id != claims.mesh_id
        || plan.partition_id != claims.partition_id
        || plan.recovery_id != claims.recovery_id
        || plan.recovery_epoch != claims.recovery_epoch
    {
        return Err(Error::CorruptState);
    }
    Ok(plan)
}

fn verify_projection(
    connection: &Connection,
    plan: &RecoveryReplacementPlan,
    revision: Revision,
    now: UnixMicros,
) -> Result<(), Error> {
    let ready: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM partition_recovery_node_key_projection p
        JOIN partition_recovery_credential_fence f ON f.singleton = p.singleton
        WHERE p.completed = 1 AND p.manifest_digest = ?1 AND p.reserved_revision = ?2
        AND p.projected_at = f.fenced_at AND p.projected_at <= ?3
        AND f.manifest_digest = p.manifest_digest AND f.source_revision + 1 = p.reserved_revision)",
        rusqlite::params![
            plan.digest().map_err(|_| Error::CorruptState)?.as_slice(),
            super::super::apply::to_i64(revision.get())?,
            now.get()
        ],
        |row| row.get(0),
    )?;
    if !ready {
        return Err(Error::InvalidCommand);
    }
    for node in &plan.nodes {
        let matches: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM nodes n
            JOIN node_wrapping_keys w ON w.node_id = n.node_id AND w.state = 1
            WHERE n.node_id = ?1 AND n.host_id = ?2 AND n.current_incarnation = ?3
            AND n.state = 2 AND n.bootstrap_private_endpoint = ?4 AND w.public_key = ?5)",
            rusqlite::params![
                node.node_id.as_bytes().as_slice(),
                node.host_id.as_bytes().as_slice(),
                super::super::apply::to_i64(node.incarnation)?,
                &node.private_endpoint,
                node.wrapping_public_key.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )?;
        if !matches {
            return Err(Error::CorruptState);
        }
    }
    Ok(())
}

pub(in crate::repository) fn read_activation(
    connection: &Connection,
) -> Result<Option<Activation>, Error> {
    let stored = connection
        .query_row(
            "SELECT permission, previous_plan, initial_term, applied_revision, activated_at
        FROM partition_recovery_consensus_activation WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    bounded_blob(row, 0, 512)?,
                    bounded_blob(row, 1, 65536)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((encoded, previous, term, revision, now)) = stored else {
        return Ok(None);
    };
    let (root, prepared) = connection.query_row("SELECT r.root_certificate_der, p.authorization
        FROM partition_recovery_preparation p JOIN mesh_recovery_authorities r ON r.mesh_id = p.mesh_id WHERE p.singleton = 1",
        [], |row| Ok((bounded_blob(row, 0, 8192)?, bounded_blob(row, 1, 284)?)))?;
    let permission =
        RecoveryConsensusAdmission::decode(&root, &encoded).map_err(|_| Error::CorruptState)?;
    let authorization =
        RecoveryAuthorization::decode(&root, &prepared).map_err(|_| Error::CorruptState)?;
    let plan = read_plan(connection, &authorization)?;
    let previous_plan = ActiveQuorumPlan::decode(&previous).map_err(|_| Error::CorruptState)?;
    let initial_term = u64::try_from(term).map_err(|_| Error::CorruptState)?;
    let revision = Revision::new(u64::try_from(revision).map_err(|_| Error::CorruptState)?);
    if permission.claims().authorization != authorization
        || initial_term <= authorization.claims().source_log_term
        || authorization
            .claims()
            .source_revision
            .next()
            .map_err(|_| Error::CorruptState)?
            != revision
        || previous_plan.membership_epoch().checked_add(1) != Some(plan.quorum.membership_epoch())
    {
        return Err(Error::CorruptState);
    }
    let current: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM applied_state a JOIN consensus_vote v ON v.singleton = a.singleton
        WHERE a.singleton = 1 AND a.partition_id = ?1 AND v.partition_id = ?1
        AND a.state_revision >= ?2 AND a.last_log_index >= ?3 AND v.current_term >= ?4
        AND v.membership_epoch >= ?5)", rusqlite::params![plan.partition_id.as_bytes().as_slice(),
            super::super::apply::to_i64(revision.get())?, super::super::apply::to_i64(authorization.claims().source_log_index)?,
            term, super::super::apply::to_i64(plan.quorum.membership_epoch())?], |row| row.get(0))?;
    if !current {
        return Err(Error::CorruptState);
    }
    Ok(Some(Activation {
        permission,
        plan,
        previous_plan,
        initial_term,
        revision,
        activated_at: UnixMicros::new(now),
    }))
}

pub(in crate::repository) fn verify_quorum_origin(
    connection: &Connection,
    active: &ActiveQuorumPlan,
    position: LogPosition,
) -> Result<(), Error> {
    let activation = read_activation(connection)?.ok_or(Error::CorruptState)?;
    let source = activation.permission.claims().authorization.claims();
    if &activation.plan.quorum != active
        || position.index != source.source_log_index
        || position.term != source.source_log_term
    {
        return Err(Error::CorruptState);
    }
    Ok(())
}
