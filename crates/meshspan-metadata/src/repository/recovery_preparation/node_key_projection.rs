// SPDX-License-Identifier: GPL-2.0-only

//! Canonical node/key records in a disposable runtime candidate, still admission-fenced.

mod nodes;
mod providers;
mod secrets;

use super::{RecoveryControlKeys, RecoveryCredentialFence};
use crate::{AuthoritativeRepository, RecoveryReplacementPlan, RepositoryError as Error};
use meshspan_domain::Revision;
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveryAuthorization};
use rusqlite::{Transaction, TransactionBehavior, params};

struct Projection {
    authorization: RecoveryAuthorization,
    plan: RecoveryReplacementPlan,
    control: RecoveryControlKeys,
    fence: RecoveryCredentialFence,
    revision: Revision,
}

impl AuthoritativeRepository {
    /// Materialises selected nodes, certificates and complete key recipients in a disposable
    /// recovery snapshot. Export node key bundles BEFORE calling this: source planning deliberately
    /// ceases to apply once canonical nodes/key heads have changed. Retained ciphertext remains
    /// byte-identical; source node keys are retired and envelopes replaced, never accumulated.
    /// Collected folder targets become canonical providers with offline-root creation provenance.
    /// The returned revision is reserved, NOT applied. Consensus and service admission remain
    /// fenced; this does not install membership or claim present certificate/storage health.
    /// The coordinator must keep its original preparation and deliver a new signed state package.
    /// # Errors
    /// Rejects incomplete/unfenced preparation, altered source/material, reused stale keys,
    /// repeat projection, timestamp conflicts and failed writes. All changes roll back together.
    pub fn materialise_recovery_node_keys(
        &mut self,
        authority: &RecoveredAuthority,
    ) -> Result<Revision, Error> {
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        let projection = self.node_key_projection(authority)?;
        transaction.execute(
            "INSERT INTO partition_recovery_node_key_projection
            (singleton, manifest_digest, reserved_revision, projected_at, completed)
            VALUES (1, ?1, ?2, ?3, 0)",
            params![
                projection.fence.manifest_digest.as_slice(),
                super::super::apply::to_i64(projection.revision.get())?,
                projection.fence.fenced_at.get()
            ],
        )?;
        nodes::install(self, &transaction, authority, &projection)?;
        providers::install(&transaction, authority.root_certificate_der(), &projection)?;
        secrets::install(self, &transaction, authority, &projection)?;
        transaction.execute(
            "UPDATE partition_recovery_node_key_projection SET completed = 1 WHERE singleton = 1",
            [],
        )?;
        transaction.commit()?;
        Ok(projection.revision)
    }

    fn node_key_projection(&self, authority: &RecoveredAuthority) -> Result<Projection, Error> {
        let plan = self
            .load_recovery_replacement_plan(authority)?
            .ok_or(Error::InvalidCommand)?;
        let authorization = self.prepared_recovery_authorization(authority)?;
        let control = self
            .load_recovery_control_keys(authority, plan.recovery_id)?
            .ok_or(Error::InvalidCommand)?;
        let fence = super::credential_fence::read_fence(self.database.connection())?
            .ok_or(Error::InvalidCommand)?;
        if fence.recovery_id != plan.recovery_id
            || fence.manifest_digest != authorization.claims().replacement_manifest_digest
            || fence.source_revision != authorization.claims().source_revision
            || fence.online_generation != control.online_authority_key.secret.context.generation()
            || fence.permit_generation != control.storage_permit_key.secret.context.generation()
        {
            return Err(Error::CorruptState);
        }
        let future: bool = self.database.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM (
            SELECT admitted_at AS created FROM nodes UNION ALL SELECT created_at FROM hosts
            UNION ALL SELECT registered_at FROM node_wrapping_keys
            UNION ALL SELECT registered_at FROM secret_wrapping_recipients
            UNION ALL SELECT created_at FROM online_certificate_authorities
            UNION ALL SELECT admitted_at FROM storage_targets)
            WHERE created > ?1)",
            [fence.fenced_at.get()],
            |row| row.get(0),
        )?;
        if future {
            return Err(Error::InvalidCommand);
        }
        let revision = fence
            .source_revision
            .next()
            .map_err(|_| Error::CapacityExceeded)?;
        Ok(Projection {
            authorization,
            plan,
            control,
            fence,
            revision,
        })
    }
}
