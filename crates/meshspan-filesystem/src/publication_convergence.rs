// SPDX-License-Identifier: GPL-2.0-only

//! Durable convergence attempts: immutable application precedes authoritative head publication.

#[path = "publication_convergence/repository.rs"]
mod repository;

use meshspan_domain::{BranchId, NamespaceCommitId, ObjectRevisionId, OperationId, VolumeId};
use rusqlite::{TransactionBehavior, params};

use crate::publication::namespace;
use crate::{
    NamespaceReconciliationApplication, NamespaceReconciliationReceipt, PublicationError,
    ReconciliationFrontier, ReconciliationLimits, ReconciliationStoreError,
    VersionPublicationStore,
};

/// Restart-stable attempt whose identity is saved before applying a merge or contacting authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceConvergenceJob {
    pub(crate) volume_id: VolumeId,
    pub(crate) expected: Option<NamespaceCommitId>,
    pub(crate) selected: NamespaceCommitId,
    pub(crate) merge_required: bool,
    pub(crate) application: NamespaceReconciliationApplication,
    pub(crate) heads: Vec<NamespaceCommitId>,
}

impl NamespaceConvergenceJob {
    /// Volume whose authority is responsible for this attempt.
    #[must_use]
    pub const fn volume_id(&self) -> VolumeId {
        self.volume_id
    }
    /// Exact authoritative head on which the attempt is conditional.
    #[must_use]
    pub const fn expected_head(&self) -> Option<NamespaceCommitId> {
        self.expected
    }
    /// Immutable head selected by this attempt, not yet a claim of convergence.
    #[must_use]
    pub const fn selected_head(&self) -> NamespaceCommitId {
        self.selected
    }
    /// Frozen operation, actor, retention policy and time for application and authority retries.
    #[must_use]
    pub const fn application(&self) -> NamespaceReconciliationApplication {
        self.application
    }
}

/// Exact durable source evidence; neither variant grants converged-head authority itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceConvergenceEvidence {
    /// A validated immutable branch publication, including one imported from an admitted peer.
    Publication {
        /// Original source operation, not the convergence attempt operation.
        operation_id: OperationId,
        /// Original mutation's canonical request identity.
        request_digest: [u8; 32],
        /// Canonical record identity binding the complete immutable publication.
        result_digest: [u8; 32],
    },
    /// A fully applied and locally verified deterministic reconciliation.
    Reconciliation(NamespaceReconciliationReceipt),
}

/// Immutable root and proof ready for a separate metadata compare-and-swap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceConvergenceOutcome {
    /// Root revision bound to the job's selected commit.
    pub root_object_revision_id: ObjectRevisionId,
    /// Durable evidence required by the authoritative publisher.
    pub evidence: NamespaceConvergenceEvidence,
}

impl VersionPublicationStore {
    /// Retains a fully received publication for convergence and onward delivery.
    /// Call only after its required content-layout receipts have been durably accepted.
    /// Does not move a connector branch; incomparable heads remain pending.
    ///
    /// # Errors
    /// Rejects unknown/mismatched roots and propagates persistence failures.
    pub fn retain_received_namespace_head(
        &mut self,
        branch: BranchId,
        volume: VolumeId,
        commit: NamespaceCommitId,
        root: ObjectRevisionId,
    ) -> Result<(), PublicationError> {
        if self.namespace_commit_root(volume, commit)? != root {
            return Err(PublicationError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("INSERT OR IGNORE INTO namespace_delivery_journal(namespace_commit_id, branch_id) VALUES (?1, ?2)",
            params![commit.as_bytes().as_slice(), branch.as_bytes().as_slice()])?;
        transaction.execute("INSERT OR IGNORE INTO namespace_convergence_frontier(volume_id, namespace_commit_id) VALUES (?1, ?2)",
            params![volume.as_bytes().as_slice(), commit.as_bytes().as_slice()])?;
        transaction.commit()?;
        Ok(())
    }

    /// Saves one bounded attempt or resumes its exact persisted identity.
    /// First publication anchors the volume; competing branches remain queued for later merges.
    ///
    /// # Errors
    /// Rejects incomplete/corrupt history, invalid application inputs and database failures.
    pub fn prepare_namespace_convergence(
        &mut self,
        volume: VolumeId,
        expected: Option<NamespaceCommitId>,
        application: NamespaceReconciliationApplication,
    ) -> Result<Option<NamespaceConvergenceJob>, ReconciliationStoreError> {
        if let Some(job) = repository::load(&self.connection, volume)? {
            return Ok(Some(job));
        }
        if let Some(current) = expected {
            self.namespace_commit_root(volume, current)?;
            repository::prune(&self.connection, volume, current)?;
        }
        let heads = repository::frontier(&self.connection, volume)?;
        if heads.is_empty() {
            return Ok(None);
        }
        let frontier = ReconciliationFrontier {
            converged_head: expected,
            eligible_heads: heads,
        };
        let plan = self.plan_reconciliation(&frontier, ReconciliationLimits::DEFAULT)?;
        let Some(first) = plan.merge_parents().first().copied() else {
            return Ok(None);
        };
        if Some(first) == expected && plan.merge_parents().len() == 1 {
            repository::prune(&self.connection, volume, first)?;
            return Ok(None);
        }
        let merge_required = expected.is_some() && plan.merge_parents().len() > 1;
        let job = NamespaceConvergenceJob {
            volume_id: volume,
            expected,
            selected: if merge_required {
                application.namespace_commit_id
            } else {
                first
            },
            merge_required,
            application,
            heads: frontier.eligible_heads,
        };
        repository::save(&mut self.connection, &job)?;
        Ok(Some(job))
    }

    /// Applies the saved immutable work without changing authoritative or connector heads.
    ///
    /// # Errors
    /// Rejects a substituted attempt, invalid replay or any persistence failure.
    pub fn apply_namespace_convergence(
        &mut self,
        job: &NamespaceConvergenceJob,
    ) -> Result<NamespaceConvergenceOutcome, ReconciliationStoreError> {
        repository::require_exact(&self.connection, job)?;
        if job.merge_required {
            let frontier = ReconciliationFrontier {
                converged_head: job.expected,
                eligible_heads: job.heads.clone(),
            };
            let prepared =
                self.prepare_namespace_reconciliation(&frontier, ReconciliationLimits::DEFAULT)?;
            let receipt = self.apply_namespace_reconciliation(job.application, &prepared)?;
            Ok(NamespaceConvergenceOutcome {
                root_object_revision_id: receipt.root_object_revision_id,
                evidence: NamespaceConvergenceEvidence::Reconciliation(receipt),
            })
        } else {
            let record = namespace::transfer::export::load_commit_record(
                &self.connection,
                job.volume_id,
                job.selected,
            )?;
            let canonical = crate::NamespaceHistoryCommitRecord::from_commit(&record)
                .map_err(|_| PublicationError::Corrupt)?;
            Ok(NamespaceConvergenceOutcome {
                root_object_revision_id: record.commit.root_object_revision_id,
                evidence: NamespaceConvergenceEvidence::Publication {
                    operation_id: record.commit.operation_id,
                    request_digest: record.commit.request_digest,
                    result_digest: canonical
                        .convergence_digest()
                        .map_err(|_| PublicationError::Corrupt)?,
                },
            })
        }
    }

    /// Retires only the exact saved attempt after authority rejects its base or confirms it.
    /// Pending branch publications are retained. Authority confirmation must precede `confirmed`.
    ///
    /// # Errors
    /// Rejects substituted attempts and any persistence failure.
    pub fn finish_namespace_convergence(
        &mut self,
        job: &NamespaceConvergenceJob,
        confirmed: bool,
    ) -> Result<(), PublicationError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        repository::require_exact(&transaction, job)?;
        if confirmed {
            repository::prune(&transaction, job.volume_id, job.selected)?;
        }
        transaction.execute(
            "DELETE FROM namespace_convergence_jobs WHERE volume_id = ?1",
            [job.volume_id.as_bytes().as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }
}
